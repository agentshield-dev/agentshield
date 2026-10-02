package state

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

type ResourceQuery struct {
	Search    string
	Kind      string
	Namespace string
	After     string
	Limit     int
}

type ResourcePage struct {
	GraphSHA256 string
	Resources   []graph.Resource
	Next        string
}

type ResourceDetail struct {
	GraphSHA256   string
	Resource      graph.Resource
	Relationships []graph.Relationship
	Facets        []graph.Facet
}

type RelationshipQuery struct {
	Search     string
	Predicate  string
	ResourceID string
	After      string
	Limit      int
}

type RelationshipPage struct {
	GraphSHA256   string
	Relationships []graph.Relationship
	Next          string
}

type RelationshipDetail struct {
	GraphSHA256  string
	Relationship graph.Relationship
	Subject      graph.Resource
	Object       graph.Resource
}

func (s *Store) QueryResources(ctx context.Context, query ResourceQuery) (ResourcePage, error) {
	if query.Limit < 1 || query.Limit > 100 {
		query.Limit = 25
	}
	tx, digest, err := s.projectionRead(ctx)
	if err != nil {
		return ResourcePage{}, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT resource_id::text, kind, assertions
		FROM current_resources
		WHERE ($1='' OR kind=$1) AND ($2='' OR COALESCE(attributes->>'namespace', attributes->>'kubernetes/namespace', attributes->>'istio/namespace')=$2)
		  AND ($3='' OR lower(resource_id::text || ' ' || kind || ' ' || display_name || ' ' || attributes::text || ' ' || assertions::text) LIKE '%' || $3 || '%')
		  AND ($4='' OR resource_id > $4::uuid)
		ORDER BY resource_id LIMIT $5`, query.Kind, query.Namespace, strings.ToLower(strings.TrimSpace(query.Search)), query.After, query.Limit+1)
	if err != nil {
		return ResourcePage{}, fmt.Errorf("query current resources: %w", err)
	}
	defer rows.Close()
	page := ResourcePage{GraphSHA256: digest}
	for rows.Next() {
		resource, err := scanCurrentResource(rows)
		if err != nil {
			return ResourcePage{}, err
		}
		page.Resources = append(page.Resources, resource)
	}
	if err := rows.Err(); err != nil {
		return ResourcePage{}, err
	}
	if len(page.Resources) > query.Limit {
		page.Next = page.Resources[query.Limit-1].ID
		page.Resources = page.Resources[:query.Limit]
	}
	return page, tx.Commit(ctx)
}

func (s *Store) GetResourceDetail(ctx context.Context, resourceID string) (ResourceDetail, error) {
	tx, digest, err := s.projectionRead(ctx)
	if err != nil {
		return ResourceDetail{}, err
	}
	defer tx.Rollback(ctx)
	resource, err := queryCurrentResource(ctx, tx, resourceID)
	if err != nil {
		return ResourceDetail{}, err
	}
	detail := ResourceDetail{GraphSHA256: digest, Resource: resource}
	rows, err := tx.Query(ctx, `SELECT relationship_id::text, subject_id::text, predicate, object_id::text, qualifier, resolution_status, assertions FROM current_relationships WHERE subject_id=$1 OR object_id=$1 ORDER BY relationship_id`, resourceID)
	if err != nil {
		return ResourceDetail{}, err
	}
	for rows.Next() {
		item, err := scanCurrentRelationship(rows)
		if err != nil {
			rows.Close()
			return ResourceDetail{}, err
		}
		detail.Relationships = append(detail.Relationships, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ResourceDetail{}, err
	}
	rows, err = tx.Query(ctx, `SELECT facet_id::text, resource_id::text, kind, facet_key, resolution_status, assertions FROM current_facets WHERE resource_id=$1 ORDER BY facet_id`, resourceID)
	if err != nil {
		return ResourceDetail{}, err
	}
	for rows.Next() {
		item, err := scanCurrentFacet(rows)
		if err != nil {
			rows.Close()
			return ResourceDetail{}, err
		}
		detail.Facets = append(detail.Facets, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ResourceDetail{}, err
	}
	return detail, tx.Commit(ctx)
}

func (s *Store) QueryRelationships(ctx context.Context, query RelationshipQuery) (RelationshipPage, error) {
	if query.Limit < 1 || query.Limit > 100 {
		query.Limit = 25
	}
	tx, digest, err := s.projectionRead(ctx)
	if err != nil {
		return RelationshipPage{}, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT relationship_id::text, subject_id::text, predicate, object_id::text, qualifier, resolution_status, assertions
		FROM current_relationships
		WHERE ($1='' OR predicate=$1) AND ($2='' OR subject_id=$2::uuid OR object_id=$2::uuid)
		  AND ($3='' OR lower(relationship_id::text || ' ' || predicate || ' ' || subject_id::text || ' ' || object_id::text || ' ' || qualifier) LIKE '%' || $3 || '%')
		  AND ($4='' OR relationship_id > $4::uuid)
		ORDER BY relationship_id LIMIT $5`, query.Predicate, query.ResourceID, strings.ToLower(strings.TrimSpace(query.Search)), query.After, query.Limit+1)
	if err != nil {
		return RelationshipPage{}, fmt.Errorf("query current relationships: %w", err)
	}
	defer rows.Close()
	page := RelationshipPage{GraphSHA256: digest}
	for rows.Next() {
		item, err := scanCurrentRelationship(rows)
		if err != nil {
			return RelationshipPage{}, err
		}
		page.Relationships = append(page.Relationships, item)
	}
	if err := rows.Err(); err != nil {
		return RelationshipPage{}, err
	}
	if len(page.Relationships) > query.Limit {
		page.Next = page.Relationships[query.Limit-1].ID
		page.Relationships = page.Relationships[:query.Limit]
	}
	return page, tx.Commit(ctx)
}

func (s *Store) GetRelationshipDetail(ctx context.Context, relationshipID string) (RelationshipDetail, error) {
	tx, digest, err := s.projectionRead(ctx)
	if err != nil {
		return RelationshipDetail{}, err
	}
	defer tx.Rollback(ctx)
	relationship, err := queryCurrentRelationship(ctx, tx, relationshipID)
	if err != nil {
		return RelationshipDetail{}, err
	}
	if relationship.ResolutionStatus == graph.ResolutionUnresolved {
		return RelationshipDetail{}, errors.New("relationship endpoint is unresolved")
	}
	subject, err := queryCurrentResource(ctx, tx, relationship.SubjectID)
	if err != nil {
		return RelationshipDetail{}, err
	}
	object, err := queryCurrentResource(ctx, tx, relationship.ObjectID)
	if err != nil {
		return RelationshipDetail{}, err
	}
	return RelationshipDetail{GraphSHA256: digest, Relationship: relationship, Subject: subject, Object: object}, tx.Commit(ctx)
}

func (s *Store) projectionRead(ctx context.Context) (pgx.Tx, string, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, "", err
	}
	var digest []byte
	if err := tx.QueryRow(ctx, `SELECT digest FROM graph_state WHERE singleton=true`).Scan(&digest); err != nil {
		_ = tx.Rollback(ctx)
		return nil, "", err
	}
	if len(digest) == 0 {
		_ = tx.Rollback(ctx)
		return nil, "", ErrNotMaterialized
	}
	return tx, hex.EncodeToString(digest), nil
}

func queryCurrentResource(ctx context.Context, tx pgx.Tx, id string) (graph.Resource, error) {
	resource, err := scanCurrentResource(tx.QueryRow(ctx, `SELECT resource_id::text, kind, assertions FROM current_resources WHERE resource_id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return graph.Resource{}, ErrGraphEntityNotFound
	}
	return resource, err
}

func queryCurrentRelationship(ctx context.Context, tx pgx.Tx, id string) (graph.Relationship, error) {
	item, err := scanCurrentRelationship(tx.QueryRow(ctx, `SELECT relationship_id::text, subject_id::text, predicate, object_id::text, qualifier, resolution_status, assertions FROM current_relationships WHERE relationship_id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return graph.Relationship{}, ErrGraphEntityNotFound
	}
	return item, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanCurrentResource(row rowScanner) (graph.Resource, error) {
	var item graph.Resource
	var assertions []byte
	if err := row.Scan(&item.ID, &item.Kind, &assertions); err != nil {
		return item, err
	}
	if err := json.Unmarshal(assertions, &item.Assertions); err != nil {
		return item, err
	}
	if len(item.Assertions) == 0 {
		return item, errors.New("current resource has no assertions")
	}
	item.Identity = item.Assertions[0].Claim
	return item, nil
}

func scanCurrentRelationship(row rowScanner) (graph.Relationship, error) {
	var item graph.Relationship
	var predicate, status string
	var assertions []byte
	if err := row.Scan(&item.ID, &item.SubjectID, &predicate, &item.ObjectID, &item.Qualifier, &status, &assertions); err != nil {
		return item, err
	}
	item.Predicate = graph.Predicate(predicate)
	item.ResolutionStatus = parseResolution(status)
	return item, json.Unmarshal(assertions, &item.Assertions)
}

func scanCurrentFacet(row rowScanner) (graph.Facet, error) {
	var item graph.Facet
	var status string
	var assertions []byte
	if err := row.Scan(&item.ID, &item.ResourceID, &item.Kind, &item.Key, &status, &assertions); err != nil {
		return item, err
	}
	item.ResolutionStatus = parseResolution(status)
	return item, json.Unmarshal(assertions, &item.Assertions)
}

func parseResolution(value string) graph.ResolutionStatus {
	if value == "unresolved" {
		return graph.ResolutionUnresolved
	}
	return graph.ResolutionResolved
}
