package state

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type projectionScope struct {
	resources     map[string]struct{}
	facets        map[string]struct{}
	relationships map[string]struct{}
}

const projectionClosureLimit = 1024

func affectedProjectionScope(ctx context.Context, tx pgx.Tx, delta membershipDelta) (projectionScope, error) {
	scope := projectionScope{resources: map[string]struct{}{}, facets: map[string]struct{}{}, relationships: map[string]struct{}{}}
	for _, change := range append(slices.Clone(delta.addedChanges), delta.retractedChanges...) {
		switch change.Entity.EntityType {
		case assertionResource:
			scope.resources[change.Entity.ID] = struct{}{}
		case assertionFacet:
			scope.facets[change.Entity.ID] = struct{}{}
			scope.resources[change.Entity.ResourceID] = struct{}{}
		case assertionRelationship:
			scope.relationships[change.Entity.ID] = struct{}{}
			scope.resources[change.Entity.SubjectID] = struct{}{}
			scope.resources[change.Entity.ObjectID] = struct{}{}
		}
	}
	if len(scope.resources)+len(scope.facets)+len(scope.relationships) > projectionClosureLimit {
		return scope, nil
	}
	resourceIDs, err := projectionSetUUIDs(scope.resources)
	if err != nil || len(resourceIDs) == 0 {
		return scope, err
	}
	rows, err := tx.Query(ctx, `
		SELECT facet_id::text FROM current_facets WHERE resource_id=ANY($1)
		UNION
		SELECT DISTINCT a.facet_id::text FROM contribution_current_assertions m
		JOIN facet_assertions a ON m.assertion_type='facet' AND a.assertion_id=m.assertion_id
		WHERE a.resource_id=ANY($1)`, resourceIDs)
	if err != nil {
		return scope, fmt.Errorf("expand affected facets: %w", err)
	}
	if err := addProjectionIDs(rows, scope.facets); err != nil {
		return scope, err
	}
	rows, err = tx.Query(ctx, `
		SELECT relationship_id::text FROM current_relationships WHERE subject_id=ANY($1) OR object_id=ANY($1)
		UNION
		SELECT DISTINCT a.relationship_id::text FROM contribution_current_assertions m
		JOIN relationship_assertions a ON m.assertion_type='relationship' AND a.assertion_id=m.assertion_id
		WHERE a.subject_id=ANY($1) OR a.object_id=ANY($1)`, resourceIDs)
	if err != nil {
		return scope, fmt.Errorf("expand affected relationships: %w", err)
	}
	if err := addProjectionIDs(rows, scope.relationships); err != nil {
		return scope, err
	}
	return scope, nil
}

func addProjectionIDs(rows pgx.Rows, target map[string]struct{}) error {
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		target[id] = struct{}{}
	}
	return rows.Err()
}

func reconcileProjectionDelta(ctx context.Context, tx pgx.Tx, compiler *graph.Compiler, delta membershipDelta, now time.Time, unresolvedRetention time.Duration) ([]graph.Resource, error) {
	scope, err := affectedProjectionScope(ctx, tx, delta)
	if err != nil {
		return nil, err
	}
	if len(scope.resources)+len(scope.facets)+len(scope.relationships) > projectionClosureLimit {
		return reconcileFullProjection(ctx, tx, compiler, now, unresolvedRetention)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan=off; SET LOCAL enable_hashjoin=off; SET LOCAL enable_mergejoin=off`); err != nil {
		return nil, fmt.Errorf("select affected graph query plan: %w", err)
	}
	before, err := readScopedProjection(ctx, tx, scope)
	if err != nil {
		return nil, err
	}
	input, err := collectScopedInput(ctx, tx, before, delta)
	if err != nil {
		return nil, err
	}
	compiled, err := compiler.Compile(input)
	if err != nil {
		return nil, fmt.Errorf("compile affected graph: %w", err)
	}
	after := filterScopedSnapshot(compiled, scope)
	changedResources, _ := projectionChanges(before.Resources, after.Resources, func(item graph.Resource) string { return item.ID })
	if err := replaceCurrentProjection(ctx, tx, before, after, now, unresolvedRetention); err != nil {
		return nil, err
	}
	return changedResources, nil
}

func reconcileFullProjection(ctx context.Context, tx pgx.Tx, compiler *graph.Compiler, now time.Time, unresolvedRetention time.Duration) ([]graph.Resource, error) {
	before, err := readFullProjection(ctx, tx)
	if err != nil {
		return nil, err
	}
	input, err := collectActiveInput(ctx, tx)
	if err != nil {
		return nil, err
	}
	after, err := compiler.Compile(input)
	if err != nil {
		return nil, fmt.Errorf("compile current graph: %w", err)
	}
	changedResources, _ := projectionChanges(before.Resources, after.Resources, func(item graph.Resource) string { return item.ID })
	if err := replaceCurrentProjection(ctx, tx, before, after, now, unresolvedRetention); err != nil {
		return nil, err
	}
	return changedResources, nil
}

func readFullProjection(ctx context.Context, tx pgx.Tx) (graph.Snapshot, error) {
	var snapshot graph.Snapshot
	rows, err := tx.Query(ctx, `SELECT resource_id::text, kind, assertions FROM current_resources ORDER BY resource_id`)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		item, err := scanCurrentResource(rows)
		if err != nil {
			rows.Close()
			return snapshot, err
		}
		snapshot.Resources = append(snapshot.Resources, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return snapshot, err
	}
	rows, err = tx.Query(ctx, `SELECT resource_id::text, assertions FROM assertion_conflicts ORDER BY resource_id`)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		var conflict graph.AssertionConflict
		var assertions []byte
		if err := rows.Scan(&conflict.ResourceID, &assertions); err != nil {
			rows.Close()
			return snapshot, err
		}
		if err := json.Unmarshal(assertions, &conflict.Assertions); err != nil {
			rows.Close()
			return snapshot, err
		}
		snapshot.Conflicts = append(snapshot.Conflicts, conflict)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return snapshot, err
	}
	rows, err = tx.Query(ctx, `SELECT facet_id::text, resource_id::text, kind, facet_key, resolution_status, assertions FROM current_facets ORDER BY facet_id`)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		item, err := scanCurrentFacet(rows)
		if err != nil {
			rows.Close()
			return snapshot, err
		}
		snapshot.Facets = append(snapshot.Facets, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return snapshot, err
	}
	rows, err = tx.Query(ctx, `SELECT relationship_id::text, subject_id::text, predicate, object_id::text, qualifier, resolution_status, assertions FROM current_relationships ORDER BY relationship_id`)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		item, err := scanCurrentRelationship(rows)
		if err != nil {
			rows.Close()
			return snapshot, err
		}
		snapshot.Relationships = append(snapshot.Relationships, item)
	}
	rows.Close()
	return snapshot, rows.Err()
}

func readScopedProjection(ctx context.Context, tx pgx.Tx, scope projectionScope) (graph.Snapshot, error) {
	var snapshot graph.Snapshot
	resourceIDs, err := projectionSetUUIDs(scope.resources)
	if err != nil {
		return snapshot, err
	}
	if len(resourceIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT resource_id::text, kind, assertions FROM current_resources WHERE resource_id=ANY($1) ORDER BY resource_id`, resourceIDs)
		if err != nil {
			return snapshot, err
		}
		for rows.Next() {
			item, err := scanCurrentResource(rows)
			if err != nil {
				rows.Close()
				return snapshot, err
			}
			snapshot.Resources = append(snapshot.Resources, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return snapshot, err
		}
		rows, err = tx.Query(ctx, `SELECT resource_id::text, assertions FROM assertion_conflicts WHERE resource_id=ANY($1) ORDER BY resource_id`, resourceIDs)
		if err != nil {
			return snapshot, err
		}
		for rows.Next() {
			var conflict graph.AssertionConflict
			var assertions []byte
			if err := rows.Scan(&conflict.ResourceID, &assertions); err != nil {
				rows.Close()
				return snapshot, err
			}
			if err := json.Unmarshal(assertions, &conflict.Assertions); err != nil {
				rows.Close()
				return snapshot, err
			}
			snapshot.Conflicts = append(snapshot.Conflicts, conflict)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return snapshot, err
		}
	}
	facetIDs, err := projectionSetUUIDs(scope.facets)
	if err != nil {
		return snapshot, err
	}
	if len(facetIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT facet_id::text, resource_id::text, kind, facet_key, resolution_status, assertions FROM current_facets WHERE facet_id=ANY($1) ORDER BY facet_id`, facetIDs)
		if err != nil {
			return snapshot, err
		}
		for rows.Next() {
			item, err := scanCurrentFacet(rows)
			if err != nil {
				rows.Close()
				return snapshot, err
			}
			snapshot.Facets = append(snapshot.Facets, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return snapshot, err
		}
	}
	relationshipIDs, err := projectionSetUUIDs(scope.relationships)
	if err != nil {
		return snapshot, err
	}
	if len(relationshipIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT relationship_id::text, subject_id::text, predicate, object_id::text, qualifier, resolution_status, assertions FROM current_relationships WHERE relationship_id=ANY($1) ORDER BY relationship_id`, relationshipIDs)
		if err != nil {
			return snapshot, err
		}
		for rows.Next() {
			item, err := scanCurrentRelationship(rows)
			if err != nil {
				rows.Close()
				return snapshot, err
			}
			snapshot.Relationships = append(snapshot.Relationships, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return snapshot, err
		}
	}
	return snapshot, nil
}

func collectScopedInput(ctx context.Context, tx pgx.Tx, before graph.Snapshot, delta membershipDelta) (graph.Input, error) {
	input := inputFromSnapshot(before)
	dependencies := map[string]struct{}{}
	for _, facet := range before.Facets {
		dependencies[facet.ResourceID] = struct{}{}
	}
	for _, relationship := range before.Relationships {
		dependencies[relationship.SubjectID] = struct{}{}
		dependencies[relationship.ObjectID] = struct{}{}
	}
	for _, resource := range before.Resources {
		delete(dependencies, resource.ID)
	}
	dependencyIDs, err := projectionSetUUIDs(dependencies)
	if err != nil {
		return graph.Input{}, err
	}
	if len(dependencyIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT resource_id::text, kind, assertions FROM current_resources WHERE resource_id=ANY($1)`, dependencyIDs)
		if err != nil {
			return graph.Input{}, err
		}
		for rows.Next() {
			resource, err := scanCurrentResource(rows)
			if err != nil {
				rows.Close()
				return graph.Input{}, err
			}
			input.Resources = append(input.Resources, resource.Assertions...)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return graph.Input{}, err
		}
	}
	removed := map[assertionRef]struct{}{}
	for _, ref := range delta.retracted {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM contribution_current_assertions WHERE assertion_type=$1 AND assertion_id=$2)`, ref.Type, ref.ID).Scan(&active); err != nil {
			return graph.Input{}, err
		}
		if !active {
			removed[ref] = struct{}{}
		}
	}
	filter := func(values int, reference func(int) (assertionRef, error), keep func(int)) error {
		for index := range values {
			ref, err := reference(index)
			if err != nil {
				return err
			}
			if _, drop := removed[ref]; !drop {
				keep(index)
			}
		}
		return nil
	}
	resources := make([]graph.ResourceAssertion, 0, len(input.Resources))
	if err := filter(len(input.Resources), func(index int) (assertionRef, error) {
		return assertionReference(assertionResource, input.Resources[index])
	}, func(index int) { resources = append(resources, input.Resources[index]) }); err != nil {
		return graph.Input{}, err
	}
	facets := make([]graph.FacetAssertion, 0, len(input.Facets))
	if err := filter(len(input.Facets), func(index int) (assertionRef, error) { return assertionReference(assertionFacet, input.Facets[index]) }, func(index int) { facets = append(facets, input.Facets[index]) }); err != nil {
		return graph.Input{}, err
	}
	relationships := make([]graph.RelationshipAssertion, 0, len(input.Relationships))
	if err := filter(len(input.Relationships), func(index int) (assertionRef, error) {
		return assertionReference(assertionRelationship, input.Relationships[index])
	}, func(index int) { relationships = append(relationships, input.Relationships[index]) }); err != nil {
		return graph.Input{}, err
	}
	input.Resources, input.Facets, input.Relationships = resources, facets, relationships
	added := map[string][]string{}
	for _, ref := range delta.added {
		added[ref.Type] = append(added[ref.Type], ref.ID)
	}
	if ids := added[assertionResource]; len(ids) > 0 {
		query := `SELECT i.scheme_group, i.scheme_version, i.scheme_kind, i.authority_id, i.immutable_key, a.kind, a.display_name, a.attributes, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids FROM resource_assertions a JOIN resource_identities i ON i.resource_id=a.resource_id WHERE a.assertion_id=ANY($1)`
		values, err := collectAssertions(ctx, tx, resourceAssertions, query, ids)
		if err != nil {
			return graph.Input{}, err
		}
		input.Resources = append(input.Resources, values...)
	}
	if ids := added[assertionFacet]; len(ids) > 0 {
		query := `SELECT i.scheme_group, i.scheme_version, i.scheme_kind, i.authority_id, i.immutable_key, a.kind, a.facet_key, a.attributes, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids FROM facet_assertions a JOIN resource_identities i ON i.resource_id=a.resource_id WHERE a.assertion_id=ANY($1)`
		values, err := collectAssertions(ctx, tx, facetAssertions, query, ids)
		if err != nil {
			return graph.Input{}, err
		}
		input.Facets = append(input.Facets, values...)
	}
	if ids := added[assertionRelationship]; len(ids) > 0 {
		query := `SELECT si.scheme_group, si.scheme_version, si.scheme_kind, si.authority_id, si.immutable_key, a.predicate, oi.scheme_group, oi.scheme_version, oi.scheme_kind, oi.authority_id, oi.immutable_key, a.qualifier, a.properties, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids FROM relationship_assertions a JOIN resource_identities si ON si.resource_id=a.subject_id JOIN resource_identities oi ON oi.resource_id=a.object_id WHERE a.assertion_id=ANY($1)`
		values, err := collectAssertions(ctx, tx, relationshipAssertions, query, ids)
		if err != nil {
			return graph.Input{}, err
		}
		input.Relationships = append(input.Relationships, values...)
	}
	return input, nil
}

func collectAssertions[T any](ctx context.Context, tx pgx.Tx, table assertionTable[T], query string, args ...any) ([]T, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query affected %s assertions: %w", table.assertionType, err)
	}
	defer rows.Close()
	var result []T
	for rows.Next() {
		item, err := table.scan(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read affected %s assertions: %w", table.assertionType, err)
	}
	return result, nil
}

func filterScopedSnapshot(compiled graph.Snapshot, scope projectionScope) graph.Snapshot {
	var result graph.Snapshot
	for _, item := range compiled.Resources {
		if _, ok := scope.resources[item.ID]; ok {
			result.Resources = append(result.Resources, item)
		}
	}
	for _, item := range compiled.Conflicts {
		if _, ok := scope.resources[item.ResourceID]; ok {
			result.Conflicts = append(result.Conflicts, item)
		}
	}
	for _, item := range compiled.Facets {
		if _, ok := scope.facets[item.ID]; ok {
			result.Facets = append(result.Facets, item)
		}
	}
	for _, item := range compiled.Relationships {
		if _, ok := scope.relationships[item.ID]; ok {
			result.Relationships = append(result.Relationships, item)
		}
	}
	return result
}

func projectionSetUUIDs(values map[string]struct{}) ([]uuid.UUID, error) {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	return projectionUUIDs(keys)
}

func cloneProjectionSet(values map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for value := range values {
		result[value] = struct{}{}
	}
	return result
}
