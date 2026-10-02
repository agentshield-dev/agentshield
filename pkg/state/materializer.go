package state

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

type contributionKey struct {
	pluginID string
	sourceID string
	name     string
}

type materializedGraph struct {
	revision      int64
	generatedAt   time.Time
	hasGraph      bool
	view          GraphView
	resources     map[assertionRef]graph.ResourceAssertion
	facets        map[assertionRef]graph.FacetAssertion
	relationships map[assertionRef]graph.RelationshipAssertion
	telemetry     map[assertionRef]graph.TelemetryAssertion
	owners        map[contributionKey]map[assertionRef]struct{}
	references    map[assertionRef]int
}

func emptyMaterializedGraph(revision int64) materializedGraph {
	return materializedGraph{
		revision: revision, resources: make(map[assertionRef]graph.ResourceAssertion), facets: make(map[assertionRef]graph.FacetAssertion),
		relationships: make(map[assertionRef]graph.RelationshipAssertion), telemetry: make(map[assertionRef]graph.TelemetryAssertion),
		owners: make(map[contributionKey]map[assertionRef]struct{}), references: make(map[assertionRef]int),
	}
}

func (s *Store) loadMaterializedGraph(ctx context.Context) (materializedGraph, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return materializedGraph{}, err
	}
	defer tx.Rollback(ctx)
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM graph_state WHERE singleton=true`).Scan(&revision); err != nil {
		return materializedGraph{}, fmt.Errorf("read graph revision: %w", err)
	}
	state := emptyMaterializedGraph(revision)
	var count int
	var generatedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT count(*), max(updated_at) FROM contribution_heads`).Scan(&count, &generatedAt); err != nil {
		return materializedGraph{}, err
	}
	if count == 0 || generatedAt == nil {
		if err := tx.Commit(ctx); err != nil {
			return materializedGraph{}, err
		}
		return state, nil
	}
	input, err := collectActiveInput(ctx, tx)
	if err != nil {
		return materializedGraph{}, fmt.Errorf("collect active assertions: %w", err)
	}
	if err := state.addInput(input); err != nil {
		return materializedGraph{}, err
	}
	if err := loadActiveTelemetryAssertions(ctx, tx, state.telemetry); err != nil {
		return materializedGraph{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT c.plugin_id, c.source_id, c.contribution_name, m.assertion_type, m.assertion_id
		FROM contribution_current_assertions m JOIN contributions c USING (contribution_id)
		ORDER BY c.plugin_id, c.source_id, c.contribution_name, m.assertion_type, m.assertion_id`)
	if err != nil {
		return materializedGraph{}, err
	}
	for rows.Next() {
		var key contributionKey
		var ref assertionRef
		if err := rows.Scan(&key.pluginID, &key.sourceID, &key.name, &ref.Type, &ref.ID); err != nil {
			rows.Close()
			return materializedGraph{}, err
		}
		if state.owners[key] == nil {
			state.owners[key] = make(map[assertionRef]struct{})
		}
		state.owners[key][ref] = struct{}{}
		state.references[ref]++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return materializedGraph{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return materializedGraph{}, err
	}
	state.generatedAt = *generatedAt
	state.hasGraph = true
	state.view, err = s.compileGraphView(activeGraph{generatedAt: state.generatedAt, input: input})
	return state, err
}

func (state *materializedGraph) addInput(input graph.Input) error {
	for _, assertion := range input.Resources {
		ref, err := assertionReference(assertionResource, assertion)
		if err != nil {
			return err
		}
		state.resources[ref] = assertion
	}
	for _, assertion := range input.Facets {
		ref, err := assertionReference(assertionFacet, assertion)
		if err != nil {
			return err
		}
		state.facets[ref] = assertion
	}
	for _, assertion := range input.Relationships {
		ref, err := assertionReference(assertionRelationship, assertion)
		if err != nil {
			return err
		}
		state.relationships[ref] = assertion
	}
	return nil
}

func loadActiveTelemetryAssertions(ctx context.Context, tx pgx.Tx, target map[assertionRef]graph.TelemetryAssertion) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT a.assertion_id, a.event_id, a.kind,
		si.scheme_group, si.scheme_version, si.scheme_kind, si.authority_id, si.immutable_key,
		oi.scheme_group, oi.scheme_version, oi.scheme_kind, oi.authority_id, oi.immutable_key,
		a.operation, a.outcome, a.coverage, a.event_count, a.properties, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids
		FROM contribution_current_assertions m
		JOIN telemetry_assertions a ON m.assertion_type='telemetry' AND a.assertion_id=m.assertion_id
		JOIN resource_identities si ON si.resource_id=a.subject_id
		JOIN resource_identities oi ON oi.resource_id=a.object_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ref assertionRef
		var assertion graph.TelemetryAssertion
		var count int64
		var properties, evidence []byte
		ref.Type = assertionTelemetry
		if err := rows.Scan(&ref.ID, &assertion.EventID, &assertion.Kind,
			&assertion.Subject.Scheme.Group, &assertion.Subject.Scheme.Version, &assertion.Subject.Scheme.Kind, &assertion.Subject.AuthorityID, &assertion.Subject.ImmutableKey,
			&assertion.Object.Scheme.Group, &assertion.Object.Scheme.Version, &assertion.Object.Scheme.Kind, &assertion.Object.AuthorityID, &assertion.Object.ImmutableKey,
			&assertion.Operation, &assertion.Outcome, &assertion.Coverage, &count, &properties, &assertion.PluginID, &assertion.SourceID, &assertion.RuleID, &evidence); err != nil {
			return err
		}
		assertion.Count = uint64(count)
		if err := decodeJSONColumns(properties, &assertion.Properties, evidence, &assertion.EvidenceIDs); err != nil {
			return err
		}
		target[ref] = assertion
	}
	return rows.Err()
}

func assertionReference(assertionType string, assertion any) (assertionRef, error) {
	id, _, err := contentAddress(assertionType, assertion)
	return assertionRef{Type: assertionType, ID: id}, err
}

func inputFromSnapshot(snapshot graph.Snapshot) graph.Input {
	var input graph.Input
	for _, resource := range snapshot.Resources {
		input.Resources = append(input.Resources, resource.Assertions...)
	}
	for _, conflict := range snapshot.Conflicts {
		input.Resources = append(input.Resources, conflict.Assertions...)
	}
	for _, facet := range snapshot.Facets {
		input.Facets = append(input.Facets, facet.Assertions...)
	}
	for _, relationship := range snapshot.Relationships {
		input.Relationships = append(input.Relationships, relationship.Assertions...)
	}
	return input
}

func (state materializedGraph) candidate(key contributionKey, compiled graph.Snapshot, raw graph.Input, generatedAt time.Time) (materializedGraph, graph.Input, error) {
	next := materializedGraph{
		revision: state.revision + 1, generatedAt: generatedAt, hasGraph: true,
		resources: cloneMap(state.resources), facets: cloneMap(state.facets), relationships: cloneMap(state.relationships), telemetry: cloneMap(state.telemetry),
		owners: cloneOwners(state.owners), references: cloneMap(state.references),
	}
	for ref := range next.owners[key] {
		next.references[ref]--
		if next.references[ref] == 0 {
			delete(next.references, ref)
			next.deleteAssertion(ref)
		}
	}
	delete(next.owners, key)
	if _, err := next.addCompiledContribution(key, compiled, raw); err != nil {
		return materializedGraph{}, graph.Input{}, err
	}
	return next, next.input(), nil
}

func (state *materializedGraph) addCompiledContribution(key contributionKey, compiled graph.Snapshot, raw graph.Input) ([]assertionRef, error) {
	refs, err := state.addContribution(key, inputFromSnapshot(compiled))
	if err != nil {
		return nil, err
	}
	telemetryByKey := make(map[[3]string]graph.TelemetryAssertion, len(raw.Telemetry))
	for _, assertion := range raw.Telemetry {
		telemetryByKey[[3]string{assertion.PluginID, assertion.SourceID, assertion.EventID}] = assertion
	}
	for _, event := range compiled.Telemetry {
		assertion, exists := telemetryByKey[[3]string{event.PluginID, event.SourceID, event.EventID}]
		if !exists {
			return nil, fmt.Errorf("compiled telemetry event %q has no input assertion", event.EventID)
		}
		ref, err := assertionReference(assertionTelemetry, event)
		if err != nil {
			return nil, err
		}
		state.telemetry[ref] = assertion
		if state.owners[key] == nil {
			state.owners[key] = make(map[assertionRef]struct{})
		}
		if _, exists := state.owners[key][ref]; !exists {
			state.owners[key][ref] = struct{}{}
			state.references[ref]++
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

func (state *materializedGraph) addContribution(key contributionKey, input graph.Input) ([]assertionRef, error) {
	refs := make([]assertionRef, 0, len(input.Resources)+len(input.Facets)+len(input.Relationships)+len(input.Telemetry))
	add := func(ref assertionRef) {
		if state.owners[key] == nil {
			state.owners[key] = make(map[assertionRef]struct{})
		}
		if _, exists := state.owners[key][ref]; exists {
			return
		}
		state.owners[key][ref] = struct{}{}
		state.references[ref]++
		refs = append(refs, ref)
	}
	for _, assertion := range input.Resources {
		ref, err := assertionReference(assertionResource, assertion)
		if err != nil {
			return nil, err
		}
		state.resources[ref] = assertion
		add(ref)
	}
	for _, assertion := range input.Facets {
		ref, err := assertionReference(assertionFacet, assertion)
		if err != nil {
			return nil, err
		}
		state.facets[ref] = assertion
		add(ref)
	}
	for _, assertion := range input.Relationships {
		ref, err := assertionReference(assertionRelationship, assertion)
		if err != nil {
			return nil, err
		}
		state.relationships[ref] = assertion
		add(ref)
	}
	return refs, nil
}

func (state *materializedGraph) deleteAssertion(ref assertionRef) {
	switch ref.Type {
	case assertionResource:
		delete(state.resources, ref)
	case assertionFacet:
		delete(state.facets, ref)
	case assertionRelationship:
		delete(state.relationships, ref)
	case assertionTelemetry:
		delete(state.telemetry, ref)
	}
}

func (state materializedGraph) input() graph.Input {
	input := graph.Input{
		Resources: make([]graph.ResourceAssertion, 0, len(state.resources)), Facets: make([]graph.FacetAssertion, 0, len(state.facets)),
		Relationships: make([]graph.RelationshipAssertion, 0, len(state.relationships)), Telemetry: make([]graph.TelemetryAssertion, 0, len(state.telemetry)),
	}
	for _, assertion := range state.resources {
		input.Resources = append(input.Resources, assertion)
	}
	for _, assertion := range state.facets {
		input.Facets = append(input.Facets, assertion)
	}
	for _, assertion := range state.relationships {
		input.Relationships = append(input.Relationships, assertion)
	}
	for _, assertion := range state.telemetry {
		input.Telemetry = append(input.Telemetry, assertion)
	}
	return input
}

func cloneMap[K comparable, V any](source map[K]V) map[K]V {
	result := make(map[K]V, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneOwners(source map[contributionKey]map[assertionRef]struct{}) map[contributionKey]map[assertionRef]struct{} {
	result := make(map[contributionKey]map[assertionRef]struct{}, len(source))
	for key, refs := range source {
		result[key] = cloneMap(refs)
	}
	return result
}
