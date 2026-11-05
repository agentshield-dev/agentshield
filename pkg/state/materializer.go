package state

import (
	"context"
	"fmt"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/jackc/pgx/v5"
)

type materializedGraph struct {
	revision    int64
	generatedAt time.Time
	hasGraph    bool
	view        GraphView
}

func (s *Store) loadMaterializedGraph(ctx context.Context) (materializedGraph, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return materializedGraph{}, err
	}
	defer tx.Rollback(ctx)
	var revision int64
	var generatedAt *time.Time
	var hasGraph bool
	if err := tx.QueryRow(ctx, `SELECT revision, generated_at, EXISTS(SELECT 1 FROM contribution_heads) FROM graph_state WHERE singleton=true`).Scan(&revision, &generatedAt, &hasGraph); err != nil {
		return materializedGraph{}, fmt.Errorf("read graph revision: %w", err)
	}
	state := materializedGraph{revision: revision, hasGraph: hasGraph}
	if !hasGraph || generatedAt == nil {
		if err := tx.Commit(ctx); err != nil {
			return materializedGraph{}, err
		}
		return state, nil
	}
	snapshot, err := readFullProjection(ctx, tx)
	if err != nil {
		return materializedGraph{}, fmt.Errorf("read graph projection: %w", err)
	}
	telemetry, err := collectProjectedTelemetry(ctx, tx)
	if err != nil {
		return materializedGraph{}, err
	}
	if len(telemetry) > 0 {
		resources := inputFromSnapshot(snapshot).Resources
		compiled, err := s.compiler.Compile(graph.Input{Resources: resources, Telemetry: telemetry})
		if err != nil {
			return materializedGraph{}, fmt.Errorf("compile projected telemetry: %w", err)
		}
		snapshot.Telemetry = compiled.Telemetry
	}
	if err := tx.Commit(ctx); err != nil {
		return materializedGraph{}, err
	}
	state.generatedAt = *generatedAt
	state.view = GraphView{Revision: uint64(revision), GeneratedAt: *generatedAt, Snapshot: snapshot}
	return state, nil
}

func collectProjectedTelemetry(ctx context.Context, tx pgx.Tx) ([]graph.TelemetryAssertion, error) {
	query := `SELECT a.event_id, a.kind,
		si.scheme_group, si.scheme_version, si.scheme_kind, si.authority_id, si.immutable_key,
		oi.scheme_group, oi.scheme_version, oi.scheme_kind, oi.authority_id, oi.immutable_key,
		a.operation, a.outcome, a.coverage, a.event_count, a.properties, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids
		FROM telemetry_assertions a
		JOIN resource_identities si ON si.resource_id=a.subject_id
		JOIN resource_identities oi ON oi.resource_id=a.object_id
		WHERE EXISTS (
			SELECT 1 FROM contribution_current_assertions m
			WHERE m.assertion_type='telemetry' AND m.assertion_id=a.assertion_id)
		ORDER BY a.plugin_id, a.source_id, a.event_id`
	return collectAssertions(ctx, tx, telemetryAssertions, query)
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
