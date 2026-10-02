package state

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// Contribution head statuses, derived from Retired, Ready, and SourceHealth by
// contributionStatus. They appear in manifests and change events.
const (
	ContributionStatusActive   = "active"
	ContributionStatusDegraded = "degraded"
	ContributionStatusStale    = "stale"
	ContributionStatusRetired  = "retired"
)

// Assertion type tags. They are persisted in membership and delta rows and
// are part of each assertion's content address.
const (
	assertionResource     = "resource"
	assertionFacet        = "facet"
	assertionRelationship = "relationship"
	assertionTelemetry    = "telemetry"
)

// assertionRef identifies one content-addressed assertion row.
type assertionRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type contributionPublication struct {
	VersionID int64
	View      GraphView
	HasView   bool
}

// ManifestContribution is one contribution version pinned by a manifest.
type ManifestContribution struct {
	ContributionID        int64     `json:"contributionId"`
	PluginID              string    `json:"pluginId"`
	SourceID              string    `json:"sourceId"`
	Name                  string    `json:"name"`
	ContributionVersionID int64     `json:"contributionVersionId"`
	Generation            uint64    `json:"generation"`
	Status                string    `json:"status"`
	SourceObservedAt      time.Time `json:"sourceObservedAt"`
	PublishedAt           time.Time `json:"publishedAt"`
	Ready                 bool      `json:"ready"`
	SourceHealth          string    `json:"sourceHealth"`
}

// ManifestStatus summarizes projection health at manifest creation.
type ManifestStatus struct {
	Contributions           int `json:"contributions"`
	UnresolvedRelationships int `json:"unresolvedRelationships"`
	Conflicts               int `json:"conflicts"`
}

// GraphManifest pins one active version of each contribution, forming a
// reproducible system-wide graph selection without a global graph revision.
type GraphManifest struct {
	ID            string                 `json:"id"`
	CreatedAt     time.Time              `json:"createdAt"`
	Digest        string                 `json:"digest"`
	ParentID      string                 `json:"parentId,omitempty"`
	StatusSummary ManifestStatus         `json:"statusSummary"`
	Contributions []ManifestContribution `json:"contributions"`
}

// AnalysisViewToken adds evaluation time to a manifest for reproducible analysis.
type AnalysisViewToken struct {
	ManifestID     string    `json:"manifestId"`
	EvaluationTime time.Time `json:"evaluationTime"`
}

// publishContribution compiles a candidate graph before opening its write
// transaction. A revision compare-and-swap rejects candidates based on stale
// state, including candidates built by another process.
func (s *Store) publishContribution(ctx context.Context, contribution Contribution, inputDigest [32]byte, compiled graph.Snapshot) (contributionPublication, error) {
	ctx, cancel := context.WithTimeout(ctx, s.publication.timeout)
	defer cancel()
	s.materializerMu.Lock()
	defer s.materializerMu.Unlock()
	key := contributionKey{pluginID: contribution.PluginID, sourceID: contribution.SourceID, name: contribution.Name}
	for {
		current, err := s.currentMaterializedGraph(ctx)
		if err != nil {
			return contributionPublication{}, err
		}
		next, input, err := current.candidate(key, compiled, contribution.Input, contribution.UpdatedAt)
		if err != nil {
			return contributionPublication{}, fmt.Errorf("build candidate graph: %w", err)
		}
		next.view, err = s.compileGraphView(activeGraph{generatedAt: contribution.UpdatedAt, input: input})
		if err != nil {
			return contributionPublication{}, fmt.Errorf("compile candidate graph: %w", err)
		}
		tx, err := s.beginPublication(ctx)
		if err != nil {
			return contributionPublication{}, err
		}
		publication, stale, err := s.commitCandidate(ctx, tx, current, next, contribution, inputDigest, compiled)
		if err != nil {
			_ = tx.Rollback(ctx)
			return contributionPublication{}, err
		}
		if stale {
			_ = tx.Rollback(ctx)
			s.materialized = nil
			continue
		}
		if err := tx.Commit(ctx); err != nil {
			return contributionPublication{}, fmt.Errorf("commit contribution publication: %w", err)
		}
		if publication.HasView {
			s.materialized = &next
		}
		return publication, nil
	}
}

func (s *Store) currentMaterializedGraph(ctx context.Context) (materializedGraph, error) {
	var revision int64
	if err := s.pool.QueryRow(ctx, `SELECT revision FROM graph_state WHERE singleton=true`).Scan(&revision); err != nil {
		return materializedGraph{}, fmt.Errorf("read graph revision: %w", err)
	}
	if s.materialized != nil && s.materialized.revision == revision {
		return *s.materialized, nil
	}
	loaded, err := s.loadMaterializedGraph(ctx)
	if err != nil {
		return materializedGraph{}, err
	}
	s.materialized = &loaded
	return loaded, nil
}

func (s *Store) commitCandidate(ctx context.Context, tx pgx.Tx, current, next materializedGraph, contribution Contribution, inputDigest [32]byte, compiled graph.Snapshot) (contributionPublication, bool, error) {
	contributionID, err := resolveContribution(ctx, tx, contribution)
	if err != nil {
		return contributionPublication{}, false, err
	}
	head, hasHead, err := readContributionHead(ctx, tx, contributionID)
	if err != nil {
		return contributionPublication{}, false, err
	}
	if hasHead && int64(contribution.Generation) < head.generation {
		return contributionPublication{}, false, fmt.Errorf("contribution generation %d is older than current generation %d", contribution.Generation, head.generation)
	}
	if hasHead && int64(contribution.Generation) == head.generation {
		if !equalBytes(head.inputDigest, inputDigest[:]) {
			return contributionPublication{}, false, fmt.Errorf("contribution generation %d conflicts with the current generation", contribution.Generation)
		}
		return contributionPublication{VersionID: head.versionID}, false, nil
	}
	digest, err := hex.DecodeString(next.view.SHA256)
	if err != nil {
		return contributionPublication{}, false, fmt.Errorf("decode candidate graph digest: %w", err)
	}
	command, err := tx.Exec(ctx, `UPDATE graph_state SET revision=revision+1, digest=$2, generated_at=$3 WHERE singleton=true AND revision=$1`, current.revision, digest, next.view.GeneratedAt)
	if err != nil {
		return contributionPublication{}, false, fmt.Errorf("advance graph revision: %w", err)
	}
	if command.RowsAffected() == 0 {
		return contributionPublication{}, true, nil
	}
	newRefs, err := persistCompiledAssertions(ctx, tx, compiled)
	if err != nil {
		return contributionPublication{}, false, err
	}
	status := contributionStatus(contribution)
	versionID, err := recordContributionVersion(ctx, tx, contributionID, contribution, inputDigest, status)
	if err != nil {
		return contributionPublication{}, false, err
	}
	delta, err := replaceMembership(ctx, tx, contributionID, newRefs)
	if err != nil {
		return contributionPublication{}, false, err
	}
	changedResources, _ := projectionChanges(current.view.Snapshot.Resources, next.view.Snapshot.Resources, func(item graph.Resource) string { return item.ID })
	if err := enqueueChangedDeploymentRuleJobs(ctx, tx, changedResources); err != nil {
		return contributionPublication{}, false, err
	}
	if err := replaceCurrentProjection(ctx, tx, current.view.Snapshot, next.view.Snapshot, contribution.UpdatedAt, s.unresolvedRetention); err != nil {
		return contributionPublication{}, false, err
	}
	metadataChanged := hasHead && (head.ready != contribution.Ready || head.sourceHealth != contribution.SourceHealth || head.status != status)
	if !telemetryOnlyChanges(delta.added, delta.retracted) || metadataChanged {
		if err := appendChangeEvent(ctx, tx, versionID, contribution, status, delta); err != nil {
			return contributionPublication{}, false, err
		}
	}
	return contributionPublication{VersionID: versionID, View: next.view, HasView: true}, false, nil
}

// beginPublication opens a publication transaction with bounded lock and statement waits.
func (s *Store) beginPublication(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin contribution publication: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true), set_config('idle_in_transaction_session_timeout', $3, true)`,
		postgresMilliseconds(s.publication.lockTimeout), postgresMilliseconds(s.publication.statementTimeout), postgresMilliseconds(s.publication.timeout)); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("set contribution publication timeouts: %w", err)
	}
	return tx, nil
}

// resolveContribution returns the stable ID of (plugin, source, name),
// creating the row on first publication.
func resolveContribution(ctx context.Context, tx pgx.Tx, contribution Contribution) (int64, error) {
	var contributionID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO contributions (plugin_id, source_id, contribution_name)
		VALUES ($1,$2,$3)
		ON CONFLICT (plugin_id, source_id, contribution_name) DO UPDATE SET plugin_id=EXCLUDED.plugin_id
		RETURNING contribution_id`, contribution.PluginID, contribution.SourceID, contribution.Name).Scan(&contributionID); err != nil {
		return 0, fmt.Errorf("resolve contribution: %w", err)
	}
	return contributionID, nil
}

// contributionHead is the active version of a contribution before this
// publication.
type contributionHead struct {
	generation   int64
	versionID    int64
	inputDigest  []byte
	ready        bool
	sourceHealth string
	status       string
}

// readContributionHead reads and locks the contribution head. It reports
// false before the contribution's first publication. FOR UPDATE is redundant
// under the global lock but keeps the head row safe if that lock is narrowed.
func readContributionHead(ctx context.Context, tx pgx.Tx, contributionID int64) (contributionHead, bool, error) {
	var head contributionHead
	err := tx.QueryRow(ctx, `
		SELECT h.generation, h.active_contribution_version_id, v.input_digest, v.ready, v.source_health, v.status
		FROM contribution_heads h
		JOIN contribution_versions v ON v.contribution_version_id=h.active_contribution_version_id
		WHERE h.contribution_id=$1 FOR UPDATE OF h`, contributionID).Scan(
		&head.generation, &head.versionID, &head.inputDigest, &head.ready, &head.sourceHealth, &head.status,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return contributionHead{}, false, nil
	}
	if err != nil {
		return contributionHead{}, false, fmt.Errorf("read contribution head: %w", err)
	}
	return head, true, nil
}

// recordContributionVersion inserts an immutable contribution version and
// points the contribution head at it.
func recordContributionVersion(ctx context.Context, tx pgx.Tx, contributionID int64, contribution Contribution, inputDigest [32]byte, status string) (int64, error) {
	var versionID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO contribution_versions
			(contribution_id, generation, input_digest, source_observed_at, published_at, ready, source_health, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING contribution_version_id`, contributionID, int64(contribution.Generation), inputDigest[:],
		contribution.SourceObservedAt, contribution.UpdatedAt, contribution.Ready, contribution.SourceHealth, status).Scan(&versionID); err != nil {
		return 0, fmt.Errorf("insert contribution version: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO contribution_heads (contribution_id, active_contribution_version_id, generation, status, updated_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (contribution_id) DO UPDATE SET
			active_contribution_version_id=EXCLUDED.active_contribution_version_id,
			generation=EXCLUDED.generation, status=EXCLUDED.status, updated_at=EXCLUDED.updated_at`,
		contributionID, versionID, int64(contribution.Generation), status, contribution.UpdatedAt); err != nil {
		return 0, fmt.Errorf("advance contribution head: %w", err)
	}
	return versionID, nil
}

// membershipDelta is what one publication added to and retracted from its
// contribution's active membership, with the outbox locators of each.
type membershipDelta struct {
	added, retracted               []assertionRef
	addedChanges, retractedChanges []AssertionChange
}

// replaceMembership applies the set difference between the incoming and
// current membership and returns the additions and retractions.
func replaceMembership(ctx context.Context, tx pgx.Tx, contributionID int64, newRefs []assertionRef) (membershipDelta, error) {
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE incoming_contribution_assertions (assertion_type text NOT NULL, assertion_id text NOT NULL, PRIMARY KEY (assertion_type, assertion_id)) ON COMMIT DROP`); err != nil {
		return membershipDelta{}, fmt.Errorf("create incoming contribution membership: %w", err)
	}
	rows := make([][]any, len(newRefs))
	for index, ref := range newRefs {
		rows[index] = []any{ref.Type, ref.ID}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"incoming_contribution_assertions"}, []string{"assertion_type", "assertion_id"}, pgx.CopyFromRows(rows)); err != nil {
		return membershipDelta{}, fmt.Errorf("stage incoming contribution membership: %w", err)
	}
	changed, err := tx.Query(ctx, `
		WITH additions AS (
			SELECT assertion_type, assertion_id FROM incoming_contribution_assertions
			EXCEPT
			SELECT assertion_type, assertion_id FROM contribution_current_assertions WHERE contribution_id=$1
		), retractions AS (
			SELECT assertion_type, assertion_id FROM contribution_current_assertions WHERE contribution_id=$1
			EXCEPT
			SELECT assertion_type, assertion_id FROM incoming_contribution_assertions
		), inserted AS (
			INSERT INTO contribution_current_assertions (contribution_id, assertion_type, assertion_id)
			SELECT $1, assertion_type, assertion_id FROM additions
			RETURNING assertion_type, assertion_id
		), deleted AS (
			DELETE FROM contribution_current_assertions membership
			USING retractions
			WHERE membership.contribution_id=$1
			  AND membership.assertion_type=retractions.assertion_type
			  AND membership.assertion_id=retractions.assertion_id
			RETURNING membership.assertion_type, membership.assertion_id
		)
		SELECT 'add', assertion_type, assertion_id FROM inserted
		UNION ALL
		SELECT 'retract', assertion_type, assertion_id FROM deleted
		ORDER BY 1, 2, 3`, contributionID)
	if err != nil {
		return membershipDelta{}, fmt.Errorf("replace contribution membership: %w", err)
	}
	defer changed.Close()
	var delta membershipDelta
	for changed.Next() {
		var operation string
		var ref assertionRef
		if err := changed.Scan(&operation, &ref.Type, &ref.ID); err != nil {
			return membershipDelta{}, fmt.Errorf("scan contribution membership change: %w", err)
		}
		if operation == "add" {
			delta.added = append(delta.added, ref)
		} else {
			delta.retracted = append(delta.retracted, ref)
		}
	}
	if err := changed.Err(); err != nil {
		return membershipDelta{}, fmt.Errorf("read contribution membership changes: %w", err)
	}
	sortAssertionRefs(delta.added)
	sortAssertionRefs(delta.retracted)
	changed.Close()
	if delta.addedChanges, err = loadAssertionChanges(ctx, tx, delta.added); err != nil {
		return membershipDelta{}, err
	}
	if delta.retractedChanges, err = loadAssertionChanges(ctx, tx, delta.retracted); err != nil {
		return membershipDelta{}, err
	}
	return delta, nil
}

// appendChangeEvent writes the outbox event for one contribution version.
// The singleton sequence row serializes allocation, so sequences are gap-free
// and ordered by commit.
func appendChangeEvent(ctx context.Context, tx pgx.Tx, versionID int64, contribution Contribution, status string, delta membershipDelta) error {
	var sequence int64
	if err := tx.QueryRow(ctx, `UPDATE graph_change_sequence SET value=value+1 WHERE singleton=true RETURNING value`).Scan(&sequence); err != nil {
		return fmt.Errorf("advance graph change sequence: %w", err)
	}
	event := ContributionChangeEvent{
		Sequence: uint64(sequence),
		Contribution: ContributionEventOwner{
			VersionID: versionID, PluginID: contribution.PluginID, SourceID: contribution.SourceID, Name: contribution.Name,
			Generation: contribution.Generation, Ready: contribution.Ready, SourceHealth: contribution.SourceHealth,
			SourceObservedAt: contribution.SourceObservedAt, Status: status,
		},
		Added: changeFeedAssertions(delta.addedChanges), Retracted: changeFeedAssertions(delta.retractedChanges),
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode contribution change: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO graph_change_outbox (sequence, contribution_version_id, payload) VALUES ($1,$2,$3)`, sequence, versionID, payload); err != nil {
		return fmt.Errorf("record graph change publication: %w", err)
	}
	return nil
}

// postgresMilliseconds formats a duration as a PostgreSQL timeout setting in
// milliseconds, the unit of lock_timeout and statement_timeout.
func postgresMilliseconds(duration time.Duration) string {
	return strconv.FormatInt(duration.Milliseconds(), 10)
}

// changeFeedAssertions removes telemetry assertions from an outbox payload;
// reasoning reads telemetry through bounded queries, not the change feed.
func changeFeedAssertions(changes []AssertionChange) []AssertionChange {
	result := make([]AssertionChange, 0, len(changes))
	for _, change := range changes {
		if change.AssertionType != assertionTelemetry {
			result = append(result, change)
		}
	}
	return result
}

// telemetryOnlyChanges reports whether there is at least one change and every
// change is a telemetry assertion. No changes at all is not telemetry-only.
func telemetryOnlyChanges(added, retracted []assertionRef) bool {
	if len(added) == 0 && len(retracted) == 0 {
		return false
	}
	for _, ref := range append(append([]assertionRef(nil), added...), retracted...) {
		if ref.Type != assertionTelemetry {
			return false
		}
	}
	return true
}

// contributionStatus folds readiness and source health into one head status.
// A contribution that is not ready, or whose source health is unknown, is
// stale: its last membership stays active but is not current.
func contributionStatus(contribution Contribution) string {
	if contribution.Retired {
		return ContributionStatusRetired
	}
	if !contribution.Ready {
		return ContributionStatusStale
	}
	switch contribution.SourceHealth {
	case SourceHealthHealthy:
		return ContributionStatusActive
	case SourceHealthDegraded:
		return ContributionStatusDegraded
	default:
		return ContributionStatusStale
	}
}

// assertionTable describes how one assertion type is stored: the INSERT that
// persists a content-addressed row and the query that reads active rows back
// as compiler input of type T.
type assertionTable[T any] struct {
	assertionType string
	// insert takes assertion_id and content_digest as $1 and $2, then the
	// type's own columns.
	insert string
	// active selects the DISTINCT active rows in a stable order, and scan
	// decodes one of them.
	active string
	scan   func(pgx.Rows) (T, error)
}

type assertionInsert struct {
	ref   assertionRef
	query string
	args  []any
}

func (table assertionTable[T]) prepare(content any, values ...any) (assertionInsert, error) {
	id, digest, err := contentAddress(table.assertionType, content)
	if err != nil {
		return assertionInsert{}, err
	}
	return assertionInsert{
		ref: assertionRef{Type: table.assertionType, ID: id}, query: table.insert,
		args: append([]any{id, digest[:]}, values...),
	}, nil
}

// collect reads every active assertion of the table.
func (table assertionTable[T]) collect(ctx context.Context, tx pgx.Tx) ([]T, error) {
	rows, err := tx.Query(ctx, table.active)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []T
	for rows.Next() {
		item, err := table.scan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

var resourceAssertions = assertionTable[graph.ResourceAssertion]{
	assertionType: assertionResource,
	insert:        `INSERT INTO resource_assertions (assertion_id, content_digest, resource_id, kind, display_name, attributes, plugin_id, source_id, rule_id, evidence_ids) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (assertion_id) DO NOTHING`,
	active:        `SELECT DISTINCT i.scheme_group, i.scheme_version, i.scheme_kind, i.authority_id, i.immutable_key, a.kind, a.display_name, a.attributes, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids FROM contribution_current_assertions m JOIN resource_assertions a ON m.assertion_type='resource' AND a.assertion_id=m.assertion_id JOIN resource_identities i ON i.resource_id=a.resource_id ORDER BY i.scheme_group, i.scheme_version, i.scheme_kind, i.authority_id, i.immutable_key, a.plugin_id, a.source_id, a.rule_id`,
	scan: func(rows pgx.Rows) (graph.ResourceAssertion, error) {
		var item graph.ResourceAssertion
		var attributes, evidence []byte
		if err := rows.Scan(&item.Claim.Scheme.Group, &item.Claim.Scheme.Version, &item.Claim.Scheme.Kind, &item.Claim.AuthorityID, &item.Claim.ImmutableKey, &item.Kind, &item.DisplayName, &attributes, &item.PluginID, &item.SourceID, &item.RuleID, &evidence); err != nil {
			return item, err
		}
		return item, decodeJSONColumns(attributes, &item.Attributes, evidence, &item.EvidenceIDs)
	},
}

var facetAssertions = assertionTable[graph.FacetAssertion]{
	assertionType: assertionFacet,
	insert:        `INSERT INTO facet_assertions (assertion_id, content_digest, facet_id, resource_id, kind, facet_key, attributes, plugin_id, source_id, rule_id, evidence_ids) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (assertion_id) DO NOTHING`,
	active:        `SELECT DISTINCT i.scheme_group, i.scheme_version, i.scheme_kind, i.authority_id, i.immutable_key, a.kind, a.facet_key, a.attributes, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids FROM contribution_current_assertions m JOIN facet_assertions a ON m.assertion_type='facet' AND a.assertion_id=m.assertion_id JOIN resource_identities i ON i.resource_id=a.resource_id ORDER BY i.scheme_group, i.scheme_version, i.scheme_kind, i.authority_id, i.immutable_key, a.kind, a.facet_key, a.plugin_id, a.source_id, a.rule_id`,
	scan: func(rows pgx.Rows) (graph.FacetAssertion, error) {
		var item graph.FacetAssertion
		var attributes, evidence []byte
		if err := rows.Scan(&item.Resource.Scheme.Group, &item.Resource.Scheme.Version, &item.Resource.Scheme.Kind, &item.Resource.AuthorityID, &item.Resource.ImmutableKey, &item.Kind, &item.Key, &attributes, &item.PluginID, &item.SourceID, &item.RuleID, &evidence); err != nil {
			return item, err
		}
		return item, decodeJSONColumns(attributes, &item.Attributes, evidence, &item.EvidenceIDs)
	},
}

var relationshipAssertions = assertionTable[graph.RelationshipAssertion]{
	assertionType: assertionRelationship,
	insert:        `INSERT INTO relationship_assertions (assertion_id, content_digest, relationship_id, subject_id, object_id, predicate, qualifier, properties, plugin_id, source_id, rule_id, evidence_ids) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (assertion_id) DO NOTHING`,
	active:        `SELECT DISTINCT si.scheme_group, si.scheme_version, si.scheme_kind, si.authority_id, si.immutable_key, a.predicate, oi.scheme_group, oi.scheme_version, oi.scheme_kind, oi.authority_id, oi.immutable_key, a.qualifier, a.properties, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids FROM contribution_current_assertions m JOIN relationship_assertions a ON m.assertion_type='relationship' AND a.assertion_id=m.assertion_id JOIN resource_identities si ON si.resource_id=a.subject_id JOIN resource_identities oi ON oi.resource_id=a.object_id ORDER BY si.scheme_group, si.scheme_version, si.scheme_kind, si.authority_id, si.immutable_key, a.predicate, oi.scheme_group, oi.scheme_version, oi.scheme_kind, oi.authority_id, oi.immutable_key, a.qualifier, a.plugin_id, a.source_id, a.rule_id`,
	scan: func(rows pgx.Rows) (graph.RelationshipAssertion, error) {
		var item graph.RelationshipAssertion
		var predicate string
		var properties, evidence []byte
		if err := rows.Scan(&item.Subject.Scheme.Group, &item.Subject.Scheme.Version, &item.Subject.Scheme.Kind, &item.Subject.AuthorityID, &item.Subject.ImmutableKey, &predicate, &item.Object.Scheme.Group, &item.Object.Scheme.Version, &item.Object.Scheme.Kind, &item.Object.AuthorityID, &item.Object.ImmutableKey, &item.Qualifier, &properties, &item.PluginID, &item.SourceID, &item.RuleID, &evidence); err != nil {
			return item, err
		}
		item.Predicate = graph.Predicate(predicate)
		return item, decodeJSONColumns(properties, &item.Properties, evidence, &item.EvidenceIDs)
	},
}

// telemetryAssertions persists compiled graph.TelemetryEvent values and reads
// them back as graph.TelemetryAssertion input.
var telemetryAssertions = assertionTable[graph.TelemetryAssertion]{
	assertionType: assertionTelemetry,
	insert:        `INSERT INTO telemetry_assertions (assertion_id, content_digest, telemetry_id, event_id, kind, subject_id, object_id, operation, outcome, coverage, event_count, properties, plugin_id, source_id, rule_id, evidence_ids) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT (assertion_id) DO NOTHING`,
	active:        `SELECT DISTINCT a.event_id, a.kind, si.scheme_group, si.scheme_version, si.scheme_kind, si.authority_id, si.immutable_key, oi.scheme_group, oi.scheme_version, oi.scheme_kind, oi.authority_id, oi.immutable_key, a.operation, a.outcome, a.coverage, a.event_count, a.properties, a.plugin_id, a.source_id, a.rule_id, a.evidence_ids FROM contribution_current_assertions m JOIN telemetry_assertions a ON m.assertion_type='telemetry' AND a.assertion_id=m.assertion_id JOIN resource_identities si ON si.resource_id=a.subject_id JOIN resource_identities oi ON oi.resource_id=a.object_id ORDER BY a.plugin_id, a.source_id, a.event_id`,
	scan: func(rows pgx.Rows) (graph.TelemetryAssertion, error) {
		var item graph.TelemetryAssertion
		var count int64
		var properties, evidence []byte
		if err := rows.Scan(&item.EventID, &item.Kind, &item.Subject.Scheme.Group, &item.Subject.Scheme.Version, &item.Subject.Scheme.Kind, &item.Subject.AuthorityID, &item.Subject.ImmutableKey, &item.Object.Scheme.Group, &item.Object.Scheme.Version, &item.Object.Scheme.Kind, &item.Object.AuthorityID, &item.Object.ImmutableKey, &item.Operation, &item.Outcome, &item.Coverage, &count, &properties, &item.PluginID, &item.SourceID, &item.RuleID, &evidence); err != nil {
			return item, err
		}
		item.Count = uint64(count)
		return item, decodeJSONColumns(properties, &item.Properties, evidence, &item.EvidenceIDs)
	},
}

// persistCompiledAssertions stores every assertion in a compiled contribution
// snapshot, including the competing assertions of identity conflicts, and
// returns their sorted references.
func persistCompiledAssertions(ctx context.Context, tx pgx.Tx, compiled graph.Snapshot) ([]assertionRef, error) {
	identities := make(map[string]graph.IdentityClaim)
	var inserts []assertionInsert
	addIdentity := func(resourceID string, claim graph.IdentityClaim) error {
		if current, exists := identities[resourceID]; exists && current != claim {
			return fmt.Errorf("resource ID %s collides with a different identity claim", resourceID)
		}
		identities[resourceID] = claim
		return nil
	}
	addAssertion := func(insert assertionInsert, err error) error {
		if err != nil {
			return err
		}
		inserts = append(inserts, insert)
		return nil
	}
	for _, resource := range compiled.Resources {
		if err := addIdentity(resource.ID, resource.Identity); err != nil {
			return nil, err
		}
		for _, assertion := range resource.Assertions {
			if err := addAssertion(resourceAssertions.prepare(assertion, resource.ID, assertion.Kind, assertion.DisplayName, objectJSON(assertion.Attributes), assertion.PluginID, assertion.SourceID, assertion.RuleID, stringSliceJSON(assertion.EvidenceIDs))); err != nil {
				return nil, err
			}
		}
	}
	for _, conflict := range compiled.Conflicts {
		for _, assertion := range conflict.Assertions {
			if err := addIdentity(conflict.ResourceID, assertion.Claim); err != nil {
				return nil, err
			}
			if err := addAssertion(resourceAssertions.prepare(assertion, conflict.ResourceID, assertion.Kind, assertion.DisplayName, objectJSON(assertion.Attributes), assertion.PluginID, assertion.SourceID, assertion.RuleID, stringSliceJSON(assertion.EvidenceIDs))); err != nil {
				return nil, err
			}
		}
	}
	for _, facet := range compiled.Facets {
		for _, assertion := range facet.Assertions {
			if err := addIdentity(facet.ResourceID, assertion.Resource); err != nil {
				return nil, err
			}
			if err := addAssertion(facetAssertions.prepare(assertion, facet.ID, facet.ResourceID, facet.Kind, facet.Key, objectJSON(assertion.Attributes), assertion.PluginID, assertion.SourceID, assertion.RuleID, stringSliceJSON(assertion.EvidenceIDs))); err != nil {
				return nil, err
			}
		}
	}
	for _, relationship := range compiled.Relationships {
		for _, assertion := range relationship.Assertions {
			if err := addIdentity(relationship.SubjectID, assertion.Subject); err != nil {
				return nil, err
			}
			if err := addIdentity(relationship.ObjectID, assertion.Object); err != nil {
				return nil, err
			}
			if err := addAssertion(relationshipAssertions.prepare(assertion, relationship.ID, relationship.SubjectID, relationship.ObjectID, relationship.Predicate, relationship.Qualifier, objectJSON(assertion.Properties), assertion.PluginID, assertion.SourceID, assertion.RuleID, stringSliceJSON(assertion.EvidenceIDs))); err != nil {
				return nil, err
			}
		}
	}
	for _, event := range compiled.Telemetry {
		if err := addAssertion(telemetryAssertions.prepare(event, event.ID, event.EventID, event.Kind, event.SubjectID, event.ObjectID, event.Operation, event.Outcome, event.Coverage, int64(event.Count), objectJSON(event.Properties), event.PluginID, event.SourceID, event.RuleID, stringSliceJSON(event.EvidenceIDs))); err != nil {
			return nil, err
		}
	}
	identityIDs := make([]string, 0, len(identities))
	for resourceID := range identities {
		identityIDs = append(identityIDs, resourceID)
	}
	slices.Sort(identityIDs)
	var identityBatch pgx.Batch
	for _, resourceID := range identityIDs {
		claim := identities[resourceID]
		identityBatch.Queue(`
			INSERT INTO resource_identities (resource_id, scheme_group, scheme_version, scheme_kind, authority_id, immutable_key)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (resource_id) DO UPDATE SET resource_id=EXCLUDED.resource_id
			WHERE resource_identities.scheme_group=EXCLUDED.scheme_group
			  AND resource_identities.scheme_version=EXCLUDED.scheme_version
			  AND resource_identities.scheme_kind=EXCLUDED.scheme_kind
			  AND resource_identities.authority_id=EXCLUDED.authority_id
			  AND resource_identities.immutable_key=EXCLUDED.immutable_key
			RETURNING resource_id::text`, resourceID, claim.Scheme.Group, claim.Scheme.Version, claim.Scheme.Kind, claim.AuthorityID, claim.ImmutableKey)
	}
	identityResults := tx.SendBatch(ctx, &identityBatch)
	for _, resourceID := range identityIDs {
		var storedID string
		if err := identityResults.QueryRow().Scan(&storedID); err != nil {
			_ = identityResults.Close()
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("resource ID %s collides with a different identity claim", resourceID)
			}
			return nil, fmt.Errorf("persist resource identity %s: %w", resourceID, err)
		}
	}
	if err := identityResults.Close(); err != nil {
		return nil, fmt.Errorf("persist resource identities: %w", err)
	}
	refs := make([]assertionRef, 0, len(inserts))
	var assertionBatch pgx.Batch
	for _, insert := range inserts {
		assertionBatch.Queue(insert.query, insert.args...)
		refs = append(refs, insert.ref)
	}
	assertionResults := tx.SendBatch(ctx, &assertionBatch)
	for _, insert := range inserts {
		if _, err := assertionResults.Exec(); err != nil {
			_ = assertionResults.Close()
			return nil, fmt.Errorf("persist %s assertion: %w", insert.ref.Type, err)
		}
	}
	if err := assertionResults.Close(); err != nil {
		return nil, fmt.Errorf("persist assertions: %w", err)
	}
	sortAssertionRefs(refs)
	return refs, nil
}

// contentAddress hashes the assertion type and its JSON encoding. The compiler
// has already normalized claims and sorted evidence, and the JSON of these
// structs is deterministic, so equal assertions get equal addresses.
func contentAddress(assertionType string, value any) (string, [32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", [32]byte{}, fmt.Errorf("encode %s assertion: %w", assertionType, err)
	}
	digest := sha256.Sum256(append(append([]byte(assertionType), 0), encoded...))
	return hex.EncodeToString(digest[:]), digest, nil
}

// objectJSON encodes a JSONB object column. Marshaling a map[string]string
// cannot fail, so the error is ignored.
func objectJSON(value map[string]string) []byte {
	if value == nil {
		return []byte("{}")
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

// stringSliceJSON encodes a JSONB array column. Marshaling a []string cannot
// fail, so the error is ignored.
func stringSliceJSON(value []string) []byte {
	if value == nil {
		return []byte("[]")
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func jsonValue(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func sortAssertionRefs(refs []assertionRef) {
	slices.SortFunc(refs, func(left, right assertionRef) int {
		if left.Type == right.Type {
			return cmp.Compare(left.ID, right.ID)
		}
		return cmp.Compare(left.Type, right.Type)
	})
}

// loadAssertionChanges resolves assertion references to compact entity
// locators for the outbox. Retracted rows are still readable because
// assertion content is never deleted, which is what lets retractions carry
// tombstones.
func loadAssertionChanges(ctx context.Context, tx pgx.Tx, refs []assertionRef) ([]AssertionChange, error) {
	changes := make([]AssertionChange, 0, len(refs))
	for _, ref := range refs {
		change := AssertionChange{AssertionType: ref.Type, AssertionID: ref.ID, Entity: EntityLocator{EntityType: ref.Type}}
		var err error
		switch ref.Type {
		case assertionResource:
			err = tx.QueryRow(ctx, `SELECT resource_id::text, kind FROM resource_assertions WHERE assertion_id=$1`, ref.ID).Scan(&change.Entity.ID, &change.Entity.Kind)
		case assertionFacet:
			err = tx.QueryRow(ctx, `SELECT facet_id::text, resource_id::text, kind FROM facet_assertions WHERE assertion_id=$1`, ref.ID).Scan(&change.Entity.ID, &change.Entity.ResourceID, &change.Entity.Kind)
		case assertionRelationship:
			err = tx.QueryRow(ctx, `SELECT relationship_id::text, subject_id::text, predicate, object_id::text, qualifier FROM relationship_assertions WHERE assertion_id=$1`, ref.ID).Scan(&change.Entity.ID, &change.Entity.SubjectID, &change.Entity.Predicate, &change.Entity.ObjectID, &change.Entity.Qualifier)
		case assertionTelemetry:
			err = tx.QueryRow(ctx, `SELECT telemetry_id::text, subject_id::text, object_id::text, kind FROM telemetry_assertions WHERE assertion_id=$1`, ref.ID).Scan(&change.Entity.ID, &change.Entity.SubjectID, &change.Entity.ObjectID, &change.Entity.Kind)
		default:
			return nil, fmt.Errorf("unsupported assertion type %q", ref.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("load %s assertion %s change: %w", ref.Type, ref.ID, err)
		}
		changes = append(changes, change)
	}
	return changes, nil
}

// collectActiveInput rebuilds a graph.Input from the active membership of all
// contributions. DISTINCT collapses assertions shared by contributions, and
// ORDER BY keeps the input order stable. Provenance is verified first so a
// tampered or legacy membership row cannot enter compilation.
func collectActiveInput(ctx context.Context, tx pgx.Tx) (graph.Input, error) {
	var input graph.Input
	if err := verifyActiveAssertionProvenance(ctx, tx); err != nil {
		return input, err
	}
	var err error
	if input.Resources, err = resourceAssertions.collect(ctx, tx); err != nil {
		return input, err
	}
	if input.Facets, err = facetAssertions.collect(ctx, tx); err != nil {
		return input, err
	}
	if input.Relationships, err = relationshipAssertions.collect(ctx, tx); err != nil {
		return input, err
	}
	if input.Telemetry, err = telemetryAssertions.collect(ctx, tx); err != nil {
		return input, err
	}
	return input, nil
}

// verifyActiveAssertionProvenance fails if any active assertion's plugin or
// source differs from its owning contribution. It re-checks at read time what
// ReplaceContribution enforces at write time.
type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func verifyActiveAssertionProvenance(ctx context.Context, tx rowQuerier) error {
	var assertionType, assertionID, ownerPlugin, ownerSource, assertionPlugin, assertionSource string
	err := tx.QueryRow(ctx, `
		SELECT assertion_type, assertion_id, owner_plugin, owner_source, assertion_plugin, assertion_source
		FROM (
			SELECT m.assertion_type, m.assertion_id, c.plugin_id owner_plugin, c.source_id owner_source, a.plugin_id assertion_plugin, a.source_id assertion_source
			FROM contribution_current_assertions m JOIN contributions c USING (contribution_id) JOIN resource_assertions a ON m.assertion_type='resource' AND a.assertion_id=m.assertion_id
			UNION ALL
			SELECT m.assertion_type, m.assertion_id, c.plugin_id, c.source_id, a.plugin_id, a.source_id
			FROM contribution_current_assertions m JOIN contributions c USING (contribution_id) JOIN facet_assertions a ON m.assertion_type='facet' AND a.assertion_id=m.assertion_id
			UNION ALL
			SELECT m.assertion_type, m.assertion_id, c.plugin_id, c.source_id, a.plugin_id, a.source_id
			FROM contribution_current_assertions m JOIN contributions c USING (contribution_id) JOIN relationship_assertions a ON m.assertion_type='relationship' AND a.assertion_id=m.assertion_id
			UNION ALL
			SELECT m.assertion_type, m.assertion_id, c.plugin_id, c.source_id, a.plugin_id, a.source_id
			FROM contribution_current_assertions m JOIN contributions c USING (contribution_id) JOIN telemetry_assertions a ON m.assertion_type='telemetry' AND a.assertion_id=m.assertion_id
		) active_assertions
		WHERE assertion_plugin IS DISTINCT FROM owner_plugin OR assertion_source IS DISTINCT FROM owner_source
		ORDER BY assertion_type, assertion_id
		LIMIT 1`).Scan(&assertionType, &assertionID, &ownerPlugin, &ownerSource, &assertionPlugin, &assertionSource)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("verify active assertion provenance: %w", err)
	}
	return fmt.Errorf("stored %s assertion %s provenance %q/%q does not match active contribution owner %q/%q", assertionType, assertionID, assertionPlugin, assertionSource, ownerPlugin, ownerSource)
}

func decodeJSONColumns(first []byte, firstValue any, second []byte, secondValue any) error {
	if err := json.Unmarshal(first, firstValue); err != nil {
		return err
	}
	return json.Unmarshal(second, secondValue)
}

// replaceCurrentProjection writes only rows affected by the candidate graph.
func replaceCurrentProjection(ctx context.Context, tx pgx.Tx, before, after graph.Snapshot, now time.Time, unresolvedRetention time.Duration) error {
	resources, removedResources := projectionChanges(before.Resources, after.Resources, func(item graph.Resource) string { return item.ID })
	conflicts, removedConflicts := projectionChanges(before.Conflicts, after.Conflicts, func(item graph.AssertionConflict) string { return item.ResourceID })
	facets, removedFacets := projectionChanges(before.Facets, after.Facets, func(item graph.Facet) string { return item.ID })
	relationships, removedRelationships := projectionChanges(before.Relationships, after.Relationships, func(item graph.Relationship) string { return item.ID })

	resourceRows := make([][]any, 0, len(resources))
	for _, resource := range resources {
		first := resource.Assertions[0]
		resourceRows = append(resourceRows, []any{resource.ID, resource.Kind, first.DisplayName, objectJSON(first.Attributes), jsonValue(resource.Assertions), now})
	}
	if len(resourceRows) > 0 {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE incoming_current_resources (LIKE current_resources INCLUDING DEFAULTS) ON COMMIT DROP`); err != nil {
			return fmt.Errorf("create current resource staging table: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"incoming_current_resources"}, []string{"resource_id", "kind", "display_name", "attributes", "assertions", "updated_at"}, pgx.CopyFromRows(resourceRows)); err != nil {
			return fmt.Errorf("stage current resources: %w", err)
		}
	}
	conflictRows := make([][]any, 0, len(conflicts))
	for _, conflict := range conflicts {
		kinds := make([]string, 0)
		seen := make(map[string]struct{})
		for _, assertion := range conflict.Assertions {
			if _, ok := seen[assertion.Kind]; !ok {
				seen[assertion.Kind] = struct{}{}
				kinds = append(kinds, assertion.Kind)
			}
		}
		slices.Sort(kinds)
		encoded, err := json.Marshal(kinds)
		if err != nil {
			return fmt.Errorf("encode conflict kinds: %w", err)
		}
		conflictRows = append(conflictRows, []any{conflict.ResourceID, encoded, now})
	}
	if len(conflictRows) > 0 {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE incoming_assertion_conflicts (LIKE assertion_conflicts INCLUDING DEFAULTS) ON COMMIT DROP`); err != nil {
			return fmt.Errorf("create assertion conflict staging table: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"incoming_assertion_conflicts"}, []string{"resource_id", "kinds", "updated_at"}, pgx.CopyFromRows(conflictRows)); err != nil {
			return fmt.Errorf("stage assertion conflicts: %w", err)
		}
	}
	facetRows := make([][]any, 0, len(facets))
	for _, facet := range facets {
		first := facet.Assertions[0]
		facetRows = append(facetRows, []any{facet.ID, facet.ResourceID, facet.Kind, facet.Key, objectJSON(first.Attributes), resolutionText(facet.ResolutionStatus), jsonValue(facet.Assertions), now})
	}
	if len(facetRows) > 0 {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE incoming_current_facets (LIKE current_facets INCLUDING DEFAULTS) ON COMMIT DROP`); err != nil {
			return fmt.Errorf("create current facet staging table: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"incoming_current_facets"}, []string{"facet_id", "resource_id", "kind", "facet_key", "attributes", "resolution_status", "assertions", "updated_at"}, pgx.CopyFromRows(facetRows)); err != nil {
			return fmt.Errorf("stage current facets: %w", err)
		}
	}
	relationshipRows := make([][]any, 0, len(relationships))
	unresolvedRows := make([][]any, 0)
	unresolvedDeletes := append([]string(nil), removedRelationships...)
	for _, relationship := range relationships {
		first := relationship.Assertions[0]
		status := resolutionText(relationship.ResolutionStatus)
		relationshipRows = append(relationshipRows, []any{relationship.ID, relationship.SubjectID, relationship.ObjectID, relationship.Predicate, relationship.Qualifier, objectJSON(first.Properties), status, jsonValue(relationship.Assertions), now})
		if status == "unresolved" {
			unresolvedRows = append(unresolvedRows, []any{relationship.ID})
		} else {
			unresolvedDeletes = append(unresolvedDeletes, relationship.ID)
		}
	}
	if len(relationshipRows) > 0 {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE incoming_current_relationships (LIKE current_relationships INCLUDING DEFAULTS) ON COMMIT DROP`); err != nil {
			return fmt.Errorf("create current relationship staging table: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"incoming_current_relationships"}, []string{"relationship_id", "subject_id", "object_id", "predicate", "qualifier", "properties", "resolution_status", "assertions", "updated_at"}, pgx.CopyFromRows(relationshipRows)); err != nil {
			return fmt.Errorf("stage current relationships: %w", err)
		}
	}
	if len(unresolvedRows) > 0 {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE incoming_unresolved_relationships (relationship_id uuid PRIMARY KEY) ON COMMIT DROP`); err != nil {
			return fmt.Errorf("create unresolved relationship staging table: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"incoming_unresolved_relationships"}, []string{"relationship_id"}, pgx.CopyFromRows(unresolvedRows)); err != nil {
			return fmt.Errorf("stage unresolved relationships: %w", err)
		}
	}
	var batch pgx.Batch
	if len(resourceRows) > 0 {
		batch.Queue(`INSERT INTO current_resources SELECT * FROM incoming_current_resources
		ON CONFLICT (resource_id) DO UPDATE SET
			kind=EXCLUDED.kind, display_name=EXCLUDED.display_name, attributes=EXCLUDED.attributes, assertions=EXCLUDED.assertions, updated_at=EXCLUDED.updated_at
		WHERE (current_resources.kind, current_resources.display_name, current_resources.attributes, current_resources.assertions) IS DISTINCT FROM (EXCLUDED.kind, EXCLUDED.display_name, EXCLUDED.attributes, EXCLUDED.assertions)`)
	}
	if len(conflictRows) > 0 {
		batch.Queue(`INSERT INTO assertion_conflicts SELECT * FROM incoming_assertion_conflicts
		ON CONFLICT (resource_id) DO UPDATE SET kinds=EXCLUDED.kinds, updated_at=EXCLUDED.updated_at
		WHERE assertion_conflicts.kinds IS DISTINCT FROM EXCLUDED.kinds`)
	}
	if len(facetRows) > 0 {
		batch.Queue(`INSERT INTO current_facets SELECT * FROM incoming_current_facets
		ON CONFLICT (facet_id) DO UPDATE SET
			resource_id=EXCLUDED.resource_id, kind=EXCLUDED.kind, facet_key=EXCLUDED.facet_key,
			attributes=EXCLUDED.attributes, resolution_status=EXCLUDED.resolution_status, assertions=EXCLUDED.assertions, updated_at=EXCLUDED.updated_at
		WHERE (current_facets.resource_id, current_facets.kind, current_facets.facet_key, current_facets.attributes, current_facets.resolution_status, current_facets.assertions)
			IS DISTINCT FROM (EXCLUDED.resource_id, EXCLUDED.kind, EXCLUDED.facet_key, EXCLUDED.attributes, EXCLUDED.resolution_status, EXCLUDED.assertions)`)
	}
	if len(relationshipRows) > 0 {
		batch.Queue(`INSERT INTO current_relationships SELECT * FROM incoming_current_relationships
		ON CONFLICT (relationship_id) DO UPDATE SET
			subject_id=EXCLUDED.subject_id, object_id=EXCLUDED.object_id, predicate=EXCLUDED.predicate,
			qualifier=EXCLUDED.qualifier, properties=EXCLUDED.properties, resolution_status=EXCLUDED.resolution_status, assertions=EXCLUDED.assertions, updated_at=EXCLUDED.updated_at
		WHERE (current_relationships.subject_id, current_relationships.object_id, current_relationships.predicate, current_relationships.qualifier, current_relationships.properties, current_relationships.resolution_status, current_relationships.assertions)
			IS DISTINCT FROM (EXCLUDED.subject_id, EXCLUDED.object_id, EXCLUDED.predicate, EXCLUDED.qualifier, EXCLUDED.properties, EXCLUDED.resolution_status, EXCLUDED.assertions)`)
	}
	if len(unresolvedRows) > 0 {
		batch.Queue(`INSERT INTO unresolved_relationships (relationship_id, first_seen_at, last_seen_at, expires_at)
		SELECT relationship_id, $1, $1, $2 FROM incoming_unresolved_relationships
		ON CONFLICT (relationship_id) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at, expires_at=EXCLUDED.expires_at`, now, now.Add(unresolvedRetention))
	}
	if ids, err := projectionUUIDs(unresolvedDeletes); err != nil {
		return err
	} else if len(ids) > 0 {
		batch.Queue(`DELETE FROM unresolved_relationships WHERE relationship_id=ANY($1)`, ids)
	}
	for _, deletion := range []struct {
		query string
		ids   []string
	}{
		{`DELETE FROM current_relationships WHERE relationship_id=ANY($1)`, removedRelationships},
		{`DELETE FROM current_facets WHERE facet_id=ANY($1)`, removedFacets},
		{`DELETE FROM assertion_conflicts WHERE resource_id=ANY($1)`, removedConflicts},
		{`DELETE FROM current_resources WHERE resource_id=ANY($1)`, removedResources},
	} {
		ids, err := projectionUUIDs(deletion.ids)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			batch.Queue(deletion.query, ids)
		}
	}
	if batch.Len() == 0 {
		return nil
	}
	results := tx.SendBatch(ctx, &batch)
	for range batch.Len() {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return fmt.Errorf("reconcile current projection: %w", err)
		}
	}
	if err := results.Close(); err != nil {
		return fmt.Errorf("reconcile current projection: %w", err)
	}
	return nil
}

func projectionChanges[T any](before, after []T, id func(T) string) ([]T, []string) {
	previous := make(map[string]T, len(before))
	for _, item := range before {
		previous[id(item)] = item
	}
	changed := make([]T, 0)
	for _, item := range after {
		key := id(item)
		if old, exists := previous[key]; !exists || !reflect.DeepEqual(old, item) {
			changed = append(changed, item)
		}
		delete(previous, key)
	}
	removed := make([]string, 0, len(previous))
	for key := range previous {
		removed = append(removed, key)
	}
	slices.Sort(removed)
	return changed, removed
}

func projectionUUIDs(values []string) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		parsed, err := uuid.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("parse projection ID %q: %w", value, err)
		}
		result[index] = parsed
	}
	return result, nil
}

func resolutionText(status graph.ResolutionStatus) string {
	if status == graph.ResolutionUnresolved {
		return "unresolved"
	}
	return "resolved"
}

// Latest returns the compiled graph cached for the current database revision.
func (s *Store) Latest(ctx context.Context) (GraphView, error) {
	if err := verifyActiveAssertionProvenance(ctx, s.pool); err != nil {
		return GraphView{}, err
	}
	s.materializerMu.Lock()
	defer s.materializerMu.Unlock()
	current, err := s.currentMaterializedGraph(ctx)
	if err != nil {
		return GraphView{}, err
	}
	if !current.hasGraph {
		return GraphView{}, ErrNotMaterialized
	}
	return current.view, nil
}

// CurrentGraph returns the revision-validated materialized graph for consumers
// that intentionally need the complete graph.
func (s *Store) CurrentGraph(ctx context.Context) (GraphView, error) {
	return s.Latest(ctx)
}

// GraphRevision returns the compare-and-swap revision of the materialized graph.
func (s *Store) GraphRevision(ctx context.Context) (string, error) {
	var revision int64
	if err := s.pool.QueryRow(ctx, `SELECT revision FROM graph_state WHERE singleton=true`).Scan(&revision); err != nil {
		return "", fmt.Errorf("read graph revision: %w", err)
	}
	return strconv.FormatInt(revision, 10), nil
}

// ReadGraphCheckpoint returns the latest outbox sequence and the graph
// compiled from the same snapshot, so a reasoning consumer can start or
// recover at a point where feed position and graph agree. The graph may
// include telemetry rollups newer than the sequence, because telemetry-only
// publications do not advance it.
func (s *Store) ReadGraphCheckpoint(ctx context.Context) (GraphCheckpoint, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return GraphCheckpoint{}, err
	}
	defer tx.Rollback(ctx)
	var sequence int64
	if err := tx.QueryRow(ctx, `SELECT value FROM graph_change_sequence WHERE singleton=true`).Scan(&sequence); err != nil {
		return GraphCheckpoint{}, fmt.Errorf("read graph checkpoint sequence: %w", err)
	}
	active, err := readActiveGraph(ctx, tx)
	if err != nil {
		return GraphCheckpoint{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return GraphCheckpoint{}, err
	}
	view, err := s.compileGraphView(active)
	if err != nil {
		return GraphCheckpoint{}, err
	}
	return GraphCheckpoint{ThroughSequence: uint64(sequence), View: view}, nil
}

// activeGraph is the active assertion union read from one snapshot, before
// compilation.
type activeGraph struct {
	generatedAt time.Time
	input       graph.Input
}

// readActiveGraph reads the active assertion union inside tx. Compilation is
// left to compileGraphView so callers can end the transaction first.
func readActiveGraph(ctx context.Context, tx pgx.Tx) (activeGraph, error) {
	var generatedAt *time.Time
	var count int
	if err := tx.QueryRow(ctx, `SELECT max(updated_at), count(*) FROM contribution_heads`).Scan(&generatedAt, &count); err != nil {
		return activeGraph{}, err
	}
	if count == 0 || generatedAt == nil {
		return activeGraph{}, ErrNotMaterialized
	}
	input, err := collectActiveInput(ctx, tx)
	if err != nil {
		return activeGraph{}, fmt.Errorf("collect active assertions: %w", err)
	}
	return activeGraph{generatedAt: *generatedAt, input: input}, nil
}

func (s *Store) compileGraphView(active activeGraph) (GraphView, error) {
	snapshot, err := s.compiler.Compile(active.input)
	if err != nil {
		return GraphView{}, fmt.Errorf("compile current graph: %w", err)
	}
	canonical, err := snapshot.CanonicalJSON()
	if err != nil {
		return GraphView{}, err
	}
	digest := sha256.Sum256(canonical)
	return GraphView{GeneratedAt: active.generatedAt, SHA256: hex.EncodeToString(digest[:]), Snapshot: snapshot}, nil
}

// Neighborhood returns resolved edges reachable from resourceID within depth
// hops (1-3) in the given direction ("outgoing", "incoming", or "both"),
// stopping at limit edges (default and maximum 500). It filters the full
// compiled graph rather than querying projections.
func (s *Store) Neighborhood(ctx context.Context, resourceID string, depth int, direction string, limit int) (Neighborhood, error) {
	if err := ValidateNeighborhoodQuery(resourceID, depth, direction); err != nil {
		return Neighborhood{}, err
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	view, err := s.Latest(ctx)
	if err != nil {
		return Neighborhood{}, err
	}
	resources := map[string]graph.Resource{}
	for _, resource := range view.Snapshot.Resources {
		resources[resource.ID] = resource
	}
	selectedNodes := map[string]struct{}{resourceID: {}}
	selectedEdges := make(map[string]graph.Relationship)
	frontier := map[string]struct{}{resourceID: {}}
	for level := 0; level < depth && len(selectedEdges) < limit; level++ {
		next := make(map[string]struct{})
		for _, relationship := range view.Snapshot.Relationships {
			if relationship.ResolutionStatus == graph.ResolutionUnresolved {
				continue
			}
			_, fromSubject := frontier[relationship.SubjectID]
			_, fromObject := frontier[relationship.ObjectID]
			matches := (direction != "incoming" && fromSubject) || (direction != "outgoing" && fromObject)
			if !matches {
				continue
			}
			selectedEdges[relationship.ID] = relationship
			for _, id := range []string{relationship.SubjectID, relationship.ObjectID} {
				if _, seen := selectedNodes[id]; !seen {
					selectedNodes[id] = struct{}{}
					next[id] = struct{}{}
				}
			}
			if len(selectedEdges) >= limit {
				break
			}
		}
		frontier = next
	}
	result := Neighborhood{SHA256: view.SHA256, Resources: []graph.Resource{}, Relationships: []graph.Relationship{}}
	for id := range selectedNodes {
		if resource, ok := resources[id]; ok {
			result.Resources = append(result.Resources, resource)
		}
	}
	for _, relationship := range selectedEdges {
		result.Relationships = append(result.Relationships, relationship)
	}
	slices.SortFunc(result.Resources, func(left, right graph.Resource) int { return cmp.Compare(left.ID, right.ID) })
	slices.SortFunc(result.Relationships, func(left, right graph.Relationship) int { return cmp.Compare(left.ID, right.ID) })
	return result, nil
}

// ValidateNeighborhoodQuery checks the arguments [Store.Neighborhood] accepts.
// Its errors describe only the arguments, so callers may show them to clients.
func ValidateNeighborhoodQuery(resourceID string, depth int, direction string) error {
	if _, err := uuid.Parse(resourceID); err != nil {
		return errors.New("resource ID must be a UUID")
	}
	if depth < 1 || depth > 3 {
		return errors.New("depth must be between 1 and 3")
	}
	if direction != "outgoing" && direction != "incoming" && direction != "both" {
		return errors.New("direction must be outgoing, incoming, or both")
	}
	return nil
}

// CreateAnalysisView pins the current manifest with an evaluation time. A zero
// evaluationTime means now.
func (s *Store) CreateAnalysisView(ctx context.Context, evaluationTime time.Time) (AnalysisViewToken, GraphManifest, error) {
	if evaluationTime.IsZero() {
		evaluationTime = time.Now().UTC()
	} else {
		evaluationTime = evaluationTime.UTC()
	}
	manifest, err := s.CreateManifest(ctx)
	if err != nil {
		return AnalysisViewToken{}, GraphManifest{}, err
	}
	return AnalysisViewToken{ManifestID: manifest.ID, EvaluationTime: evaluationTime}, manifest, nil
}

// CreateManifest records the active version of every non-retired
// contribution. The manifest ID is derived from the version vector and status
// counts, so calling it again with no intervening publication returns the
// existing manifest instead of creating a new one.
func (s *Store) CreateManifest(ctx context.Context) (GraphManifest, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadWrite})
	if err != nil {
		return GraphManifest{}, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT c.contribution_id, c.plugin_id, c.source_id, c.contribution_name, h.active_contribution_version_id, h.generation, h.status, v.source_observed_at, v.published_at, v.ready, v.source_health FROM contributions c JOIN contribution_heads h USING (contribution_id) JOIN contribution_versions v ON v.contribution_version_id=h.active_contribution_version_id WHERE h.status <> 'retired' ORDER BY c.plugin_id, c.source_id, c.contribution_name`)
	if err != nil {
		return GraphManifest{}, err
	}
	var contributions []ManifestContribution
	for rows.Next() {
		var item ManifestContribution
		var generation int64
		if err := rows.Scan(&item.ContributionID, &item.PluginID, &item.SourceID, &item.Name, &item.ContributionVersionID, &generation, &item.Status, &item.SourceObservedAt, &item.PublishedAt, &item.Ready, &item.SourceHealth); err != nil {
			rows.Close()
			return GraphManifest{}, err
		}
		item.Generation = uint64(generation)
		contributions = append(contributions, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return GraphManifest{}, err
	}
	rows.Close()
	status := ManifestStatus{Contributions: len(contributions)}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM unresolved_relationships`).Scan(&status.UnresolvedRelationships); err != nil {
		return GraphManifest{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM assertion_conflicts`).Scan(&status.Conflicts); err != nil {
		return GraphManifest{}, err
	}
	digestInput, err := json.Marshal(struct {
		Contributions []ManifestContribution `json:"contributions"`
		Status        ManifestStatus         `json:"status"`
	}{contributions, status})
	if err != nil {
		return GraphManifest{}, fmt.Errorf("encode manifest digest: %w", err)
	}
	digest := sha256.Sum256(digestInput)
	manifestID := uuid.NewSHA1(uuid.NameSpaceOID, digest[:]).String()
	createdAt := time.Now().UTC()
	var parentID string
	err = tx.QueryRow(ctx, `SELECT manifest_id::text, created_at, COALESCE(parent_id::text, '') FROM graph_manifests WHERE digest=$1`, digest[:]).Scan(&manifestID, &createdAt, &parentID)
	if errors.Is(err, pgx.ErrNoRows) {
		var parent any
		if parentErr := tx.QueryRow(ctx, `SELECT manifest_id::text FROM graph_manifests ORDER BY created_at DESC, manifest_id DESC LIMIT 1`).Scan(&parentID); parentErr == nil {
			parent = parentID
		} else if !errors.Is(parentErr, pgx.ErrNoRows) {
			return GraphManifest{}, parentErr
		}
		if _, err := tx.Exec(ctx, `INSERT INTO graph_manifests (manifest_id, created_at, digest, parent_id, contribution_count, unresolved_relationship_count, conflict_count) VALUES ($1,$2,$3,$4,$5,$6,$7)`, manifestID, createdAt, digest[:], parent, status.Contributions, status.UnresolvedRelationships, status.Conflicts); err != nil {
			return GraphManifest{}, err
		}
	} else if err != nil {
		return GraphManifest{}, err
	}
	for _, item := range contributions {
		if _, err := tx.Exec(ctx, `INSERT INTO graph_manifest_contributions (manifest_id, contribution_id, contribution_version_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, manifestID, item.ContributionID, item.ContributionVersionID); err != nil {
			return GraphManifest{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return GraphManifest{}, err
	}
	return GraphManifest{ID: manifestID, CreatedAt: createdAt, Digest: hex.EncodeToString(digest[:]), ParentID: parentID, StatusSummary: status, Contributions: contributions}, nil
}
