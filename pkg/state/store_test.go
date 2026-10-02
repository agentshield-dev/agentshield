package state

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

var testIdentityScheme = graph.IdentityScheme{Group: "test.agentshield.io", Version: "v1", Kind: "Resource"}

func TestConfigValidation(t *testing.T) {
	if err := (Config{}).withDefaults().validate(); err == nil {
		t.Fatal("empty database URL was accepted")
	}
	if err := (Config{DatabaseURL: "postgres://localhost/test", MaxConnections: 1, MinConnections: 2}).validate(); err == nil {
		t.Fatal("min connections above max connections was accepted")
	}
	if err := (Config{DatabaseURL: "postgres://localhost/test", PublicationLockTimeout: time.Microsecond}).withDefaults().validate(); err == nil {
		t.Fatal("sub-millisecond publication lock timeout was accepted")
	}
	if err := (Config{DatabaseURL: "postgres://localhost/test", InvestigationMaxAttempts: -1}).withDefaults().validate(); err == nil {
		t.Fatal("negative investigation max attempts was accepted")
	}
}

func TestPostgreSQLPublicationLockWaitIsBounded(t *testing.T) {
	_, compiler := integrationStore(t)
	config := testConfig(t)
	config.PublicationLockTimeout = 200 * time.Millisecond
	store, err := Open(context.Background(), config, compiler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	holder, err := store.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.Background()) }()
	if _, err := holder.Exec(context.Background(), `SELECT revision FROM graph_state WHERE singleton=true FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 1, "a")); err == nil || !strings.Contains(err.Error(), "advance graph revision") {
		t.Fatalf("publication behind a held lock returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("lock wait took %s", elapsed)
	}
	if err := holder.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 1, "a")); err != nil {
		t.Fatalf("publication after the lock was released: %v", err)
	}
	var lockTimeout string
	if err := store.pool.QueryRow(context.Background(), `SHOW lock_timeout`).Scan(&lockTimeout); err != nil {
		t.Fatal(err)
	}
	if lockTimeout != "0" {
		t.Fatalf("publication lock_timeout leaked into a pooled session: %q", lockTimeout)
	}
}

func TestPostgreSQLFindingRoundTripAndIdempotency(t *testing.T) {
	store, _ := integrationStore(t)
	proposal, err := remediation.NewProposal(
		"finding:test", "analysis:test", strings.Repeat("a", 64),
		remediation.Suggestion{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}},
		remediation.Target{EntityID: "target", Kind: "kubernetes/pod", Identity: graph.IdentityClaim{
			Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "pod/uid",
		}},
		[]string{"evidence"},
	)
	if err != nil {
		t.Fatal(err)
	}
	finding := Finding{
		ID: proposal.FindingID, AnalysisID: proposal.AnalysisID, GraphSHA256: proposal.GraphSHA256,
		Category: "new_exposure", Severity: "high",
		ModelUncertainty: "low", Summary: "Unexpected ingress", SignalIDs: []string{"signal"},
		AffectedEntityIDs: []string{"target"}, Remediations: []remediation.Proposal{proposal}, CreatedAt: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
	}
	if err := store.PutFinding(context.Background(), finding); err != nil {
		t.Fatal(err)
	}
	if err := store.PutFinding(context.Background(), finding); err != nil {
		t.Fatalf("idempotent finding write: %v", err)
	}
	got, err := store.GetFinding(context.Background(), finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != finding.Summary || len(got.Remediations) != 1 || got.Remediations[0].ID != proposal.ID {
		t.Fatalf("stored finding = %#v", got)
	}
	conflicting := finding
	conflicting.Summary = "Different content"
	if err := store.PutFinding(context.Background(), conflicting); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("finding collision error = %v", err)
	}
	second := finding
	second.ID = "finding:other"
	second.AnalysisID = "analysis:other"
	second.Severity = "medium"
	second.AffectedEntityIDs = []string{"other"}
	second.Remediations = nil
	second.CreatedAt = finding.CreatedAt.Add(time.Hour)
	if err := store.PutFinding(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	page, err := store.QueryFindings(context.Background(), FindingQuery{Limit: 1})
	if err != nil || len(page.Findings) != 1 || page.Findings[0].ID != second.ID || !page.HasMore || page.Total != 2 {
		t.Fatalf("first finding page = %#v, err = %v", page, err)
	}
	page, err = store.QueryFindings(context.Background(), FindingQuery{
		Severity: "high", Category: "new_exposure", AffectedEntityID: "target", Limit: 10,
		BeforeCreatedAt: &second.CreatedAt, BeforeFindingID: second.ID,
	})
	if err != nil || len(page.Findings) != 1 || page.Findings[0].ID != finding.ID || page.HasMore || page.Total != 1 {
		t.Fatalf("filtered finding page = %#v, err = %v", page, err)
	}
	invalidatedAt := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	if err := store.InvalidateFindings(context.Background(), strings.Repeat("b", 64), 2, []string{"target"}, invalidatedAt); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetFinding(context.Background(), finding.ID)
	if err != nil || got.Status != FindingStatusInvalidated || got.InvalidatedAt == nil || !got.InvalidatedAt.Equal(invalidatedAt) || got.InvalidatedBySequence == nil || *got.InvalidatedBySequence != 2 || got.InvalidatedGraphSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("invalidated finding = %#v, err = %v", got, err)
	}
	page, err = store.QueryFindings(context.Background(), FindingQuery{Status: FindingStatusActive, Limit: 10})
	if err != nil || len(page.Findings) != 1 || page.Findings[0].ID != second.ID || page.Total != 1 {
		t.Fatalf("active findings = %#v, err = %v", page, err)
	}
	if err := store.InvalidateFindings(context.Background(), strings.Repeat("c", 64), 3, nil, invalidatedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetFinding(context.Background(), second.ID)
	if err != nil || got.Status != FindingStatusInvalidated || got.InvalidatedBySequence == nil || *got.InvalidatedBySequence != 3 {
		t.Fatalf("finding invalidated after rebase = %#v, err = %v", got, err)
	}
}

func TestPostgreSQLDetectionRuleFindingRoundTrip(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	finding := Finding{
		ID: "finding:rule", Origin: FindingOriginDetectionRule, AnalysisID: "detection-window:test", GraphSHA256: strings.Repeat("a", 64),
		Category: "detection_rule_match", Severity: "critical", Summary: "Detection rule matched",
		DetectionRuleID: "deployment/checkout/rule-1", DetectionRuleRevision: 3,
		SignalIDs: []string{"signal"}, AffectedEntityIDs: []string{"checkout"}, CreatedAt: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC),
	}
	for range 2 {
		if err := store.PutFinding(ctx, finding); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.GetFinding(ctx, finding.ID)
	if err != nil || got.Origin != FindingOriginDetectionRule || got.DetectionRuleID != finding.DetectionRuleID || got.DetectionRuleRevision != 3 || got.ModelUncertainty != "" {
		t.Fatalf("rule finding = %#v err = %v", got, err)
	}
	agentic := finding
	agentic.ID, agentic.Origin = "finding:agentic", ""
	agentic.DetectionRuleID, agentic.DetectionRuleRevision, agentic.ModelUncertainty = "", 0, "low"
	if err := store.PutFinding(ctx, agentic); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetFinding(ctx, agentic.ID); err != nil || got.Origin != FindingOriginAgenticInvestigation {
		t.Fatalf("default origin = %#v err = %v", got, err)
	}
	for _, invalid := range []func(*Finding){
		func(candidate *Finding) { candidate.DetectionRuleRevision = 0 },
		func(candidate *Finding) { candidate.Origin = FindingOriginAgenticInvestigation },
		func(candidate *Finding) { candidate.Origin = "unknown" },
	} {
		candidate := finding
		candidate.ID = "finding:invalid"
		invalid(&candidate)
		if err := store.PutFinding(ctx, candidate); err == nil {
			t.Fatalf("invalid finding accepted: %#v", candidate)
		}
	}
	for _, entityIDs := range [][]string{{"checkout"}, nil} {
		if err := store.InvalidateFindings(ctx, strings.Repeat("b", 64), 5, entityIDs, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := store.GetFinding(ctx, finding.ID); err != nil || got.Status != FindingStatusActive {
		t.Fatalf("rule finding after graph change and rebase = %#v err = %v", got, err)
	}
	if got, err := store.GetFinding(ctx, agentic.ID); err != nil || got.Status != FindingStatusInvalidated {
		t.Fatalf("agentic finding after graph change = %#v err = %v", got, err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO findings (finding_id, analysis_id, graph_sha256, category, severity, model_uncertainty, summary, signal_ids, remediations, created_at, origin)
		VALUES ('finding:raw', 'analysis', $1, 'category', 'high', '', 'summary', '[]', '[]', now(), 'agentic_investigation')`, strings.Repeat("a", 64)); err == nil {
		t.Fatal("schema accepted an agentic finding without model uncertainty")
	}
}

func TestNativeEventDigestNormalizesPayloadAndIgnoresObservedAt(t *testing.T) {
	first := NativeEvent{PluginID: "test", SourceID: "source", Collection: "objects", Key: "a", Operation: "upsert", ObservedAt: time.Now(), Payload: json.RawMessage(`{"a":1,"b":2}`)}
	second := first
	second.ObservedAt = first.ObservedAt.Add(time.Hour)
	second.Payload = json.RawMessage(`{"b":2,"a":1}`)
	firstDigest, err := nativeEventDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := nativeEventDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatal("semantically identical events produced different digests")
	}
	second.Operation = "delete"
	secondDigest, err = nativeEventDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Fatal("semantically different events produced the same digest")
	}
	second = first
	second.Collection = "kubernetes/resources/core/v1/pods"
	secondDigest, err = nativeEventDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Fatal("events from different collections produced the same digest")
	}
}

func TestPostgreSQLLatestBeforeFirstContributionIsNotMaterialized(t *testing.T) {
	store, _ := integrationStore(t)
	if _, err := store.Latest(context.Background()); !errors.Is(err, ErrNotMaterialized) {
		t.Fatalf("Latest() error = %v, want %v", err, ErrNotMaterialized)
	}
}

func TestPostgreSQLGraphRevisionChangesOnlyWithPublication(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	revision := func() string {
		t.Helper()
		value, err := store.GraphRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	empty := revision()
	if _, err := store.ReplaceContribution(ctx, testContribution("first", 1, "a")); err != nil {
		t.Fatal(err)
	}
	first := revision()
	if first == empty {
		t.Fatalf("revision %q did not change after the first publication", first)
	}
	if _, err := store.ReplaceContribution(ctx, testContribution("first", 1, "a")); err != nil {
		t.Fatal(err)
	}
	if got := revision(); got != first {
		t.Fatalf("idempotent retry changed revision from %q to %q", first, got)
	}
	if _, err := store.ReplaceContribution(ctx, testContribution("second", 1, "b")); err != nil {
		t.Fatal(err)
	}
	second := revision()
	if second == first {
		t.Fatal("revision did not change after a new contribution")
	}
	// Republishing an older contribution must change the token even though
	// another contribution holds a newer version.
	if _, err := store.ReplaceContribution(ctx, testContribution("first", 2, "c")); err != nil {
		t.Fatal(err)
	}
	if got := revision(); got == second {
		t.Fatal("revision did not change after republishing an older contribution")
	}
}

func TestPostgreSQLReasoningCursorIsMonotonicAndIdempotent(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, found, err := store.ReadReasoningCursor(ctx, "reasoning/default"); err != nil || found {
		t.Fatalf("initial cursor found=%t err=%v, want false nil", found, err)
	}
	first := ReasoningCursor{ConsumerID: "reasoning/default", ThroughSequence: 2, GraphSHA256: "graph-2", UpdatedAt: time.Now().UTC()}
	if err := store.AdvanceReasoningCursor(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceReasoningCursor(ctx, first); err != nil {
		t.Fatalf("idempotent cursor advance: %v", err)
	}
	if err := store.AdvanceReasoningCursor(ctx, ReasoningCursor{ConsumerID: first.ConsumerID, ThroughSequence: 1, GraphSHA256: "graph-1"}); err == nil {
		t.Fatal("reasoning cursor regression was accepted")
	}
	if err := store.AdvanceReasoningCursor(ctx, ReasoningCursor{ConsumerID: first.ConsumerID, ThroughSequence: 2, GraphSHA256: "different"}); err == nil {
		t.Fatal("same-sequence graph digest change was accepted")
	}
	second := ReasoningCursor{ConsumerID: first.ConsumerID, ThroughSequence: 3, GraphSHA256: "graph-3"}
	if err := store.AdvanceReasoningCursor(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.ReadReasoningCursor(ctx, first.ConsumerID)
	if err != nil {
		t.Fatal(err)
	}
	if !found || got.ThroughSequence != second.ThroughSequence || got.GraphSHA256 != second.GraphSHA256 {
		t.Fatalf("cursor = %#v found=%t, want sequence 3 graph-3", got, found)
	}
}

func TestPostgreSQLReasoningCursorConcurrentInitialization(t *testing.T) {
	store, _ := integrationStore(t)
	cursors := []ReasoningCursor{
		{ConsumerID: "reasoning/concurrent", ThroughSequence: 1, GraphSHA256: "graph-1"},
		{ConsumerID: "reasoning/concurrent", ThroughSequence: 2, GraphSHA256: "graph-2"},
	}
	var wait sync.WaitGroup
	errorsChannel := make(chan error, len(cursors))
	for _, cursor := range cursors {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- store.AdvanceReasoningCursor(context.Background(), cursor)
		}()
	}
	wait.Wait()
	close(errorsChannel)
	var failures int
	for err := range errorsChannel {
		if err != nil {
			failures++
		}
	}
	if failures > 1 {
		t.Fatalf("concurrent initialization failures = %d, want at most one monotonic regression", failures)
	}
	cursor, found, err := store.ReadReasoningCursor(context.Background(), "reasoning/concurrent")
	if err != nil {
		t.Fatal(err)
	}
	if !found || cursor.ThroughSequence < 1 || cursor.ThroughSequence > 2 {
		t.Fatalf("cursor = %#v found=%t", cursor, found)
	}
}

func TestPostgreSQLReplaceContributionConcurrencyAndStaleGeneration(t *testing.T) {
	store, compiler := integrationStore(t)
	second, err := Open(context.Background(), testConfig(t), compiler)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	var wait sync.WaitGroup
	records := make(chan GraphView, 2)
	errorsChannel := make(chan error, 2)
	for index, current := range []*Store{store, second} {
		wait.Add(1)
		go func(index int, current *Store) {
			defer wait.Done()
			record, err := current.ReplaceContribution(context.Background(), testContribution("contribution-"+string(rune('a'+index)), 1, string(rune('a'+index))))
			if err != nil {
				errorsChannel <- err
				return
			}
			records <- record
		}(index, current)
	}
	wait.Wait()
	close(records)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	var hashes []string
	for record := range records {
		hashes = append(hashes, record.SHA256)
	}
	slices.Sort(hashes)
	if len(hashes) != 2 || hashes[0] == "" || hashes[1] == "" {
		t.Fatalf("concurrent graph hashes = %v", hashes)
	}
	var contributionVersions int
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM contribution_versions`).Scan(&contributionVersions); err != nil {
		t.Fatal(err)
	}
	if contributionVersions != 2 {
		t.Fatalf("independent contribution versions = %d, want 2", contributionVersions)
	}
	latest, err := store.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(latest.Snapshot.Resources) != 2 {
		t.Fatalf("latest concurrent snapshot is incoherent: %+v", latest)
	}
	if _, err := store.ReplaceContribution(context.Background(), testContribution("contribution-a", 2, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := second.ReplaceContribution(context.Background(), testContribution("contribution-a", 1, "a")); err == nil {
		t.Fatal("stale generation succeeded")
	}
}

func TestPostgreSQLReplaceContributionSameGenerationIsIdempotent(t *testing.T) {
	store, _ := integrationStore(t)
	contribution := testContribution("inventory", 1, "a")
	first, err := store.ReplaceContribution(context.Background(), contribution)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.ReplaceContribution(context.Background(), contribution)
	if err != nil {
		t.Fatal(err)
	}
	if retry.SHA256 != first.SHA256 {
		t.Fatalf("same-generation retry changed the graph: first=%+v retry=%+v", first, retry)
	}
	if _, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 1, "b")); err == nil {
		t.Fatal("conflicting same-generation replacement succeeded")
	}
	var versions int
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM contribution_versions`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 1 {
		t.Fatalf("same-generation writes created %d contribution versions, want 1", versions)
	}
	second, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 2, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if second.SHA256 != first.SHA256 {
		t.Fatalf("new generation with unchanged content changed hash: %+v, want %s", second, first.SHA256)
	}
	events, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Contribution.Generation != 2 || len(events[1].Added) != 0 || len(events[1].Retracted) != 0 {
		t.Fatalf("idempotent and status-only contribution changes = %+v", events)
	}
}

func TestPostgreSQLPublicationPreservesUnchangedProjectionRows(t *testing.T) {
	store, _ := integrationStore(t)
	first := testContribution("inventory", 1, "a")
	first.Input.Resources = append(first.Input.Resources, graph.ResourceAssertion{
		Claim: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "test", ImmutableKey: "stable"},
		Kind:  "test/resource", PluginID: "test", SourceID: "source", RuleID: "resource",
	})
	if _, err := store.ReplaceContribution(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err := store.pool.QueryRow(context.Background(), `SELECT updated_at FROM current_resources WHERE display_name=''`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	second := testContribution("inventory", 2, "b")
	second.Input.Resources = append(second.Input.Resources, first.Input.Resources[1])
	second.UpdatedAt = first.UpdatedAt.Add(time.Minute)
	if _, err := store.ReplaceContribution(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	var after time.Time
	if err := store.pool.QueryRow(context.Background(), `SELECT updated_at FROM current_resources WHERE display_name=''`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) {
		t.Fatalf("unchanged projection updated_at = %s, want %s", after, before)
	}
}

func TestPostgreSQLResourceQueryUsesCurrentProjection(t *testing.T) {
	store, _ := integrationStore(t)
	contribution := testContribution("inventory", 1, "checkout")
	contribution.Input.Resources[0].Attributes = map[string]string{"kubernetes/namespace": "payments"}
	contribution.Input.Resources[0].DisplayName = "checkout"
	contribution.Input.Resources[0].RuleID = "inventory.searchable-rule"
	if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
		t.Fatal(err)
	}
	page, err := store.QueryResources(context.Background(), ResourceQuery{Namespace: "payments", Search: "searchable-rule"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Resources) != 1 || page.Resources[0].Identity.ImmutableKey != "checkout" || len(page.Resources[0].Assertions) != 1 {
		t.Fatalf("resource page = %+v, want projected checkout with provenance", page)
	}
}

func TestPostgreSQLPublicationRejectsStoredIdentityCollision(t *testing.T) {
	store, _ := integrationStore(t)
	contribution := testContribution("inventory", 1, "a")
	if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(context.Background(), `UPDATE resource_identities SET immutable_key='tampered'`); err != nil {
		t.Fatal(err)
	}
	contribution.Generation = 2
	if _, err := store.ReplaceContribution(context.Background(), contribution); err == nil || !strings.Contains(err.Error(), "collides with a different identity claim") {
		t.Fatalf("identity collision error = %v", err)
	}
}

func TestPostgreSQLContributionChangesPreservePublicationBoundaries(t *testing.T) {
	store, _ := integrationStore(t)
	first := testContribution("inventory", 1, "a")
	first.Input.Facets = []graph.FacetAssertion{{
		Resource: first.Input.Resources[0].Claim, Kind: "security", Key: "policy-a",
		Attributes: map[string]string{"mode": "audit", "scope": "production"}, PluginID: "test", SourceID: "source",
		RuleID: "test.facet", EvidenceIDs: []string{"evidence-x"},
	}}
	if _, err := store.ReplaceContribution(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := testContribution("inventory", 2, "a")
	if _, err := store.ReplaceContribution(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	third := first
	third.Generation = 3
	if _, err := store.ReplaceContribution(context.Background(), third); err != nil {
		t.Fatal(err)
	}
	fourth := third
	fourth.Generation = 4
	fourth.Input.Facets[0].Attributes = map[string]string{"mode": "enforce", "scope": "production"}
	if _, err := store.ReplaceContribution(context.Background(), fourth); err != nil {
		t.Fatal(err)
	}
	events, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("contribution changes = %d, want 4: %+v", len(events), events)
	}
	for index, event := range events {
		if (index > 0 && event.Sequence != events[index-1].Sequence+1) || event.Contribution.Generation != uint64(index+1) || event.Contribution.Status != "active" {
			t.Fatalf("contribution change %d = %+v", index, event)
		}
	}
	if len(events[1].Retracted) != 1 || events[1].Retracted[0].AssertionType != assertionFacet || events[1].Retracted[0].Entity.Kind != "security" {
		t.Fatalf("facet retraction = %+v", events[1])
	}
	if len(events[2].Added) != 1 || events[2].Added[0].AssertionID != events[1].Retracted[0].AssertionID || events[2].Added[0].Entity.ID != events[1].Retracted[0].Entity.ID {
		t.Fatalf("facet restoration = %+v, retraction = %+v", events[2], events[1])
	}
	if len(events[3].Added) != 1 || len(events[3].Retracted) != 1 || events[3].Added[0].Entity.ID != events[3].Retracted[0].Entity.ID || events[3].Added[0].AssertionID == events[3].Retracted[0].AssertionID {
		t.Fatalf("facet replacement = %+v", events[3])
	}
	checkpoint, err := store.ReadGraphCheckpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	latest, err := store.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.ThroughSequence != events[len(events)-1].Sequence || checkpoint.View.SHA256 != latest.SHA256 {
		t.Fatalf("graph checkpoint = %+v, latest hash = %s", checkpoint, latest.SHA256)
	}
}

func TestPostgreSQLContributionChangeLocatorsCoverGraphEntities(t *testing.T) {
	store, _ := integrationStore(t)
	observedAt := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "subject"}
	object := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "object"}
	contribution := Contribution{
		PluginID: "test", SourceID: "source", Name: "all-entities", Generation: 1,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: observedAt,
		Input: graph.Input{
			Resources: []graph.ResourceAssertion{
				{Claim: subject, Kind: "test/workload", PluginID: "test", SourceID: "source", RuleID: "resource"},
				{Claim: object, Kind: "test/service", PluginID: "test", SourceID: "source", RuleID: "resource"},
			},
			Facets:        []graph.FacetAssertion{{Resource: subject, Kind: "security", Key: "policy", PluginID: "test", SourceID: "source", RuleID: "facet"}},
			Relationships: []graph.RelationshipAssertion{{Subject: subject, Predicate: graph.PredicateCommunicates, Object: object, Qualifier: "tcp", PluginID: "test", SourceID: "source", RuleID: "relationship"}},
			Telemetry:     []graph.TelemetryAssertion{{EventID: "flow-1", Kind: "network-flow", Subject: subject, Object: object, Count: 1, PluginID: "test", SourceID: "source", RuleID: "telemetry"}},
		},
	}
	if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
		t.Fatal(err)
	}
	events, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(events[0].Added) != 4 {
		t.Fatalf("contribution changes = %+v", events)
	}
	changes := make(map[string][]AssertionChange)
	for _, change := range events[0].Added {
		changes[change.AssertionType] = append(changes[change.AssertionType], change)
		if change.Entity.ID == "" || change.Entity.EntityType != change.AssertionType {
			t.Fatalf("invalid entity locator: %+v", change)
		}
	}
	if len(changes[assertionResource]) != 2 || changes[assertionFacet][0].Entity.ResourceID == "" {
		t.Fatalf("resource locators = %+v", changes)
	}
	if len(changes[assertionTelemetry]) != 0 {
		t.Fatalf("telemetry locators leaked into default change feed: %+v", changes[assertionTelemetry])
	}
	locator := changes[assertionRelationship][0].Entity
	if locator.SubjectID == "" || locator.ObjectID == "" {
		t.Fatalf("relationship endpoint locator = %+v", locator)
	}
	if changes[assertionRelationship][0].Entity.Predicate != string(graph.PredicateCommunicates) || changes[assertionRelationship][0].Entity.Qualifier != "tcp" {
		t.Fatalf("relationship locator = %+v", changes[assertionRelationship][0])
	}
}

func TestPostgreSQLTelemetryOnlyContributionDoesNotAdvanceChangeFeed(t *testing.T) {
	store, _ := integrationStore(t)
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "workload"}
	inventory := Contribution{
		PluginID: "inventory", SourceID: "runtime", Name: "workloads", Generation: 1,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{Resources: []graph.ResourceAssertion{{
			Claim: claim, Kind: "test/workload", PluginID: "inventory", SourceID: "runtime",
			RuleID: "inventory", EvidenceIDs: []string{"resource-1"},
		}}},
	}
	if _, err := store.ReplaceContribution(context.Background(), inventory); err != nil {
		t.Fatal(err)
	}
	initialEvents, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil || len(initialEvents) != 1 {
		t.Fatalf("initial contribution changes = %+v, err = %v", initialEvents, err)
	}
	contribution := Contribution{
		PluginID: "telemetry", SourceID: "runtime", Name: "rollups", Generation: 1,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{Telemetry: []graph.TelemetryAssertion{{
			EventID: "flow-1", Kind: "network-flow", Count: 1, Subject: claim, Object: claim,
			PluginID: "telemetry", SourceID: "runtime", RuleID: "rollup",
		}}},
	}
	if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
		t.Fatal(err)
	}
	events, err := store.ReadContributionChanges(context.Background(), initialEvents[0].Sequence, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("telemetry-only publication emitted change events: %+v", events)
	}
}

func TestPostgreSQLExecutesLeaseAdvancesChangeFeed(t *testing.T) {
	store, _ := integrationStore(t)
	pod := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "pod"}
	shell, err := graph.ProcessClassClaim("source", graph.ProcessClassShell)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "inventory", SourceID: "runtime", Name: "workloads", Generation: 1, Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{Resources: []graph.ResourceAssertion{{Claim: pod, Kind: "test/workload", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory", EvidenceIDs: []string{"pod"}}}},
	}); err != nil {
		t.Fatal(err)
	}
	before, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil || len(before) != 1 {
		t.Fatalf("initial changes = %+v, err = %v", before, err)
	}
	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "falco", SourceID: "runtime", Name: "rollups", Generation: 1, Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{
			Resources: []graph.ResourceAssertion{{Claim: shell, Kind: "process/class", PluginID: "falco", SourceID: "runtime", RuleID: "telemetry.process-class", EvidenceIDs: []string{"shell-1"}}},
			Relationships: []graph.RelationshipAssertion{{
				Subject: pod, Predicate: graph.PredicateExecutes, Object: shell, Qualifier: "telemetry-observed",
				PluginID: "falco", SourceID: "runtime", RuleID: "telemetry.process-execution-lease", EvidenceIDs: []string{"shell-1"},
			}},
			Telemetry: []graph.TelemetryAssertion{{
				EventID: "series-1", Kind: telemetry.EventKindProcessExec, Operation: "spawn-shell", Outcome: "observed", Count: 1,
				Subject: pod, Object: shell, PluginID: "falco", SourceID: "runtime", RuleID: "telemetry.time-window-rollup", EvidenceIDs: []string{"shell-1"},
			}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	events, err := store.ReadContributionChanges(context.Background(), before[0].Sequence, 10)
	if err != nil {
		t.Fatal(err)
	}
	var addedExecutes bool
	for _, event := range events {
		for _, change := range event.Added {
			if change.AssertionType == assertionTelemetry {
				t.Fatalf("telemetry locator leaked into the change feed: %+v", change)
			}
			addedExecutes = addedExecutes || change.Entity.Predicate == string(graph.PredicateExecutes)
		}
	}
	if len(events) != 1 || !addedExecutes {
		t.Fatalf("executes lease publication changes = %+v", events)
	}
}

func TestPostgreSQLMixedContributionTelemetryDeltaDoesNotAdvanceChangeFeed(t *testing.T) {
	store, _ := integrationStore(t)
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "workload"}
	contribution := Contribution{
		PluginID: "mixed", SourceID: "runtime", Name: "inventory-and-rollups", Generation: 1,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{
			Resources: []graph.ResourceAssertion{{
				Claim: claim, Kind: "test/workload", PluginID: "mixed", SourceID: "runtime",
				RuleID: "inventory", EvidenceIDs: []string{"resource-1"},
			}},
			Telemetry: []graph.TelemetryAssertion{{
				EventID: "flow-1", Kind: "network-flow", Count: 1, Subject: claim, Object: claim,
				PluginID: "mixed", SourceID: "runtime", RuleID: "rollup",
			}},
		},
	}
	if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
		t.Fatal(err)
	}
	contribution.Generation = 2
	contribution.Input.Telemetry[0].EventID = "flow-2"
	if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
		t.Fatal(err)
	}
	events, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Contribution.Generation != 1 {
		t.Fatalf("contribution changes = %+v, want only initial mixed publication", events)
	}
}

func TestPostgreSQLTelemetryEdgeLifecycleAdvancesChangeFeedSparsely(t *testing.T) {
	store, _ := integrationStore(t)
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "subject"}
	object := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "object"}
	inventory := Contribution{
		PluginID: "inventory", SourceID: "runtime", Name: "workloads", Generation: 1,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{Resources: []graph.ResourceAssertion{
			{Claim: subject, Kind: "test/workload", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory"},
			{Claim: object, Kind: "test/service", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory"},
		}},
	}
	if _, err := store.ReplaceContribution(context.Background(), inventory); err != nil {
		t.Fatal(err)
	}
	initialEvents, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil || len(initialEvents) != 1 {
		t.Fatalf("initial contribution changes = %+v, err = %v", initialEvents, err)
	}

	rollup := telemetry.NewRollup(telemetry.RollupConfig{
		Window: time.Minute, Retention: time.Hour, EdgeRefreshBefore: 15 * time.Minute, MaxSeries: 10,
	})
	observedAt := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	event := telemetry.Event{
		EventID: "flow-1", PluginID: "test-telemetry", SourceID: "flow-source", Kind: "network-flow",
		Subject: subject, Object: object, ObservedAt: observedAt, Count: 1, EvidenceIDs: []string{"evidence-1"},
	}
	const pluginID, sourceID = "test-telemetry", "flow-source"
	publish := func(generation uint64) {
		t.Helper()
		if _, err := store.ReplaceContribution(context.Background(), Contribution{
			PluginID: pluginID, SourceID: sourceID, Name: "rollups", Generation: generation,
			Ready: true, SourceHealth: "healthy", SourceObservedAt: event.ObservedAt, Input: rollup.Input(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	rollup.ObserveBatch([]telemetry.Event{event})
	publish(1)
	current, err := store.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	restarted := telemetry.NewRollup(telemetry.RollupConfig{
		Window: time.Minute, Retention: time.Hour, EdgeRefreshBefore: 15 * time.Minute, MaxSeries: 10,
	})
	if err := restarted.Restore(current.Snapshot); err != nil {
		t.Fatal(err)
	}
	rollup = restarted

	event.EventID = "flow-2"
	event.ObservedAt = observedAt.Add(30 * time.Minute)
	event.EvidenceIDs = []string{"evidence-2"}
	rollup.ObserveBatch([]telemetry.Event{event})
	publish(2)

	event.EventID = "flow-3"
	event.ObservedAt = observedAt.Add(46 * time.Minute)
	event.EvidenceIDs = []string{"evidence-3"}
	rollup.ObserveBatch([]telemetry.Event{event})
	publish(3)

	rollup.Advance(observedAt.Add(107 * time.Minute))
	publish(4)

	events, err := store.ReadContributionChanges(context.Background(), initialEvents[0].Sequence, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("telemetry edge lifecycle emitted %d events, want create, refresh, expire: %+v", len(events), events)
	}
	if events[0].Contribution.Generation != 1 || len(events[0].Added) != 1 || events[0].Added[0].AssertionType != assertionRelationship {
		t.Fatalf("edge creation event = %+v", events[0])
	}
	if events[1].Contribution.Generation != 3 || len(events[1].Added) != 1 || len(events[1].Retracted) != 1 {
		t.Fatalf("edge refresh event = %+v", events[1])
	}
	if events[2].Contribution.Generation != 4 || len(events[2].Added) != 0 || len(events[2].Retracted) != 1 {
		t.Fatalf("edge expiration event = %+v", events[2])
	}
}

func TestPostgreSQLTelemetryEdgeResolvesAfterInventoryPublication(t *testing.T) {
	store, _ := integrationStore(t)
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "subject"}
	object := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "object"}
	rollup := telemetry.NewRollup(telemetry.RollupConfig{Retention: time.Hour, MaxSeries: 10})
	rollup.ObserveBatch([]telemetry.Event{{
		EventID: "flow-1", PluginID: "test-telemetry", SourceID: "flow-source", Kind: "network-flow",
		Subject: subject, Object: object, ObservedAt: time.Now().UTC(), Count: 1, EvidenceIDs: []string{"evidence-1"},
	}})
	input := rollup.Input()
	input.Telemetry = nil
	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "test-telemetry", SourceID: "flow-source", Name: "rollups", Generation: 1,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(), Input: input,
	}); err != nil {
		t.Fatal(err)
	}
	before, err := store.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Snapshot.Relationships) != 1 || before.Snapshot.Relationships[0].ResolutionStatus != graph.ResolutionUnresolved {
		t.Fatalf("relationship before inventory = %#v", before.Snapshot.Relationships)
	}

	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "inventory", SourceID: "runtime", Name: "workloads", Generation: 1,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{Resources: []graph.ResourceAssertion{
			{Claim: subject, Kind: "test/workload", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory"},
			{Claim: object, Kind: "test/service", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	after, err := store.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Snapshot.Relationships) != 1 || after.Snapshot.Relationships[0].ResolutionStatus != graph.ResolutionResolved {
		t.Fatalf("relationship after inventory = %#v", after.Snapshot.Relationships)
	}
}

func TestPostgreSQLTelemetryHealthChangeAdvancesChangeFeed(t *testing.T) {
	store, _ := integrationStore(t)
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "workload"}
	contribution := Contribution{
		PluginID: "telemetry", SourceID: "runtime", Name: "rollups", Generation: 1,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{
			Resources: []graph.ResourceAssertion{{
				Claim: claim, Kind: "test/workload", PluginID: "telemetry", SourceID: "runtime",
				RuleID: "inventory", EvidenceIDs: []string{"resource-1"},
			}},
			Telemetry: []graph.TelemetryAssertion{{
				EventID: "flow-1", Kind: "network-flow", Count: 1, Subject: claim, Object: claim,
				PluginID: "telemetry", SourceID: "runtime", RuleID: "rollup",
			}},
		},
	}
	if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
		t.Fatal(err)
	}
	contribution.Generation = 2
	contribution.SourceHealth = "degraded"
	contribution.Input.Telemetry[0].EventID = "flow-2"
	if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
		t.Fatal(err)
	}
	events, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Contribution.Generation != 2 || events[1].Contribution.SourceHealth != "degraded" {
		t.Fatalf("contribution changes = %+v, want degraded health publication", events)
	}
}

func TestPostgreSQLAtomicRollbackAndRestartPersistence(t *testing.T) {
	store, compiler := integrationStore(t)
	_, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 1, "a"))
	if err != nil {
		t.Fatal(err)
	}
	invalid := testContribution("inventory", 3, "invalid")
	invalid.Input.Resources[0].Claim.Scheme = graph.IdentityScheme{Group: "unregistered.agentshield.io", Version: "v1", Kind: "Resource"}
	if _, err := store.ReplaceContribution(context.Background(), invalid); err == nil {
		t.Fatal("invalid graph compilation succeeded")
	}
	second, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 2, "b"))
	if err != nil {
		t.Fatalf("failed contribution replacement was partially committed: %v", err)
	}
	var versions int
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM contribution_versions`).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 2 {
		t.Fatalf("rollback left %d contribution versions, want 2", versions)
	}
	store.Close()
	reopened, err := Open(context.Background(), testConfig(t), compiler)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	latest, err := reopened.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	generation, err := reopened.ContributionGeneration(context.Background(), "test", "source")
	if err != nil {
		t.Fatal(err)
	}
	if latest.SHA256 != second.SHA256 || generation != 2 {
		t.Fatalf("state did not survive restart: latest=%+v generation=%d", latest, generation)
	}
}

func TestValidateContributionRejectsSpoofedAssertionProvenance(t *testing.T) {
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	tests := []struct {
		name  string
		input graph.Input
	}{
		{name: "resource", input: graph.Input{Resources: []graph.ResourceAssertion{{Claim: claim, PluginID: "spoofed", SourceID: "source"}}}},
		{name: "facet", input: graph.Input{Facets: []graph.FacetAssertion{{Resource: claim, PluginID: "test", SourceID: "spoofed"}}}},
		{name: "relationship", input: graph.Input{Relationships: []graph.RelationshipAssertion{{Subject: claim, Object: claim, PluginID: "spoofed", SourceID: "spoofed"}}}},
		{name: "telemetry", input: graph.Input{Telemetry: []graph.TelemetryAssertion{{Subject: claim, Object: claim, PluginID: "test", SourceID: "spoofed"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contribution := Contribution{PluginID: "test", SourceID: "source", Name: "owned", Generation: 1, Input: test.input}
			if err := validateContribution(contribution); err == nil || !strings.Contains(err.Error(), "does not match contribution owner") {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestPostgreSQLLatestRejectsStoredSpoofedAssertionProvenance(t *testing.T) {
	store, _ := integrationStore(t)
	if _, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 1, "owned")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(context.Background(), `UPDATE resource_assertions SET plugin_id='spoofed' WHERE assertion_id IN (SELECT assertion_id FROM contribution_current_assertions WHERE assertion_type='resource')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match active contribution owner") {
		t.Fatalf("stored spoofed provenance error = %v", err)
	}
}

func TestPostgreSQLNativeEventIsIdempotent(t *testing.T) {
	store, _ := integrationStore(t)
	event := NativeEvent{EventID: "event-1", PluginID: "test", SourceID: "source", Collection: "objects", Key: "a", Operation: "upsert", ObservedAt: time.Now().UTC(), Payload: json.RawMessage(`{"a":1,"b":2}`)}
	if err := store.RecordNative(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	event.ObservedAt = event.ObservedAt.Add(time.Minute)
	event.Payload = json.RawMessage(`{"b":2,"a":1}`)
	if err := store.RecordNative(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	event.Operation = "delete"
	if err := store.RecordNative(context.Background(), event); err == nil {
		t.Fatal("event ID reuse with different content succeeded")
	}
}

func TestPostgreSQLNeighborhoodTraversal(t *testing.T) {
	store, _ := integrationStore(t)
	record, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "test", SourceID: "source", Name: "neighborhood", Generation: 1,
		Input: graph.Input{
			Resources: []graph.ResourceAssertion{
				{Claim: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "a"}, Kind: "test/resource", PluginID: "test", SourceID: "source", RuleID: "resource"},
				{Claim: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "b"}, Kind: "test/resource", PluginID: "test", SourceID: "source", RuleID: "resource"},
				{Claim: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "c"}, Kind: "test/resource", PluginID: "test", SourceID: "source", RuleID: "resource"},
			},
			Relationships: []graph.RelationshipAssertion{
				{Subject: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "a"}, Predicate: graph.PredicateCommunicates, Object: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "b"}, PluginID: "test", SourceID: "source", RuleID: "edge"},
				{Subject: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "b"}, Predicate: graph.PredicateCommunicates, Object: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "c"}, PluginID: "test", SourceID: "source", RuleID: "edge"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceIDs := map[string]string{}
	for _, resource := range record.Snapshot.Resources {
		resourceIDs[resource.Identity.ImmutableKey] = resource.ID
	}
	depthOne, err := store.Neighborhood(context.Background(), resourceIDs["a"], 1, "outgoing", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(depthOne.Resources) != 2 || len(depthOne.Relationships) != 1 {
		t.Fatalf("depth one neighborhood = %d resources, %d relationships", len(depthOne.Resources), len(depthOne.Relationships))
	}
	depthTwo, err := store.Neighborhood(context.Background(), resourceIDs["a"], 2, "outgoing", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(depthTwo.Resources) != 3 || len(depthTwo.Relationships) != 2 {
		t.Fatalf("depth two neighborhood = %d resources, %d relationships", len(depthTwo.Resources), len(depthTwo.Relationships))
	}
	incoming, err := store.Neighborhood(context.Background(), resourceIDs["c"], 2, "incoming", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(incoming.Resources) != 3 || len(incoming.Relationships) != 2 {
		t.Fatalf("incoming neighborhood = %d resources, %d relationships", len(incoming.Resources), len(incoming.Relationships))
	}
}

func TestPostgreSQLUnresolvedRelationshipLifecycle(t *testing.T) {
	store, _ := integrationStore(t)
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "subject"}
	object := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "object"}
	record, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "edges", SourceID: "source", Name: "topology", Generation: 1, Ready: true, SourceHealth: "healthy",
		Input: graph.Input{
			Resources: []graph.ResourceAssertion{{Claim: subject, Kind: "test/resource", PluginID: "edges", SourceID: "source", RuleID: "resource"}},
			Relationships: []graph.RelationshipAssertion{{
				Subject: subject, Predicate: graph.PredicateCommunicates, Object: object,
				PluginID: "edges", SourceID: "source", RuleID: "edge",
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Snapshot.Relationships) != 1 || record.Snapshot.Relationships[0].ResolutionStatus != graph.ResolutionUnresolved {
		t.Fatalf("current graph relationship = %#v", record.Snapshot.Relationships)
	}
	var relationshipStatus string
	var unresolvedCount int
	if err := store.pool.QueryRow(context.Background(), `SELECT resolution_status FROM current_relationships`).Scan(&relationshipStatus); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM unresolved_relationships`).Scan(&unresolvedCount); err != nil {
		t.Fatal(err)
	}
	if relationshipStatus != "unresolved" || unresolvedCount != 1 {
		t.Fatalf("unresolved projection status=%q count=%d", relationshipStatus, unresolvedCount)
	}
	subjectID := record.Snapshot.Resources[0].ID
	neighborhood, err := store.Neighborhood(context.Background(), subjectID, 2, "outgoing", 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(neighborhood.Resources) != 1 || len(neighborhood.Relationships) != 0 {
		t.Fatalf("unresolved edge entered traversal: %+v", neighborhood)
	}
	var firstSeen, lastSeen time.Time
	if err := store.pool.QueryRow(context.Background(), `SELECT first_seen_at, last_seen_at FROM unresolved_relationships`).Scan(&firstSeen, &lastSeen); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := store.ReplaceContribution(context.Background(), testContribution("unrelated", 1, "unrelated")); err != nil {
		t.Fatal(err)
	}
	var keptFirstSeen, refreshedLastSeen time.Time
	if err := store.pool.QueryRow(context.Background(), `SELECT first_seen_at, last_seen_at FROM unresolved_relationships`).Scan(&keptFirstSeen, &refreshedLastSeen); err != nil {
		t.Fatal(err)
	}
	if !keptFirstSeen.Equal(firstSeen) || !refreshedLastSeen.Equal(lastSeen) {
		t.Fatalf("unrelated publication moved unresolved timestamps: first_seen_at %s -> %s, last_seen_at %s -> %s", firstSeen, keptFirstSeen, lastSeen, refreshedLastSeen)
	}

	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "inventory", SourceID: "source", Name: "resources", Generation: 1, Ready: true, SourceHealth: "healthy",
		Input: graph.Input{Resources: []graph.ResourceAssertion{{
			Claim: object, Kind: "test/resource", PluginID: "inventory", SourceID: "source", RuleID: "resource",
		}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(context.Background(), `SELECT resolution_status FROM current_relationships`).Scan(&relationshipStatus); err != nil {
		t.Fatal(err)
	}
	if relationshipStatus != "resolved" {
		t.Fatalf("late endpoint left relationship %q", relationshipStatus)
	}
	neighborhood, err = store.Neighborhood(context.Background(), subjectID, 2, "outgoing", 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(neighborhood.Resources) != 2 || len(neighborhood.Relationships) != 1 {
		t.Fatalf("resolved edge missing from traversal: %+v", neighborhood)
	}

	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "inventory", SourceID: "source", Name: "resources", Generation: 2, Ready: true, SourceHealth: "healthy", Input: graph.Input{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(context.Background(), `SELECT resolution_status FROM current_relationships`).Scan(&relationshipStatus); err != nil {
		t.Fatal(err)
	}
	if relationshipStatus != "unresolved" {
		t.Fatalf("endpoint retraction left relationship %q", relationshipStatus)
	}
	events, err := store.ReadContributionChanges(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	latest := events[len(events)-1]
	if len(latest.Retracted) != 1 || latest.Retracted[0].AssertionType != assertionResource {
		t.Fatalf("transactional retractions=%+v", latest.Retracted)
	}
}

func TestPostgreSQLSelfRelationshipResolves(t *testing.T) {
	store, _ := integrationStore(t)
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "self"}
	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "test", SourceID: "source", Name: "self-edge", Generation: 1, Ready: true, SourceHealth: "healthy",
		Input: graph.Input{
			Resources: []graph.ResourceAssertion{{Claim: claim, Kind: "test/resource", PluginID: "test", SourceID: "source", RuleID: "resource"}},
			Relationships: []graph.RelationshipAssertion{{
				Subject: claim, Predicate: graph.PredicateCommunicates, Object: claim,
				PluginID: "test", SourceID: "source", RuleID: "edge",
			}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := store.pool.QueryRow(context.Background(), `SELECT resolution_status FROM current_relationships`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "resolved" {
		t.Fatalf("self relationship status = %q, want resolved", status)
	}
}

func TestPostgreSQLProjectsConflicts(t *testing.T) {
	store, _ := integrationStore(t)
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "shared"}
	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "inventory", SourceID: "source", Name: "base", Generation: 1, Ready: true, SourceHealth: "healthy",
		Input: graph.Input{Resources: []graph.ResourceAssertion{{
			Claim: claim, Kind: "machine", PluginID: "inventory", SourceID: "source", RuleID: "resource",
		}}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReplaceContribution(context.Background(), Contribution{
		PluginID: "security", SourceID: "source", Name: "analysis", Generation: 1, Ready: true, SourceHealth: "healthy",
		Input: graph.Input{Resources: []graph.ResourceAssertion{{Claim: claim, Kind: "service", PluginID: "security", SourceID: "source", RuleID: "resource"}}},
	}); err != nil {
		t.Fatal(err)
	}
	var resources, conflicts int
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM current_resources`).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM assertion_conflicts`).Scan(&conflicts); err != nil {
		t.Fatal(err)
	}
	if resources != 0 || conflicts != 1 {
		t.Fatalf("projection resources=%d conflicts=%d", resources, conflicts)
	}
}

func TestPostgreSQLAnalysisViewPinsContributionVersions(t *testing.T) {
	store, _ := integrationStore(t)
	if _, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 1, "a")); err != nil {
		t.Fatal(err)
	}
	evaluationTime := time.Date(2026, time.October, 2, 15, 0, 0, 0, time.UTC)
	firstToken, first, err := store.CreateAnalysisView(context.Background(), evaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if firstToken.ManifestID != first.ID || !firstToken.EvaluationTime.Equal(evaluationTime) || len(first.Contributions) != 1 {
		t.Fatalf("first analysis view = token=%+v manifest=%+v", firstToken, first)
	}
	firstVersion := first.Contributions[0].ContributionVersionID
	if _, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 2, "b")); err != nil {
		t.Fatal(err)
	}
	_, second, err := store.CreateAnalysisView(context.Background(), evaluationTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID || second.Contributions[0].ContributionVersionID == firstVersion {
		t.Fatalf("updated head reused manifest vector: first=%+v second=%+v", first, second)
	}
	_, retry, err := store.CreateAnalysisView(context.Background(), evaluationTime.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if retry.ID != second.ID || retry.ParentID == retry.ID {
		t.Fatalf("idempotent manifest = %+v, want id %s with distinct parent", retry, second.ID)
	}
	var pinnedVersion int64
	if err := store.pool.QueryRow(context.Background(), `
		SELECT contribution_version_id FROM graph_manifest_contributions WHERE manifest_id=$1`, first.ID).Scan(&pinnedVersion); err != nil {
		t.Fatal(err)
	}
	if pinnedVersion != firstVersion {
		t.Fatalf("first manifest moved from version %d to %d", firstVersion, pinnedVersion)
	}
}

func TestPostgreSQLContributionRetirementRetractsAssertions(t *testing.T) {
	store, _ := integrationStore(t)
	if _, err := store.ReplaceContribution(context.Background(), testContribution("inventory", 1, "a")); err != nil {
		t.Fatal(err)
	}
	record, err := store.RetireContribution(context.Background(), "test", "source", "inventory", 2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Snapshot.Resources) != 0 {
		t.Fatalf("retired current graph has %d resources", len(record.Snapshot.Resources))
	}
	var status string
	var currentResources int
	if err := store.pool.QueryRow(context.Background(), `SELECT status FROM contribution_heads`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(context.Background(), `SELECT count(*) FROM current_resources`).Scan(&currentResources); err != nil {
		t.Fatal(err)
	}
	events, err := store.ReadContributionChanges(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	latest := events[len(events)-1]
	if status != "retired" || currentResources != 0 || len(latest.Retracted) != 1 || latest.Retracted[0].AssertionType != assertionResource {
		t.Fatalf("retirement status=%q current_resources=%d retractions=%+v", status, currentResources, latest.Retracted)
	}
}

func integrationStore(t *testing.T) (*Store, *graph.Compiler) {
	t.Helper()
	registry := graph.NewRegistry()
	if err := registry.Register(graph.TrimmedIdentityScheme(testIdentityScheme)); err != nil {
		t.Fatal(err)
	}
	compiler := graph.NewCompiler(registry)
	store, err := Open(context.Background(), testConfig(t), compiler)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(context.Background(), `TRUNCATE deployment_rule_jobs, detection_signals, investigation_jobs, contributions, resource_identities, native_events, reasoning_cursors, findings RESTART IDENTITY CASCADE`); err != nil {
		store.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, compiler
}

func testConfig(t *testing.T) Config {
	t.Helper()
	databaseURL := os.Getenv("AGENTSHIELD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set AGENTSHIELD_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	return Config{DatabaseURL: databaseURL, MaxConnections: 8, MinConnections: 1}
}

func testContribution(name string, generation uint64, key string) Contribution {
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: key}
	return Contribution{PluginID: "test", SourceID: "source", Name: name, Generation: generation, Ready: true, SourceHealth: "healthy", Input: graph.Input{Resources: []graph.ResourceAssertion{{Claim: claim, Kind: "test/resource", PluginID: "test", SourceID: "source", RuleID: "test.resource", EvidenceIDs: []string{"event-" + key}}}}}
}
