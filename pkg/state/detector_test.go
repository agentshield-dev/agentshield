package state

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/detector"
)

func detectorStore(t *testing.T) *Store {
	t.Helper()
	store, _ := integrationStore(t)
	if _, err := store.pool.Exec(context.Background(), `TRUNCATE detector_rule_revisions, detector_rulesets, detector_ruleset_members, detector_activations, detector_active_ruleset`); err != nil {
		t.Fatal(err)
	}
	return store
}

// celRuleset returns a ruleset with one CEL rule; builtin/v1 has no CEL rules.
func celRuleset(id string) detector.Ruleset {
	return detector.Ruleset{ID: id, Rules: []detector.Rule{{
		ID: "public-egress", Revision: 1, InputVersion: detector.InputVersion, PluginID: "cilium", Type: "telemetry", Kind: "network-flow",
		Expression: "operation == 'egress' && outcome == 'forwarded' && destination_ip_class == 'public'",
		Risk:       detector.RiskMedium, Reasons: []string{"public_egress"}, WindowSeconds: 60,
	}}}
}

func TestPostgreSQLDetectorRulesetLifecycle(t *testing.T) {
	store := detectorStore(t)
	ctx := context.Background()
	if _, err := store.ReadActiveDetectorRuleset(ctx); !errors.Is(err, detector.ErrNoActiveRuleset) {
		t.Fatalf("err=%v", err)
	}
	if err := store.EnsureDefaultDetectorRuleset(ctx); err != nil {
		t.Fatal(err)
	}
	active, err := store.ReadActiveDetectorRuleset(ctx)
	if err != nil || active.Revision != 1 || active.Ruleset.ID != "builtin/v1" {
		t.Fatalf("active=%#v err=%v", active, err)
	}
	if err := store.EnsureDefaultDetectorRuleset(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDetectorRuleset(ctx, active.Ruleset, "test/retry"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDetectorRuleset(ctx, celRuleset("rules/v1"), "test"); err != nil {
		t.Fatal(err)
	}
	mutated := celRuleset("rules/v1")
	mutated.Rules[0].Expression = "false"
	if err := store.SaveDetectorRuleset(ctx, mutated, "test"); err == nil {
		t.Fatal("mutated ruleset accepted")
	}
	mutated.ID = "changed"
	if err := store.SaveDetectorRuleset(ctx, mutated, "test"); err == nil {
		t.Fatal("mutated rule revision accepted")
	}
	mutated.Rules[0].Revision++
	if err := store.SaveDetectorRuleset(ctx, mutated, "test/agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateDetectorRuleset(ctx, mutated.ID, 0, "test"); !errors.Is(err, detector.ErrActivationConflict) {
		t.Fatalf("err=%v", err)
	}
	if revision, err := store.ActivateDetectorRuleset(ctx, mutated.ID, 1, "test/operator"); err != nil || revision != 2 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	engine, err := detector.Load(ctx, store, detector.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if revision, err := store.ActivateDetectorRuleset(ctx, "builtin/v1", 2, "test/rollback"); err != nil || revision != 3 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	if err := engine.Reload(ctx, store); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.RulesetID != "builtin/v1" || status.ActivationRevision != 3 {
		t.Fatalf("status=%#v", status)
	}
	disabled := detector.Ruleset{ID: "disabled", Rules: []detector.Rule{}}
	if err := store.SaveDetectorRuleset(ctx, disabled, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateDetectorRuleset(ctx, disabled.ID, 3, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureDefaultDetectorRuleset(ctx); err != nil {
		t.Fatal(err)
	}
	active, err = store.ReadActiveDetectorRuleset(ctx)
	if err != nil || active.Ruleset.ID != "disabled" {
		t.Fatalf("active=%#v err=%v", active, err)
	}
	var auditCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM detector_activations`).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("audit count=%d err=%v", auditCount, err)
	}
}

func TestPostgreSQLDetectorConcurrentActivation(t *testing.T) {
	store := detectorStore(t)
	ctx := context.Background()
	if err := store.SaveDetectorRuleset(ctx, detector.DefaultRuleset(), "test"); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.ActivateDetectorRuleset(ctx, "builtin/v1", 0, "test")
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, detector.ErrActivationConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestPostgreSQLDetectorRejectsCorruptionAndInvalidRules(t *testing.T) {
	store := detectorStore(t)
	ctx := context.Background()
	invalid := celRuleset("invalid")
	invalid.Rules[0].Expression = "not_a_variable"
	if err := store.SaveDetectorRuleset(ctx, invalid, "test"); err == nil {
		t.Fatal("invalid CEL saved")
	}
	valid := celRuleset("rules/v1")
	if err := store.SaveDetectorRuleset(ctx, valid, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateDetectorRuleset(ctx, valid.ID, 0, "test"); err != nil {
		t.Fatal(err)
	}
	engine, err := detector.Load(ctx, store, detector.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE detector_rule_revisions SET definition=jsonb_set(definition, '{expression}', '"false"') WHERE rule_id='public-egress'`); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(ctx, store); err == nil {
		t.Fatal("corruption accepted")
	}
	if engine.Status().LastReloadError == "" {
		t.Fatal("reload failure not visible")
	}
}
