package detector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

type workloadRuleRepository struct {
	ruleRepository
	rules []WorkloadRule
	err   error
}

func (repository workloadRuleRepository) ReadWorkloadRules(context.Context) ([]WorkloadRule, error) {
	return repository.rules, repository.err
}

func testWorkloadRule(id, workload string, mode RuleMode) WorkloadRule {
	rule := testRule()
	rule.ID = id
	rule.PluginID = "*"
	rule.WorkloadResourceID = workload
	return WorkloadRule{Rule: rule, Mode: mode}
}

func TestWorkloadRulesSignalActiveAndShadowMatches(t *testing.T) {
	ctx := context.Background()
	repository := workloadRuleRepository{
		ruleRepository: ruleRepository{activation: Activation{Revision: 1, Ruleset: DefaultRuleset()}},
		rules: []WorkloadRule{
			testWorkloadRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive),
			testWorkloadRule("deployment/deployment-b/rule-1", "deployment-b", RuleModeShadow),
			testWorkloadRule("deployment/deployment-c/rule-1", "deployment-c", RuleModeActive),
		},
	}
	engine, err := Load(ctx, repository, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.ActiveWorkloadRules != 2 || status.ShadowWorkloadRules != 1 || status.WorkloadRulesDigest == "" {
		t.Fatalf("status=%#v", status)
	}
	active, shadow := testEvent(), testEvent()
	shadow.ID = "shadow-event"
	shadow.AnchorIDs, shadow.SubjectIDs = []string{"deployment-b", "destination"}, []string{"deployment-b"}
	result, err := engine.Evaluate(ctx, []Event{active, shadow})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Signals) != 2 || result.WorkloadRulesDigest != engine.Status().WorkloadRulesDigest {
		t.Fatalf("result=%#v", result)
	}
	modes := map[string]RuleMode{}
	for _, signal := range result.Signals {
		modes[signal.RuleID] = signal.RuleMode
	}
	if modes["deployment/deployment-a/rule-1"] != "" || modes["deployment/deployment-b/rule-1"] != RuleModeShadow {
		t.Fatalf("signal modes=%#v", modes)
	}
}

func TestWorkloadRulesReloadRetainsLastKnownGoodRulesOnReadFailure(t *testing.T) {
	ctx := context.Background()
	base := ruleRepository{activation: Activation{Revision: 1, Ruleset: DefaultRuleset()}}
	initial := []WorkloadRule{testWorkloadRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeShadow)}
	engine, err := Load(ctx, workloadRuleRepository{ruleRepository: base, rules: initial}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	digest := engine.Status().WorkloadRulesDigest
	if err := engine.Reload(ctx, workloadRuleRepository{ruleRepository: base, err: errors.New("database unavailable")}); err == nil {
		t.Fatal("failed workload read accepted")
	}
	if status := engine.Status(); status.WorkloadRulesDigest != digest || status.ShadowWorkloadRules != 1 || status.LastReloadError == "" {
		t.Fatalf("status=%#v", status)
	}
	approved := []WorkloadRule{testWorkloadRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive)}
	if err := engine.Reload(ctx, workloadRuleRepository{ruleRepository: base, rules: approved}); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.ActiveWorkloadRules != 1 || status.ShadowWorkloadRules != 0 || status.LastReloadError != "" {
		t.Fatalf("status=%#v", status)
	}
	if err := engine.Reload(ctx, workloadRuleRepository{ruleRepository: base}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(ctx, []Event{testEvent()})
	if err != nil || len(result.Signals) != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestWorkloadRulesSkipInvalidRulesAndKeepTheRest(t *testing.T) {
	ctx := context.Background()
	base := ruleRepository{activation: Activation{Revision: 1, Ruleset: DefaultRuleset()}}
	valid := testWorkloadRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive)
	invalid := testWorkloadRule("deployment/deployment-b/rule-1", "deployment-b", RuleModeActive)
	invalid.Rule.Expression = "unknown_variable"
	rules := []WorkloadRule{
		invalid, valid,
		testWorkloadRule("deployment/unscoped/rule-1", "", RuleModeActive),
		testWorkloadRule("deployment/deployment-c/rule-1", "deployment-c", "enforcing"),
		valid,
	}
	// Startup succeeds with the valid rule loaded and the others reported.
	engine, err := Load(ctx, workloadRuleRepository{ruleRepository: base, rules: rules}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	status := engine.Status()
	if status.ActiveWorkloadRules != 1 || status.SkippedWorkloadRules != 4 || status.LastReloadError == "" {
		t.Fatalf("status=%#v", status)
	}
	result, err := engine.Evaluate(ctx, []Event{testEvent()})
	if err != nil || len(result.Signals) != 1 || result.Signals[0].RuleID != valid.Rule.ID {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	// An unchanged read is not recompiled and clears the reported error.
	if err := engine.Reload(ctx, workloadRuleRepository{ruleRepository: base, rules: rules}); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.SkippedWorkloadRules != 4 || status.LastReloadError != "" {
		t.Fatalf("status=%#v", status)
	}
	if err := ValidateWorkloadRules(rules); err == nil {
		t.Fatal("validation accepted invalid workload rules")
	}
}

func TestWorkloadRulesMatchOnlyTheirSubject(t *testing.T) {
	engine, err := New(DefaultConfig(), DefaultRuleset())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.SetWorkloadRules([]WorkloadRule{testWorkloadRule("deployment/server/rule-1", "server", RuleModeActive)}); err != nil {
		t.Fatal(err)
	}
	inbound, outbound := testEvent(), testEvent()
	inbound.ID, inbound.AnchorIDs, inbound.SubjectIDs = "inbound", []string{"client", "server"}, []string{"client"}
	outbound.ID, outbound.AnchorIDs, outbound.SubjectIDs = "outbound", []string{"server", "destination"}, []string{"server"}
	result, err := engine.Evaluate(context.Background(), []Event{inbound, outbound})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Signals) != 1 || !slices.Contains(result.Signals[0].AnchorIDs, "destination") {
		t.Fatalf("a workload rule matched an input where the workload is only the object: %#v", result.Signals)
	}
}

func TestWorkloadRulesAreBoundedAndUnique(t *testing.T) {
	duplicate := testWorkloadRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive)
	if err := ValidateWorkloadRules([]WorkloadRule{duplicate, duplicate}); err == nil {
		t.Fatal("duplicate workload rules accepted")
	}
	oversized := make([]WorkloadRule, MaxWorkloadRules+2)
	for index := range oversized {
		mode := RuleModeShadow
		if index == len(oversized)-1 {
			mode = RuleModeActive
		}
		oversized[index] = testWorkloadRule(fmt.Sprintf("deployment/d-%05d/rule-1", index), fmt.Sprintf("d-%05d", index), mode)
	}
	if err := ValidateWorkloadRules(oversized); err == nil {
		t.Fatal("oversized workload rules accepted")
	}
	engine, err := New(DefaultConfig(), DefaultRuleset())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.SetWorkloadRules(oversized); err == nil {
		t.Fatal("rules over the bound were not reported")
	}
	// Active rules are kept first, then shadow rules by ID; the last shadow rule is left out.
	if status := engine.Status(); status.ActiveWorkloadRules != 1 || status.ShadowWorkloadRules != MaxWorkloadRules-1 || status.SkippedWorkloadRules != 1 {
		t.Fatalf("status=%#v", status)
	}
}
