package detector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

type resourceRuleRepository struct {
	ruleRepository
	rules []ResourceRule
	err   error
}

func (repository resourceRuleRepository) ReadResourceRulesForDetector(context.Context) ([]ResourceRule, error) {
	return repository.rules, repository.err
}

func testResourceRule(id, workload string, mode RuleMode) ResourceRule {
	rule := testRule()
	rule.ID = id
	rule.PluginID = "*"
	rule.ScopeResourceID = workload
	return ResourceRule{Rule: rule, Mode: mode}
}

func TestResourceRulesSignalActiveAndShadowMatches(t *testing.T) {
	ctx := context.Background()
	repository := resourceRuleRepository{
		ruleRepository: ruleRepository{activation: Activation{Revision: 1, Ruleset: DefaultRuleset()}},
		rules: []ResourceRule{
			testResourceRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive),
			testResourceRule("deployment/deployment-b/rule-1", "deployment-b", RuleModeShadow),
			testResourceRule("deployment/deployment-c/rule-1", "deployment-c", RuleModeActive),
		},
	}
	engine, err := Load(ctx, repository, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.ActiveResourceRules != 2 || status.ShadowResourceRules != 1 || status.ResourceRulesDigest == "" {
		t.Fatalf("status=%#v", status)
	}
	active, shadow := testEvent(), testEvent()
	shadow.ID = "shadow-event"
	shadow.AnchorIDs, shadow.SubjectIDs = []string{"deployment-b", "destination"}, []string{"deployment-b"}
	result, err := engine.Evaluate(ctx, []Event{active, shadow})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Signals) != 2 || result.ResourceRulesDigest != engine.Status().ResourceRulesDigest {
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

func TestResourceRuleShadowSignalsCannotDisplaceActiveSignals(t *testing.T) {
	ctx := context.Background()
	repository := resourceRuleRepository{
		ruleRepository: ruleRepository{activation: Activation{Revision: 1, Ruleset: DefaultRuleset()}},
		rules: []ResourceRule{
			testResourceRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive),
			testResourceRule("deployment/deployment-b/rule-1", "deployment-b", RuleModeShadow),
		},
	}
	engine, err := Load(ctx, repository, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	events := make([]Event, MaxEvaluationSignals+1)
	for index := range MaxEvaluationSignals {
		events[index] = testEvent()
		events[index].ID = fmt.Sprintf("shadow-%04d", index)
		events[index].AnchorIDs, events[index].SubjectIDs = []string{"deployment-b", "destination"}, []string{"deployment-b"}
	}
	events[MaxEvaluationSignals] = testEvent()
	result, err := engine.Evaluate(ctx, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Signals) != MaxEvaluationSignals || result.Omitted["signals"] != 1 {
		t.Fatalf("signals=%d omitted=%#v", len(result.Signals), result.Omitted)
	}
	if !slices.ContainsFunc(result.Signals, func(signal InvestigationSignal) bool {
		return signal.RuleID == "deployment/deployment-a/rule-1" && signal.RuleMode == ""
	}) {
		t.Fatal("an active signal was displaced by shadow matches")
	}
}

func TestResourceRulesReloadRetainsLastKnownGoodRulesOnReadFailure(t *testing.T) {
	ctx := context.Background()
	base := ruleRepository{activation: Activation{Revision: 1, Ruleset: DefaultRuleset()}}
	initial := []ResourceRule{testResourceRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeShadow)}
	engine, err := Load(ctx, resourceRuleRepository{ruleRepository: base, rules: initial}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	digest := engine.Status().ResourceRulesDigest
	if err := engine.Reload(ctx, resourceRuleRepository{ruleRepository: base, err: errors.New("database unavailable")}); err == nil {
		t.Fatal("failed workload read accepted")
	}
	if status := engine.Status(); status.ResourceRulesDigest != digest || status.ShadowResourceRules != 1 || status.LastReloadError == "" {
		t.Fatalf("status=%#v", status)
	}
	approved := []ResourceRule{testResourceRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive)}
	if err := engine.Reload(ctx, resourceRuleRepository{ruleRepository: base, rules: approved}); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.ActiveResourceRules != 1 || status.ShadowResourceRules != 0 || status.LastReloadError != "" {
		t.Fatalf("status=%#v", status)
	}
	if err := engine.Reload(ctx, resourceRuleRepository{ruleRepository: base}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(ctx, []Event{testEvent()})
	if err != nil || len(result.Signals) != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestResourceRulesSkipInvalidRulesAndKeepTheRest(t *testing.T) {
	ctx := context.Background()
	base := ruleRepository{activation: Activation{Revision: 1, Ruleset: DefaultRuleset()}}
	valid := testResourceRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive)
	invalid := testResourceRule("deployment/deployment-b/rule-1", "deployment-b", RuleModeActive)
	invalid.Rule.Expression = "unknown_variable"
	rules := []ResourceRule{
		invalid, valid,
		testResourceRule("deployment/unscoped/rule-1", "", RuleModeActive),
		testResourceRule("deployment/deployment-c/rule-1", "deployment-c", "enforcing"),
		valid,
	}
	// Startup succeeds with the valid rule loaded and the others reported.
	engine, err := Load(ctx, resourceRuleRepository{ruleRepository: base, rules: rules}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	status := engine.Status()
	if status.ActiveResourceRules != 1 || status.SkippedResourceRules != 4 || status.LastReloadError == "" {
		t.Fatalf("status=%#v", status)
	}
	result, err := engine.Evaluate(ctx, []Event{testEvent()})
	if err != nil || len(result.Signals) != 1 || result.Signals[0].RuleID != valid.Rule.ID {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	// An unchanged read is not recompiled and clears the reported error.
	if err := engine.Reload(ctx, resourceRuleRepository{ruleRepository: base, rules: rules}); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.SkippedResourceRules != 4 || status.LastReloadError != "" {
		t.Fatalf("status=%#v", status)
	}
	if err := ValidateResourceRules(rules); err == nil {
		t.Fatal("validation accepted invalid resource rules")
	}
}

func TestResourceRulesMatchOnlyTheirSubject(t *testing.T) {
	engine, err := New(DefaultConfig(), DefaultRuleset())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.SetResourceRules([]ResourceRule{testResourceRule("deployment/server/rule-1", "server", RuleModeActive)}); err != nil {
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
		t.Fatalf("a resource rule matched an input where the resource is only the object: %#v", result.Signals)
	}
}

func TestResourceRulesAreBoundedAndUnique(t *testing.T) {
	duplicate := testResourceRule("deployment/deployment-a/rule-1", "deployment-a", RuleModeActive)
	if err := ValidateResourceRules([]ResourceRule{duplicate, duplicate}); err == nil {
		t.Fatal("duplicate resource rules accepted")
	}
	oversized := make([]ResourceRule, MaxResourceRules+2)
	for index := range oversized {
		mode := RuleModeShadow
		if index == len(oversized)-1 {
			mode = RuleModeActive
		}
		oversized[index] = testResourceRule(fmt.Sprintf("deployment/d-%05d/rule-1", index), fmt.Sprintf("d-%05d", index), mode)
	}
	if err := ValidateResourceRules(oversized); err == nil {
		t.Fatal("oversized resource rules accepted")
	}
	engine, err := New(DefaultConfig(), DefaultRuleset())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.SetResourceRules(oversized); err == nil {
		t.Fatal("rules over the bound were not reported")
	}
	// Active rules are kept first, then shadow rules by ID; the last shadow rule is left out.
	if status := engine.Status(); status.ActiveResourceRules != 1 || status.ShadowResourceRules != MaxResourceRules-1 || status.SkippedResourceRules != 1 {
		t.Fatalf("status=%#v", status)
	}
}
