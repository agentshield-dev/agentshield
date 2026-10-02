package detector

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

type ruleRepository struct {
	activation Activation
	err        error
}

func (repository ruleRepository) ReadActiveDetectorRuleset(context.Context) (Activation, error) {
	return repository.activation, repository.err
}

func testRule() Rule {
	return Rule{
		ID: "outside-egress", Revision: 1, InputVersion: InputVersion, PluginID: "cilium", Type: "telemetry", Kind: "network-flow",
		Expression: "operation == 'egress' && outcome == 'forwarded' && destination_ip_class == 'public'",
		Risk:       RiskMedium, Reasons: []string{"public_egress"}, WindowSeconds: 60,
	}
}

func testEvent() Event {
	return Event{
		ID: "event", PluginID: "cilium", SourceID: "hubble/local", Type: "telemetry", Kind: "network-flow",
		AnchorIDs: []string{"deployment-a", "destination"}, SubjectIDs: []string{"deployment-a"}, ObservedAt: time.Unix(100, 0).UTC(),
		Input: Input{Operation: "egress", Outcome: "forwarded", DestinationIPClass: "public"},
	}
}

func TestRuleMatchesOnlyItsSelectorsAndExpression(t *testing.T) {
	engine, err := New(DefaultConfig(), Ruleset{ID: "test", Rules: []Rule{testRule()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Event)
		want   int
	}{
		{name: "match", want: 1},
		{name: "plugin", mutate: func(event *Event) { event.PluginID = "istio" }},
		{name: "type", mutate: func(event *Event) { event.Type = "resource" }},
		{name: "kind", mutate: func(event *Event) { event.Kind = "gateway-request" }},
		{name: "expression", mutate: func(event *Event) { event.Input.Operation = "ingress" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := testEvent()
			if test.mutate != nil {
				test.mutate(&event)
			}
			result, err := engine.Evaluate(context.Background(), []Event{event})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Signals) != test.want {
				t.Fatalf("signals=%#v, want %d", result.Signals, test.want)
			}
		})
	}
}

func TestCELUsesOnlyMinimalInputAndUnknownIsNotExternal(t *testing.T) {
	engine, err := New(DefaultConfig(), Ruleset{ID: "test", Rules: []Rule{testRule()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		class string
		want  int
	}{
		{name: "public", class: "public", want: 1},
		{name: "private", class: "private"},
		{name: "special", class: "special"},
		{name: "unknown", class: "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := testEvent()
			event.Input.DestinationIPClass = test.class
			result, err := engine.Evaluate(context.Background(), []Event{event})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Signals) != test.want {
				t.Fatalf("signals=%#v, want %d", result.Signals, test.want)
			}
		})
	}
	unknownCEL, err := New(DefaultConfig(), Ruleset{ID: "invalid", Rules: []Rule{{
		ID: "legacy", Revision: 1, InputVersion: InputVersion, PluginID: "cilium", Type: "telemetry", Kind: "network-flow",
		Expression: "plugin_id == 'cilium'", Risk: RiskLow, Reasons: []string{"legacy_field"},
	}}})
	if err == nil || unknownCEL != nil {
		t.Fatal("legacy fields were accepted in the minimal CEL contract")
	}
}

func TestWorkloadRuleUsesHostAnchorScoping(t *testing.T) {
	rule := testRule()
	rule.WorkloadResourceID = "deployment-a"
	engine, err := New(DefaultConfig(), Ruleset{ID: "workload", Rules: []Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		anchors []string
		want    int
	}{
		{name: "target deployment", anchors: []string{"deployment-a", "destination"}, want: 1},
		{name: "different deployment", anchors: []string{"deployment-b", "destination"}},
		{name: "unrelated event", anchors: []string{"destination", "client"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := testEvent()
			event.AnchorIDs = test.anchors
			result, err := engine.Evaluate(context.Background(), []Event{event})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Signals) != test.want {
				t.Fatalf("signals=%#v, want %d", result.Signals, test.want)
			}
		})
	}
}

func TestRulesRejectInvalidDefinitions(t *testing.T) {
	for _, field := range []string{"expression", "type", "version", "risk", "window", "revision", "duplicate"} {
		t.Run(field, func(t *testing.T) {
			rule := testRule()
			switch field {
			case "expression":
				rule.Expression = "unknown_variable == 1"
			case "type":
				rule.Type = "resource"
			case "version":
				rule.InputVersion = "v2"
			case "risk":
				rule.Risk = "unexpected"
			case "window":
				rule.WindowSeconds = -1
			case "revision":
				rule.Revision = 0
			}
			rules := []Rule{rule}
			if field == "duplicate" {
				rules = append(rules, rule)
			}
			if err := ValidateRuleset(Ruleset{ID: "invalid", Rules: rules}); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
}

func TestReloadRetainsLastKnownGoodRules(t *testing.T) {
	ctx := context.Background()
	initial := Activation{Revision: 1, Ruleset: Ruleset{ID: "initial", Rules: []Rule{testRule()}}}
	engine, err := Load(ctx, ruleRepository{activation: initial}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	invalid := Activation{Revision: 2, Ruleset: Ruleset{ID: "invalid", Rules: []Rule{testRule()}}}
	invalid.Ruleset.Rules[0].Expression = "invalid"
	for _, repository := range []ruleRepository{{err: errors.New("database unavailable")}, {activation: invalid}} {
		if err := engine.Reload(ctx, repository); err == nil {
			t.Fatal("reload should fail")
		}
		if status := engine.Status(); status.RulesetID != "initial" || status.LastReloadError == "" {
			t.Fatalf("status=%#v", status)
		}
		result, err := engine.Evaluate(ctx, []Event{testEvent()})
		if err != nil || len(result.Signals) != 1 {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	}
	if err := engine.Reload(ctx, ruleRepository{activation: Activation{Revision: 2, Ruleset: Ruleset{ID: "disabled"}}}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(ctx, []Event{testEvent()})
	if err != nil || len(result.Signals) != 0 || engine.Status().LastReloadError != "" {
		t.Fatalf("result=%#v err=%v status=%#v", result, err, engine.Status())
	}
	if err := engine.Reload(ctx, ruleRepository{activation: initial}); err == nil {
		t.Fatal("regressing reload accepted")
	}
	if err := engine.Reload(ctx, ruleRepository{activation: Activation{Revision: 2, Ruleset: initial.Ruleset}}); err == nil {
		t.Fatal("same-revision mutation accepted")
	}
}

func TestConcurrentReloadAndEvaluation(t *testing.T) {
	ctx := context.Background()
	engine, err := New(DefaultConfig(), Ruleset{ID: "initial", Rules: []Rule{testRule()}})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		for index := range 100 {
			activation := Activation{Revision: uint64(index + 1), Ruleset: Ruleset{ID: "replacement", Rules: []Rule{testRule()}}}
			if err := engine.Reload(ctx, ruleRepository{activation: activation}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for range 100 {
		result, err := engine.Evaluate(ctx, []Event{testEvent()})
		if err != nil || len(result.Signals) != 1 || result.Signals[0].RulesetDigest != result.RulesetDigest {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	}
	wait.Wait()
}

func TestEvaluationIsStableUnderReorderingAndRetry(t *testing.T) {
	rule := testRule()
	otherRule := rule
	otherRule.ID = "other-rule"
	set := Ruleset{ID: "test", Rules: []Rule{rule, otherRule}}
	engine, err := New(DefaultConfig(), set)
	if err != nil {
		t.Fatal(err)
	}
	first, second := testEvent(), testEvent()
	second.ID, second.AnchorIDs = "other-event", []string{"destination", "client"}
	result, err := engine.Evaluate(context.Background(), []Event{first, second})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(set.Rules)
	reordered, err := New(DefaultConfig(), set)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reordered.Evaluate(context.Background(), []Event{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, retry) {
		t.Fatalf("results differ: %#v %#v", result, retry)
	}
}

func TestEvaluationHonorsCancellation(t *testing.T) {
	engine, err := New(DefaultConfig(), Ruleset{ID: "test", Rules: []Rule{testRule()}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Evaluate(ctx, []Event{testEvent()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestDefaultRulesetHasNoBuiltInDetections(t *testing.T) {
	ruleset := DefaultRuleset()
	if len(ruleset.Rules) != 0 {
		t.Fatalf("default ruleset contains built-in rules: %#v", ruleset.Rules)
	}
	engine, err := New(DefaultConfig(), ruleset)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(context.Background(), []Event{testEvent()})
	if err != nil || len(result.Signals) != 0 {
		t.Fatalf("default engine emitted signals=%#v err=%v", result.Signals, err)
	}
}

func TestCELRuleWindowAndInputSizeLimits(t *testing.T) {
	config := DefaultConfig()
	config.Window = 10 * time.Minute
	rule := testRule()
	rule.WindowSeconds = 0
	engine, err := New(config, Ruleset{ID: "window", Rules: []Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Evaluate(context.Background(), []Event{testEvent()})
	if err != nil || len(result.Signals) != 1 || result.Signals[0].Window.End.Sub(result.Signals[0].Window.Start) != 20*time.Minute {
		t.Fatalf("signals=%#v err=%v", result.Signals, err)
	}
	oversized := testEvent()
	oversized.ID = "oversized"
	oversized.Input.Operation = string(make([]byte, 65*1024))
	result, err = engine.Evaluate(context.Background(), []Event{oversized, testEvent()})
	if err != nil || len(result.Signals) != 1 || result.Omitted["oversizedEvents"] != 1 {
		t.Fatalf("oversized input was not skipped and counted: result=%#v err=%v", result, err)
	}
}

func TestEvaluateTruncatesSignalsAndEventsInsteadOfFailing(t *testing.T) {
	engine, err := New(DefaultConfig(), Ruleset{ID: "bounded", Rules: []Rule{testRule()}})
	if err != nil {
		t.Fatal(err)
	}
	events := make([]Event, MaxEvaluationSignals+5)
	for index := range events {
		events[index] = testEvent()
		events[index].ID = fmt.Sprintf("event-%05d", index)
	}
	first, err := engine.Evaluate(context.Background(), events)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Signals) != MaxEvaluationSignals || first.Omitted["signals"] != 5 {
		t.Fatalf("signals=%d omitted=%v", len(first.Signals), first.Omitted)
	}
	second, err := engine.Evaluate(context.Background(), events)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("truncation is not deterministic: err=%v", err)
	}
	many := make([]Event, MaxEvaluationEvents+3)
	for index := range many {
		many[index] = Event{ID: fmt.Sprintf("other-%06d", index), Type: "relationship", Kind: "contains"}
	}
	result, err := engine.Evaluate(context.Background(), many)
	if err != nil || result.Omitted["events"] != 3 {
		t.Fatalf("omitted=%v err=%v", result.Omitted, err)
	}
}

func TestRulesetDigestNormalizesEmptyRules(t *testing.T) {
	first, err := RulesetDigest(Ruleset{ID: "disabled"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := RulesetDigest(Ruleset{ID: "disabled", Rules: []Rule{}})
	if err != nil || first != second {
		t.Fatalf("first=%s second=%s err=%v", first, second, err)
	}
}
