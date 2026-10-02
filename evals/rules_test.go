package evals

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/deploymentauthoring"
	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

func probeEvent(id, subject, object, operation string, observedAt time.Time) graph.TelemetryEvent {
	return graph.TelemetryEvent{
		ID: id, EventID: id, Kind: "active-probe", SubjectID: subject, ObjectID: object, Operation: operation, Outcome: "allowed", Count: 1,
		Properties: map[string]string{"telemetry/first-seen": observedAt.Format(time.RFC3339Nano)},
		PluginID:   "istio", SourceID: "cluster", RuleID: "istio.active-probe", EvidenceIDs: []string{"evidence-" + id},
	}
}

func checkpointOf(sequence uint64, snapshot graph.Snapshot) state.GraphCheckpoint {
	digest := strings.Repeat(string("abcdef"[sequence%6]), 64)
	return state.GraphCheckpoint{ThroughSequence: sequence, View: state.GraphView{SHA256: digest, Snapshot: snapshot}}
}

// campaignWindows returns setup, baseline, and observed windows in which the
// source Deployment calls the baseline service, then the observed service.
func campaignWindows(baselineOperation, observedOperation string) ([]ruleWindow, *ObservationEvidence) {
	start := time.Date(2026, time.October, 17, 12, 0, 0, 0, time.UTC)
	resources := []graph.Resource{
		{ID: "source", Kind: "kubernetes/deployment"},
		{ID: "baseline-target", Kind: "kubernetes/service"},
		{ID: "observed-target", Kind: "kubernetes/service"},
	}
	empty := graph.Snapshot{}
	settled := graph.Snapshot{Resources: resources}
	baseline := settled
	baseline.Telemetry = []graph.TelemetryEvent{probeEvent("baseline", "source", "baseline-target", baselineOperation, start)}
	observed := baseline
	observed.Telemetry = append(observed.Telemetry, probeEvent("observed", "source", "observed-target", observedOperation, start.Add(time.Minute)))
	evidence := &ObservationEvidence{SubjectID: "source", ObjectID: "observed-target"}
	return []ruleWindow{
		{phase: "setup", previous: checkpointOf(1, empty), current: checkpointOf(2, settled)},
		{phase: "baseline", previous: checkpointOf(2, settled), current: checkpointOf(3, baseline)},
		{phase: "observed", previous: checkpointOf(3, baseline), current: checkpointOf(4, observed), scored: true, observation: evidence},
	}, evidence
}

func allowlistPolicy(expression string) []RulePolicy {
	return []RulePolicy{{ID: "allowlist", Selector: "telemetry:active-probe", Expression: expression, Rationale: "test"}}
}

func TestEvaluateRulesScoresPolicyFindingsByClass(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.October, 17, 13, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		class          string
		expression     string
		observed       string
		outcome        string
		normalFindings int
		matches        bool
	}{
		{name: "violation is caught", class: "security", expression: "!operation.matches('^GET /v1/orders/')", observed: "GET /v1/secret/data/key", outcome: RuleTruePositive, matches: true},
		{name: "violation is missed", class: "security", expression: "operation == 'DELETE /'", observed: "GET /v1/secret/data/key", outcome: RuleFalseNegative},
		{name: "allowed access is quiet", class: "benign", expression: "!operation.matches('^GET /v1/(orders|secret/data)/')", observed: "GET /v1/secret/data/key", outcome: RuleTrueNegative, matches: true},
		{name: "allowed access alarms", class: "benign", expression: "!operation.matches('^GET /v1/orders/')", observed: "GET /v1/secret/data/key", outcome: RuleFalsePositive},
		{name: "normal activity alarms", class: "security", expression: "true", observed: "GET /v1/secret/data/key", outcome: RuleTruePositive, normalFindings: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			windows, _ := campaignWindows("GET /v1/orders/pending", test.observed)
			rules, err := policyRules(allowlistPolicy(test.expression), "source")
			if err != nil {
				t.Fatal(err)
			}
			evaluation, err := evaluateRules(ctx, RuleSourcePolicy, test.class, rules, false, windows, now)
			if err != nil {
				t.Fatal(err)
			}
			if evaluation.Outcome != test.outcome || evaluation.NormalPhaseFindings != test.normalFindings || evaluation.MatchesExpectation != test.matches {
				t.Fatalf("evaluation = %+v", evaluation)
			}
			if len(evaluation.Phases) != 3 {
				t.Fatalf("phases = %+v", evaluation.Phases)
			}
			if test.outcome == RuleTruePositive {
				findings := evaluation.Phases[2].Findings
				if len(findings) != 1 || findings[0].Origin != state.FindingOriginDetectionRule || findings[0].DetectionRuleID != "evals/policy/allowlist" {
					t.Fatalf("observed findings = %+v", findings)
				}
			}
		})
	}
}

func TestEvaluateRulesIgnoresOtherWorkloadsAndRunsAuthoredRulesAsDeploymentRules(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.October, 17, 13, 0, 0, 0, time.UTC)
	windows, _ := campaignWindows("GET /v1/orders/pending", "GET /v1/secret/data/key")
	rules, err := policyRules(allowlistPolicy("!operation.matches('^GET /v1/orders/')"), "another-workload")
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := evaluateRules(ctx, RuleSourcePolicy, "security", rules, false, windows, now)
	if err != nil || evaluation.Outcome != RuleFalseNegative {
		t.Fatalf("rule scoped to another workload = %+v err=%v", evaluation, err)
	}
	authored := rules[0]
	authored.ID, authored.WorkloadResourceID = "deployment/source/rule-1", "source"
	evaluation, err = evaluateRules(ctx, RuleSourceAuthored, "security", []detector.Rule{authored}, true, windows, now)
	if err != nil || evaluation.Outcome != RuleTruePositive || !evaluation.MatchesExpectation {
		t.Fatalf("authored rule = %+v err=%v", evaluation, err)
	}
	evaluation, err = evaluateRules(ctx, RuleSourceAuthored, "security", nil, true, windows, now)
	if err != nil || evaluation.Outcome != RuleFalseNegative || len(evaluation.Rules) != 0 {
		t.Fatalf("abstention = %+v err=%v", evaluation, err)
	}
	summary := &RuleSummary{}
	summary.add(evaluation)
	summary.add(RuleEvaluation{Outcome: RuleTrueNegative, Error: "model unavailable"})
	summary.finish()
	if summary.Abstentions != 1 || summary.Errors != 1 || summary.SecurityRecall != 0 || summary.BenignSpecificity != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

type fakeAuthor struct {
	seen     state.DeploymentAuthoringContext
	proposal deploymentauthoring.Proposal
	err      error
}

func (author *fakeAuthor) Author(_ context.Context, workload state.DeploymentAuthoringContext) (deploymentauthoring.Proposal, error) {
	author.seen = workload
	return author.proposal, author.err
}

func TestAuthorRulesUsesTheProductionAuthoringContext(t *testing.T) {
	deployment := graph.Resource{ID: "source", Kind: "kubernetes/deployment", Assertions: []graph.ResourceAssertion{{
		PluginID: "kubernetes", RuleID: "kubernetes.deployment.authoring-context",
		Attributes: map[string]string{"kubernetes/name": "checkout-api", "kubernetes/namespace": "shop", "kubernetes/service-account-name": "checkout-api", "kubernetes/label/app": "checkout-api"},
	}}}
	rule := detector.Rule{ID: "deployment/source/rule-1"}
	author := &fakeAuthor{proposal: deploymentauthoring.Proposal{Rationale: "why", Rules: []deploymentauthoring.ProposalRule{{Rule: rule}}}}
	workload := state.DeploymentAuthoringContextFor(deployment)
	workload.ObservedBehavior = &state.DeploymentBehavior{Requests: []state.ObservedRequest{}}
	rules, rationale, err := authorRules(context.Background(), author, workload)
	if err != nil || len(rules) != 1 || rules[0].ID != rule.ID || rationale != "why" {
		t.Fatalf("rules=%+v rationale=%q err=%v", rules, rationale, err)
	}
	want := state.DeploymentAuthoringContext{ResourceID: "source", Kind: "kubernetes/deployment", Name: "checkout-api", Namespace: "shop", ServiceAccountName: "checkout-api", ObservedBehavior: workload.ObservedBehavior}
	if author.seen != want {
		t.Fatalf("authoring context = %+v, want %+v", author.seen, want)
	}
	author.err = errors.New("model unavailable")
	if _, _, err := authorRules(context.Background(), author, workload); err == nil {
		t.Fatal("authoring error was not returned")
	}
	if _, found := findDeployment(graph.Snapshot{Resources: []graph.Resource{deployment}}, "shop", "checkout-api"); !found {
		t.Fatal("source Deployment not found by namespace and name")
	}
}
