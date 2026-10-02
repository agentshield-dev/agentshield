package detector

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

func TestEventsEmitOnlyNewEdgesWithDestinationClassAndRole(t *testing.T) {
	resource := func(id, kind, key string, attributes map[string]string) graph.Resource {
		return graph.Resource{ID: id, Kind: kind, Identity: graph.IdentityClaim{ImmutableKey: key}, Assertions: []graph.ResourceAssertion{{Attributes: attributes}}}
	}
	edge := func(object, leaseExpiry string) graph.Relationship {
		return graph.Relationship{ID: "edge-" + object, SubjectID: "pod", Predicate: graph.PredicateCommunicates, ObjectID: object, Assertions: []graph.RelationshipAssertion{{
			Predicate: graph.PredicateCommunicates, Properties: map[string]string{"telemetry/lease-expires-at": leaseExpiry},
			PluginID: "telemetry", SourceID: "runtime", RuleID: "telemetry.communication-edge-lease",
		}}}
	}
	resources := []graph.Resource{
		resource("deployment", "kubernetes/deployment", "deployment", nil),
		resource("pod", "kubernetes/pod", "pod", nil),
		resource("api-service", "kubernetes/service", "service", map[string]string{"network/role": graph.NetworkRoleControlPlaneAPI, "network/addresses": `["ip/34.1.2.3"]`}),
		resource("api", "network/destination", "ip/34.1.2.3", nil),
		resource("known", "network/destination", "ip/1.1.1.1", nil),
		resource("internet", "network/destination", "ip/8.8.8.8", nil),
	}
	instantiates := graph.Relationship{ID: "instantiates", SubjectID: "deployment", Predicate: graph.PredicateInstantiates, ObjectID: "pod"}
	previous := graph.Snapshot{Resources: resources, Relationships: []graph.Relationship{instantiates, edge("known", "t1")}}
	current := graph.Snapshot{Resources: resources, Relationships: []graph.Relationship{instantiates, edge("known", "t2"), edge("api", "t2"), edge("internet", "t2")}}

	inputs := map[string]Input{}
	for _, event := range Events(previous, current, time.Unix(100, 0)) {
		if event.Kind != string(graph.PredicateCommunicates) {
			continue
		}
		for _, object := range []string{"api", "known", "internet"} {
			if slices.Contains(event.AnchorIDs, object) {
				inputs[object] = event.Input
			}
		}
	}
	want := map[string]Input{
		"api":      {DestinationIPClass: "public", DestinationRole: graph.NetworkRoleControlPlaneAPI},
		"internet": {DestinationIPClass: "public"},
	}
	if len(inputs) != len(want) || inputs["api"] != want["api"] || inputs["internet"] != want["internet"] {
		t.Fatalf("inputs=%#v, want only new edges %#v", inputs, want)
	}

	rule := Rule{
		ID: "new-public", Revision: 1, InputVersion: InputVersion, PluginID: "*", WorkloadResourceID: "deployment",
		Type: "relationship", Kind: string(graph.PredicateCommunicates),
		Expression: "destination_ip_class == 'public' && destination_role == ''", Risk: RiskMedium, Reasons: []string{"new_public_destination"},
	}
	engine, err := New(DefaultConfig(), Ruleset{ID: "edges", Rules: []Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Detect(context.Background(), previous, current, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	var ruleSignals []InvestigationSignal
	for _, signal := range result.Signals {
		if signal.RuleID != "" {
			ruleSignals = append(ruleSignals, signal)
		}
	}
	if len(ruleSignals) != 1 || ruleSignals[0].RuleID != "new-public" || !slices.Contains(ruleSignals[0].AnchorIDs, "internet") {
		t.Fatalf("rule signals=%#v, want only the new unknown public edge", ruleSignals)
	}
}

func TestWorkloadShellRuleFiresOncePerNewPodProcessSeries(t *testing.T) {
	shellClaim, err := graph.ProcessClassClaim("cluster-a", graph.ProcessClassShell)
	if err != nil {
		t.Fatal(err)
	}
	resources := []graph.Resource{
		{ID: "deployment", Kind: "kubernetes/deployment"}, {ID: "other-deployment", Kind: "kubernetes/deployment"},
		{ID: "pod", Kind: "kubernetes/pod"}, {ID: "other-pod", Kind: "kubernetes/pod"}, {ID: "shell", Kind: "process/class", Identity: shellClaim},
	}
	relationships := []graph.Relationship{
		{ID: "instantiates", SubjectID: "deployment", Predicate: graph.PredicateInstantiates, ObjectID: "pod"},
		{ID: "other-instantiates", SubjectID: "other-deployment", Predicate: graph.PredicateInstantiates, ObjectID: "other-pod"},
	}
	shell := func(id, pod, firstSeen string, count uint64) graph.TelemetryEvent {
		return graph.TelemetryEvent{
			ID: id, Kind: telemetry.EventKindProcessExec, SubjectID: pod, ObjectID: "shell", Operation: "spawn-shell", Outcome: "observed", Count: count,
			Properties: map[string]string{"telemetry/first-seen": firstSeen}, PluginID: "falco", SourceID: "cluster-a/falco",
		}
	}
	rule := Rule{
		ID: "deployment-no-shell", Revision: 1, InputVersion: InputVersion, PluginID: "falco", WorkloadResourceID: "deployment",
		Type: "telemetry", Kind: telemetry.EventKindProcessExec, Expression: "operation == 'spawn-shell' && process_class == 'shell'", Risk: RiskHigh, Reasons: []string{"workload_spawned_shell"},
	}
	edgeRule := Rule{
		ID: "deployment-executes-shell", Revision: 1, InputVersion: InputVersion, PluginID: "falco", WorkloadResourceID: "deployment",
		Type: "relationship", Kind: string(graph.PredicateExecutes), Expression: "process_class == 'shell'", Risk: RiskHigh, Reasons: []string{"workload_executes_shell"},
	}
	engine, err := New(DefaultConfig(), Ruleset{ID: "shell", Rules: []Rule{rule, edgeRule}})
	if err != nil {
		t.Fatal(err)
	}
	executes := func(pod string) graph.Relationship {
		return graph.Relationship{ID: "executes-" + pod, SubjectID: pod, Predicate: graph.PredicateExecutes, ObjectID: "shell", Assertions: []graph.RelationshipAssertion{{
			Predicate: graph.PredicateExecutes, PluginID: "falco", SourceID: "cluster-a/falco", RuleID: "telemetry.process-execution-lease",
		}}}
	}
	empty := graph.Snapshot{Resources: resources, Relationships: relationships}
	first := graph.Snapshot{
		Resources: resources, Relationships: append(slices.Clone(relationships), executes("pod")),
		Telemetry: []graph.TelemetryEvent{shell("a", "pod", "2026-10-15T12:00:00Z", 1)},
	}
	result, err := engine.Detect(context.Background(), empty, first, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	fired := map[string]int{}
	for _, signal := range result.Signals {
		if signal.RuleID == "" {
			if slices.Contains(signal.Reasons, "new_communication_pair") {
				t.Fatalf("builtin novelty labeled process execution as communication: %#v", signal)
			}
			continue
		}
		if !slices.Contains(signal.AnchorIDs, "deployment") {
			t.Fatalf("rule signal is not anchored to the Deployment: %#v", signal)
		}
		fired[signal.RuleID]++
	}
	if len(fired) != 2 || fired[rule.ID] != 1 || fired[edgeRule.ID] != 1 {
		t.Fatalf("signals=%#v, want one telemetry and one relationship shell signal", result.Signals)
	}
	for _, event := range Events(empty, first, time.Time{}) {
		if !slices.Equal(event.SubjectIDs, []string{"deployment", "pod"}) || !slices.Contains(event.AnchorIDs, "shell") {
			t.Fatalf("event subjects=%v anchors=%v, want the Pod and its Deployment as subjects", event.SubjectIDs, event.AnchorIDs)
		}
	}

	repeated := graph.Snapshot{Resources: resources, Relationships: append(slices.Clone(relationships), executes("pod"), executes("other-pod")), Telemetry: []graph.TelemetryEvent{
		shell("a2", "pod", "2026-10-15T12:00:00Z", 2), shell("b", "other-pod", "2026-10-15T12:01:00Z", 1),
	}}
	result, err = engine.Detect(context.Background(), first, repeated, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, signal := range result.Signals {
		if signal.RuleID != "" {
			t.Fatalf("repeat shell or another Deployment's shell signaled: %#v", signal)
		}
	}

	if _, err := New(DefaultConfig(), Ruleset{ID: "invalid", Rules: []Rule{{
		ID: "role", Revision: 1, InputVersion: InputVersion, PluginID: "falco", Type: "telemetry", Kind: telemetry.EventKindProcessExec,
		Expression: "destination_role == ''", Risk: RiskLow, Reasons: []string{"role"},
	}}}); err == nil {
		t.Fatal("process execution selector declared a network destination role")
	}
	if _, err := New(DefaultConfig(), Ruleset{ID: "invalid", Rules: []Rule{{
		ID: "class", Revision: 1, InputVersion: InputVersion, PluginID: "cilium", Type: "telemetry", Kind: telemetry.EventKindNetworkFlow,
		Expression: "process_class == 'shell'", Risk: RiskLow, Reasons: []string{"class"},
	}}}); err == nil {
		t.Fatal("network flow selector declared a process class")
	}
	if !strings.Contains(CELSelectorDescription(), "`relationship:executes`") || !strings.Contains(CELExpressionDescription(), "`shell` (an interactive shell") {
		t.Fatalf("authoring contract omits process classes:\n%s\n%s", CELSelectorDescription(), CELExpressionDescription())
	}
}
