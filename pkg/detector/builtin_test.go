package detector

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestDetectNovelTelemetryEmitsNeutralRiskSignal(t *testing.T) {
	previous := graph.Snapshot{Telemetry: []graph.TelemetryEvent{{
		Kind: "network-flow", SubjectID: "worker", ObjectID: "store", Operation: "egress", Outcome: "forwarded",
		Properties: map[string]string{"telemetry/first-seen": "2026-10-06T12:00:00Z"},
	}}}
	current := graph.Snapshot{
		Resources: []graph.Resource{{
			ID: "control", Assertions: []graph.ResourceAssertion{{Attributes: map[string]string{"network/role": "control-plane-api"}}},
		}},
		Telemetry: []graph.TelemetryEvent{{
			ID: "private-fact", Kind: "network-flow", SubjectID: "worker", ObjectID: "control", Operation: "egress", Outcome: "forwarded",
			Properties: map[string]string{"telemetry/first-seen": "2026-10-06T12:01:00.123456789Z"}, EvidenceIDs: []string{"private-evidence"},
		}},
	}
	signals := DetectNovelTelemetry(previous, current, DefaultConfig())
	if len(signals) != 1 {
		t.Fatalf("signals = %#v", signals)
	}
	signal := signals[0]
	if signal.Risk != RiskHigh || !slices.Contains(signal.Reasons, "sensitive_destination_role") {
		t.Fatalf("signal = %#v", signal)
	}
	if slices.Contains(signal.AnchorIDs, "private-fact") || signal.ID == "private-fact" {
		t.Fatalf("signal leaked telemetry identity: %#v", signal)
	}
}

func TestDetectNovelTelemetrySuppressesKnownAndLowRiskFacts(t *testing.T) {
	event := graph.TelemetryEvent{
		Kind: "network-flow", SubjectID: "worker", ObjectID: "store", Operation: "egress", Outcome: "forwarded",
		Properties: map[string]string{"telemetry/first-seen": "2026-10-06T12:00:00Z"},
	}
	if signals := DetectNovelTelemetry(graph.Snapshot{Telemetry: []graph.TelemetryEvent{event}}, graph.Snapshot{Telemetry: []graph.TelemetryEvent{event}}, DefaultConfig()); len(signals) != 0 {
		t.Fatalf("known telemetry signals = %#v", signals)
	}
	config := DefaultConfig()
	config.MinimumScore = 3
	if signals := DetectNovelTelemetry(graph.Snapshot{}, graph.Snapshot{Telemetry: []graph.TelemetryEvent{event}}, config); len(signals) != 0 {
		t.Fatalf("low-risk telemetry signals = %#v", signals)
	}
}

func TestDetectNovelChangesEmitsNeutralTopologySignals(t *testing.T) {
	observedAt := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		previous graph.Snapshot
		current  graph.Snapshot
		reason   string
	}{
		{
			name:     "new public exposure",
			previous: graph.Snapshot{Facets: []graph.Facet{semanticFacet(t, "service", "internal", "old")}},
			current:  graph.Snapshot{Facets: []graph.Facet{semanticFacet(t, "service", "external-addressable", "new")}},
			reason:   "new_public_exposure",
		},
		{
			name: "lost governance",
			previous: graph.Snapshot{
				Resources:     []graph.Resource{{ID: "workload"}, {ID: "policy", Kind: "istio/authorizationpolicy"}},
				Relationships: []graph.Relationship{{ID: "governance", SubjectID: "workload", Predicate: graph.PredicateGovernedBy, ObjectID: "policy"}},
			},
			current: graph.Snapshot{Resources: []graph.Resource{{ID: "workload"}}},
			reason:  "lost_governance",
		},
		{
			name:     "policy configuration changed",
			previous: semanticGovernanceSnapshot(t, "old"),
			current:  semanticGovernanceSnapshot(t, "new"),
			reason:   "governance_semantics_changed",
		},
		{
			name:     "public route added before status",
			previous: graph.Snapshot{Resources: []graph.Resource{{ID: "route", Kind: "vendor/route"}, {ID: "backend", Kind: "vendor/backend"}}},
			current: graph.Snapshot{
				Resources:     []graph.Resource{{ID: "route", Kind: "vendor/route"}, {ID: "backend", Kind: "vendor/backend"}},
				Relationships: []graph.Relationship{semanticExposureRelationship(t)},
			},
			reason: "new_public_exposure",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signals := DetectNovelChanges(test.previous, test.current, observedAt, DefaultConfig())
			if len(signals) != 1 || !slices.Contains(signals[0].Reasons, test.reason) {
				t.Fatalf("signals = %#v, want one %s signal", signals, test.reason)
			}
		})
	}
}

func semanticExposureRelationship(t *testing.T) graph.Relationship {
	t.Helper()
	return graph.Relationship{
		ID: "route-edge", SubjectID: "route", Predicate: graph.PredicateExposes, ObjectID: "backend",
		Assertions: []graph.RelationshipAssertion{{
			PluginID: "vendor", SourceID: "source", RuleID: "route-exposure", Properties: semanticAttributes(t, graph.SecuritySemantics{
				Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
				State: graph.SecurityStateDeclared, Effect: "external-addressable", Scope: "gateway", Direction: "ingress", Coverage: "partial",
			}),
		}},
	}
}

func TestDetectNovelChangesIgnoresServiceRolloutEdges(t *testing.T) {
	resources := []graph.Resource{{ID: "service", Kind: "kubernetes/service"}, {ID: "old", Kind: "kubernetes/pod"}, {ID: "new", Kind: "kubernetes/pod"}}
	previous := graph.Snapshot{Resources: resources, Relationships: []graph.Relationship{{
		ID: "old-edge", SubjectID: "service", Predicate: graph.PredicateExposes, ObjectID: "old",
	}}}
	current := graph.Snapshot{Resources: resources, Relationships: []graph.Relationship{{
		ID: "new-edge", SubjectID: "service", Predicate: graph.PredicateExposes, ObjectID: "new",
	}}}
	if signals := DetectNovelChanges(previous, current, time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC), DefaultConfig()); len(signals) != 0 {
		t.Fatalf("service rollout signals = %#v", signals)
	}
}

func TestDetectNovelChangesIgnoresOrdinaryResourceAddition(t *testing.T) {
	previous := graph.Snapshot{Resources: []graph.Resource{{ID: "workload", Kind: "vendor/workload"}}}
	current := graph.Snapshot{Resources: []graph.Resource{
		{ID: "workload", Kind: "vendor/workload"},
		{ID: "workload-b", Kind: "vendor/workload"},
		{ID: "pod", Kind: "kubernetes/pod"},
	}}
	if signals := DetectNovelChanges(previous, current, time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC), DefaultConfig()); len(signals) != 0 {
		t.Fatalf("resource addition signals = %#v", signals)
	}
}

func TestDetectNovelChangesSignalsSensitiveResourceAddition(t *testing.T) {
	existing := graph.Resource{ID: "binding-old", Kind: "kubernetes/clusterrolebinding"}
	previous := graph.Snapshot{Resources: []graph.Resource{existing}}
	current := graph.Snapshot{Resources: []graph.Resource{
		existing,
		{ID: "binding-b", Kind: "kubernetes/clusterrolebinding"},
		{ID: "binding-a", Kind: "kubernetes/rolebinding"},
		{ID: "webhook", Kind: "kubernetes/mutatingwebhookconfiguration"},
	}}
	signals := DetectNovelChanges(previous, current, time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC), DefaultConfig())
	if len(signals) != 2 {
		t.Fatalf("sensitive addition signals = %#v", signals)
	}
	for _, signal := range signals {
		if signal.Risk != RiskMedium || !slices.Contains(signal.Reasons, "sensitive_resource_added") {
			t.Fatalf("sensitive addition signal = %#v", signal)
		}
		if slices.Contains(signal.Reasons, "rbac_binding") && !reflect.DeepEqual(signal.AnchorIDs, []string{"binding-a", "binding-b"}) {
			t.Fatalf("binding anchors = %#v", signal.AnchorIDs)
		}
	}
}

func TestDetectNovelChangesScoresWorkloadCommunicationPaths(t *testing.T) {
	observedAt := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		previous graph.Snapshot
		current  graph.Snapshot
		risk     Risk
		reasons  []string
	}{
		{
			name:     "established workload reaches a new destination",
			previous: workloadGraph(edge("pod-1", "orders")),
			current:  workloadGraph(edge("pod-1", "orders"), edge("pod-1", "secrets")),
			risk:     RiskMedium, reasons: []string{"new_communication_path", "established_source"},
		},
		{
			name:     "new workload's first call is recorded at low risk",
			previous: workloadGraph(),
			current:  workloadGraph(edge("pod-1", "orders")),
			risk:     RiskLow, reasons: []string{"new_communication_path", "first_source_activity"},
		},
		{
			name:     "first call to the control plane is high risk",
			previous: workloadGraph(),
			current:  workloadGraph(edge("pod-1", "apiserver")),
			risk:     RiskHigh, reasons: []string{"new_communication_path", "first_source_activity", "sensitive_destination_role"},
		},
		{
			name:     "established workload egresses to the internet",
			previous: workloadGraph(edge("pod-1", "orders")),
			current:  workloadGraph(edge("pod-1", "orders"), edge("pod-1", "internet")),
			risk:     RiskHigh, reasons: []string{"new_communication_path", "established_source", "external_destination"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signals := DetectNovelChanges(test.previous, test.current, observedAt, DefaultConfig())
			if len(signals) != 1 || signals[0].Risk != test.risk || !reflect.DeepEqual(signals[0].Reasons, sorted(test.reasons)) {
				t.Fatalf("signals = %#v, want one %s %v signal", signals, test.risk, test.reasons)
			}
			if !slices.Contains(signals[0].AnchorIDs, "pod-1") || !slices.Contains(signals[0].AnchorIDs, "checkout") {
				t.Fatalf("anchors = %#v, want instance and workload", signals[0].AnchorIDs)
			}
		})
	}
}

func TestDetectNovelChangesFoldsRolloutsIntoWorkloads(t *testing.T) {
	previous := workloadGraph(edge("pod-1", "orders"))
	previous.Telemetry = []graph.TelemetryEvent{flow("pod-1", "orders")}
	current := workloadGraph(edge("pod-2", "orders"), edge("pod-3", "orders"))
	current.Telemetry = []graph.TelemetryEvent{flow("pod-2", "orders"), flow("pod-3", "orders")}
	if signals := DetectNovelChanges(previous, current, time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC), DefaultConfig()); len(signals) != 0 {
		t.Fatalf("rollout signals = %#v", signals)
	}
}

func TestDetectNovelTelemetryAggregatesInstancesOfOneWorkload(t *testing.T) {
	current := workloadGraph()
	current.Telemetry = []graph.TelemetryEvent{flow("pod-1", "secrets"), flow("pod-2", "secrets")}
	signals := DetectNovelTelemetry(workloadGraph(), current, DefaultConfig())
	if len(signals) != 1 || signals[0].Risk != RiskLow || !reflect.DeepEqual(signals[0].AnchorIDs, []string{"checkout", "pod-1", "pod-2", "secrets"}) {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestDetectNovelChangesSignalsWorkloadIdentityChange(t *testing.T) {
	previous := workloadGraph()
	previous.Relationships = append(previous.Relationships, graph.Relationship{ID: "identity-1", SubjectID: "pod-1", Predicate: graph.PredicateUsesIdentity, ObjectID: "reader"})
	current := workloadGraph()
	current.Relationships = append(current.Relationships,
		graph.Relationship{ID: "identity-1", SubjectID: "pod-1", Predicate: graph.PredicateUsesIdentity, ObjectID: "reader"},
		graph.Relationship{ID: "identity-2", SubjectID: "pod-2", Predicate: graph.PredicateUsesIdentity, ObjectID: "admin"},
	)
	signals := DetectNovelChanges(previous, current, time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC), DefaultConfig())
	if len(signals) != 1 || signals[0].Risk != RiskMedium || !reflect.DeepEqual(signals[0].AnchorIDs, []string{"admin", "checkout"}) {
		t.Fatalf("identity signals = %#v", signals)
	}
	unchanged := workloadGraph()
	unchanged.Relationships = append(unchanged.Relationships, graph.Relationship{ID: "identity-3", SubjectID: "pod-3", Predicate: graph.PredicateUsesIdentity, ObjectID: "reader"})
	if signals := DetectNovelChanges(previous, unchanged, time.Time{}, DefaultConfig()); len(signals) != 0 {
		t.Fatalf("same-identity rollout signals = %#v", signals)
	}
}

func TestDetectNovelChangesIsStableUnderInputReordering(t *testing.T) {
	previous := workloadGraph(edge("pod-1", "orders"))
	current := workloadGraph(edge("pod-1", "orders"), edge("pod-1", "secrets"), edge("pod-2", "secrets"), edge("pod-3", "internet"))
	current.Telemetry = []graph.TelemetryEvent{flow("pod-1", "secrets"), flow("pod-2", "secrets")}
	first := DetectNovelChanges(previous, current, time.Unix(100, 0), DefaultConfig())
	reversed := current
	reversed.Resources = slices.Clone(current.Resources)
	reversed.Relationships = slices.Clone(current.Relationships)
	reversed.Telemetry = slices.Clone(current.Telemetry)
	slices.Reverse(reversed.Resources)
	slices.Reverse(reversed.Relationships)
	slices.Reverse(reversed.Telemetry)
	second := DetectNovelChanges(previous, reversed, time.Unix(100, 0), DefaultConfig())
	if len(first) == 0 || !reflect.DeepEqual(first, second) {
		t.Fatalf("reordered signals differ: first=%#v second=%#v", first, second)
	}
}

// workloadGraph has one checkout Deployment with three Pods on one node and
// destinations of each role; edges are communicates-with relationships.
func workloadGraph(edges ...graph.Relationship) graph.Snapshot {
	snapshot := graph.Snapshot{
		Resources: []graph.Resource{
			{ID: "checkout", Kind: "kubernetes/deployment"},
			{ID: "node", Kind: "kubernetes/node"},
			{ID: "pod-1", Kind: "kubernetes/pod"}, {ID: "pod-2", Kind: "kubernetes/pod"}, {ID: "pod-3", Kind: "kubernetes/pod"},
			{ID: "orders", Kind: "kubernetes/service"}, {ID: "secrets", Kind: "kubernetes/service"},
			{ID: "apiserver", Kind: "kubernetes/service", Assertions: []graph.ResourceAssertion{{Attributes: map[string]string{"network/role": graph.NetworkRoleControlPlaneAPI}}}},
			{ID: "internet", Kind: "network/peer-class", Identity: graph.IdentityClaim{ImmutableKey: "external-destination"}},
		},
	}
	for _, pod := range []string{"pod-1", "pod-2", "pod-3"} {
		snapshot.Relationships = append(snapshot.Relationships,
			graph.Relationship{ID: "owns-" + pod, SubjectID: "checkout", Predicate: graph.PredicateInstantiates, ObjectID: pod},
			graph.Relationship{ID: "static-" + pod, SubjectID: "node", Predicate: graph.PredicateInstantiates, ObjectID: pod},
			graph.Relationship{ID: "host-" + pod, SubjectID: pod, Predicate: graph.PredicateRunsOn, ObjectID: "node"},
		)
	}
	snapshot.Relationships = append(snapshot.Relationships, edges...)
	return snapshot
}

func edge(subject, object string) graph.Relationship {
	return graph.Relationship{
		ID: subject + "->" + object, SubjectID: subject, Predicate: graph.PredicateCommunicates, ObjectID: object, Qualifier: "telemetry-observed",
		Assertions: []graph.RelationshipAssertion{{PluginID: "telemetry", SourceID: "runtime", RuleID: "rollup"}},
	}
}

func flow(subject, object string) graph.TelemetryEvent {
	return graph.TelemetryEvent{
		ID: subject + "->" + object, Kind: "network-flow", SubjectID: subject, ObjectID: object, Operation: "egress", Outcome: "forwarded",
		Properties: map[string]string{"telemetry/first-seen": "2026-10-07T12:00:00Z"},
	}
}

func sorted(values []string) []string {
	values = slices.Clone(values)
	slices.Sort(values)
	return values
}

func TestDetectNovelChangesIgnoresEvidenceOnlyResourceChurn(t *testing.T) {
	previous := graph.Resource{ID: "workload", Kind: "vendor/workload", Assertions: []graph.ResourceAssertion{{Kind: "vendor/workload", EvidenceIDs: []string{"old"}}}}
	current := previous
	current.Assertions = slices.Clone(previous.Assertions)
	current.Assertions[0].EvidenceIDs = []string{"new"}
	if signals := DetectNovelChanges(graph.Snapshot{Resources: []graph.Resource{previous}}, graph.Snapshot{Resources: []graph.Resource{current}}, time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC), DefaultConfig()); len(signals) != 0 {
		t.Fatalf("evidence-only signals = %#v", signals)
	}
}

func TestDetectNovelChangesSignalsRemovedSemanticsOnRetainedPolicy(t *testing.T) {
	previous := semanticGovernanceSnapshot(t, "old")
	current := graph.Snapshot{
		Resources:     previous.Resources,
		Relationships: []graph.Relationship{{ID: "governance", SubjectID: "workload", Predicate: graph.PredicateGovernedBy, ObjectID: "policy"}},
	}
	signals := DetectNovelChanges(previous, current, time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC), DefaultConfig())
	if len(signals) != 1 || !slices.Contains(signals[0].Reasons, "security_semantics_removed") {
		t.Fatalf("removed semantics signals = %#v", signals)
	}
}

func TestDetectNovelChangesIsStableAcrossRetry(t *testing.T) {
	previous := graph.Snapshot{Facets: []graph.Facet{semanticFacet(t, "service", "internal", "old")}}
	current := graph.Snapshot{Facets: []graph.Facet{semanticFacet(t, "service", "external-addressable", "new")}}
	first := DetectNovelChanges(previous, current, time.Time{}, DefaultConfig())
	second := DetectNovelChanges(previous, current, time.Time{}, DefaultConfig())
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("retry signals differ: first=%#v second=%#v", first, second)
	}
}

func TestDetectNovelChangesSuppressesOperationalMetadata(t *testing.T) {
	previous := graph.Snapshot{Resources: []graph.Resource{{
		ID: "service", Kind: "kubernetes/service", Assertions: []graph.ResourceAssertion{{Attributes: map[string]string{"kubernetes/annotation/owner": "platform"}}},
	}}}
	current := graph.Snapshot{Resources: []graph.Resource{{
		ID: "service", Kind: "kubernetes/service", Assertions: []graph.ResourceAssertion{{Attributes: map[string]string{"kubernetes/annotation/owner": "sre"}}},
	}}}
	if signals := DetectNovelChanges(previous, current, time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC), DefaultConfig()); len(signals) != 0 {
		t.Fatalf("operational metadata signals = %#v", signals)
	}
}

func TestEngineDetectMergesBuiltinAndRuleSignals(t *testing.T) {
	rule := Rule{
		ID: "new-edge", Revision: 1, InputVersion: InputVersion, PluginID: "*", Type: "relationship", Kind: string(graph.PredicateCommunicates),
		Expression: "true", Risk: RiskHigh, Reasons: []string{"rule_match"},
	}
	engine, err := New(DefaultConfig(), Ruleset{ID: "merge", Rules: []Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	previous := workloadGraph(edge("pod-1", "orders"))
	current := workloadGraph(edge("pod-1", "orders"), edge("pod-1", "secrets"))
	result, err := engine.Detect(context.Background(), previous, current, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	var builtin, ruled bool
	for _, signal := range result.Signals {
		builtin = builtin || slices.Contains(signal.Reasons, "new_communication_path")
		ruled = ruled || signal.RuleID == "new-edge"
	}
	if !builtin || !ruled {
		t.Fatalf("signals=%#v, want built-in and rule signals", result.Signals)
	}
}

func semanticFacet(t *testing.T, resourceID, effect, digest string) graph.Facet {
	t.Helper()
	return graph.Facet{ID: "exposure", ResourceID: resourceID, Kind: "network-exposure", Key: "default", Assertions: []graph.FacetAssertion{{
		PluginID: "vendor", SourceID: "source", RuleID: "exposure", Attributes: semanticAttributes(t, graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
			State: graph.SecurityStateDeclared, Effect: effect, Scope: "external", Direction: "ingress", Coverage: "complete", ConfigurationDigest: digest,
		}),
	}}}
}

func semanticGovernanceSnapshot(t *testing.T, digest string) graph.Snapshot {
	t.Helper()
	relationship := graph.Relationship{
		ID: "governance", SubjectID: "workload", Predicate: graph.PredicateGovernedBy, ObjectID: "policy",
		Assertions: []graph.RelationshipAssertion{{
			PluginID: "vendor", SourceID: "source", RuleID: "governance", Properties: semanticAttributes(t, graph.SecuritySemantics{
				Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainAuthorization,
				State: graph.SecurityStateDeclared, Effect: "allow", Scope: "workload", Direction: "ingress", Coverage: "partial", ConfigurationDigest: digest,
			}),
		}},
	}
	return graph.Snapshot{
		Resources:     []graph.Resource{{ID: "workload"}, {ID: "policy", Kind: "vendor/policy"}},
		Relationships: []graph.Relationship{relationship},
	}
}

func semanticAttributes(t *testing.T, semantics graph.SecuritySemantics) map[string]string {
	t.Helper()
	attributes, err := graph.WithSecuritySemantics(nil, semantics)
	if err != nil {
		t.Fatal(err)
	}
	return attributes
}
