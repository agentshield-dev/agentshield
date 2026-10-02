package reasoning

import (
	"slices"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

func TestContextProviderPinsTokenAndReturnsBoundedTemplate(t *testing.T) {
	packet := Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph",
		Resources:     []Resource{{ID: "a"}, {ID: "b"}, {ID: "c"}},
		Relationships: []Relationship{{ID: "ab", SubjectID: "a", ObjectID: "b"}, {ID: "bc", SubjectID: "b", ObjectID: "c"}},
	}
	provider, err := NewContextProviderWithTelemetry(packet, PinnedTelemetryContext{
		Token: AnalysisToken{AnalysisID: "analysis", GraphSHA256: "graph"},
		Telemetry: []Telemetry{
			{ID: "ab-flow", SubjectID: "a", ObjectID: "b", EvidenceIDs: []string{"e-ab"}},
			{ID: "bc-flow", SubjectID: "b", ObjectID: "c", EvidenceIDs: []string{"e-bc"}},
		},
	}, ContextLimits{Resources: 2, Relationships: 10, Facets: 10, Telemetry: 10})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Query(ContextQuery{Token: provider.Token(), Template: "telemetry_chain", AnchorIDs: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Closure != "untruncated" || len(result.Resources) != 2 || len(result.Telemetry) != 1 || result.Telemetry[0].ID != "ab-flow" {
		t.Fatalf("context result = %#v", result)
	}
	if _, err := provider.Query(ContextQuery{Token: AnalysisToken{AnalysisID: "other", GraphSHA256: "graph"}, Template: "telemetry_chain", AnchorIDs: []string{"a"}}); err == nil {
		t.Fatal("mismatched analysis token was accepted")
	}
}

func TestContextProviderQueriesFullSnapshotAndLongitudinalContext(t *testing.T) {
	observedAt := time.Unix(10, 0).UTC()
	packet := Packet{AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []Resource{{ID: "a"}}}
	incident, err := NewIncidentContext("incident", observedAt, []BehaviorBaseline{{SubjectID: "a", ObjectID: "b", Kind: "network-flow", FirstObservedAt: observedAt, LastObservedAt: observedAt}}, []IncidentEvent{{SubjectID: "b", ObjectID: "c", Kind: "network-flow", ObservedAt: observedAt, EvidenceIDs: []string{"e"}}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewContextProviderWithSnapshot(packet, graph.Snapshot{
		Resources:     []graph.Resource{{ID: "a"}, {ID: "b"}, {ID: "c"}},
		Relationships: []graph.Relationship{{ID: "ab", SubjectID: "a", Predicate: graph.PredicateCommunicates, ObjectID: "b"}, {ID: "bc", SubjectID: "b", Predicate: graph.PredicateCommunicates, ObjectID: "c"}},
	}, PinnedTelemetryContext{Token: AnalysisToken{AnalysisID: "analysis", GraphSHA256: "graph"}}, incident, DefaultContextLimits())
	if err != nil {
		t.Fatal(err)
	}
	path, err := provider.Query(ContextQuery{Token: provider.Token(), Template: "graph_path", AnchorIDs: []string{"a"}, Predicates: []graph.Predicate{graph.PredicateCommunicates}})
	if err != nil {
		t.Fatal(err)
	}
	if len(path.Resources) != 3 || len(path.Relationships) != 2 {
		t.Fatalf("path = %#v", path)
	}
	baseline, err := provider.Query(ContextQuery{Token: provider.Token(), Template: "behavior_baseline", AnchorIDs: []string{"a"}})
	if err != nil || len(baseline.Baselines) != 1 || len(baseline.Resources) != 2 || baseline.Resources[1].ID != "b" {
		t.Fatalf("baseline = %#v, err = %v", baseline, err)
	}
	timeline, err := provider.Query(ContextQuery{Token: provider.Token(), Template: "incident_timeline", AnchorIDs: []string{"b"}})
	if err != nil || len(timeline.IncidentEvents) != 1 || len(timeline.Resources) != 2 || timeline.Resources[1].ID != "c" {
		t.Fatalf("timeline = %#v, err = %v", timeline, err)
	}
	effective := MergeContext(packet, timeline)
	if len(effective.IncidentEvents) != 1 || effective.IncidentEvents[0].ID == "" || len(effective.ContextReceipts) != 1 || effective.ContextReceipts[0].Template != "incident_timeline" || effective.ContextReceipts[0].Closure != "untruncated" {
		t.Fatalf("effective incident context = %#v", effective.IncidentEvents)
	}
}

func TestContextProviderGraphPathExcludesRunsOnByDefault(t *testing.T) {
	resources := []graph.Resource{{ID: "source"}, {ID: "source-pod"}, {ID: "node"}, {ID: "unrelated-pod"}, {ID: "target"}, {ID: "shell"}}
	relationships := []graph.Relationship{
		{ID: "communication", SubjectID: "source", Predicate: graph.PredicateCommunicates, ObjectID: "target"},
		{ID: "source-instance", SubjectID: "source", Predicate: graph.PredicateInstantiates, ObjectID: "source-pod"},
		{ID: "source-placement", SubjectID: "source-pod", Predicate: graph.PredicateRunsOn, ObjectID: "node"},
		{ID: "unrelated-placement", SubjectID: "unrelated-pod", Predicate: graph.PredicateRunsOn, ObjectID: "node"},
		{ID: "source-shell", SubjectID: "source-pod", Predicate: graph.PredicateExecutes, ObjectID: "shell"},
	}
	packet := Packet{AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []Resource{{ID: "source"}, {ID: "target"}}}
	provider, err := NewContextProviderWithSnapshot(packet, graph.Snapshot{Resources: resources, Relationships: relationships}, PinnedTelemetryContext{Token: AnalysisToken{AnalysisID: "analysis", GraphSHA256: "graph"}}, IncidentContext{}, DefaultContextLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Query(ContextQuery{Token: provider.Token(), Template: "graph_path", AnchorIDs: []string{"source", "target"}, Predicates: []graph.Predicate{"same-as"}}); err == nil {
		t.Fatal("graph path with an unsupported predicate was accepted")
	}
	result, err := provider.Query(ContextQuery{Token: provider.Token(), Template: "graph_path", AnchorIDs: []string{"source", "target"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Closure != "untruncated" || len(result.Resources) != 4 || len(result.Relationships) != 3 || slices.Contains(result.Predicates, graph.PredicateRunsOn) ||
		!slices.Contains(result.Predicates, graph.PredicateExecutes) {
		t.Fatalf("filtered graph path = %#v", result)
	}
	placement, err := provider.Query(ContextQuery{Token: provider.Token(), Template: "graph_path", AnchorIDs: []string{"source-pod"}, Predicates: []graph.Predicate{graph.PredicateRunsOn}})
	if err != nil {
		t.Fatal(err)
	}
	if len(placement.Resources) != 3 || len(placement.Relationships) != 2 {
		t.Fatalf("placement graph path = %#v", placement)
	}
}

func TestCompactPacketRetainsOnlyCandidateFacts(t *testing.T) {
	packet := Packet{
		Changes:   []Change{{Entity: state.EntityLocator{EntityType: "resource", ID: "changed"}}},
		Resources: []Resource{{ID: "a"}, {ID: "b"}, {ID: "changed"}, {ID: "unrelated"}},
		Telemetry: []Telemetry{{ID: "candidate", SubjectID: "a", ObjectID: "b"}, {ID: "noise", SubjectID: "unrelated", ObjectID: "b"}},
		Signals:   []detector.InvestigationSignal{{ID: "s", AnchorIDs: []string{"a", "b"}}},
	}
	compact := CompactPacket(packet)
	if len(compact.Resources) != 3 || compact.Resources[2].ID != "changed" || len(compact.Telemetry) != 0 {
		t.Fatalf("compact packet = %#v", compact)
	}
}

func TestContextProviderRejectsMismatchedTelemetryContext(t *testing.T) {
	packet := Packet{AnalysisID: "analysis", HydratedGraphSHA256: "graph"}
	_, err := NewContextProviderWithTelemetry(packet, PinnedTelemetryContext{
		Token: AnalysisToken{AnalysisID: "other", GraphSHA256: "graph"},
	}, DefaultContextLimits())
	if err == nil {
		t.Fatal("mismatched telemetry context token was accepted")
	}
}
