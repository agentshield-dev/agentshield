package reasoning

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

func TestBuildPacketIncludesBoundedDescriptiveContextAndDefersTelemetry(t *testing.T) {
	events := []state.ContributionChangeEvent{{
		Sequence: 7,
		Added: []state.AssertionChange{{
			AssertionType: "telemetry", AssertionID: "assertion-1",
			Entity: state.EntityLocator{EntityType: "telemetry", ID: "telemetry-1", ResourceID: "resource-1", Kind: "network-flow"},
		}},
	}}
	checkpoint := state.GraphCheckpoint{ThroughSequence: 7, View: state.GraphView{
		SHA256: "graph-sha",
		Snapshot: graph.Snapshot{
			Resources: []graph.Resource{{
				ID: "resource-1", Kind: "vendor/workload",
				Assertions: []graph.ResourceAssertion{{DisplayName: "ML workspace exploit worker", Attributes: map[string]string{
					"description": "template injection vulnerability", "vendor/service-type": "LoadBalancer", "network/role": "workload",
				}}},
			}},
			Facets: []graph.Facet{{
				ID: "facet-1", ResourceID: "resource-1", Kind: "network-exposure",
				Assertions: []graph.FacetAssertion{{Attributes: semanticAttributes(t, graph.SecuritySemantics{
					Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
					State: graph.SecurityStateDeclared, Effect: "external-addressable", Scope: "external", Direction: "ingress", Coverage: "partial",
				}), EvidenceIDs: []string{"evidence-facet"}}},
			}},
			Telemetry: []graph.TelemetryEvent{{
				ID: "telemetry-1", Kind: "network-flow", SubjectID: "resource-1", ObjectID: "resource-2",
				Operation: "egress", Outcome: "forwarded", Coverage: "flow-log", Count: 1,
				Properties: map[string]string{"protocol": "tcp", "payload": "vulnerability exploit"}, EvidenceIDs: []string{"evidence-flow"},
			}},
		},
	}}
	packet, canonical, err := BuildPacket(events, checkpoint, time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptive := range []string{"ML workspace exploit worker", "template injection vulnerability", "vendor/service-type"} {
		if !strings.Contains(string(canonical), descriptive) {
			t.Fatalf("canonical packet omitted descriptive context %q: %s", descriptive, canonical)
		}
	}
	if len(packet.Telemetry) != 0 || strings.Contains(string(canonical), "telemetry-1") || strings.Contains(string(canonical), "evidence-flow") {
		t.Fatalf("initial packet contains deferred telemetry: %s", canonical)
	}
	if len(packet.Facets[0].SecuritySemantics) != 1 || packet.Facets[0].SecuritySemantics[0].Effect != "external-addressable" {
		t.Fatalf("typed security semantics were removed: %#v", packet)
	}
	if packet.Resources[0].Attributes["vendor/service-type"] != "LoadBalancer" {
		t.Fatalf("provider-native attributes were not preserved: %#v", packet)
	}
	if packet.AnalysisID == "" || packet.TriggerFirstSequence != 7 || packet.HydratedAtSequence != 7 {
		t.Fatalf("packet identity or sequence bounds are incomplete: %#v", packet)
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

func TestBuildPacketMarksFirstSequenceAsBaseline(t *testing.T) {
	packet, _, err := BuildPacket(
		[]state.ContributionChangeEvent{{Sequence: 1}},
		state.GraphCheckpoint{ThroughSequence: 1},
		time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
		DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !packet.Baseline {
		t.Fatal("first sequence packet was not marked as baseline")
	}
}

func TestBuildPacketRetainsMultiplyAssertedResource(t *testing.T) {
	checkpoint := state.GraphCheckpoint{View: state.GraphView{Snapshot: graph.Snapshot{Resources: []graph.Resource{{
		ID: "shared", Kind: "kubernetes/pod", Assertions: []graph.ResourceAssertion{
			{PluginID: "kubernetes", SourceID: "cluster"},
			{PluginID: "security", SourceID: "cluster"},
		},
	}}}}}
	packet, _, err := BuildPacket([]state.ContributionChangeEvent{{Sequence: 1}}, checkpoint, time.Unix(1, 0).UTC(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Resources) != 1 || packet.Resources[0].ID != "shared" {
		t.Fatalf("resources = %#v, want multiply asserted resource", packet.Resources)
	}
}

func TestBuildPacketWithSignalsSeparatesTriggerFromTelemetry(t *testing.T) {
	previous := graph.Snapshot{
		Resources: []graph.Resource{
			{ID: "service", Kind: "kubernetes/service"},
			{ID: "backend", Kind: "kubernetes/pod", Assertions: []graph.ResourceAssertion{{Attributes: map[string]string{"network/role": "workload"}}}},
			{ID: "worker", Kind: "kubernetes/pod", Assertions: []graph.ResourceAssertion{{Attributes: map[string]string{"network/role": "workload"}}}},
			{ID: "control", Kind: "network/destination", Assertions: []graph.ResourceAssertion{{Attributes: map[string]string{"network/role": "control-plane-api"}}}},
		},
		Relationships: []graph.Relationship{{ID: "route", SubjectID: "service", Predicate: graph.PredicateExposes, ObjectID: "backend"}},
		Facets:        []graph.Facet{{ID: "backend-facet", ResourceID: "service", Kind: "agentgateway-backend"}},
	}
	current := previous
	current.Telemetry = []graph.TelemetryEvent{
		{ID: "ingress", Kind: "gateway-request", SubjectID: "external", ObjectID: "backend", Outcome: "allowed", Properties: map[string]string{"telemetry/first-seen": "2026-10-06T12:00:00Z"}, EvidenceIDs: []string{"ingress-evidence"}},
		{ID: "dispatch", Kind: "network-flow", SubjectID: "backend", ObjectID: "worker", Operation: "egress", Outcome: "forwarded", Properties: map[string]string{"telemetry/first-seen": "2026-10-06T12:00:10Z"}, EvidenceIDs: []string{"dispatch-evidence"}},
		{ID: "control-flow", Kind: "network-flow", SubjectID: "worker", ObjectID: "control", Operation: "egress", Outcome: "forwarded", Properties: map[string]string{"telemetry/first-seen": "2026-10-06T12:00:20Z"}, EvidenceIDs: []string{"control-evidence"}},
	}
	signal := detector.InvestigationSignal{
		ID: "signal-1", Risk: detector.RiskHigh, Reasons: []string{"new_communication_pair"}, AnchorIDs: []string{"backend"},
		Window: detector.TimeWindow{Start: time.Date(2026, 10, 6, 11, 59, 0, 0, time.UTC), End: time.Date(2026, 10, 6, 12, 2, 0, 0, time.UTC)},
	}
	packet, canonical, err := BuildPacketWithSignals(
		[]state.ContributionChangeEvent{{Sequence: 2}},
		state.GraphCheckpoint{ThroughSequence: 2, View: state.GraphView{SHA256: "current", Snapshot: current}},
		&previous, false, []detector.InvestigationSignal{signal},
		time.Date(2026, 10, 6, 12, 1, 0, 0, time.UTC),
		DefaultLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if packet.TopologyChange != "unchanged" {
		t.Fatalf("topology change = %q, want unchanged", packet.TopologyChange)
	}
	if len(packet.Telemetry) != 0 || strings.Contains(string(canonical), "control-flow") || strings.Contains(string(canonical), "control-evidence") {
		t.Fatalf("initial packet contains telemetry: %s", canonical)
	}
	if packet.TelemetryWindow == nil || !slices.Contains(packet.AvailableContext, "telemetry_chain") {
		t.Fatalf("signal context metadata = %#v, %#v", packet.TelemetryWindow, packet.AvailableContext)
	}
	if !slices.Equal(packet.SuggestedContextAnchors, []string{"backend"}) {
		t.Fatalf("suggested context anchors = %#v", packet.SuggestedContextAnchors)
	}
}

func TestResourceAttributesExposeBoundedDescriptiveFactsAndRedactCredentials(t *testing.T) {
	attributes := resourceAttributes([]graph.ResourceAssertion{{Attributes: map[string]string{
		"kubernetes/name": "sso-server", "kubernetes/label/app": "identity", "provider/credential": "do-not-send", "provider/access-token": "also-do-not-send",
	}}})
	if attributes["kubernetes/name"] != "sso-server" || attributes["kubernetes/label/app"] != "identity" {
		t.Fatalf("descriptive attributes = %#v", attributes)
	}
	if _, found := attributes["provider/credential"]; found {
		t.Fatalf("credential attribute was exposed: %#v", attributes)
	}
	if _, found := attributes["provider/access-token"]; found {
		t.Fatalf("token attribute was exposed: %#v", attributes)
	}
}

func TestBuildPacketWithSignalsRetainsAnchorsWhenResourcesAreTruncated(t *testing.T) {
	current := graph.Snapshot{Resources: []graph.Resource{
		{ID: "first", Kind: "test"},
		{ID: "second", Kind: "test"},
		{ID: "anchor", Kind: "test"},
	}}
	limits := DefaultLimits()
	limits.Resources = 2
	packet, _, err := BuildPacketWithSignals(
		[]state.ContributionChangeEvent{{Sequence: 1}},
		state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "current", Snapshot: current}},
		nil, false, []detector.InvestigationSignal{{ID: "signal", AnchorIDs: []string{"anchor"}}},
		time.Unix(1, 0).UTC(), limits,
	)
	if err != nil {
		t.Fatal(err)
	}
	resourceIDs := []string{packet.Resources[0].ID, packet.Resources[1].ID}
	if !slices.Contains(resourceIDs, "anchor") {
		t.Fatalf("packet resources = %v, want signal anchor", resourceIDs)
	}
	if packet.Truncated["resources"] != 1 {
		t.Fatalf("truncated resources = %d, want 1", packet.Truncated["resources"])
	}
}

func TestBuildPacketRetainsChangedResourcesWhenResourcesAreTruncated(t *testing.T) {
	current := graph.Snapshot{Resources: []graph.Resource{
		{ID: "first", Kind: "test"},
		{ID: "second", Kind: "test"},
		{ID: "changed", Kind: "test"},
	}}
	limits := DefaultLimits()
	limits.Resources = 2
	packet, _, err := BuildPacketWithSignals(
		[]state.ContributionChangeEvent{{Sequence: 1, Added: []state.AssertionChange{{
			AssertionType: "resource", Entity: state.EntityLocator{ID: "changed"},
		}}}},
		state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "current", Snapshot: current}},
		nil, false, []detector.InvestigationSignal{{ID: "signal", AnchorIDs: []string{"first"}}},
		time.Unix(1, 0).UTC(), limits,
	)
	if err != nil {
		t.Fatal(err)
	}
	resourceIDs := []string{packet.Resources[0].ID, packet.Resources[1].ID}
	if !slices.Contains(resourceIDs, "changed") {
		t.Fatalf("packet resources = %v, want changed resource", resourceIDs)
	}
}

func TestBuildPacketRejectsSequenceGap(t *testing.T) {
	events := []state.ContributionChangeEvent{{Sequence: 1}, {Sequence: 3}}
	_, _, err := BuildPacket(events, state.GraphCheckpoint{}, time.Now(), DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "not contiguous") {
		t.Fatalf("sequence gap error = %v", err)
	}
}

func TestBuildPacketTruncatesRequiredResourcesAndChangesInsteadOfFailing(t *testing.T) {
	var resources []graph.Resource
	var added []state.AssertionChange
	for index := range 5 {
		id := fmt.Sprintf("pod-%d", index)
		resources = append(resources, graph.Resource{ID: id, Kind: "kubernetes/pod"})
		added = append(added, state.AssertionChange{AssertionType: "resource", Entity: state.EntityLocator{ID: id}})
	}
	resources = append(resources, graph.Resource{ID: "deployment", Kind: "kubernetes/deployment"})
	limits := DefaultLimits()
	limits.Resources, limits.Changes = 2, 3
	packet, _, err := BuildPacketWithSignals(
		[]state.ContributionChangeEvent{{Sequence: 1, Added: added}},
		state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "current", Snapshot: graph.Snapshot{Resources: resources}}},
		nil, false, []detector.InvestigationSignal{{ID: "signal", AnchorIDs: []string{"deployment"}}},
		time.Unix(1, 0).UTC(), limits,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Resources) != 2 || !slices.ContainsFunc(packet.Resources, func(resource Resource) bool { return resource.ID == "deployment" }) {
		t.Fatalf("packet resources = %#v, want the signal anchor kept first", packet.Resources)
	}
	if len(packet.Changes) != 3 || packet.Truncated["changes"] != 2 || packet.Truncated["requiredResources"] != 2 || packet.Truncated["resources"] != 4 {
		t.Fatalf("changes=%d truncated=%v", len(packet.Changes), packet.Truncated)
	}
}

func TestBuildPacketSelectsRelationshipsAndFacetsNearTheChange(t *testing.T) {
	resources := []graph.Resource{{ID: "anchor"}, {ID: "peer"}}
	var relationships []graph.Relationship
	var facets []graph.Facet
	for index := range 4 {
		other := fmt.Sprintf("a-unrelated-%d", index)
		resources = append(resources, graph.Resource{ID: other})
		relationships = append(relationships, graph.Relationship{ID: "a-edge-" + other, SubjectID: other, Predicate: graph.PredicateContains, ObjectID: other + "-child"})
		facets = append(facets, graph.Facet{ID: "a-facet-" + other, ResourceID: other, Kind: "test"})
	}
	relationships = append(relationships, graph.Relationship{ID: "z-near", SubjectID: "anchor", Predicate: graph.PredicateCommunicates, ObjectID: "peer"})
	facets = append(facets, graph.Facet{ID: "z-near-facet", ResourceID: "anchor", Kind: "test"})
	limits := DefaultLimits()
	limits.Resources, limits.Relationships, limits.Facets = 2, 1, 1
	packet, _, err := BuildPacketWithSignals(
		[]state.ContributionChangeEvent{{Sequence: 1}},
		state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "current", Snapshot: graph.Snapshot{Resources: resources, Relationships: relationships, Facets: facets}}},
		nil, false, []detector.InvestigationSignal{{ID: "signal", AnchorIDs: []string{"anchor", "peer"}}},
		time.Unix(1, 0).UTC(), limits,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Relationships) != 1 || packet.Relationships[0].ID != "z-near" || len(packet.Facets) != 1 || packet.Facets[0].ID != "z-near-facet" {
		t.Fatalf("relationships=%#v facets=%#v, want the facts touching the signal anchors", packet.Relationships, packet.Facets)
	}
	if compact := CompactPacket(packet); len(compact.Relationships) != 1 {
		t.Fatalf("compact packet lost the near relationship: %#v", compact.Relationships)
	}
}
