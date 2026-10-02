package telemetry

import (
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestResolveGraphEndpointsUsesInventoryAndBoundedPeerClasses(t *testing.T) {
	pod := graph.IdentityClaim{Scheme: graph.IdentityScheme{Group: "kubernetes.io", Version: "v1", Kind: "Object"}, AuthorityID: "cluster", ImmutableKey: "v1/pod/pod-1"}
	known, _ := graph.NetworkDestinationClaim("network", "ip/10.0.0.2")
	publicOne, _ := graph.NetworkDestinationClaim("network", "ip/8.8.8.8")
	publicTwo, _ := graph.NetworkDestinationClaim("network", "ip/1.1.1.1")
	snapshot := graph.Snapshot{
		Resources: []graph.Resource{{Identity: pod}, {Identity: known}},
		Relationships: []graph.Relationship{{Predicate: graph.PredicateExposes, Assertions: []graph.RelationshipAssertion{{
			Subject: pod, Predicate: graph.PredicateExposes, Object: known, RuleID: "custom.address-binding",
		}}}},
	}
	events := []Event{
		{Subject: known, Object: publicOne},
		{Subject: publicTwo, Object: known},
	}
	resolved := ResolveGraphEndpoints(events, snapshot)
	if resolved[0].Subject != pod || resolved[1].Object != pod {
		t.Fatalf("inventory endpoints were not resolved: %#v", resolved)
	}
	if resolved[0].Object.ImmutableKey != "external-destination" || resolved[1].Subject.ImmutableKey != "external-source" {
		t.Fatalf("internet peers were not directionally classified: %#v", resolved)
	}
	if events[0].Subject != known || events[0].Object != publicOne {
		t.Fatal("raw events were mutated during graph endpoint resolution")
	}
}

func TestUnknownInternetAddressesShareOneRollupIdentity(t *testing.T) {
	subject := graph.IdentityClaim{Scheme: graph.IdentityScheme{Group: "test", Version: "v1", Kind: "Resource"}, AuthorityID: "test", ImmutableKey: "subject"}
	first, _ := graph.NetworkDestinationClaim("network", "ip/8.8.8.8")
	second, _ := graph.NetworkDestinationClaim("network", "ip/1.1.1.1")
	now := time.Unix(100, 0).UTC()
	events := ResolveGraphEndpoints([]Event{
		{ObservedAt: now, Kind: "network-flow", Subject: subject, Object: first, PluginID: "test", SourceID: "source", Count: 1, EvidenceIDs: []string{"one"}},
		{ObservedAt: now, Kind: "network-flow", Subject: subject, Object: second, PluginID: "test", SourceID: "source", Count: 1, EvidenceIDs: []string{"two"}},
	}, graph.Snapshot{})
	rollup := NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour})
	rollup.ObserveBatch(events)
	input := rollup.Input()
	if len(input.Telemetry) != 1 || input.Telemetry[0].Count != 2 || input.Telemetry[0].Object.ImmutableKey != "external-destination" {
		t.Fatalf("unexpected collapsed rollup: %#v", input.Telemetry)
	}
	if len(input.Resources) != 1 || input.Resources[0].Claim != input.Telemetry[0].Object {
		t.Fatalf("peer class was not materialized: %#v", input.Resources)
	}
	if len(input.Resources[0].EvidenceIDs) != 1 || input.Resources[0].EvidenceIDs[0] != "one" {
		t.Fatalf("peer class evidence = %v, want first observation", input.Resources[0].EvidenceIDs)
	}
	third, _ := graph.NetworkDestinationClaim("network", "ip/9.9.9.9")
	rollup.ObserveBatch(ResolveGraphEndpoints([]Event{{
		ObservedAt: now.Add(time.Second), Kind: "network-flow", Subject: subject, Object: third,
		PluginID: "test", SourceID: "source", Count: 1, EvidenceIDs: []string{"three"},
	}}, graph.Snapshot{}))
	if got := rollup.Input().Resources[0].EvidenceIDs; len(got) != 1 || got[0] != "one" {
		t.Fatalf("peer class evidence churned with traffic: %v", got)
	}
}
