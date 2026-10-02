package istio

import (
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestCanonicalHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		wildcard bool
		wantErr  bool
	}{
		{name: "DNS case and trailing dot", input: "API.Example.COM.", want: "api.example.com"},
		{name: "wildcard", input: "*.Example.com", want: "*.example.com", wildcard: true},
		{name: "IPv4", input: "192.0.2.10", want: "192.0.2.10"},
		{name: "IPv6", input: "2001:0db8::1", want: "2001:db8::1"},
		{name: "URL", input: "https://example.com", wantErr: true},
		{name: "port", input: "example.com:443", wantErr: true},
		{name: "path", input: "example.com/api", wantErr: true},
		{name: "credentials", input: "user@example.com", wantErr: true},
		{name: "interior wildcard", input: "api.*.example.com", wantErr: true},
		{name: "bare wildcard", input: "*", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, wildcard, err := canonicalHost(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("canonicalHost(%q) succeeded: %q", test.input, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want || wildcard != test.wildcard {
				t.Fatalf("canonicalHost(%q) = (%q, %t), want (%q, %t)", test.input, got, wildcard, test.want, test.wildcard)
			}
		})
	}
}

func TestNetworkDestinationClaimConvergesAcrossContributors(t *testing.T) {
	first, err := networkDestinationClaim("network-a", "API.EXAMPLE.COM.")
	if err != nil {
		t.Fatal(err)
	}
	second, err := graph.NetworkDestinationClaim("network-a", "dns/api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first.ImmutableKey != "dns/api.example.com" {
		t.Fatalf("immutable key = %q", first.ImmutableKey)
	}
	if first != second {
		t.Fatalf("Istio and generic destination claims differ: %#v != %#v", first, second)
	}

	registry := graph.NewRegistry()
	snapshot, err := graph.NewCompiler(registry).Compile(graph.Input{
		Resources: []graph.ResourceAssertion{{
			Claim: first, Kind: "network/destination", PluginID: PluginID, SourceID: "source",
			RuleID: "istio.serviceentry-host", EvidenceIDs: []string{"config-event"},
		}},
		Telemetry: []graph.TelemetryAssertion{{
			EventID: "traffic-event", Kind: "network-flow", Subject: second, Object: second, Count: 1,
			PluginID: "telemetry", SourceID: "flow-source", RuleID: "telemetry.network-flow",
			EvidenceIDs: []string{"flow-event"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 1 || len(snapshot.Telemetry) != 1 || snapshot.Telemetry[0].ObjectID != snapshot.Resources[0].ID {
		t.Fatalf("telemetry did not converge on the configured destination: %#v", snapshot)
	}
}
