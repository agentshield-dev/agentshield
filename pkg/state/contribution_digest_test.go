package state

import (
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestContributionInputDigestIsDeterministic(t *testing.T) {
	build := func(attributeOrder []string) graph.Input {
		attributes := make(map[string]string, len(attributeOrder))
		for _, key := range attributeOrder {
			attributes[key] = "value-" + key
		}
		claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "a"}
		return graph.Input{
			Resources: []graph.ResourceAssertion{{
				Claim: claim, Kind: "machine", Attributes: attributes,
				PluginID: "test", SourceID: "fixture", RuleID: "test.resource", EvidenceIDs: []string{"event-a"},
			}},
			Telemetry: []graph.TelemetryAssertion{{
				EventID: "series", Kind: "network-flow", Subject: claim, Object: claim, Count: 3, Properties: attributes,
				PluginID: "test", SourceID: "fixture", RuleID: "test.telemetry", EvidenceIDs: []string{"event-a"},
			}},
		}
	}
	first, err := contributionInputDigest(build([]string{"a", "b", "c", "d", "e", "f", "g", "h"}))
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		again, err := contributionInputDigest(build([]string{"h", "g", "f", "e", "d", "c", "b", "a"}))
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatal("equal inputs produced different contribution digests")
		}
	}
}

func TestContributionInputDigestIsOrderSensitive(t *testing.T) {
	a := digestTestResource("a")
	b := digestTestResource("b")
	forward, err := contributionInputDigest(graph.Input{Resources: []graph.ResourceAssertion{a, b}})
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := contributionInputDigest(graph.Input{Resources: []graph.ResourceAssertion{b, a}})
	if err != nil {
		t.Fatal(err)
	}
	// Same-generation idempotency relies on resubmitting the same input, not
	// an equivalent reordering; see contributionInputDigest.
	if forward == reversed {
		t.Fatal("reordered input produced the same digest; update the contributionInputDigest contract")
	}
}

func digestTestResource(key string) graph.ResourceAssertion {
	return graph.ResourceAssertion{
		Claim: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: key},
		Kind:  "machine", PluginID: "test", SourceID: "fixture", RuleID: "test.resource", EvidenceIDs: []string{"event-" + key},
	}
}
