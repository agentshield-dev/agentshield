package reasoning

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

const remediationTestGraphSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestPromoteSuppressesOrdinaryCommunicationAndPromotesValidatedPath(t *testing.T) {
	ordinary := Promote(Packet{}, Response{})
	if ordinary.Status != "suppressed" || ordinary.Reason != "no_investigation_signal" {
		t.Fatalf("ordinary communication promotion = %#v", ordinary)
	}
	packet := Packet{
		HydratedGraphSHA256: remediationTestGraphSHA256,
		Resources:           []Resource{{ID: "a", Kind: "kubernetes/pod"}, {ID: "b"}},
		Telemetry:           []Telemetry{{ID: "t", SubjectID: "a", ObjectID: "b", EvidenceIDs: []string{"e"}}},
		Signals:             []detector.InvestigationSignal{{ID: "s", Risk: detector.RiskHigh}},
	}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "possible_lateral_path", SignalIDs: []string{"s"}, AffectedEntityIDs: []string{"a"},
		Severity: "high", ModelUncertainty: "low",
		Claims: []Claim{{Mode: "observed", SupportingIDs: []string{"s", "t", "e"}}},
		RemediationSuggestions: []remediation.Suggestion{
			{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"a"}, SupportingIDs: []string{"s", "t", "e"}},
			{Intent: remediation.IntentTransportRequireMutualTLS, TargetEntityIDs: []string{"a"}, SupportingIDs: []string{"s", "t", "e"}},
		},
	}}
	promotion := Promote(packet, response)
	if promotion.Status != "promoted" || promotion.FindingID == "" || len(promotion.Remediations) != 2 {
		t.Fatalf("promotion = %#v", promotion)
	}
	encodedPromotion, err := json.Marshal(promotion)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encodedPromotion), `"remediations":[`) || strings.Contains(string(encodedPromotion), `"remediationSuggestion"`) {
		t.Fatalf("serialized promotion = %s", encodedPromotion)
	}
	packet.AnalysisID = "analysis"
	packet.Resources[0] = Resource{
		ID: "a", Kind: "kubernetes/pod", Identity: graph.IdentityClaim{
			Scheme: graph.IdentityScheme{Group: "kubernetes.io", Version: "v1", Kind: "Object"}, AuthorityID: "cluster", ImmutableKey: "v1/pod/uid",
		},
	}
	proposals, err := NewRemediationProposals(AnalysisOutcome{Validation: "accepted", EffectivePacket: packet, Response: response, Promotion: promotion})
	if err != nil {
		t.Fatal(err)
	}
	if len(proposals) != 2 || proposals[0].FindingID != promotion.FindingID || proposals[0].AnalysisID != packet.AnalysisID || proposals[0].Target.EntityID != "a" || proposals[0].Intent != remediation.IntentNetworkDeclareIngressIsolation || proposals[1].Intent != remediation.IntentTransportRequireMutualTLS || len(proposals[0].EvidenceIDs) != 1 || proposals[0].EvidenceIDs[0] != "e" {
		t.Fatalf("proposals = %#v", proposals)
	}
}

func TestPromoteRejectsCommunicationNoveltyWithoutSecurityConsequence(t *testing.T) {
	packet := Packet{
		HydratedGraphSHA256: remediationTestGraphSHA256,
		Resources:           []Resource{{ID: "a"}, {ID: "b"}},
		Telemetry:           []Telemetry{{ID: "t", SubjectID: "a", ObjectID: "b", EvidenceIDs: []string{"e"}}},
		Signals:             []detector.InvestigationSignal{{ID: "s", Risk: detector.RiskHigh}},
	}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "new_observed_communication", Severity: "medium", ModelUncertainty: "low",
		AffectedEntityIDs: []string{"a", "b"}, SignalIDs: []string{"s"},
		Claims: []Claim{{Mode: "observed", Text: "new communication", SupportingIDs: []string{"s", "t", "e"}}},
	}}
	promotion := Promote(packet, response)
	if promotion.Status != "rejected" || promotion.Reason != "novelty_without_security_consequence" {
		t.Fatalf("promotion = %#v", promotion)
	}
}

func TestNewRemediationProposalsRejectFabricatedPromotion(t *testing.T) {
	packet := Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: remediationTestGraphSHA256,
		Resources: []Resource{{
			ID: "target", Kind: "kubernetes/pod", Identity: graph.IdentityClaim{
				Scheme: graph.IdentityScheme{Group: "kubernetes.io", Version: "v1", Kind: "Object"}, AuthorityID: "cluster", ImmutableKey: "v1/pod/uid",
			},
		}},
		Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", EvidenceIDs: []string{"evidence"}}},
		Signals:   []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
	}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low",
		AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
		Claims:                 []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
		RemediationSuggestions: []remediation.Suggestion{{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}}},
	}}
	promotion := Promote(packet, response)
	promotion.FindingID = "finding:fabricated"
	if _, err := NewRemediationProposals(AnalysisOutcome{Validation: "accepted", EffectivePacket: packet, Response: response, Promotion: promotion}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("proposal hydration error = %v", err)
	}
}

func TestNewRemediationProposalsHydrateEveryClosedIntentIndependentlyOfTargetKind(t *testing.T) {
	for _, intent := range []remediation.Intent{
		remediation.IntentNetworkDeclareIngressIsolation,
		remediation.IntentTransportRequireMutualTLS,
		remediation.IntentGatewayPreventRouteDelivery,
	} {
		t.Run(string(intent), func(t *testing.T) {
			packet := Packet{
				AnalysisID: "analysis", HydratedGraphSHA256: remediationTestGraphSHA256,
				Resources: []Resource{{ID: "target", Kind: "example/unsupported", Identity: graph.IdentityClaim{Scheme: graph.IdentityScheme{Group: "example.io", Version: "v1", Kind: "Object"}, AuthorityID: "authority", ImmutableKey: "object/uid"}}},
				Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", EvidenceIDs: []string{"evidence"}}},
				Signals:   []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
			}
			response := Response{Assessment: Assessment{
				Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low",
				AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
				Claims:                 []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
				RemediationSuggestions: []remediation.Suggestion{{Intent: intent, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}}},
			}}
			promotion := Promote(packet, response)
			proposals, err := NewRemediationProposals(AnalysisOutcome{Validation: "accepted", EffectivePacket: packet, Response: response, Promotion: promotion})
			if err != nil {
				t.Fatal(err)
			}
			if len(proposals) != 1 {
				t.Fatalf("proposals = %#v", proposals)
			}
			proposal := proposals[0]
			if proposal.Intent != intent || proposal.Target.Kind != "example/unsupported" || proposal.FindingID == "" || proposal.GraphSHA256 != remediationTestGraphSHA256 || len(proposal.EvidenceIDs) != 1 || proposal.EvidenceIDs[0] != "evidence" {
				t.Fatalf("proposal = %#v", proposal)
			}
		})
	}
}

func TestPromotionDoesNotInvokeRemediationProvider(t *testing.T) {
	provider := &countingRemediationProvider{}
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: "kubernetes", SourceID: "source", Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remediation.NewExecutor(registry, func(context.Context) (remediation.GraphView, error) {
		return remediation.GraphView{SHA256: remediationTestGraphSHA256}, nil
	}); err != nil {
		t.Fatal(err)
	}
	packet := Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: remediationTestGraphSHA256, Resources: []Resource{{ID: "target", Kind: "kubernetes/pod"}},
		Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", EvidenceIDs: []string{"evidence"}}}, Signals: []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
	}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "unknown_security_effect", AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
		Severity: "high", ModelUncertainty: "low",
		Claims:                 []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
		RemediationSuggestions: []remediation.Suggestion{{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}}},
	}}
	if promotion := Promote(packet, response); promotion.Status != "promoted" {
		t.Fatalf("promotion = %#v", promotion)
	}
	if provider.calls != 0 {
		t.Fatalf("reasoning invoked remediation provider %d times", provider.calls)
	}
}

type countingRemediationProvider struct {
	calls int
}

func (*countingRemediationProvider) RemediationDescriptor() remediation.Descriptor {
	return remediation.Descriptor{Actions: []remediation.Action{{
		ID: "network-policy/v1", Intent: remediation.IntentNetworkDeclareIngressIsolation,
		TargetKind: "kubernetes/pod", Mode: remediation.ModeExecutable,
		Scheme: graph.IdentityScheme{Group: "kubernetes.io", Version: "v1", Kind: "Object"}, AuthorityID: "cluster",
	}}}
}

func (provider *countingRemediationProvider) Plan(context.Context, remediation.Proposal, string) (remediation.Plan, error) {
	provider.calls++
	return remediation.Plan{}, nil
}

func (provider *countingRemediationProvider) Prepare(context.Context, remediation.Proposal, remediation.Plan) (remediation.Preparation, error) {
	provider.calls++
	return remediation.Preparation{}, nil
}

func (provider *countingRemediationProvider) Execute(context.Context, remediation.Proposal, remediation.Plan, remediation.Preparation) (remediation.ExecutionResult, error) {
	provider.calls++
	return remediation.ExecutionResult{}, nil
}

func (provider *countingRemediationProvider) Verify(context.Context, remediation.Proposal, remediation.Plan, remediation.ExecutionResult) (remediation.Verification, error) {
	provider.calls++
	return remediation.Verification{}, nil
}
