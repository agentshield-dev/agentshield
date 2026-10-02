package reasoning

import (
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

func TestValidateAcceptsEvidenceLinkedFacts(t *testing.T) {
	packet := Packet{
		Resources:     []Resource{{ID: "a"}, {ID: "b"}},
		Relationships: []Relationship{{ID: "r", SubjectID: "a", ObjectID: "b", EvidenceIDs: []string{"e-r"}}},
		Telemetry:     []Telemetry{{ID: "t", SubjectID: "a", ObjectID: "b", EvidenceIDs: []string{"e-t"}}},
		Signals:       []detector.InvestigationSignal{{ID: "s", Risk: detector.RiskHigh}},
	}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "possible_lateral_path", AffectedEntityIDs: []string{"a", "b"},
		Severity: "high", ModelUncertainty: "low", Claims: []Claim{{Mode: "observed", SupportingIDs: []string{"s", "r", "t", "e-r", "e-t"}}}, SignalIDs: []string{"s"},
	}}
	if err := Validate(packet, response); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRemediationSuggestionIsClosedAndBounded(t *testing.T) {
	packet := Packet{
		Resources: []Resource{{ID: "target", Kind: "kubernetes/pod"}}, Signals: []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
		Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", EvidenceIDs: []string{"evidence"}}},
	}
	valid := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "unknown_security_effect", AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
		Severity: "high", ModelUncertainty: "low",
		Claims:                 []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
		RemediationSuggestions: []remediation.Suggestion{{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}}},
	}}
	if err := Validate(packet, valid); err != nil {
		t.Fatal(err)
	}
	valid.Assessment.RemediationSuggestions = append(valid.Assessment.RemediationSuggestions, remediation.Suggestion{Intent: remediation.IntentTransportRequireMutualTLS, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}})
	if err := Validate(packet, valid); err != nil {
		t.Fatalf("multiple distinct remediations: %v", err)
	}
	invalid := valid
	invalid.Assessment.RemediationSuggestions = append(invalid.Assessment.RemediationSuggestions, valid.Assessment.RemediationSuggestions[0])
	if err := Validate(packet, invalid); err == nil || !strings.Contains(err.Error(), "duplicate remediation") {
		t.Fatalf("duplicate suggestion error = %v", err)
	}
	invalid = valid
	for len(invalid.Assessment.RemediationSuggestions) <= remediation.MaxSuggestions {
		invalid.Assessment.RemediationSuggestions = append(invalid.Assessment.RemediationSuggestions, remediation.Suggestion{})
	}
	if err := Validate(packet, invalid); err == nil || !strings.Contains(err.Error(), "more than 8") {
		t.Fatalf("suggestion bound error = %v", err)
	}
}

func TestDropInvalidRemediationsPreservesFindingAndValidSuggestions(t *testing.T) {
	packet := Packet{
		Resources: []Resource{{ID: "target", Kind: "kubernetes/pod"}}, Signals: []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
		Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", EvidenceIDs: []string{"evidence"}}},
	}
	valid := remediation.Suggestion{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}}
	invalid := remediation.Suggestion{Intent: remediation.IntentTransportRequireMutualTLS, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"missing"}}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low",
		AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
		Claims:                 []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
		RemediationSuggestions: []remediation.Suggestion{invalid, valid, valid},
	}}

	sanitized := DropInvalidRemediations(packet, response)
	if len(sanitized.Assessment.RemediationSuggestions) != 1 || sanitized.Assessment.RemediationSuggestions[0].Intent != valid.Intent {
		t.Fatalf("remediation suggestions = %#v", sanitized.Assessment.RemediationSuggestions)
	}
	if err := Validate(packet, sanitized); err != nil {
		t.Fatalf("sanitized finding validation: %v", err)
	}
}

func TestValidateKnownRemediationIntentsIndependentlyOfTargetKind(t *testing.T) {
	packet := Packet{
		Resources: []Resource{{ID: "target", Kind: "example/unsupported"}},
		Signals:   []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
		Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", EvidenceIDs: []string{"evidence"}}},
	}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low",
		AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
		Claims: []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
	}}
	for _, intent := range []remediation.Intent{
		remediation.IntentNetworkDeclareIngressIsolation,
		remediation.IntentTransportRequireMutualTLS,
		remediation.IntentGatewayPreventRouteDelivery,
	} {
		t.Run(string(intent), func(t *testing.T) {
			response.Assessment.RemediationSuggestions = []remediation.Suggestion{{Intent: intent, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}}}
			if err := Validate(packet, response); err != nil {
				t.Fatal(err)
			}
		})
	}
	response.Assessment.RemediationSuggestions = []remediation.Suggestion{{Intent: "unknown.intent", TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}}}
	if err := Validate(packet, response); err == nil || !strings.Contains(err.Error(), "unsupported remediation intent") {
		t.Fatalf("unknown intent error = %v", err)
	}
}

func TestValidateRemediationSuggestionRequiresAffectedImplicatedTarget(t *testing.T) {
	response := func(affectedEntityIDs []string) Response {
		return Response{Assessment: Assessment{
			Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low",
			AffectedEntityIDs: affectedEntityIDs, SignalIDs: []string{"signal"},
			Claims:                 []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
			RemediationSuggestions: []remediation.Suggestion{{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}}},
		}}
	}
	tests := []struct {
		name      string
		packet    Packet
		response  Response
		wantError string
	}{
		{
			name: "target is not affected",
			packet: Packet{
				Resources: []Resource{{ID: "target", Kind: "kubernetes/pod"}, {ID: "other"}}, Signals: []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
				Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", ObjectID: "other", EvidenceIDs: []string{"evidence"}}},
			},
			response: response([]string{"other"}), wantError: "affected entity",
		},
		{
			name: "cited fact does not implicate target",
			packet: Packet{
				Resources: []Resource{{ID: "target", Kind: "kubernetes/pod"}, {ID: "other"}}, Signals: []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
				Telemetry: []Telemetry{{ID: "fact", SubjectID: "other", EvidenceIDs: []string{"evidence"}}},
			},
			response: response([]string{"target"}), wantError: "implicating its target",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Validate(test.packet, test.response); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validation error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestValidateRemediationSuggestionRequiresClaimLocalIntersection(t *testing.T) {
	packet := Packet{
		Resources: []Resource{{ID: "target", Kind: "kubernetes/pod"}, {ID: "other"}},
		Telemetry: []Telemetry{
			{ID: "target-fact", SubjectID: "target", EvidenceIDs: []string{"target-evidence"}},
			{ID: "other-fact", SubjectID: "other", EvidenceIDs: []string{"other-evidence"}},
		},
		Signals: []detector.InvestigationSignal{{ID: "selected", Risk: detector.RiskHigh}, {ID: "unselected", Risk: detector.RiskHigh}},
	}
	base := Assessment{
		Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low",
		AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"selected"},
	}
	tests := []struct {
		name       string
		claims     []Claim
		supporting []string
	}{
		{name: "unselected suggestion signal", claims: []Claim{{Mode: "observed", SupportingIDs: []string{"selected", "target-fact", "target-evidence"}}}, supporting: []string{"unselected", "target-fact", "target-evidence"}},
		{name: "signal and target fact split across claims", claims: []Claim{{Mode: "observed", SupportingIDs: []string{"selected", "other-fact", "other-evidence"}}, {Mode: "observed", SupportingIDs: []string{"unselected", "target-fact", "target-evidence"}}}, supporting: []string{"selected", "target-fact", "target-evidence"}},
		{name: "suggestion cites unrelated fact", claims: []Claim{{Mode: "observed", SupportingIDs: []string{"selected", "target-fact", "target-evidence"}}}, supporting: []string{"selected", "other-fact", "other-evidence"}},
		{name: "linked evidence is only in another claim", claims: []Claim{{Mode: "observed", SupportingIDs: []string{"selected", "target-fact", "other-evidence"}}, {Mode: "observed", SupportingIDs: []string{"selected", "other-fact", "target-evidence"}}}, supporting: []string{"selected", "target-fact", "target-evidence"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assessment := base
			assessment.Claims = test.claims
			assessment.RemediationSuggestions = []remediation.Suggestion{{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: test.supporting}}
			if err := Validate(packet, Response{Assessment: assessment}); err == nil {
				t.Fatal("validation accepted a suggestion without one qualifying claim intersection")
			}
		})
	}
}

func TestValidateRejectsHallucinatedReferences(t *testing.T) {
	packet := Packet{Resources: []Resource{{ID: "a"}}, Telemetry: []Telemetry{{ID: "t", EvidenceIDs: []string{"real"}}}}
	tests := []struct {
		name     string
		response Response
		want     string
	}{
		{name: "entity", response: Response{Assessment: Assessment{Decision: "no_finding", Category: "unknown_security_effect", Severity: "none", ModelUncertainty: "low", AffectedEntityIDs: []string{"missing"}}}, want: "was not supplied"},
		{name: "reference", response: Response{Assessment: Assessment{Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low", Claims: []Claim{{Mode: "observed", SupportingIDs: []string{"missing"}}}}}, want: "reference"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Validate(packet, test.response); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateRequiresClaimLocalSignalFactAndEvidence(t *testing.T) {
	packet := Packet{
		Resources: []Resource{{ID: "a"}, {ID: "b"}},
		Relationships: []Relationship{
			{ID: "fact-a", SubjectID: "a", ObjectID: "b", EvidenceIDs: []string{"evidence-a"}},
			{ID: "fact-b", SubjectID: "a", ObjectID: "b", EvidenceIDs: []string{"evidence-b"}},
		},
		Signals: []detector.InvestigationSignal{{ID: "signal-a", Risk: detector.RiskHigh}},
	}
	tests := []struct {
		name       string
		references []string
		want       string
	}{
		{name: "linked", references: []string{"signal-a", "fact-a", "evidence-a"}},
		{name: "cross-fact evidence", references: []string{"signal-a", "fact-a", "evidence-b"}, want: "linked evidence"},
		{name: "signal only", references: []string{"signal-a"}, want: "returned fact"},
		{name: "fact without selected signal", references: []string{"fact-a", "evidence-a"}, want: "selected by the assessment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := Response{Assessment: Assessment{
				Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low",
				Claims: []Claim{{Mode: "observed", SupportingIDs: test.references}}, SignalIDs: []string{"signal-a"},
			}}
			err := Validate(packet, response)
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateClassificationAcceptsIncompleteGrounding(t *testing.T) {
	packet := Packet{
		Resources: []Resource{{ID: "target"}},
		Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", EvidenceIDs: []string{"evidence"}}},
		Signals:   []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
	}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "unknown_security_effect", Severity: "high", ModelUncertainty: "low",
		AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
		Claims: []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "evidence"}}},
	}}
	if err := ValidateClassification(packet, response); err != nil {
		t.Fatalf("classification validation: %v", err)
	}
	if err := Validate(packet, response); err == nil || !strings.Contains(err.Error(), "returned fact") {
		t.Fatalf("strict validation error = %v, want missing returned fact", err)
	}
}

func TestModelAndPromptAreFixedAndBlind(t *testing.T) {
	if Model != "gpt-6-astra" {
		t.Fatalf("model = %q", Model)
	}
	for _, forbidden := range []string{"ML workspace", "vulnerability identifier", "template injection", "model artifact", "model provider"} {
		if strings.Contains(SystemPrompt, forbidden) {
			t.Fatalf("system prompt leaked %q", forbidden)
		}
	}
}
