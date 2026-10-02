package reasoning

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

func TestFindingSinkPersistsPromotedFindingRemediations(t *testing.T) {
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
		Decision: "candidate_finding", Category: "new_exposure", Severity: "high", ModelUncertainty: "low", Summary: "Unexpected ingress",
		AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
		Claims: []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
		RemediationSuggestions: []remediation.Suggestion{
			{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}},
			{Intent: remediation.IntentTransportRequireMutualTLS, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "fact", "evidence"}},
		},
	}}
	promotion := Promote(packet, response)
	store := &recordingFindingStore{}
	createdAt := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	sink, err := NewFindingSink(store, func() time.Time { return createdAt })
	if err != nil {
		t.Fatal(err)
	}
	evaluation := Evaluation{Analysis: AnalysisRun{Outcome: AnalysisOutcome{
		Validation: "accepted", EffectivePacket: packet, Response: response, Promotion: promotion,
	}}}
	if err := sink.RecordReasoningEvaluation(context.Background(), evaluation); err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.finding.ID != promotion.FindingID || store.finding.Summary != "Unexpected ingress" || store.finding.CreatedAt != createdAt || len(store.finding.Remediations) != 2 {
		t.Fatalf("stored finding = %#v, calls = %d", store.finding, store.calls)
	}
	if store.finding.Remediations[0].Intent != remediation.IntentNetworkDeclareIngressIsolation || store.finding.Remediations[1].Intent != remediation.IntentTransportRequireMutualTLS {
		t.Fatalf("stored remediations = %#v", store.finding.Remediations)
	}
}

func TestFindingSinkPersistsPromotedFindingWithoutRemediations(t *testing.T) {
	packet := Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: remediationTestGraphSHA256,
		Resources: []Resource{{ID: "target", Kind: "kubernetes/pod", Identity: graph.IdentityClaim{
			Scheme: graph.IdentityScheme{Group: "kubernetes.io", Version: "v1", Kind: "Object"}, AuthorityID: "cluster", ImmutableKey: "v1/pod/uid",
		}}},
		Telemetry: []Telemetry{{ID: "fact", SubjectID: "target", EvidenceIDs: []string{"evidence"}}},
		Signals:   []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskHigh}},
	}
	response := Response{Assessment: Assessment{
		Decision: "candidate_finding", Category: "new_exposure", Severity: "high", ModelUncertainty: "low", Summary: "Unexpected ingress",
		AffectedEntityIDs: []string{"target"}, SignalIDs: []string{"signal"},
		Claims: []Claim{{Mode: "observed", SupportingIDs: []string{"signal", "fact", "evidence"}}},
	}}
	promotion := Promote(packet, response)
	store := &recordingFindingStore{}
	sink, err := NewFindingSink(store, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	evaluation := Evaluation{Analysis: AnalysisRun{Outcome: AnalysisOutcome{
		Validation: "accepted", EffectivePacket: packet, Response: response, Promotion: promotion,
	}}}
	if err := sink.RecordReasoningEvaluation(context.Background(), evaluation); err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.finding.ID != promotion.FindingID || len(store.finding.Remediations) != 0 {
		t.Fatalf("stored finding = %#v, calls = %d", store.finding, store.calls)
	}
}

func TestFindingSinkInvalidatesFindingsTouchedByContribution(t *testing.T) {
	store := &recordingFindingStore{}
	invalidatedAt := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	sink, err := NewFindingSink(store, func() time.Time { return invalidatedAt })
	if err != nil {
		t.Fatal(err)
	}
	evaluation := Evaluation{Window: ChangeWindow{
		Checkpoint: state.GraphCheckpoint{ThroughSequence: 9, View: state.GraphView{SHA256: remediationTestGraphSHA256}},
		Events: []state.ContributionChangeEvent{{Added: []state.AssertionChange{{Entity: state.EntityLocator{
			EntityType: "relationship", SubjectID: "target", ObjectID: "policy",
		}}}}},
	}}
	if err := sink.RecordReasoningEvaluation(context.Background(), evaluation); err != nil {
		t.Fatal(err)
	}
	if store.invalidationCalls != 1 || store.invalidationSequence != 9 || store.invalidationGraphSHA256 != remediationTestGraphSHA256 || store.invalidatedAt != invalidatedAt || len(store.invalidatedEntityIDs) != 2 || store.invalidatedEntityIDs[0] != "policy" || store.invalidatedEntityIDs[1] != "target" {
		t.Fatalf("invalidation = %#v", store)
	}
}

func TestFindingSinkInvalidatesAllFindingsAfterRebase(t *testing.T) {
	store := &recordingFindingStore{}
	invalidatedAt := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	sink, err := NewFindingSink(store, func() time.Time { return invalidatedAt })
	if err != nil {
		t.Fatal(err)
	}
	evaluation := Evaluation{
		Window:  ChangeWindow{Checkpoint: state.GraphCheckpoint{ThroughSequence: 9, View: state.GraphView{SHA256: remediationTestGraphSHA256}}},
		Rebased: true,
	}
	if err := sink.RecordReasoningEvaluation(context.Background(), evaluation); err != nil {
		t.Fatal(err)
	}
	if store.invalidationCalls != 1 || store.invalidationSequence != 9 || store.invalidationGraphSHA256 != remediationTestGraphSHA256 || store.invalidatedAt != invalidatedAt || store.invalidatedEntityIDs != nil {
		t.Fatalf("invalidation = %#v", store)
	}
}

func TestFindingSinkPersistsActiveRuleMatchesWithoutAgent(t *testing.T) {
	store := &recordingFindingStore{}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	sink, err := NewFindingSink(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	rule := func(id, ruleID string, risk detector.Risk, anchors ...string) detector.InvestigationSignal {
		return detector.InvestigationSignal{ID: id, Risk: risk, Reasons: []string{"workload_rule_match"}, AnchorIDs: anchors, RuleID: ruleID, RuleRevision: 2}
	}
	evaluation := Evaluation{
		Window: ChangeWindow{Checkpoint: state.GraphCheckpoint{ThroughSequence: 9, View: state.GraphView{SHA256: remediationTestGraphSHA256}}},
		RuleSignals: []detector.InvestigationSignal{
			rule("signal-b", "deployment/checkout/rule-1", detector.RiskMedium, "checkout", "secrets"),
			rule("signal-a", "deployment/checkout/rule-1", detector.RiskHigh, "checkout", "orders"),
		},
		Investigation: InvestigationBelowThreshold,
	}
	if err := sink.RecordReasoningEvaluation(context.Background(), evaluation); err != nil {
		t.Fatal(err)
	}
	finding := store.finding
	if store.calls != 1 || finding.Origin != state.FindingOriginDetectionRule || finding.DetectionRuleID != "deployment/checkout/rule-1" ||
		finding.DetectionRuleRevision != 2 || finding.Severity != "high" || finding.Category != "detection_rule_match" ||
		!slices.Equal(finding.SignalIDs, []string{"signal-a", "signal-b"}) || !slices.Equal(finding.AffectedEntityIDs, []string{"checkout", "orders", "secrets"}) {
		t.Fatalf("rule finding = %#v calls=%d", finding, store.calls)
	}
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(evaluation.RuleSignals)
	if again := RuleFindings(evaluation, now); len(again) != 1 || again[0].ID != finding.ID || again[0].Summary != finding.Summary {
		t.Fatalf("rule finding is not stable under reordering: %#v", again)
	}
	evaluation.RuleSignals = nil
	evaluation.ShadowSignals = []detector.InvestigationSignal{{ID: "shadow", Risk: detector.RiskCritical, Reasons: []string{"draft"}, RuleID: "draft", RuleRevision: 1, RuleMode: detector.RuleModeShadow}}
	evaluation.Signals = []detector.InvestigationSignal{{ID: "novelty", Risk: detector.RiskCritical, Reasons: []string{"new_public_exposure"}}}
	if findings := RuleFindings(evaluation, now); len(findings) != 0 {
		t.Fatalf("shadow and novelty signals created rule findings: %#v", findings)
	}
}

type recordingFindingStore struct {
	finding                 state.Finding
	calls                   int
	invalidationCalls       int
	invalidationGraphSHA256 string
	invalidationSequence    uint64
	invalidatedEntityIDs    []string
	invalidatedAt           time.Time
}

func (store *recordingFindingStore) PutFinding(_ context.Context, finding state.Finding) error {
	store.calls++
	store.finding = finding
	return nil
}

func (store *recordingFindingStore) InvalidateFindings(_ context.Context, graphSHA256 string, sequence uint64, entityIDs []string, invalidatedAt time.Time) error {
	store.invalidationCalls++
	store.invalidationGraphSHA256 = graphSHA256
	store.invalidationSequence = sequence
	store.invalidatedEntityIDs = append([]string(nil), entityIDs...)
	store.invalidatedAt = invalidatedAt
	return nil
}
