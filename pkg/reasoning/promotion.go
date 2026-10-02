package reasoning

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

const findingIDDomain = "reasoning.evidence-backed-signal"

// Promotion statuses. These values are persisted in evaluation records and
// eval reports; do not rename them.
const (
	// PromotionSuppressed means the packet never warranted a model request.
	PromotionSuppressed = "suppressed"
	// PromotionRejected means a model response did not pass the promotion gate.
	PromotionRejected = "rejected"
	// PromotionPromoted means the response became a finding.
	PromotionPromoted = "promoted"
)

// Promotion reasons, paired with a status in [Promotion]. These values are
// persisted; do not rename them.
const (
	ReasonBaseline                   = "baseline"
	ReasonNoInvestigationSignal      = "no_investigation_signal"
	ReasonModelDidNotSelectCandidate = "model_did_not_select_candidate"
	ReasonNoveltyWithoutConsequence  = "novelty_without_security_consequence"
	ReasonCandidateValidationFailed  = "candidate_validation_failed"
	ReasonCandidateContextTruncated  = "candidate_context_truncated"
	ReasonNoEligibleCandidate        = "no_eligible_candidate_selected"
	ReasonEvidenceBackedSignal       = "evidence_backed_signal"
)

// Promotion is the deterministic outcome of the gate between a model response
// and a finding. FindingID, SignalIDs, and Remediations are set only when
// Status is [PromotionPromoted].
type Promotion struct {
	Status       string                   `json:"status"`
	Reason       string                   `json:"reason"`
	FindingID    string                   `json:"findingId,omitempty"`
	SignalIDs    []string                 `json:"signalIds,omitempty"`
	Remediations []remediation.Suggestion `json:"remediations,omitempty"`
}

// Promote decides whether a response to packet becomes a finding. It is pure
// and is re-run by [NewRemediationProposals] to prove a stored outcome still
// matches its inputs.
//
// Checks run cheapest and least model-dependent first, so the recorded reason
// names the earliest policy that excluded the candidate:
//
//   - baseline: a baseline packet is the reference state, not a change.
//   - no_investigation_signal: without a detector signal there is nothing the
//     model may promote; this and baseline are suppression, not rejection,
//     because no model request is needed.
//   - model_did_not_select_candidate: the model returned no_finding or
//     unsupported.
//   - novelty_without_security_consequence: new communication alone is not a
//     security finding; the model must name a more specific consequence.
//   - candidate_validation_failed: after dropping remediation suggestions that
//     do not validate on their own, the response fails grounded validation
//     (every candidate claim cites a selected signal, a returned fact, and
//     evidence linked to that fact).
//   - no_eligible_candidate_selected: none of the selected signals is
//     medium-or-higher risk. Low-risk telemetry novelty can inform an
//     investigation but never promote one.
//
// Invalid suggestions are dropped before validation so that one bad
// suggestion cannot discard an otherwise grounded finding.
func Promote(packet Packet, response Response) Promotion {
	if packet.Baseline {
		return Promotion{Status: PromotionSuppressed, Reason: ReasonBaseline}
	}
	if len(packet.Signals) == 0 {
		return Promotion{Status: PromotionSuppressed, Reason: ReasonNoInvestigationSignal}
	}
	if response.Assessment.Decision != DecisionCandidateFinding {
		return Promotion{Status: PromotionRejected, Reason: ReasonModelDidNotSelectCandidate}
	}
	if response.Assessment.Category == CategoryNewObservedCommunication {
		return Promotion{Status: PromotionRejected, Reason: ReasonNoveltyWithoutConsequence}
	}
	response = DropInvalidRemediations(packet, response)
	if err := Validate(packet, response); err != nil {
		return Promotion{Status: PromotionRejected, Reason: ReasonCandidateValidationFailed}
	}
	selected := make(map[string]struct{}, len(response.Assessment.SignalIDs))
	for _, signalID := range response.Assessment.SignalIDs {
		selected[signalID] = struct{}{}
	}
	var promoted []string
	for _, signal := range packet.Signals {
		if signal.Risk.Rank() < detector.RiskMedium.Rank() {
			continue
		}
		if _, ok := selected[signal.ID]; ok {
			promoted = append(promoted, signal.ID)
		}
	}
	if len(promoted) == 0 {
		return Promotion{Status: PromotionRejected, Reason: ReasonNoEligibleCandidate}
	}
	// Signals are sorted by ID in the packet, so the finding ID is stable for
	// the same promoted signals over the same graph digest.
	digest := sha256.Sum256([]byte(findingIDDomain + "\x00" + strings.Join(promoted, "\x00") + "\x00" + packet.HydratedGraphSHA256))
	promotion := Promotion{
		Status: PromotionPromoted, Reason: ReasonEvidenceBackedSignal, FindingID: "finding:sha256:" + hex.EncodeToString(digest[:]),
		SignalIDs: promoted,
	}
	promotion.Remediations = append([]remediation.Suggestion(nil), response.Assessment.RemediationSuggestions...)
	return promotion
}

// NewRemediationProposals hydrates each validated suggestion on a promoted
// outcome into a canonical [remediation.Proposal] bound to the finding,
// analysis, graph digest, and target identity. It recomputes the promotion
// rather than trusting outcome.Promotion, so a tampered or stale outcome cannot
// mint proposals. Only evidence cited by both the suggestion and a qualifying
// candidate claim is carried onto the proposal.
func NewRemediationProposals(outcome AnalysisOutcome) ([]remediation.Proposal, error) {
	promotion := Promote(outcome.EffectivePacket, outcome.Response)
	if !reflect.DeepEqual(promotion, outcome.Promotion) {
		return nil, errors.New("analysis promotion does not match validated effective packet and response")
	}
	if outcome.Validation != ValidationAccepted || promotion.Status != PromotionPromoted || promotion.FindingID == "" || len(promotion.Remediations) == 0 {
		return nil, errors.New("only a promoted finding with validated remediations can create remediation proposals")
	}
	resources := make(map[string]Resource, len(outcome.EffectivePacket.Resources))
	for _, resource := range outcome.EffectivePacket.Resources {
		resources[resource.ID] = resource
	}
	proposals := make([]remediation.Proposal, 0, len(promotion.Remediations))
	for _, suggestion := range promotion.Remediations {
		target, found := resources[suggestion.TargetEntityIDs[0]]
		if !found {
			return nil, errors.New("remediation target was not supplied in the effective packet")
		}
		evidenceIDs := qualifyingSuggestionEvidence(outcome.EffectivePacket, outcome.Response.Assessment, suggestion)
		proposal, err := remediation.NewProposal(
			promotion.FindingID, outcome.EffectivePacket.AnalysisID, outcome.EffectivePacket.HydratedGraphSHA256, suggestion,
			remediation.Target{EntityID: target.ID, Identity: target.Identity, Kind: target.Kind},
			evidenceIDs,
		)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, proposal)
	}
	return proposals, nil
}

// InvestigationEligible reports whether a signal can support promotion. Agentic
// investigation of a window without an eligible signal can never promote a finding.
func InvestigationEligible(signal detector.InvestigationSignal) bool {
	return signal.Risk.Rank() >= detector.RiskMedium.Rank()
}
