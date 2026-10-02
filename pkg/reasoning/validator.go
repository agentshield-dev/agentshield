package reasoning

import (
	"errors"
	"fmt"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

// Assessment decisions. These values are part of the strict model response
// schema, eval campaign expectations, and persisted reports.
const (
	DecisionNoFinding        = "no_finding"
	DecisionCandidateFinding = "candidate_finding"
	DecisionUnsupported      = "unsupported"
)

// Assessment categories. These values are part of the strict model response
// schema and persisted findings.
const (
	// CategoryNewObservedCommunication is novelty without a stated consequence;
	// [Promote] never promotes it.
	CategoryNewObservedCommunication = "new_observed_communication"
	CategoryBoundaryCrossing         = "boundary_crossing"
	CategoryLossOfGovernance         = "loss_of_governance"
	CategoryNewExposure              = "new_exposure"
	CategoryIdentityReuse            = "identity_reuse"
	CategoryPossibleLateralPath      = "possible_lateral_path"
	CategoryUnknownSecurityEffect    = "unknown_security_effect"
)

// Closed response vocabularies shared by the validator and the strict schema
// sent to the model, so the two cannot drift.
var (
	decisionValues    = []string{DecisionNoFinding, DecisionCandidateFinding, DecisionUnsupported}
	categoryValues    = []string{CategoryNewObservedCommunication, CategoryBoundaryCrossing, CategoryLossOfGovernance, CategoryNewExposure, CategoryIdentityReuse, CategoryPossibleLateralPath, CategoryUnknownSecurityEffect}
	severityValues    = []string{"none", "low", "medium", "high"}
	uncertaintyValues = []string{"low", "medium", "high"}
	claimModeValues   = []string{"observed", "configured", "inferred_by_model", "unknown"}
)

// Response is the strict structured output requested from the model.
type Response struct {
	Assessment Assessment `json:"assessment"`
}

// Assessment is the model's classification of one packet. Every ID it cites
// must have been supplied in the effective packet; see [Validate].
type Assessment struct {
	Decision               string                   `json:"decision"`
	Category               string                   `json:"category"`
	Severity               string                   `json:"severity"`
	ModelUncertainty       string                   `json:"modelUncertainty"`
	Summary                string                   `json:"summary"`
	AffectedEntityIDs      []string                 `json:"affectedEntityIds"`
	Claims                 []Claim                  `json:"claims"`
	Uncertainties          []string                 `json:"uncertainties"`
	SignalIDs              []string                 `json:"signalIds"`
	RemediationSuggestions []remediation.Suggestion `json:"remediationSuggestions"`
}

// Claim is one statement in an assessment. Mode records whether the model
// presents it as observed, configured, or its own inference; SupportingIDs
// must reference signals, facts, or evidence handles from the packet.
type Claim struct {
	Mode          string   `json:"mode"`
	Text          string   `json:"text"`
	SupportingIDs []string `json:"supportingIds"`
}

// DropInvalidRemediations removes remediation suggestions that would make an
// otherwise valid response invalid, keeping the rest in order. Suggestions are
// tried one at a time against the accumulated set, so a duplicate or
// ungrounded suggestion is dropped without discarding the finding. If the
// response is invalid even without suggestions, it is returned with none.
func DropInvalidRemediations(packet Packet, response Response) Response {
	suggestions := response.Assessment.RemediationSuggestions
	response.Assessment.RemediationSuggestions = nil
	if len(suggestions) == 0 || Validate(packet, response) != nil {
		return response
	}
	for _, suggestion := range suggestions {
		candidate := response
		candidate.Assessment.RemediationSuggestions = append(append([]remediation.Suggestion(nil), response.Assessment.RemediationSuggestions...), suggestion)
		if Validate(packet, candidate) == nil {
			response = candidate
		}
	}
	return response
}

// Validate applies the grounded validation required for promotion: in
// addition to [ValidateClassification], every candidate claim must cite at
// least one returned fact, and every fact it cites must be accompanied by one
// of that fact's own evidence handles. Signals alone and resource attributes
// alone cannot ground a candidate.
//
// Remediation suggestions are checked in both modes: each must target one
// supplied, affected entity, be unique per (intent, target), and share an
// eligible selected signal, a fact implicating the target, and that fact's
// evidence with one candidate claim.
func Validate(packet Packet, response Response) error {
	return validate(packet, response, true)
}

// ValidateClassification verifies that a model response uses the closed
// vocabularies, stays within response bounds, and references only IDs supplied
// in packet. A candidate claim must cite a signal the assessment selected.
// It is the check that triggers the single repair turn; promotion applies the
// stricter grounding in [Validate].
func ValidateClassification(packet Packet, response Response) error {
	return validate(packet, response, false)
}

// validate checks a response in phases, cheapest first: the closed
// vocabularies and bounds, the IDs it references, its remediation
// suggestions, its claims, and finally the candidate's completeness.
func validate(packet Packet, response Response, requireGrounding bool) error {
	assessment := response.Assessment
	if err := validateVocabulary(assessment); err != nil {
		return err
	}
	index := newValidationIndex(packet)
	if err := index.validateReferences(assessment); err != nil {
		return err
	}
	if err := index.validateRemediations(assessment); err != nil {
		return err
	}
	if err := index.validateClaims(assessment, requireGrounding); err != nil {
		return err
	}
	for _, suggestion := range assessment.RemediationSuggestions {
		if len(qualifyingSuggestionEvidence(packet, assessment, suggestion)) == 0 {
			return errors.New("remediation suggestion must share an eligible selected signal, target fact, and linked evidence with one candidate claim")
		}
	}
	if assessment.Decision == DecisionCandidateFinding && len(assessment.Claims) == 0 {
		return errors.New("candidate finding has no claims")
	}
	if assessment.Decision == DecisionCandidateFinding && len(assessment.SignalIDs) == 0 {
		return errors.New("candidate finding has no investigation signal")
	}
	return nil
}

// validateVocabulary checks the closed vocabularies and response bounds.
func validateVocabulary(assessment Assessment) error {
	if !oneOf(assessment.Decision, decisionValues...) {
		return fmt.Errorf("unknown decision %q", assessment.Decision)
	}
	if !oneOf(assessment.Category, categoryValues...) {
		return fmt.Errorf("unknown category %q", assessment.Category)
	}
	if !oneOf(assessment.Severity, severityValues...) {
		return fmt.Errorf("unknown severity %q", assessment.Severity)
	}
	if !oneOf(assessment.ModelUncertainty, uncertaintyValues...) {
		return fmt.Errorf("unknown model uncertainty %q", assessment.ModelUncertainty)
	}
	if len(assessment.Summary) > 4000 || len(assessment.AffectedEntityIDs) > 100 || len(assessment.Claims) > 100 || len(assessment.Uncertainties) > 100 || len(assessment.SignalIDs) > 100 {
		return errors.New("assessment exceeds response bounds")
	}
	return nil
}

// validationIndex is what a packet supplies for a response to cite.
type validationIndex struct {
	packet          Packet
	entities        map[string]Resource
	supportingIDs   map[string]struct{}
	facts           []factBinding
	factEvidenceIDs map[string]map[string]struct{}
	signals         map[string]detector.InvestigationSignal
}

func newValidationIndex(packet Packet) validationIndex {
	index := validationIndex{
		packet: packet, entities: make(map[string]Resource, len(packet.Resources)), supportingIDs: make(map[string]struct{}),
		facts: factBindings(packet), signals: make(map[string]detector.InvestigationSignal, len(packet.Signals)),
	}
	for _, resource := range packet.Resources {
		index.entities[resource.ID] = resource
	}
	index.factEvidenceIDs = make(map[string]map[string]struct{}, len(index.facts))
	for _, fact := range index.facts {
		evidence := make([]string, 0, len(fact.evidenceIDs))
		for evidenceID := range fact.evidenceIDs {
			evidence = append(evidence, evidenceID)
		}
		addSupportingIDs(index.supportingIDs, fact.id, evidence)
		index.factEvidenceIDs[fact.id] = fact.evidenceIDs
	}
	for _, signal := range packet.Signals {
		index.signals[signal.ID] = signal
		index.supportingIDs[signal.ID] = struct{}{}
	}
	return index
}

// validateReferences checks that affected entities and selected signals were supplied.
func (index validationIndex) validateReferences(assessment Assessment) error {
	for _, entityID := range assessment.AffectedEntityIDs {
		if _, ok := index.entities[entityID]; !ok {
			return fmt.Errorf("affected entity %q was not supplied", entityID)
		}
	}
	for _, signalID := range assessment.SignalIDs {
		if _, ok := index.signals[signalID]; !ok {
			return fmt.Errorf("investigation signal %q was not supplied", signalID)
		}
	}
	return nil
}

// validateRemediations checks each suggestion on its own: closed intent,
// unique per target, an affected and supplied target, supplied support, an
// eligible signal, and a fact with linked evidence implicating the target.
func (index validationIndex) validateRemediations(assessment Assessment) error {
	if len(assessment.RemediationSuggestions) > remediation.MaxSuggestions {
		return fmt.Errorf("assessment contains more than %d remediation suggestions", remediation.MaxSuggestions)
	}
	if len(assessment.RemediationSuggestions) > 0 && assessment.Decision != DecisionCandidateFinding {
		return errors.New("only a candidate finding may contain a remediation suggestion")
	}
	remediationChoices := make(map[string]struct{}, len(assessment.RemediationSuggestions))
	for _, suggestion := range assessment.RemediationSuggestions {
		if err := suggestion.Validate(); err != nil {
			return err
		}
		choice := string(suggestion.Intent) + "\x00" + suggestion.TargetEntityIDs[0]
		if _, duplicate := remediationChoices[choice]; duplicate {
			return errors.New("assessment contains a duplicate remediation outcome for one target")
		}
		remediationChoices[choice] = struct{}{}
		if _, found := index.entities[suggestion.TargetEntityIDs[0]]; !found {
			return fmt.Errorf("remediation target %q was not supplied", suggestion.TargetEntityIDs[0])
		}
		if _, affected := idSet(assessment.AffectedEntityIDs)[suggestion.TargetEntityIDs[0]]; !affected {
			return errors.New("remediation target must be an affected entity")
		}
		for _, supportingID := range suggestion.SupportingIDs {
			if _, found := index.supportingIDs[supportingID]; !found {
				return fmt.Errorf("remediation support %q was not supplied", supportingID)
			}
		}
		references := idSet(suggestion.SupportingIDs)
		eligibleSignal := false
		for _, signal := range index.packet.Signals {
			if signal.Risk.Rank() >= detector.RiskMedium.Rank() {
				_, eligibleSignal = references[signal.ID]
				if eligibleSignal {
					break
				}
			}
		}
		if !eligibleSignal {
			return errors.New("remediation suggestion must cite an eligible selected signal")
		}
		targetID := suggestion.TargetEntityIDs[0]
		implicated := false
		for _, fact := range index.facts {
			if _, cited := references[fact.id]; !cited || !fact.entities[targetID] || !setsIntersect(references, fact.evidenceIDs) {
				continue
			}
			implicated = true
			break
		}
		if !implicated {
			return errors.New("remediation suggestion must cite a fact and linked evidence implicating its target")
		}
	}
	return nil
}

// validateClaims checks each claim's mode, bounds, and references. A
// candidate claim must cite a selected signal and, with requireGrounding, at
// least one supplied fact together with that fact's own evidence.
func (index validationIndex) validateClaims(assessment Assessment, requireGrounding bool) error {
	selectedSignals := idSet(assessment.SignalIDs)
	for _, claim := range assessment.Claims {
		if !oneOf(claim.Mode, claimModeValues...) {
			return fmt.Errorf("unknown claim mode %q", claim.Mode)
		}
		if len(claim.Text) > 4000 || len(claim.SupportingIDs) > remediation.MaxSupportingIDs {
			return errors.New("claim exceeds response bounds")
		}
		if len(claim.SupportingIDs) == 0 && assessment.Decision == DecisionCandidateFinding {
			return errors.New("candidate claim has no supporting references")
		}
		claimReferences := idSet(claim.SupportingIDs)
		if len(claimReferences) != len(claim.SupportingIDs) {
			return errors.New("claim contains duplicate supporting IDs")
		}
		for _, supportingID := range claim.SupportingIDs {
			if _, ok := index.supportingIDs[supportingID]; !ok {
				return fmt.Errorf("claim reference %q was not supplied", supportingID)
			}
		}
		if assessment.Decision != DecisionCandidateFinding {
			continue
		}
		if !setsIntersect(claimReferences, selectedSignals) {
			return errors.New("candidate claim must cite an investigation signal selected by the assessment")
		}
		if !requireGrounding {
			continue
		}
		citedFact := false
		for factID, evidenceIDs := range index.factEvidenceIDs {
			if _, cited := claimReferences[factID]; !cited {
				continue
			}
			citedFact = true
			if !setsIntersect(claimReferences, evidenceIDs) {
				return fmt.Errorf("candidate claim fact %q has no linked evidence reference", factID)
			}
		}
		if !citedFact {
			return errors.New("candidate claim must cite at least one returned fact")
		}
	}
	return nil
}

// qualifyingSuggestionEvidence returns the evidence handles that a suggestion
// and at least one candidate claim both cite for a fact implicating the
// suggestion's target, where that claim also cites an eligible selected signal
// the suggestion cites. An empty result means the suggestion is not grounded.
func qualifyingSuggestionEvidence(packet Packet, assessment Assessment, suggestion remediation.Suggestion) []string {
	targetID := suggestion.TargetEntityIDs[0]
	suggestionReferences := idSet(suggestion.SupportingIDs)
	selectedEligibleSignals := make(map[string]struct{})
	selectedSignals := idSet(assessment.SignalIDs)
	for _, signal := range packet.Signals {
		if signal.Risk.Rank() < detector.RiskMedium.Rank() {
			continue
		}
		if _, selected := selectedSignals[signal.ID]; !selected {
			continue
		}
		if _, cited := suggestionReferences[signal.ID]; cited {
			selectedEligibleSignals[signal.ID] = struct{}{}
		}
	}
	if len(selectedEligibleSignals) == 0 {
		return nil
	}
	evidence := make(map[string]struct{})
	for _, claim := range assessment.Claims {
		claimReferences := idSet(claim.SupportingIDs)
		if !setsIntersect(claimReferences, selectedEligibleSignals) {
			continue
		}
		for _, fact := range factBindings(packet) {
			if !fact.entities[targetID] {
				continue
			}
			if _, claimCitesFact := claimReferences[fact.id]; !claimCitesFact {
				continue
			}
			if _, suggestionCitesFact := suggestionReferences[fact.id]; !suggestionCitesFact {
				continue
			}
			for evidenceID := range fact.evidenceIDs {
				_, claimCitesEvidence := claimReferences[evidenceID]
				_, suggestionCitesEvidence := suggestionReferences[evidenceID]
				if claimCitesEvidence && suggestionCitesEvidence {
					evidence[evidenceID] = struct{}{}
				}
			}
		}
	}
	result := make([]string, 0, len(evidence))
	for evidenceID := range evidence {
		result = append(result, evidenceID)
	}
	return result
}

// factBinding is a citable fact in a packet with the entities it implicates
// and the evidence handles that may accompany a citation of it.
type factBinding struct {
	id          string
	entities    map[string]bool
	evidenceIDs map[string]struct{}
}

func factBindings(packet Packet) []factBinding {
	result := make([]factBinding, 0, len(packet.Relationships)+len(packet.Facets)+len(packet.Telemetry)+len(packet.IncidentEvents)+len(packet.Baselines))
	for _, relationship := range packet.Relationships {
		result = append(result, factBinding{id: relationship.ID, entities: map[string]bool{relationship.SubjectID: true, relationship.ObjectID: true}, evidenceIDs: idSet(relationship.EvidenceIDs)})
	}
	for _, facet := range packet.Facets {
		result = append(result, factBinding{id: facet.ID, entities: map[string]bool{facet.ResourceID: true}, evidenceIDs: idSet(facet.EvidenceIDs)})
	}
	for _, telemetry := range packet.Telemetry {
		result = append(result, factBinding{id: telemetry.ID, entities: map[string]bool{telemetry.SubjectID: true, telemetry.ObjectID: true}, evidenceIDs: idSet(telemetry.EvidenceIDs)})
	}
	for _, event := range packet.IncidentEvents {
		result = append(result, factBinding{id: event.ID, entities: map[string]bool{event.SubjectID: true, event.ObjectID: true}, evidenceIDs: idSet(event.EvidenceIDs)})
	}
	for _, baseline := range packet.Baselines {
		result = append(result, factBinding{id: baseline.ID, entities: map[string]bool{baseline.SubjectID: true, baseline.ObjectID: true}, evidenceIDs: map[string]struct{}{}})
	}
	return result
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func addSupportingIDs(result map[string]struct{}, factID string, evidenceIDs []string) {
	result[factID] = struct{}{}
	for _, evidenceID := range evidenceIDs {
		result[evidenceID] = struct{}{}
	}
}

func idSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func setsIntersect(left, right map[string]struct{}) bool {
	for value := range left {
		if _, ok := right[value]; ok {
			return true
		}
	}
	return false
}
