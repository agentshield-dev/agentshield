package remediation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// Intent is a closed vocabulary of desired security outcomes. It describes
// what should become true, not how a provider achieves it.
type Intent string

// Supported intents. Network and transport intents declare provider
// configuration; gateway.prevent-route-delivery is advisory-only.
const (
	IntentNetworkDeclareIngressIsolation Intent = "network.declare-ingress-isolation"
	IntentTransportRequireMutualTLS      Intent = "transport.require-mutual-tls"
	IntentGatewayPreventRouteDelivery    Intent = "gateway.prevent-route-delivery"
)

// Valid reports whether intent is in the supported vocabulary.
func (intent Intent) Valid() bool {
	switch intent {
	case IntentNetworkDeclareIngressIsolation, IntentTransportRequireMutualTLS, IntentGatewayPreventRouteDelivery:
		return true
	default:
		return false
	}
}

// Bounds on model-supplied remediation content.
const (
	MaxSupportingIDs = 100
	MaxSuggestions   = 8
)

// Suggestion is a model-proposed outcome for one target entity, grounded by
// SupportingIDs from the analyzed packet. It contains no provider payload.
type Suggestion struct {
	Intent          Intent   `json:"intent"`
	TargetEntityIDs []string `json:"targetEntityIds"`
	SupportingIDs   []string `json:"supportingIds"`
}

// Validate checks the suggestion's own shape: a supported intent, exactly one
// target, and 1-[MaxSupportingIDs] unique, non-empty supporting IDs. Grounding
// against the packet is checked by pkg/reasoning.
func (suggestion Suggestion) Validate() error {
	if !suggestion.Intent.Valid() {
		return fmt.Errorf("unsupported remediation intent %q", suggestion.Intent)
	}
	if len(suggestion.TargetEntityIDs) != 1 || strings.TrimSpace(suggestion.TargetEntityIDs[0]) == "" {
		return errors.New("remediation suggestion requires exactly one target entity")
	}
	if len(suggestion.SupportingIDs) == 0 {
		return errors.New("remediation suggestion requires supporting IDs")
	}
	if len(suggestion.SupportingIDs) > MaxSupportingIDs {
		return fmt.Errorf("remediation suggestion exceeds %d supporting IDs", MaxSupportingIDs)
	}
	seen := make(map[string]struct{}, len(suggestion.SupportingIDs))
	for _, supportingID := range suggestion.SupportingIDs {
		if strings.TrimSpace(supportingID) == "" {
			return errors.New("remediation suggestion contains an empty supporting ID")
		}
		if _, found := seen[supportingID]; found {
			return fmt.Errorf("remediation suggestion contains duplicate supporting ID %q", supportingID)
		}
		seen[supportingID] = struct{}{}
	}
	return nil
}

// Target is the canonical identity of the entity a proposal acts on. Providers
// match actions by kind, identity scheme, and authority.
type Target struct {
	EntityID string              `json:"entityId"`
	Identity graph.IdentityClaim `json:"identity"`
	Kind     string              `json:"kind"`
}

// Proposal is a host-hydrated, server-owned suggestion bound to its finding,
// analysis, graph digest, target, and evidence. The API never accepts a
// proposal from a client.
type Proposal struct {
	ID            string   `json:"id"`
	FindingID     string   `json:"findingId"`
	AnalysisID    string   `json:"analysisId"`
	GraphSHA256   string   `json:"graphSha256"`
	Intent        Intent   `json:"intent"`
	Target        Target   `json:"target"`
	SupportingIDs []string `json:"supportingIds"`
	EvidenceIDs   []string `json:"evidenceIds"`
}

// NewProposal canonicalizes supporting and evidence IDs and derives the
// proposal ID from content. evidenceIDs must be a non-empty subset of the
// suggestion's supporting IDs.
func NewProposal(findingID, analysisID, graphSHA256 string, suggestion Suggestion, target Target, evidenceIDs []string) (Proposal, error) {
	if err := suggestion.Validate(); err != nil {
		return Proposal{}, err
	}
	if target.EntityID != suggestion.TargetEntityIDs[0] {
		return Proposal{}, errors.New("remediation proposal target does not match the suggestion")
	}
	supportingIDs := canonicalStrings(suggestion.SupportingIDs)
	evidenceIDs = canonicalStrings(evidenceIDs)
	proposal := Proposal{
		FindingID: findingID, AnalysisID: analysisID, GraphSHA256: graphSHA256,
		Intent: suggestion.Intent, Target: target, SupportingIDs: supportingIDs, EvidenceIDs: evidenceIDs,
	}
	proposal.ID = canonicalID("proposal", proposal)
	if err := proposal.Validate(); err != nil {
		return Proposal{}, err
	}
	return proposal, nil
}

// Validate checks that the proposal is canonical and that its ID matches its
// content, so a modified proposal is rejected everywhere it is used.
func (proposal Proposal) Validate() error {
	if strings.TrimSpace(proposal.FindingID) == "" || strings.TrimSpace(proposal.AnalysisID) == "" {
		return errors.New("remediation proposal requires finding and analysis IDs")
	}
	if len(proposal.GraphSHA256) != sha256.Size*2 || strings.ToLower(proposal.GraphSHA256) != proposal.GraphSHA256 {
		return errors.New("remediation proposal requires a canonical graph SHA-256")
	}
	if _, err := hex.DecodeString(proposal.GraphSHA256); err != nil {
		return errors.New("remediation proposal requires a canonical graph SHA-256")
	}
	if !proposal.Intent.Valid() {
		return fmt.Errorf("unsupported remediation intent %q", proposal.Intent)
	}
	if strings.TrimSpace(proposal.Target.EntityID) == "" || strings.TrimSpace(proposal.Target.EntityID) != proposal.Target.EntityID || strings.TrimSpace(proposal.Target.Kind) == "" {
		return errors.New("remediation proposal requires a target entity and kind")
	}
	identity := proposal.Target.Identity
	identityValues := []string{identity.Scheme.Group, identity.Scheme.Version, identity.Scheme.Kind, identity.AuthorityID, identity.ImmutableKey}
	for _, value := range identityValues {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value {
			return errors.New("remediation proposal requires a canonical target identity")
		}
	}
	if err := validateCanonicalIDs("supporting", proposal.SupportingIDs, true); err != nil {
		return err
	}
	if len(proposal.SupportingIDs) > MaxSupportingIDs {
		return fmt.Errorf("remediation proposal exceeds %d supporting IDs", MaxSupportingIDs)
	}
	if err := validateCanonicalIDs("evidence", proposal.EvidenceIDs, true); err != nil {
		return err
	}
	if !containsAll(proposal.SupportingIDs, proposal.EvidenceIDs) {
		return errors.New("remediation proposal evidence must be a nonempty subset of supporting IDs")
	}
	actual := proposal.ID
	proposal.ID = ""
	if actual == "" || actual != canonicalID("proposal", proposal) {
		return errors.New("remediation proposal ID does not match its canonical content")
	}
	return nil
}

func (proposal Proposal) validateID() error {
	return proposal.Validate()
}

func validateCanonicalIDs(name string, values []string, required bool) error {
	if required && len(values) == 0 {
		return fmt.Errorf("remediation proposal requires %s IDs", name)
	}
	for index, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("remediation proposal contains an empty %s ID", name)
		}
		if index > 0 && values[index-1] >= value {
			return fmt.Errorf("remediation proposal %s IDs are not canonical", name)
		}
	}
	return nil
}

// Mode says whether an action can change provider state.
type Mode string

// Action modes. Advisory-only actions can be planned but never prepared,
// executed, or verified.
const (
	ModeExecutable   Mode = "executable"
	ModeAdvisoryOnly Mode = "advisory-only"
)

// Valid reports whether mode is known.
func (mode Mode) Valid() bool {
	return mode == ModeExecutable || mode == ModeAdvisoryOnly
}

// Plan is a provider's deterministic answer for one proposal and selected
// action: DesiredSHA256 digests the content it would declare. ID is a content
// digest and is the value a user approves.
type Plan struct {
	ID            string `json:"id"`
	ProposalID    string `json:"proposalId"`
	ProviderID    string `json:"providerId"`
	SourceID      string `json:"sourceId"`
	ActionID      string `json:"actionId"`
	Mode          Mode   `json:"mode"`
	GraphSHA256   string `json:"graphSha256"`
	DesiredSHA256 string `json:"desiredSha256"`
	Advisory      string `json:"advisory,omitempty"`
}

// NewPlan returns an executable plan for proposal.
func NewPlan(proposal Proposal, providerID, sourceID, actionID, desiredSHA256 string) (Plan, error) {
	return newPlan(proposal, providerID, sourceID, actionID, ModeExecutable, desiredSHA256, "")
}

// NewAdvisoryPlan returns an advisory-only plan whose desired-state digest
// covers the advisory text.
func NewAdvisoryPlan(proposal Proposal, providerID, sourceID, actionID, advisory string) (Plan, error) {
	if strings.TrimSpace(advisory) == "" {
		return Plan{}, errors.New("advisory remediation plan requires explanatory output")
	}
	return newPlan(proposal, providerID, sourceID, actionID, ModeAdvisoryOnly, canonicalID("advisory", advisory), advisory)
}

func newPlan(proposal Proposal, providerID, sourceID, actionID string, mode Mode, desiredSHA256, advisory string) (Plan, error) {
	if err := proposal.validateID(); err != nil {
		return Plan{}, err
	}
	if providerID == "" || sourceID == "" || actionID == "" || !mode.Valid() || desiredSHA256 == "" {
		return Plan{}, errors.New("remediation plan requires proposal, provider, source, action, and desired-state IDs")
	}
	plan := Plan{ProposalID: proposal.ID, ProviderID: providerID, SourceID: sourceID, ActionID: actionID, Mode: mode, GraphSHA256: proposal.GraphSHA256, DesiredSHA256: desiredSHA256, Advisory: advisory}
	plan.ID = canonicalID("plan", plan)
	return plan, nil
}

func (plan Plan) validateID() error {
	actual := plan.ID
	plan.ID = ""
	if actual == "" || actual != canonicalID("plan", plan) {
		return errors.New("remediation plan ID does not match its canonical content")
	}
	return nil
}

// Bounds on provider-owned state carried by preparations and results.
const (
	MaxProviderStateEntries = 16
	MaxProviderStateBytes   = 256 * 1024
	MaxProviderStateValue   = 64 * 1024
	MaxProviderStateKey     = 128
)

// Preparation is a provider's pre-execution check of a plan. ProviderState
// holds the bounded, canonically encoded observations execution will compare
// against. Only a successful preparation can be executed.
type Preparation struct {
	ID            string          `json:"id"`
	PlanID        string          `json:"planId"`
	ProposalID    string          `json:"proposalId"`
	ProviderID    string          `json:"providerId"`
	SourceID      string          `json:"sourceId"`
	ActionID      string          `json:"actionId"`
	GraphSHA256   string          `json:"graphSha256"`
	Successful    bool            `json:"successful"`
	ProviderState []ProviderState `json:"providerState,omitempty"`
}

// NewPreparation canonicalizes providerState and derives the preparation ID.
func NewPreparation(plan Plan, successful bool, providerState []ProviderState) (Preparation, error) {
	if err := plan.validateID(); err != nil {
		return Preparation{}, err
	}
	providerState, err := canonicalProviderState(providerState)
	if err != nil {
		return Preparation{}, err
	}
	preparation := Preparation{
		PlanID: plan.ID, ProposalID: plan.ProposalID, ProviderID: plan.ProviderID, SourceID: plan.SourceID, ActionID: plan.ActionID,
		GraphSHA256: plan.GraphSHA256, Successful: successful,
		ProviderState: providerState,
	}
	preparation.ID = canonicalID("preparation", preparation)
	return preparation, nil
}

func (preparation Preparation) validateID() error {
	if _, err := canonicalProviderState(preparation.ProviderState); err != nil {
		return err
	}
	actual := preparation.ID
	preparation.ID = ""
	if actual == "" || actual != canonicalID("preparation", preparation) {
		return errors.New("remediation preparation ID does not match its canonical content")
	}
	return nil
}

// ProviderState is one provider-owned observation. Current is what the
// provider read; Prepared is what it validated for writing. Values must be
// canonical JSON so content-derived IDs are stable.
type ProviderState struct {
	Key      string          `json:"key"`
	Current  json.RawMessage `json:"current,omitempty"`
	Prepared json.RawMessage `json:"prepared,omitempty"`
}

// ExecutionResult records the outcome of executing one prepared plan.
type ExecutionResult struct {
	ID            string          `json:"id"`
	PlanID        string          `json:"planId"`
	ProposalID    string          `json:"proposalId"`
	ProviderID    string          `json:"providerId"`
	SourceID      string          `json:"sourceId"`
	ActionID      string          `json:"actionId"`
	PreparationID string          `json:"preparationId"`
	Successful    bool            `json:"successful"`
	ProviderState []ProviderState `json:"providerState,omitempty"`
}

// NewExecutionResult validates that preparation belongs to plan and derives
// the result ID.
func NewExecutionResult(plan Plan, preparation Preparation, successful bool, providerState []ProviderState) (ExecutionResult, error) {
	if err := plan.validateID(); err != nil {
		return ExecutionResult{}, err
	}
	if err := preparation.validateID(); err != nil || preparation.PlanID != plan.ID {
		return ExecutionResult{}, errors.New("remediation execution result requires a matching preparation")
	}
	providerState, err := canonicalProviderState(providerState)
	if err != nil {
		return ExecutionResult{}, err
	}
	result := ExecutionResult{
		PlanID: plan.ID, ProposalID: plan.ProposalID, ProviderID: plan.ProviderID, SourceID: plan.SourceID, ActionID: plan.ActionID,
		PreparationID: preparation.ID, Successful: successful, ProviderState: providerState,
	}
	result.ID = canonicalID("execution-result", result)
	return result, nil
}

func (result ExecutionResult) validateID() error {
	if _, err := canonicalProviderState(result.ProviderState); err != nil {
		return err
	}
	actual := result.ID
	result.ID = ""
	if actual == "" || actual != canonicalID("execution-result", result) {
		return errors.New("remediation execution result ID does not match its canonical content")
	}
	return nil
}

// Verification reports whether the provider declaration recorded by an
// execution is still present. Satisfied does not prove effective enforcement.
type Verification struct {
	PlanID            string `json:"planId"`
	ProviderID        string `json:"providerId"`
	SourceID          string `json:"sourceId"`
	ActionID          string `json:"actionId"`
	ExecutionResultID string `json:"executionResultId"`
	Satisfied         bool   `json:"satisfied"`
}

func canonicalProviderState(values []ProviderState) ([]ProviderState, error) {
	if len(values) > MaxProviderStateEntries {
		return nil, fmt.Errorf("remediation provider state exceeds %d entries", MaxProviderStateEntries)
	}
	result := slices.Clone(values)
	slices.SortFunc(result, func(left, right ProviderState) int { return stringsCompare(left.Key, right.Key) })
	total := 0
	for index := range result {
		state := &result[index]
		if state.Key == "" || strings.TrimSpace(state.Key) != state.Key || len(state.Key) > MaxProviderStateKey {
			return nil, errors.New("remediation provider state requires a bounded canonical key")
		}
		if index > 0 && result[index-1].Key == state.Key {
			return nil, fmt.Errorf("remediation provider state contains duplicate key %q", state.Key)
		}
		for _, value := range []*json.RawMessage{&state.Current, &state.Prepared} {
			if len(*value) == 0 {
				continue
			}
			if len(*value) > MaxProviderStateValue || !json.Valid(*value) {
				return nil, fmt.Errorf("remediation provider state %q contains invalid or oversized JSON", state.Key)
			}
			var decoded any
			if err := json.Unmarshal(*value, &decoded); err != nil {
				return nil, fmt.Errorf("decode remediation provider state %q: %w", state.Key, err)
			}
			canonical, err := json.Marshal(decoded)
			if err != nil || !bytes.Equal(canonical, *value) {
				return nil, fmt.Errorf("remediation provider state %q is not canonically encoded", state.Key)
			}
			*value = slices.Clone(*value)
			total += len(*value)
		}
	}
	if total > MaxProviderStateBytes {
		return nil, fmt.Errorf("remediation provider state exceeds %d bytes", MaxProviderStateBytes)
	}
	return result, nil
}

func canonicalID(kind string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(encoded)
	return kind + ":sha256:" + hex.EncodeToString(digest[:])
}

func canonicalStrings(values []string) []string {
	result := slices.Clone(values)
	slices.Sort(result)
	return slices.Compact(result)
}

func containsAll(values, required []string) bool {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	for _, value := range required {
		if _, found := set[value]; !found {
			return false
		}
	}
	return true
}
