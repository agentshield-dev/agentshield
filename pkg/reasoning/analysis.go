package reasoning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// AnalysisConfig selects how one analysis is run. Compact sends only resources
// touched by the changes or anchored by signals in the initial request and
// leaves the rest to MCP retrieval.
type AnalysisConfig struct {
	Name          string `json:"name"`
	Compact       bool   `json:"compact"`
	RetrievalMode string `json:"retrievalMode,omitempty"`
}

// Retrieval modes. In model-selected mode the model chooses every MCP call. In
// deterministic mode the host first retrieves the behavior baseline, incident
// timeline, default graph path, and governance posture for the signal anchors,
// and the model may still call more tools.
const (
	RetrievalModelSelected = "model_selected"
	RetrievalDeterministic = "deterministic"
)

// Validation outcomes recorded on [AnalysisOutcome]. These values are
// persisted; do not rename them.
const (
	// ValidationNotApplicable means no model request was made.
	ValidationNotApplicable = "not_applicable"
	// ValidationAccepted means the final response passed classification
	// validation; promotion may still reject it.
	ValidationAccepted = "accepted"
	// ValidationRejected means the response was invalid after the repair turn
	// or relied on truncated context.
	ValidationRejected = "rejected"
)

// AnalysisOutcome is the auditable record of one analysis. InitialPacket is
// what the model first received; EffectivePacket adds every retrieved context
// result and is the packet validation and promotion are judged against.
type AnalysisOutcome struct {
	Config          AnalysisConfig  `json:"config"`
	Validation      string          `json:"validation"`
	ValidationError string          `json:"validationError,omitempty"`
	ModelResults    []ModelResult   `json:"-"`
	Retrievals      []ContextResult `json:"retrievals,omitempty"`
	InitialPacket   Packet          `json:"-"`
	EffectivePacket Packet          `json:"-"`
	Response        Response        `json:"response"`
	Promotion       Promotion       `json:"promotion"`
}

// AnalyzeCandidate is [AnalyzeCandidateWithTools] without an MCP session. It
// only succeeds for packets that need no model request.
func AnalyzeCandidate(ctx context.Context, client Client, full Packet, config AnalysisConfig) (AnalysisOutcome, error) {
	return AnalyzeCandidateWithTools(ctx, client, full, config, nil)
}

// AnalyzeCandidateWithTools runs one investigation of full over session.
//
// Baseline and signal-free packets return [ValidationNotApplicable] without
// calling the model. Otherwise the model investigates until it returns a final
// response, and the outcome is decided in this order:
//
//  1. A candidate that relied on any truncated retrieval is rejected with
//     candidate_context_truncated. The model may infer absence of a control
//     only from an untruncated view, and the host cannot tell which claims
//     depended on the missing part.
//  2. A response that fails [ValidateClassification] gets exactly one
//     tool-free repair turn. The repair is limited to an allowlist of the
//     signal, fact, and evidence IDs in the effective packet (the initial
//     packet plus every MCP result), exactly the IDs validation accepts. The
//     repaired response is validated from scratch, and the truncation rule is
//     applied again.
//  3. A response that is still invalid is rejected with
//     candidate_validation_failed.
//  4. Otherwise validation is [ValidationAccepted] and [Promote] decides.
//
// Errors are returned only for transport, MCP, or decoding failures; policy
// rejections are recorded on the outcome.
func AnalyzeCandidateWithTools(ctx context.Context, client Client, full Packet, config AnalysisConfig, session *mcp.ClientSession) (AnalysisOutcome, error) {
	outcome := AnalysisOutcome{Config: config, InitialPacket: full, EffectivePacket: full}
	if full.Baseline || !hasReasoningSignal(full) {
		outcome.Validation = ValidationNotApplicable
		outcome.Promotion = Promote(full, Response{})
		return outcome, nil
	}
	initial := full
	if config.Compact {
		initial = CompactPacket(full)
	}
	outcome.InitialPacket = initial
	if session == nil {
		return AnalysisOutcome{}, errors.New("reasoning signal requires an MCP client session")
	}
	if config.RetrievalMode == "" {
		config.RetrievalMode = RetrievalModelSelected
		outcome.Config = config
	}
	if config.RetrievalMode != RetrievalModelSelected && config.RetrievalMode != RetrievalDeterministic {
		return AnalysisOutcome{}, errors.New("unsupported retrieval mode")
	}
	var prefetched []ContextResult
	var err error
	if config.RetrievalMode == RetrievalDeterministic {
		initial, prefetched, err = deterministicIncidentContext(ctx, session, initial)
		if err != nil {
			return AnalysisOutcome{}, err
		}
		outcome.InitialPacket = initial
	}
	investigation, err := client.Investigate(ctx, initial, session)
	if err != nil {
		return AnalysisOutcome{}, err
	}
	outcome.ModelResults = investigation.ModelResults
	outcome.Response = DropInvalidRemediations(investigation.EffectivePacket, investigation.Response)
	outcome.Retrievals = append(prefetched, investigation.ContextResults...)
	outcome.EffectivePacket = investigation.EffectivePacket
	if outcome.Response.Assessment.Decision == DecisionCandidateFinding && hasTruncatedContext(outcome.Retrievals) {
		outcome.Validation = ValidationRejected
		outcome.ValidationError = "candidate finding relies on truncated MCP context"
		outcome.Promotion = Promotion{Status: PromotionRejected, Reason: ReasonCandidateContextTruncated}
		return outcome, nil
	}
	validationMessage, invalid := validationFailure(outcome.EffectivePacket, outcome.Response)
	if invalid {
		repaired, err := client.Repair(ctx, outcome.EffectivePacket, outcome.Response, validationMessage, claimReferenceIDs(outcome.EffectivePacket))
		if err != nil {
			return AnalysisOutcome{}, err
		}
		outcome.ModelResults = append(outcome.ModelResults, repaired)
		outcome.Response = DropInvalidRemediations(outcome.EffectivePacket, repaired.Response)
		if outcome.Response.Assessment.Decision == DecisionCandidateFinding && hasTruncatedContext(outcome.Retrievals) {
			outcome.Validation = ValidationRejected
			outcome.ValidationError = "candidate finding relies on truncated MCP context"
			outcome.Promotion = Promotion{Status: PromotionRejected, Reason: ReasonCandidateContextTruncated}
			return outcome, nil
		}
		validationMessage, invalid = validationFailure(outcome.EffectivePacket, outcome.Response)
		if invalid {
			outcome.Validation = ValidationRejected
			outcome.ValidationError = validationMessage
			outcome.Promotion = Promotion{Status: PromotionRejected, Reason: ReasonCandidateValidationFailed}
			return outcome, nil
		}
	}
	outcome.Validation = ValidationAccepted
	outcome.Promotion = Promote(outcome.EffectivePacket, outcome.Response)
	return outcome, nil
}

// claimReferenceIDs is the repair allowlist: the signal IDs and the fact and
// evidence IDs of the effective packet. These are the IDs [Validate] accepts;
// facts in the initial packet come from the same pinned checkpoint as tool
// results, so they ground a claim the same way.
func claimReferenceIDs(packet Packet) []string {
	ids := make(map[string]struct{})
	for _, signal := range packet.Signals {
		ids[signal.ID] = struct{}{}
	}
	for _, fact := range factBindings(packet) {
		ids[fact.id] = struct{}{}
		for evidenceID := range fact.evidenceIDs {
			ids[evidenceID] = struct{}{}
		}
	}
	delete(ids, "")
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	return ordered
}

func hasReasoningSignal(packet Packet) bool {
	return len(packet.Signals) > 0
}

// deterministicIncidentContext prefetches context for deterministic retrieval.
// Resources reached by the graph-path query become governance anchors, so
// policy attached to adjacent resources is visible to the model.
func deterministicIncidentContext(ctx context.Context, session *mcp.ClientSession, packet Packet) (Packet, []ContextResult, error) {
	anchors := packet.SuggestedContextAnchors
	if len(anchors) == 0 {
		for _, signal := range packet.Signals {
			anchors = append(anchors, signal.AnchorIDs...)
		}
		sort.Strings(anchors)
		anchors = slices.Compact(anchors)
	}
	result := packet
	var retrievals []ContextResult
	for _, tool := range []string{"get_behavior_baseline", "get_incident_timeline", "find_graph_paths"} {
		contextResult, err := callContextTool(ctx, session, tool, anchors)
		if err != nil {
			return Packet{}, nil, err
		}
		retrievals = append(retrievals, contextResult)
		result = MergeContext(result, contextResult)
		if tool == "find_graph_paths" {
			for _, resource := range contextResult.Resources {
				anchors = append(anchors, resource.ID)
			}
			sort.Strings(anchors)
			anchors = slices.Compact(anchors)
		}
	}
	governance, err := callContextTool(ctx, session, "get_governance_posture", anchors)
	if err != nil {
		return Packet{}, nil, err
	}
	retrievals = append(retrievals, governance)
	result = MergeContext(result, governance)
	return result, retrievals, nil
}

func callContextTool(ctx context.Context, session *mcp.ClientSession, name string, anchorIDs []string) (ContextResult, error) {
	called, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{"anchorIds": anchorIDs}})
	if err != nil {
		return ContextResult{}, fmt.Errorf("call required MCP tool %s: %w", name, err)
	}
	if called.IsError {
		return ContextResult{}, fmt.Errorf("required MCP tool %s returned an error", name)
	}
	encoded, err := json.Marshal(called.StructuredContent)
	if err != nil {
		return ContextResult{}, err
	}
	var result ContextResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		return ContextResult{}, err
	}
	return result, nil
}

func hasTruncatedContext(results []ContextResult) bool {
	for _, result := range results {
		if result.Closure != ClosureUntruncated {
			return true
		}
	}
	return false
}

func validationFailure(packet Packet, response Response) (string, bool) {
	if err := ValidateClassification(packet, response); err != nil {
		return err.Error(), true
	}
	return "", false
}

// Usage sums token usage across every model turn, including the repair turn.
func (outcome AnalysisOutcome) Usage() Usage {
	var result Usage
	for _, modelResult := range outcome.ModelResults {
		result.PromptTokens += modelResult.Usage.PromptTokens
		result.CompletionTokens += modelResult.Usage.CompletionTokens
		result.ReasoningTokens += modelResult.Usage.ReasoningTokens
		result.TotalTokens += modelResult.Usage.TotalTokens
	}
	return result
}

// Latency returns total model latency across every turn, in milliseconds.
func (outcome AnalysisOutcome) Latency() int64 {
	var milliseconds int64
	for _, modelResult := range outcome.ModelResults {
		milliseconds += modelResult.Latency.Milliseconds()
	}
	return milliseconds
}
