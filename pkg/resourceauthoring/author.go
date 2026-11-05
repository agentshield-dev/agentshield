package resourceauthoring

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// authoringPrompt is the system prompt for rule drafting.
//
//go:embed authoring_prompt.txt
var authoringPrompt string

// maxDraftRules bounds one proposal; the tool budget leaves room to correct each rejected rule once.
const (
	maxDraftRules            = 3
	ModelAuthorInputMaxBytes = 96 << 10
)

// Host-owned rule metadata.
const (
	draftReason        = "resource_rule_match"
	draftWindowSeconds = 300
)

// Proposal is a validated, inactive rule draft for one resource. Rules holds
// at most three distinct rules, recorded through add_rule, and may be empty
// when no available field distinguishes the behavior of interest.
type Proposal struct {
	Rationale       string                         `json:"rationale"`
	Rules           []ProposalRule                 `json:"rules"`
	ApprovedRuleIDs []string                       `json:"approvedRuleIds,omitempty"`
	ToolCalls       []reasoning.StructuredToolCall `json:"toolCalls,omitempty"`
	Context         json.RawMessage                `json:"context,omitempty"`
	Attributes      map[string]string              `json:"attributes,omitempty"`
	// ObservedBehavior is the baseline the draft was written from, kept for review.
	ObservedBehavior *state.WorkloadBehavior `json:"observedBehavior,omitempty"`
}

// ProposalRule is a drafted rule with the model's rationale, including the
// false positives it expects.
type ProposalRule struct {
	Rule      detector.Rule `json:"rule"`
	Rationale string        `json:"rationale"`
}

type modelDraft struct {
	Rationale string      `json:"rationale"`
	Rules     []modelRule `json:"rules"`
}

type modelRule struct {
	Selector   string        `json:"selector"`
	Expression string        `json:"expression"`
	Risk       detector.Risk `json:"risk"`
	Rationale  string        `json:"rationale"`
}

// Author drafts rules for one resource authoring context.
type Author interface {
	Author(context.Context, state.ResourceAuthoringContext) (Proposal, error)
}

// ModelAuthor drafts rules with a model through Client's tool-only loop: the
// model records rules with add_rule and ends with finish. Each rule is compiled
// with the production detector when it is added.
type ModelAuthor struct {
	Client reasoning.Client
	// Logger receives Debug traces of add_rule calls and the run outcome; nil uses slog.Default().
	Logger *slog.Logger
	// Selectors, when set, are the only rule selectors offered to and accepted
	// from the model, such as the selectors this resource has producers for.
	// Empty offers every selector.
	Selectors []string
}

// selectors returns the selectors offered to the model, validated against the catalog.
func (author ModelAuthor) selectors(resource state.ResourceAuthoringContext) ([]string, error) {
	if len(author.Selectors) == 0 {
		resourceSelector := "resource:" + resource.Kind
		if !observedBehaviorKind(resource.Kind) {
			return []string{resourceSelector}, nil
		}
		return append(detector.CELSelectorNames(), resourceSelector), nil
	}
	for _, name := range author.Selectors {
		if _, _, ok := detector.ParseCELSelector(name); !ok {
			return nil, fmt.Errorf("unsupported authoring selector %q", name)
		}
	}
	return slices.Clone(author.Selectors), nil
}

// Author implements [Author].
func (author ModelAuthor) Author(ctx context.Context, resource state.ResourceAuthoringContext) (Proposal, error) {
	if err := ValidateContext(resource); err != nil {
		return Proposal{}, err
	}
	input, err := json.Marshal(struct {
		Kind             string                  `json:"kind"`
		Name             string                  `json:"name,omitempty"`
		Namespace        string                  `json:"namespace,omitempty"`
		Context          json.RawMessage         `json:"context"`
		Attributes       map[string]string       `json:"attributes,omitempty"`
		ObservedBehavior *state.WorkloadBehavior `json:"observedBehavior,omitempty"`
	}{resource.Kind, resource.Name, resource.Namespace, resource.Context, resource.Attributes, resource.ObservedBehavior})
	if err != nil {
		return Proposal{}, fmt.Errorf("encode authoring input: %w", err)
	}
	if len(input) > ModelAuthorInputMaxBytes {
		return Proposal{}, fmt.Errorf("authoring input exceeds %d bytes", ModelAuthorInputMaxBytes)
	}
	selectors, err := author.selectors(resource)
	if err != nil {
		return Proposal{}, err
	}
	logger := author.Logger
	if logger == nil {
		logger = slog.Default()
	}
	collector := &ruleCollector{resource: resource, selectors: selectors, logger: logger}
	output, err := author.Client.GenerateWithTools(ctx, authoringPrompt, input, []reasoning.StructuredTool{collector.addRuleTool(), finishTool()}, reasoning.StructuredToolLimits{
		MaxTurns: 2*maxDraftRules + 2, MaxCalls: 2 * maxDraftRules, MaxArgumentBytes: 2 * 1024, MaxResultBytes: 2 * 1024, MaxTotalResultBytes: 12 * 1024,
	})
	if err != nil {
		return Proposal{}, err
	}
	var final finishArguments
	if err := decodeStrict(output.FinalArguments, &final); err != nil {
		return Proposal{}, fmt.Errorf("decode resource rule draft: %w", err)
	}
	addRuleCalls := 0
	for _, call := range output.Calls {
		if call.Name == "add_rule" {
			addRuleCalls++
		}
	}
	logger.DebugContext(ctx, "model finished resource rule draft",
		"resource_id", resource.ResourceID, "tool_calls", len(output.Calls), "add_rule_calls", addRuleCalls, "accepted_rules", len(collector.rules))
	// Rules come only from accepted add_rule calls and are stored only after a successful finish.
	proposal, err := buildProposal(resource, modelDraft{Rationale: final.Rationale, Rules: collector.rules}, selectors)
	if err != nil {
		return Proposal{}, err
	}
	proposal.ToolCalls, proposal.Context, proposal.Attributes, proposal.ObservedBehavior = output.Calls, slices.Clone(resource.Context), maps.Clone(resource.Attributes), resource.ObservedBehavior
	return proposal, nil
}

// buildProposal applies host-owned scoping and metadata, then compiles the result with the production detector.
func buildProposal(resource state.ResourceAuthoringContext, draft modelDraft, selectors []string) (Proposal, error) {
	if len(draft.Rationale) > 2048 || len(draft.Rules) > maxDraftRules {
		return Proposal{}, fmt.Errorf("resource draft exceeds the rationale limit or %d rules", maxDraftRules)
	}
	proposal := Proposal{Rationale: draft.Rationale, Rules: []ProposalRule{}}
	ruleset := detector.Ruleset{ID: "resource-draft"}
	seen := make(map[[2]string]int, len(draft.Rules))
	for index, candidate := range draft.Rules {
		duplicate := [2]string{candidate.Selector, strings.TrimSpace(candidate.Expression)}
		if previous, found := seen[duplicate]; found {
			return Proposal{}, fmt.Errorf("draft rule %d repeats the selector and expression of rule %d", index, previous)
		}
		seen[duplicate] = index
		inputType, kind, ok := detector.ParseCELSelector(candidate.Selector)
		if !ok || !slices.Contains(selectors, candidate.Selector) {
			return Proposal{}, fmt.Errorf("draft rule %d has unsupported selector %q", index, candidate.Selector)
		}
		if candidate.Rationale == "" || len(candidate.Rationale) > 1024 {
			return Proposal{}, fmt.Errorf("draft rule %d requires a rationale of at most 1024 bytes", index)
		}
		rule := detector.Rule{
			Revision: 1, InputVersion: detector.InputVersion,
			PluginID: "*", ScopeResourceID: resource.ResourceID, Type: inputType, Kind: kind, Expression: candidate.Expression,
			Risk: candidate.Risk, Reasons: []string{draftReason}, WindowSeconds: draftWindowSeconds,
		}
		var err error
		if rule.ID, err = ruleID(resource, rule); err != nil {
			return Proposal{}, fmt.Errorf("identify draft rule %d: %w", index, err)
		}
		ruleset.Rules = append(ruleset.Rules, rule)
		proposal.Rules = append(proposal.Rules, ProposalRule{Rule: rule, Rationale: candidate.Rationale})
	}
	if err := detector.ValidateRuleset(ruleset); err != nil {
		return Proposal{}, fmt.Errorf("validate resource rule draft: %w", err)
	}
	return proposal, nil
}

// ruleID scopes a draft rule to its resource authoring context revision. Its
// behavior digest keeps identity stable when a proposal reorders its rules.
func ruleID(resource state.ResourceAuthoringContext, rule detector.Rule) (string, error) {
	prefix := strings.TrimPrefix(resource.Kind, "kubernetes/")
	resourceDigest := sha256.Sum256([]byte(resource.ResourceID))
	rule.ID, rule.Revision, rule.Expression = "", 0, strings.TrimSpace(rule.Expression)
	encoded, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}
	ruleDigest := sha256.Sum256(encoded)
	id := fmt.Sprintf("%s/%x/v-%s/r-%x", prefix, resourceDigest[:16], resource.ContextSHA256[:12], ruleDigest[:])
	if len(id) > 128 {
		id = fmt.Sprintf("%s/%x/v-%s/r-%x", prefix, resourceDigest[:16], resource.ContextSHA256[:12], ruleDigest[:24])
	}
	if len(id) > 128 {
		kindDigest := sha256.Sum256([]byte(resource.Kind))
		id = fmt.Sprintf("kind-%x/%x/v-%s/r-%x", kindDigest[:8], resourceDigest[:16], resource.ContextSHA256[:12], ruleDigest[:24])
	}
	return id, nil
}

// BaselineSource reads a resource's observed behavior from the current graph.
// *state.Store implements it.
type BaselineSource interface {
	WorkloadObservedBehavior(context.Context, string) (state.WorkloadBehavior, error)
}

// WithObservedBehavior returns resource with its observed behavior from source, the
// context the authoring worker sends to the model.
func WithObservedBehavior(ctx context.Context, source BaselineSource, resource state.ResourceAuthoringContext) (state.ResourceAuthoringContext, error) {
	if !observedBehaviorKind(resource.Kind) {
		return resource, nil
	}
	behavior, err := source.WorkloadObservedBehavior(ctx, resource.ResourceID)
	if err != nil {
		return state.ResourceAuthoringContext{}, err
	}
	resource.ObservedBehavior = &behavior
	return resource, nil
}

// ValidateContext checks the bounded resource authoring context before it is sent to a model.
func ValidateContext(resource state.ResourceAuthoringContext) error {
	if resource.ResourceID == "" || len(resource.ResourceID) > 128 || resource.Kind == "" || len(resource.Kind) > 128 || !strings.Contains(resource.Kind, "/") {
		return errors.New("authoring context must identify a bounded resource")
	}
	if decoded, err := hex.DecodeString(resource.ContextSHA256); err != nil || len(decoded) != sha256.Size {
		return errors.New("authoring context revision must be a SHA-256")
	}
	if len(resource.Name) > 253 || len(resource.Namespace) > 253 {
		return errors.New("resource authoring context exceeds field limits")
	}
	var authoringContext map[string]any
	if len(resource.Context) == 0 || json.Unmarshal(resource.Context, &authoringContext) != nil || authoringContext == nil {
		return errors.New("resource authoring context must be a JSON object")
	}
	if len(resource.Attributes) > graph.ResourceAuthoringAttributesMaxItems {
		return errors.New("resource authoring attributes exceed the item limit")
	}
	for key, value := range resource.Attributes {
		if key == "" || len(key) > 128 || len(value) > 2048 {
			return errors.New("resource authoring attribute exceeds field limits")
		}
	}
	if behavior := resource.ObservedBehavior; behavior != nil {
		if len(behavior.Requests) > state.MaxObservedRequests || len(behavior.CollectedTelemetry) > state.MaxCollectedTelemetry {
			return errors.New("resource observed behavior exceeds the request or telemetry kind limit")
		}
		for _, kind := range behavior.CollectedTelemetry {
			if len(kind) > 128 {
				return errors.New("resource observed behavior exceeds field limits")
			}
		}
		for _, request := range behavior.Requests {
			if len(request.Telemetry) > 128 || len(request.Destination) > 507 || len(request.DestinationResourceID) > 128 || len(request.DestinationKind) > 128 ||
				len(request.DestinationRole) > 64 || len(request.Operation) > 256 || len(request.Outcome) > 64 {
				return errors.New("resource observed behavior exceeds field limits")
			}
		}
	}
	return nil
}

func observedBehaviorKind(kind string) bool {
	return kind == "kubernetes/deployment" || kind == "kubernetes/statefulset" || kind == "kubernetes/daemonset"
}

func decodeStrict(encoded []byte, result any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	return decoder.Decode(result)
}

func modelRuleSchema(selectors []string) map[string]any {
	return map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []string{"selector", "expression", "risk", "rationale"},
		"properties": map[string]any{
			"selector": map[string]any{"type": "string", "enum": selectors, "description": detector.CELSelectorDescriptionFor(selectors)},
			"expression": map[string]any{"type": "string", "minLength": 1, "maxLength": 8192,
				"description": detector.CELExpressionDescription()},
			"risk":      map[string]any{"type": "string", "enum": []string{string(detector.RiskLow), string(detector.RiskMedium), string(detector.RiskHigh), string(detector.RiskCritical)}},
			"rationale": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024},
		},
	}
}
