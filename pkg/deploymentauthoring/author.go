package deploymentauthoring

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// authoringPrompt is the system prompt for rule drafting.
//
//go:embed authoring_prompt.txt
var authoringPrompt string

// maxDraftRules bounds one proposal; the tool budget leaves room to correct each rejected rule once.
const maxDraftRules = 3

// Host-owned rule metadata; the model chooses only the selector, expression, and rationale.
const (
	draftRisk          = detector.RiskMedium
	draftReason        = "workload_rule_match"
	draftWindowSeconds = 300
)

// Proposal is a validated, inactive rule draft for one Deployment. Rules holds
// at most three distinct rules, recorded through add_rule, and may be empty
// when no available field distinguishes the behavior of interest.
type Proposal struct {
	Rationale string                         `json:"rationale"`
	Rules     []ProposalRule                 `json:"rules"`
	ToolCalls []reasoning.StructuredToolCall `json:"toolCalls,omitempty"`
	// ObservedBehavior is the baseline the draft was written from, kept for review.
	ObservedBehavior *state.DeploymentBehavior `json:"observedBehavior,omitempty"`
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
	Selector   string `json:"selector"`
	Expression string `json:"expression"`
	Rationale  string `json:"rationale"`
}

// Author drafts rules for one Deployment authoring context.
type Author interface {
	Author(context.Context, state.DeploymentAuthoringContext) (Proposal, error)
}

// ModelAuthor drafts rules with a model through Client's tool-only loop: the
// model records rules with add_rule and ends with finish. Each rule is compiled
// with the production detector when it is added.
type ModelAuthor struct {
	Client reasoning.Client
	// Logger receives Debug traces of add_rule calls and the run outcome; nil uses slog.Default().
	Logger *slog.Logger
	// Selectors, when set, are the only rule selectors offered to and accepted
	// from the model, such as the selectors this deployment has producers for.
	// Empty offers every selector.
	Selectors []string
}

// selectors returns the selectors offered to the model, validated against the catalog.
func (author ModelAuthor) selectors() ([]string, error) {
	if len(author.Selectors) == 0 {
		return detector.CELSelectorNames(), nil
	}
	for _, name := range author.Selectors {
		if _, _, ok := detector.ParseCELSelector(name); !ok {
			return nil, fmt.Errorf("unsupported authoring selector %q", name)
		}
	}
	return slices.Clone(author.Selectors), nil
}

// Author implements [Author].
func (author ModelAuthor) Author(ctx context.Context, workload state.DeploymentAuthoringContext) (Proposal, error) {
	if err := ValidateContext(workload); err != nil {
		return Proposal{}, err
	}
	input, err := json.Marshal(struct {
		Kind               string                    `json:"kind"`
		Name               string                    `json:"name,omitempty"`
		Namespace          string                    `json:"namespace,omitempty"`
		ServiceAccountName string                    `json:"serviceAccountName,omitempty"`
		ObservedBehavior   *state.DeploymentBehavior `json:"observedBehavior,omitempty"`
	}{workload.Kind, workload.Name, workload.Namespace, workload.ServiceAccountName, workload.ObservedBehavior})
	if err != nil {
		return Proposal{}, fmt.Errorf("encode authoring input: %w", err)
	}
	selectors, err := author.selectors()
	if err != nil {
		return Proposal{}, err
	}
	logger := author.Logger
	if logger == nil {
		logger = slog.Default()
	}
	collector := &ruleCollector{workload: workload, selectors: selectors, logger: logger}
	output, err := author.Client.GenerateWithTools(ctx, authoringPrompt, input, []reasoning.StructuredTool{collector.addRuleTool(), finishTool()}, reasoning.StructuredToolLimits{
		MaxTurns: 2*maxDraftRules + 2, MaxCalls: 2 * maxDraftRules, MaxArgumentBytes: 2 * 1024, MaxResultBytes: 2 * 1024, MaxTotalResultBytes: 12 * 1024,
	})
	if err != nil {
		return Proposal{}, err
	}
	var final finishArguments
	if err := decodeStrict(output.FinalArguments, &final); err != nil {
		return Proposal{}, fmt.Errorf("decode Deployment rule draft: %w", err)
	}
	addRuleCalls := 0
	for _, call := range output.Calls {
		if call.Name == "add_rule" {
			addRuleCalls++
		}
	}
	logger.DebugContext(ctx, "model finished Deployment rule draft",
		"resource_id", workload.ResourceID, "tool_calls", len(output.Calls), "add_rule_calls", addRuleCalls, "accepted_rules", len(collector.rules))
	// Rules come only from accepted add_rule calls and are stored only after a successful finish.
	proposal, err := buildProposal(workload, modelDraft{Rationale: final.Rationale, Rules: collector.rules}, selectors)
	if err != nil {
		return Proposal{}, err
	}
	proposal.ToolCalls, proposal.ObservedBehavior = output.Calls, workload.ObservedBehavior
	return proposal, nil
}

// buildProposal applies host-owned scoping and metadata, then compiles the result with the production detector.
func buildProposal(workload state.DeploymentAuthoringContext, draft modelDraft, selectors []string) (Proposal, error) {
	if len(draft.Rationale) > 2048 || len(draft.Rules) > maxDraftRules {
		return Proposal{}, fmt.Errorf("Deployment draft exceeds the rationale limit or %d rules", maxDraftRules)
	}
	proposal := Proposal{Rationale: draft.Rationale, Rules: []ProposalRule{}}
	ruleset := detector.Ruleset{ID: "deployment-draft"}
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
			ID: ruleID(workload, index), Revision: 1, InputVersion: detector.InputVersion,
			PluginID: "*", WorkloadResourceID: workload.ResourceID, Type: inputType, Kind: kind, Expression: candidate.Expression,
			Risk: draftRisk, Reasons: []string{draftReason}, WindowSeconds: draftWindowSeconds,
		}
		ruleset.Rules = append(ruleset.Rules, rule)
		proposal.Rules = append(proposal.Rules, ProposalRule{Rule: rule, Rationale: candidate.Rationale})
	}
	if err := detector.ValidateRuleset(ruleset); err != nil {
		return Proposal{}, fmt.Errorf("validate Deployment rule draft: %w", err)
	}
	return proposal, nil
}

// ruleID scopes a draft rule to its Deployment and, when known, its Pod
// template revision, so drafts for different revisions can be loaded together.
func ruleID(workload state.DeploymentAuthoringContext, index int) string {
	if workload.TemplateSHA256 == "" {
		return fmt.Sprintf("deployment/%s/rule-%d", workload.ResourceID, index+1)
	}
	return fmt.Sprintf("deployment/%s/template-%s/rule-%d", workload.ResourceID, workload.TemplateSHA256[:12], index+1)
}

// BaselineSource reads a Deployment's observed behavior from the current graph.
// *state.Store implements it.
type BaselineSource interface {
	DeploymentObservedBehavior(context.Context, string) (state.DeploymentBehavior, error)
}

// WithBaseline returns workload with its observed behavior from source, the
// context the authoring worker sends to the model.
func WithBaseline(ctx context.Context, source BaselineSource, workload state.DeploymentAuthoringContext) (state.DeploymentAuthoringContext, error) {
	behavior, err := source.DeploymentObservedBehavior(ctx, workload.ResourceID)
	if err != nil {
		return state.DeploymentAuthoringContext{}, err
	}
	workload.ObservedBehavior = &behavior
	return workload, nil
}

// ValidateContext checks that workload identifies a Deployment and fits
// field limits before anything is sent to a model.
func ValidateContext(workload state.DeploymentAuthoringContext) error {
	if workload.ResourceID == "" || len(workload.ResourceID) > 128 || workload.Kind != "kubernetes/deployment" {
		return errors.New("authoring context must identify a Kubernetes Deployment")
	}
	if workload.TemplateSHA256 != "" && len(workload.TemplateSHA256) != 64 {
		return errors.New("authoring context template digest must be a SHA-256")
	}
	if len(workload.Name) > 253 || len(workload.Namespace) > 253 || len(workload.ServiceAccountName) > 253 {
		return errors.New("Deployment authoring context exceeds field limits")
	}
	if behavior := workload.ObservedBehavior; behavior != nil {
		if len(behavior.Requests) > state.MaxObservedRequests || len(behavior.CollectedTelemetry) > state.MaxCollectedTelemetry {
			return errors.New("Deployment observed behavior exceeds the request or telemetry kind limit")
		}
		for _, kind := range behavior.CollectedTelemetry {
			if len(kind) > 128 {
				return errors.New("Deployment observed behavior exceeds field limits")
			}
		}
		for _, request := range behavior.Requests {
			if len(request.Telemetry) > 128 || len(request.Destination) > 507 || len(request.DestinationKind) > 128 ||
				len(request.DestinationRole) > 64 || len(request.Operation) > 256 || len(request.Outcome) > 64 {
				return errors.New("Deployment observed behavior exceeds field limits")
			}
		}
	}
	return nil
}

func decodeStrict(encoded []byte, result any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	return decoder.Decode(result)
}

func modelRuleSchema(selectors []string) map[string]any {
	return map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []string{"selector", "expression", "rationale"},
		"properties": map[string]any{
			"selector": map[string]any{"type": "string", "enum": selectors, "description": detector.CELSelectorDescriptionFor(selectors)},
			"expression": map[string]any{"type": "string", "minLength": 1, "maxLength": 8192,
				"description": detector.CELExpressionDescription()},
			"rationale": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024},
		},
	}
}
