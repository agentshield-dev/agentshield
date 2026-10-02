package deploymentauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// ruleCollector records the rules one authoring run accepts. The structured tool
// loop executes calls sequentially, so it needs no locking.
type ruleCollector struct {
	workload  state.DeploymentAuthoringContext
	selectors []string
	logger    *slog.Logger
	rules     []modelRule
}

type finishArguments struct {
	Rationale string `json:"rationale"`
}

// finishTool ends the run; the proposal is built only after it succeeds.
func finishTool() reasoning.StructuredTool {
	return reasoning.StructuredTool{
		Name:        "finish",
		Description: "Finish the draft with the overall rationale for the added rules, or for adding none. Rules described here instead of added with add_rule are discarded.",
		InputSchema: map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"rationale"},
			"properties": map[string]any{"rationale": map[string]any{"type": "string", "minLength": 1, "maxLength": 2048}},
		},
		Final: true,
		Execute: func(_ context.Context, arguments json.RawMessage) (json.RawMessage, error) {
			var finish finishArguments
			if err := decodeStrict(arguments, &finish); err != nil {
				return nil, fmt.Errorf("decode tool arguments: %w", err)
			}
			if finish.Rationale == "" || len(finish.Rationale) > 2048 {
				return nil, errors.New("finish requires a rationale of at most 2048 bytes")
			}
			return json.RawMessage(`{"finished":true}`), nil
		},
	}
}

func (collector *ruleCollector) log() *slog.Logger {
	if collector.logger == nil {
		return slog.Default()
	}
	return collector.logger
}

func (collector *ruleCollector) addRuleTool() reasoning.StructuredTool {
	return reasoning.StructuredTool{
		Name:        "add_rule",
		Description: fmt.Sprintf("Validate a rule and add it to the draft. Validation covers the selector, the host-applied scoping, compilation of the expression with the production detector, the limit of %d rules, and duplicates of an already added rule. Returns added, or the validation error; a rejected rule is not recorded.", maxDraftRules),
		InputSchema: modelRuleSchema(collector.selectors),
		Execute: func(ctx context.Context, arguments json.RawMessage) (json.RawMessage, error) {
			var rule modelRule
			if err := decodeStrict(arguments, &rule); err != nil {
				collector.log().DebugContext(ctx, "add_rule arguments rejected", "error", err)
				return nil, fmt.Errorf("decode tool arguments: %w", err)
			}
			candidate := append(slices.Clone(collector.rules), rule)
			if _, err := buildProposal(collector.workload, modelDraft{Rules: candidate}, collector.selectors); err != nil {
				collector.log().DebugContext(ctx, "add_rule rejected rule", "selector", rule.Selector, "expression", rule.Expression, "error", err)
				return json.Marshal(map[string]any{"added": false, "error": err.Error()})
			}
			collector.rules = candidate
			collector.log().DebugContext(ctx, "add_rule added rule", "selector", rule.Selector, "expression", rule.Expression, "rules", len(collector.rules))
			return json.Marshal(map[string]any{"added": true, "rules": len(collector.rules), "remaining": maxDraftRules - len(collector.rules)})
		},
	}
}
