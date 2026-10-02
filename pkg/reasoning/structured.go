package reasoning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Provider selects the model API dialect.
type Provider string

// Supported model API dialects. OpenAI is the default.
const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
)

// RequestPreviewError carries the request body captured by a [Client] with
// DryRun set. It never contains HTTP headers or credentials.
type RequestPreviewError struct {
	Body []byte
}

// Error implements error.
func (preview *RequestPreviewError) Error() string {
	return "model request preview captured"
}

// StructuredTool is a host-executed function the model may call during
// [Client.GenerateWithTools]. Execute must return valid JSON; its error text is
// returned to the model, truncated.
type StructuredTool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Execute     func(context.Context, json.RawMessage) (json.RawMessage, error)
	// Final ends the run when the call succeeds; its arguments become the run's result.
	// Final calls do not consume MaxCalls.
	Final bool
}

// StructuredToolLimits bounds a structured tool loop. MaxTurns is 1-32,
// MaxCalls 0-32, argument and per-result bytes at most 64 KiB, and total
// result bytes at most 512 KiB.
type StructuredToolLimits struct {
	MaxTurns            int
	MaxCalls            int
	MaxArgumentBytes    int
	MaxResultBytes      int
	MaxTotalResultBytes int
}

// StructuredToolCall records one tool call for audit, with its result or the
// error returned to the model.
type StructuredToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// StructuredToolOutput is the Final call that ended the run and every tool call
// made, in order.
type StructuredToolOutput struct {
	// FinalTool and FinalArguments identify the successful Final call that ended the run.
	FinalTool      string
	FinalArguments json.RawMessage
	Calls          []StructuredToolCall
}

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	// responsesOutput replays the provider's raw Responses items, including reasoning state.
	responsesOutput []json.RawMessage
}

type chatTurn struct {
	Result    ModelResult
	Message   chatMessage
	ToolCalls []chatToolCall
}

// GenerateWithTools runs a bounded, tool-only loop. Every turn must call a
// tool, and the run ends when the tool marked Final succeeds; its arguments are
// the result. No response format is requested, so the request prefix stays
// identical across turns. Budget violations (oversized arguments or results,
// unknown tools, an exhausted call budget) are returned to the model as tool
// errors rather than failing the request. Final calls do not consume
// MaxCalls, and the last turn forces the Final tool.
func (client Client) GenerateWithTools(ctx context.Context, systemPrompt string, input json.RawMessage, tools []StructuredTool, limits StructuredToolLimits) (StructuredToolOutput, error) {
	if client.ValidateInput != nil {
		if err := client.ValidateInput(input); err != nil {
			return StructuredToolOutput{}, fmt.Errorf("validate model input: %w", err)
		}
	}
	if strings.TrimSpace(systemPrompt) == "" || !json.Valid(input) {
		return StructuredToolOutput{}, errors.New("tool model request requires a prompt and valid JSON input")
	}
	if err := limits.validate(64*1024, 64*1024, 512*1024); err != nil {
		return StructuredToolOutput{}, err
	}
	definitions := make([]*mcp.Tool, 0, len(tools))
	byName := make(map[string]StructuredTool, len(tools))
	finalTool := ""
	for _, tool := range tools {
		if tool.Name == "" || tool.InputSchema == nil || tool.Execute == nil {
			return StructuredToolOutput{}, errors.New("structured tools require a name, input schema, and handler")
		}
		if _, exists := byName[tool.Name]; exists {
			return StructuredToolOutput{}, fmt.Errorf("duplicate structured tool %q", tool.Name)
		}
		if tool.Final {
			if finalTool != "" {
				return StructuredToolOutput{}, errors.New("structured tools allow exactly one final tool")
			}
			finalTool = tool.Name
		}
		byName[tool.Name] = tool
		definitions = append(definitions, &mcp.Tool{Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema})
	}
	if finalTool == "" {
		return StructuredToolOutput{}, errors.New("structured tools require a final tool")
	}
	messages := []chatMessage{{Role: "system", Content: systemPrompt}, {Role: "user", Content: string(input)}}
	result := StructuredToolOutput{Calls: []StructuredToolCall{}}
	names := make(map[string]struct{}, len(byName))
	for name := range byName {
		names[name] = struct{}{}
	}
	loop := toolLoop{
		limits: limits, tools: names, final: finalTool,
		next: func(ctx context.Context, last bool) ([]toolLoopCall, error) {
			// The last turn may only finish; earlier turns may call any tool.
			forced := ""
			if last {
				forced = finalTool
			}
			turn, err := client.toolTurn(ctx, messages, definitions, forced, 3000)
			if err != nil {
				return nil, err
			}
			if len(turn.ToolCalls) > 0 {
				messages = append(messages, turn.Message)
			}
			calls := make([]toolLoopCall, 0, len(turn.ToolCalls))
			for _, toolCall := range turn.ToolCalls {
				calls = append(calls, toolLoopCall{ID: toolCall.ID, Name: toolCall.Function.Name, Arguments: []byte(toolCall.Function.Arguments)})
			}
			return calls, nil
		},
		run: func(ctx context.Context, call toolLoopCall) (json.RawMessage, string, error) {
			toolResult, err := byName[call.Name].Execute(ctx, append(json.RawMessage(nil), call.Arguments...))
			if err != nil {
				return nil, truncateToolError(err.Error(), 1024), nil
			}
			return toolResult, "", nil
		},
		reply: func(call toolLoopCall, outcome toolLoopOutcome) error {
			recorded := StructuredToolCall{Name: call.Name, Result: outcome.Result, Error: outcome.Refusal}
			if outcome.Executed {
				recorded.Arguments = append(json.RawMessage(nil), call.Arguments...)
			}
			if call.Name == finalTool && outcome.Executed && outcome.Refusal == "" {
				result.FinalTool, result.FinalArguments = recorded.Name, recorded.Arguments
			}
			result.Calls = append(result.Calls, recorded)
			toolContent, err := json.Marshal(struct {
				Result json.RawMessage `json:"result,omitempty"`
				Error  string          `json:"error,omitempty"`
			}{Result: recorded.Result, Error: recorded.Error})
			if err != nil {
				return fmt.Errorf("encode tool %s result: %w", call.Name, err)
			}
			messages = append(messages, chatMessage{Role: "tool", ToolCallID: call.ID, Content: string(toolContent)})
			return nil
		},
	}
	if err := loop.execute(ctx); err != nil {
		return StructuredToolOutput{}, err
	}
	return result, nil
}

func truncateToolError(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// toolTurn requests one tool call: of any offered tool, or of forced when it is set.
func (client Client) toolTurn(ctx context.Context, messages []chatMessage, tools []*mcp.Tool, forced string, maxTokens int) (chatTurn, error) {
	if client.Provider == ProviderAnthropic {
		return client.anthropicToolTurn(ctx, messages, tools, forced, maxTokens)
	}
	var instructions []string
	input := make([]any, 0, len(messages))
	for _, message := range messages {
		switch {
		case message.Role == "system":
			instructions = append(instructions, message.Content)
		case message.Role == "tool":
			input = append(input, map[string]any{"type": "function_call_output", "call_id": message.ToolCallID, "output": message.Content})
		case len(message.responsesOutput) > 0:
			for _, item := range message.responsesOutput {
				input = append(input, item)
			}
		default:
			input = append(input, map[string]any{"role": message.Role, "content": message.Content})
		}
	}
	var toolChoice any = "required"
	if forced != "" {
		toolChoice = map[string]any{"type": "function", "name": forced}
	}
	body := map[string]any{
		"instructions": strings.Join(instructions, "\n\n"), "input": input, "max_output_tokens": maxTokens,
		"tools": responsesToolDefinitions(tools), "tool_choice": toolChoice,
	}
	reply, err := client.callResponses(ctx, body)
	if err != nil {
		return chatTurn{}, err
	}
	message := chatMessage{Role: "assistant", Content: reply.Text, responsesOutput: reply.Output}
	for _, call := range reply.ToolCalls {
		toolCall := chatToolCall{ID: call.CallID, Type: "function"}
		toolCall.Function.Name, toolCall.Function.Arguments = call.Name, call.Arguments
		message.ToolCalls = append(message.ToolCalls, toolCall)
	}
	return chatTurn{Result: reply.Result, Message: message, ToolCalls: message.ToolCalls}, nil
}
