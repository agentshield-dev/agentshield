package reasoning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// anthropicModel is used when Client.Model is empty.
const anthropicModel = "claude-sonnet-4-6"

// anthropicMessage is one Messages API turn made of typed content blocks.
type anthropicMessage struct {
	Role    string           `json:"role"`
	Content []map[string]any `json:"content"`
}

// anthropicToolTurn runs one tool turn against Anthropic's Messages API. Only
// [Client.GenerateWithTools], used for Deployment rule authoring, reaches it.
// Runtime reasoning (Analyze, Repair, Investigate) is built on the OpenAI
// Responses API and has no Anthropic path.
//
// The request maps the provider-neutral chat history as follows: system
// messages join into the top-level system field; tool calls become
// assistant tool_use blocks; tool results become user tool_result blocks.
// Consecutive blocks with the same role merge into one message, so the
// results for one turn's tool calls arrive together in a single user message
// as the API expects. Tools are sent with strict schemas, and tool_choice is
// any, or the forced tool when it is set. No output format is requested.
//
// The response maps back to the OpenAI-shaped chatTurn: text blocks
// concatenate into the message content, tool_use inputs become JSON argument
// strings, and other block types are ignored.
func (client Client) anthropicToolTurn(ctx context.Context, messages []chatMessage, tools []*mcp.Tool, forced string, maxTokens int) (chatTurn, error) {
	model := strings.TrimSpace(client.Model)
	if model == "" {
		model = anthropicModel
	}
	var system []string
	var requestMessages []anthropicMessage
	appendMessage := func(role string, block map[string]any) {
		if len(requestMessages) > 0 && requestMessages[len(requestMessages)-1].Role == role {
			requestMessages[len(requestMessages)-1].Content = append(requestMessages[len(requestMessages)-1].Content, block)
			return
		}
		requestMessages = append(requestMessages, anthropicMessage{Role: role, Content: []map[string]any{block}})
	}
	for _, message := range messages {
		switch message.Role {
		case "system":
			system = append(system, message.Content)
		case "user", "assistant":
			if message.Content != "" {
				appendMessage(message.Role, map[string]any{"type": "text", "text": message.Content})
			}
			for _, call := range message.ToolCalls {
				var input map[string]any
				if err := json.Unmarshal([]byte(call.Function.Arguments), &input); err != nil {
					return chatTurn{}, fmt.Errorf("decode Anthropic tool %s arguments: %w", call.Function.Name, err)
				}
				// tool_use input must be an object, even for "null" arguments.
				if input == nil {
					input = map[string]any{}
				}
				appendMessage("assistant", map[string]any{
					"type": "tool_use", "id": call.ID, "name": call.Function.Name, "input": input,
				})
			}
		case "tool":
			appendMessage("user", map[string]any{
				"type": "tool_result", "tool_use_id": message.ToolCallID, "content": message.Content,
			})
		default:
			return chatTurn{}, fmt.Errorf("unsupported Anthropic conversation role %q", message.Role)
		}
	}
	if len(requestMessages) == 0 {
		return chatTurn{}, errors.New("Anthropic request requires at least one user or assistant message")
	}
	body := map[string]any{"model": model, "max_tokens": maxTokens, "messages": requestMessages}
	if len(system) > 0 {
		body["system"] = strings.Join(system, "\n\n")
	}
	if len(tools) > 0 {
		definitions := make([]map[string]any, 0, len(tools))
		for _, tool := range tools {
			inputSchema, err := anthropicSchema(tool.InputSchema)
			if err != nil {
				return chatTurn{}, fmt.Errorf("prepare Anthropic tool %s schema: %w", tool.Name, err)
			}
			definitions = append(definitions, map[string]any{
				"name": tool.Name, "description": tool.Description, "input_schema": inputSchema, "strict": true,
			})
		}
		body["tools"] = definitions
		body["tool_choice"] = map[string]any{"type": "any"}
		if forced != "" {
			body["tool_choice"] = map[string]any{"type": "tool", "name": forced}
		}
	}
	raw, latency, err := client.post(ctx, "/v1/messages", body)
	if err != nil {
		return chatTurn{}, err
	}
	var envelope struct {
		ID      string            `json:"id"`
		Model   string            `json:"model"`
		Content []json.RawMessage `json:"content"`
		Usage   struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return chatTurn{}, fmt.Errorf("decode Anthropic response: %w", err)
	}
	message := chatMessage{Role: "assistant"}
	for _, encodedBlock := range envelope.Content {
		var block struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal(encodedBlock, &block); err != nil {
			return chatTurn{}, fmt.Errorf("decode Anthropic response content block: %w", err)
		}
		switch block.Type {
		case "text":
			message.Content += block.Text
		case "tool_use":
			arguments := block.Input
			if len(arguments) == 0 || !json.Valid(arguments) {
				return chatTurn{}, fmt.Errorf("Anthropic tool %s returned invalid JSON input", block.Name)
			}
			message.ToolCalls = append(message.ToolCalls, chatToolCall{
				ID: block.ID, Type: "function", Function: struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				}{Name: block.Name, Arguments: string(arguments)},
			})
		}
	}
	totalTokens := envelope.Usage.InputTokens + envelope.Usage.OutputTokens
	usage := Usage{PromptTokens: envelope.Usage.InputTokens, CompletionTokens: envelope.Usage.OutputTokens, TotalTokens: totalTokens}
	responseModel := envelope.Model
	if responseModel == "" {
		responseModel = model
	}
	result := ModelResult{Raw: raw, RequestID: envelope.ID, Model: responseModel, Usage: usage, Latency: latency}
	return chatTurn{Result: result, Message: message, ToolCalls: message.ToolCalls}, nil
}

// anthropicSchema deep-copies schema through JSON, so normalization never
// mutates the caller's schema, and rewrites it for Anthropic's strict mode.
func anthropicSchema(schema any) (map[string]any, error) {
	encoded, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, err
	}
	copy, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("JSON Schema must be an object")
	}
	normalizeAnthropicSchema(copy)
	return copy, nil
}

// normalizeAnthropicSchema removes JSON Schema keywords that Anthropic's
// structured outputs reject (numeric bounds, string lengths, maxItems,
// minItems other than 0 or 1, and unsupported string formats) and restates
// them in the description so the model still sees them; the caller must
// enforce them after generation. Strict mode also requires
// additionalProperties: false on every object. It recurses through every
// nested map and list.
func normalizeAnthropicSchema(schema map[string]any) {
	var moved []string
	for _, key := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "maxItems"} {
		if value, exists := schema[key]; exists {
			encoded, _ := json.Marshal(map[string]any{key: value})
			moved = append(moved, string(encoded))
			delete(schema, key)
		}
	}
	if value, exists := schema["minItems"]; exists {
		if minimum, ok := value.(float64); !ok || (minimum != 0 && minimum != 1) {
			encoded, _ := json.Marshal(map[string]any{"minItems": value})
			moved = append(moved, string(encoded))
			delete(schema, "minItems")
		}
	}
	if format, ok := schema["format"].(string); ok && !oneOf(format, "date-time", "time", "date", "duration", "email", "hostname", "uri", "ipv4", "ipv6", "uuid") {
		encoded, _ := json.Marshal(map[string]any{"format": format})
		moved = append(moved, string(encoded))
		delete(schema, "format")
	}
	if isAnthropicObjectSchema(schema["type"]) {
		schema["additionalProperties"] = false
	}
	if len(moved) > 0 {
		description, _ := schema["description"].(string)
		if description != "" {
			description += " "
		}
		schema["description"] = description + "The following constraints are enforced by the host after generation: " + strings.Join(moved, ", ") + "."
	}
	for _, value := range schema {
		switch nested := value.(type) {
		case map[string]any:
			normalizeAnthropicSchema(nested)
		case []any:
			for _, item := range nested {
				if child, ok := item.(map[string]any); ok {
					normalizeAnthropicSchema(child)
				}
			}
		}
	}
}

// isAnthropicObjectSchema reports whether a "type" value is or includes
// "object".
func isAnthropicObjectSchema(schemaType any) bool {
	if schemaType == "object" {
		return true
	}
	types, ok := schemaType.([]any)
	if !ok {
		return false
	}
	for _, value := range types {
		if value == "object" {
			return true
		}
	}
	return false
}
