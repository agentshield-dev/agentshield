package reasoning

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

// Model is the default OpenAI Responses model for reasoning.
const Model = "gpt-6-astra"

// SystemPrompt is the reasoning system prompt. It restates the evidence and
// promotion rules the host enforces so that a compliant response survives
// validation; enforcement never depends on the model following it.
//
//go:embed system_prompt.txt
var SystemPrompt string

// Client calls an OpenAI Responses-compatible endpoint, or Anthropic's
// Messages API for structured authoring when Provider is [ProviderAnthropic].
// Responses requests are sent with store=false. When ReasoningEffort is set,
// encrypted reasoning state is requested and replayed across turns.
type Client struct {
	Endpoint        string
	APIKey          string
	Model           string
	ReasoningEffort string
	Provider        Provider
	// DryRun returns the first request body as a *[RequestPreviewError]
	// instead of sending it.
	DryRun     bool
	HTTPClient *http.Client
	// ValidateInput, if set, inspects every encoded model input before it is
	// sent and aborts the request on error.
	ValidateInput func([]byte) error
	// InvestigationLimits bounds the [Client.Investigate] tool loop; zero uses
	// [DefaultInvestigationToolLimits].
	InvestigationLimits StructuredToolLimits
}

// DefaultInvestigationToolLimits bounds one investigation: 16 model turns, 32
// MCP tool calls, 16 KiB of arguments per call, 256 KiB per tool result, and
// 1 MiB of tool results in total. Every turn replays the whole conversation,
// so the total result bound also bounds each request.
func DefaultInvestigationToolLimits() StructuredToolLimits {
	return StructuredToolLimits{MaxTurns: 16, MaxCalls: 32, MaxArgumentBytes: 16 << 10, MaxResultBytes: 256 << 10, MaxTotalResultBytes: 1 << 20}
}

// StatusError is a non-2xx response from the model endpoint.
type StatusError struct {
	StatusCode int
	Status     string
	Body       string
}

// Error implements error.
func (failure *StatusError) Error() string {
	return fmt.Sprintf("model endpoint returned %s: %s", failure.Status, failure.Body)
}

// Permanent reports whether repeating the request cannot succeed: a 4xx other
// than 408 (timeout) and 429 (rate limit), such as an invalid request or
// rejected credentials.
func (failure *StatusError) Permanent() bool {
	return failure.StatusCode >= 400 && failure.StatusCode < 500 &&
		failure.StatusCode != http.StatusRequestTimeout && failure.StatusCode != http.StatusTooManyRequests
}

// IsPermanentModelError reports whether err contains a [StatusError] that
// retrying cannot fix.
func IsPermanentModelError(err error) bool {
	var failure *StatusError
	return errors.As(err, &failure) && failure.Permanent()
}

// Usage is token usage reported by the model endpoint.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	ReasoningTokens  int `json:"reasoning_tokens,omitempty"`
	TotalTokens      int `json:"total_tokens"`
}

// ModelResult is one model turn: the parsed response, the raw provider body
// for audit, and usage and latency.
type ModelResult struct {
	Response  Response
	Raw       []byte
	RequestID string
	Model     string
	Usage     Usage
	Latency   time.Duration
	Trace     ModelTrace
}

// ModelTrace records what a turn did: its stage (analysis, investigation, or
// repair), the tools it requested, or its final assessment.
type ModelTrace struct {
	Stage      string          `json:"stage"`
	ToolCalls  []ModelToolCall `json:"toolCalls,omitempty"`
	Assessment *Assessment     `json:"assessment,omitempty"`
}

// ModelToolCall is a tool invocation requested by the model.
type ModelToolCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// InvestigationResult is a completed tool-using investigation. EffectivePacket
// is the input packet merged with every successful MCP result.
type InvestigationResult struct {
	Response        Response
	ModelResults    []ModelResult
	ContextResults  []ContextResult
	EffectivePacket Packet
}

// Analyze sends an encoded packet in a single tool-free turn.
func (client Client) Analyze(ctx context.Context, packet []byte) (ModelResult, error) {
	if client.ValidateInput != nil {
		if err := client.ValidateInput(packet); err != nil {
			return ModelResult{}, fmt.Errorf("validate model input: %w", err)
		}
	}
	if strings.TrimSpace(client.Endpoint) == "" {
		return ModelResult{}, errors.New("model endpoint is required")
	}
	input := []map[string]any{{"role": "user", "content": string(packet)}}
	turn, err := client.responses(ctx, input, nil, "")
	if err != nil {
		return ModelResult{}, err
	}
	turn.Result.Trace.Stage = "analysis"
	return turn.Result, nil
}

// Repair asks for one corrected response after previous failed validation.
// The model sees the effective packet, its own invalid response, the
// validation error, and the IDs it may cite, and receives no tools.
func (client Client) Repair(ctx context.Context, packet Packet, previous Response, validationError string, allowedSupportingIDs []string) (ModelResult, error) {
	encodedPacket, err := EncodePacket(packet)
	if err != nil {
		return ModelResult{}, err
	}
	if client.ValidateInput != nil {
		if err := client.ValidateInput(encodedPacket); err != nil {
			return ModelResult{}, fmt.Errorf("validate repair input: %w", err)
		}
	}
	encodedPrevious, err := json.Marshal(previous)
	if err != nil {
		return ModelResult{}, fmt.Errorf("encode invalid model response: %w", err)
	}
	encodedAllowedIDs, err := json.Marshal(allowedSupportingIDs)
	if err != nil {
		return ModelResult{}, fmt.Errorf("encode allowed supporting IDs: %w", err)
	}
	repairInstruction := "The response failed deterministic validation: " + validationError + ". For claims.supportingIds, use only values from this allowlist: " + string(encodedAllowedIDs) + ". Copy selected signal IDs into assessment.signalIds. Return one corrected response and do not request tools."
	input := []map[string]any{
		{"role": "user", "content": string(encodedPacket)},
		{"role": "assistant", "content": string(encodedPrevious)},
		{"role": "user", "content": repairInstruction},
	}
	turn, err := client.responses(ctx, input, nil, "")
	if err != nil {
		return ModelResult{}, err
	}
	turn.Result.Trace.Stage = "repair"
	return turn.Result, nil
}

// Investigate runs the tool loop: each turn may call MCP tools from session,
// whose results are returned to the model and merged into the effective
// packet, until the model returns a final structured response. The loop is
// bounded by [Client.InvestigationLimits]: the last allowed turn offers no
// tool, so the model must answer, and calls or results over the budget are
// refused to the model rather than run or merged. Tool errors are returned to
// the model, not merged.
func (client Client) Investigate(ctx context.Context, packet Packet, session *mcp.ClientSession) (InvestigationResult, error) {
	if session == nil {
		return InvestigationResult{}, errors.New("MCP client session is required")
	}
	limits := client.InvestigationLimits
	if limits == (StructuredToolLimits{}) {
		limits = DefaultInvestigationToolLimits()
	}
	if err := limits.validate(1<<20, 1<<20, 8<<20); err != nil {
		return InvestigationResult{}, fmt.Errorf("investigation tool limits: %w", err)
	}
	encoded, err := EncodePacket(packet)
	if err != nil {
		return InvestigationResult{}, err
	}
	if client.ValidateInput != nil {
		if err := client.ValidateInput(encoded); err != nil {
			return InvestigationResult{}, fmt.Errorf("validate model input: %w", err)
		}
	}
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		return InvestigationResult{}, fmt.Errorf("list MCP tools: %w", err)
	}
	return client.investigateResponses(ctx, encoded, listed.Tools, session, packet, limits)
}

func (client Client) model() string {
	if strings.TrimSpace(client.Model) == "" {
		return Model
	}
	return client.Model
}

type responsesToolCall struct {
	CallID    string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type responsesTurn struct {
	Result    ModelResult
	Output    []json.RawMessage
	ToolCalls []responsesToolCall
}

func (client Client) investigateResponses(ctx context.Context, encoded []byte, tools []*mcp.Tool, session *mcp.ClientSession, packet Packet, limits StructuredToolLimits) (InvestigationResult, error) {
	initial, err := json.Marshal(map[string]any{"role": "user", "content": string(encoded)})
	if err != nil {
		return InvestigationResult{}, err
	}
	input := []json.RawMessage{initial}
	result := InvestigationResult{EffectivePacket: packet}
	names := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		names[tool.Name] = struct{}{}
	}
	loop := toolLoop{
		limits: limits, tools: names,
		next: func(ctx context.Context, last bool) ([]toolLoopCall, error) {
			// The last turn offers no tool, so the model must answer.
			choice := "auto"
			if last {
				choice = "none"
			}
			turn, err := client.responses(ctx, input, tools, choice)
			if err != nil {
				return nil, err
			}
			turn.Result.Trace.Stage = "investigation"
			result.ModelResults = append(result.ModelResults, turn.Result)
			input = append(input, turn.Output...)
			if len(turn.ToolCalls) == 0 {
				result.Response = turn.Result.Response
			}
			calls := make([]toolLoopCall, 0, len(turn.ToolCalls))
			for _, toolCall := range turn.ToolCalls {
				calls = append(calls, toolLoopCall{ID: toolCall.CallID, Name: toolCall.Name, Arguments: []byte(toolCall.Arguments)})
			}
			return calls, nil
		},
		run: func(ctx context.Context, call toolLoopCall) (json.RawMessage, string, error) {
			// Bad arguments are refused back to the model, not a loop error.
			arguments, ok := toolArguments(call.Arguments)
			if !ok {
				return nil, "tool arguments must be a JSON object", nil
			}
			called, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.Name, Arguments: arguments})
			if err != nil {
				return nil, "", fmt.Errorf("call MCP tool %s: %w", call.Name, err)
			}
			if called.IsError {
				content, _ := json.Marshal(called.Content)
				return nil, string(content), nil
			}
			output, err := json.Marshal(called.StructuredContent)
			if err != nil {
				return nil, "", fmt.Errorf("encode MCP tool %s result: %w", call.Name, err)
			}
			return output, "", nil
		},
		reply: func(call toolLoopCall, outcome toolLoopOutcome) error {
			output := outcome.Refusal
			if outcome.Result != nil {
				var contextResult ContextResult
				if err := json.Unmarshal(outcome.Result, &contextResult); err != nil {
					return fmt.Errorf("decode MCP tool %s result: %w", call.Name, err)
				}
				result.ContextResults = append(result.ContextResults, contextResult)
				result.EffectivePacket = MergeContext(result.EffectivePacket, contextResult)
				output = string(outcome.Result)
			}
			item, err := json.Marshal(map[string]any{"type": "function_call_output", "call_id": call.ID, "output": output})
			if err != nil {
				return err
			}
			input = append(input, item)
			return nil
		},
	}
	if err := loop.execute(ctx); err != nil {
		return InvestigationResult{}, err
	}
	return result, nil
}

// responses requests one structured turn. With tools, toolChoice is the
// Responses tool_choice: "auto", or "none" to require an answer.
func (client Client) responses(ctx context.Context, input any, tools []*mcp.Tool, toolChoice string) (responsesTurn, error) {
	body := map[string]any{
		"instructions": SystemPrompt, "input": input, "max_output_tokens": 32000,
		"text": jsonSchemaTextFormat("agentshield_change_assessment", responseSchema()),
	}
	if len(tools) > 0 {
		body["tools"] = responsesToolDefinitions(tools)
		body["tool_choice"] = toolChoice
	}
	reply, err := client.callResponses(ctx, body)
	if err != nil {
		return responsesTurn{}, err
	}
	turn := responsesTurn{Output: reply.Output, ToolCalls: reply.ToolCalls}
	var parsed Response
	if len(turn.ToolCalls) == 0 {
		if err := decodeStrictJSON([]byte(reply.Text), &parsed); err != nil {
			return responsesTurn{}, fmt.Errorf("decode structured Responses output: %w", err)
		}
	}
	turn.Result = reply.Result
	turn.Result.Response = parsed
	for _, toolCall := range turn.ToolCalls {
		turn.Result.Trace.ToolCalls = append(turn.Result.Trace.ToolCalls, ModelToolCall{Name: toolCall.Name, Arguments: toolCall.Arguments})
	}
	if len(turn.ToolCalls) == 0 {
		assessment := parsed.Assessment
		turn.Result.Trace.Assessment = &assessment
	}
	return turn, nil
}

type responsesReply struct {
	Result    ModelResult
	Output    []json.RawMessage
	ToolCalls []responsesToolCall
	Text      string
}

func (client Client) callResponses(ctx context.Context, body map[string]any) (responsesReply, error) {
	body["model"] = client.model()
	body["store"] = false
	if client.ReasoningEffort != "" {
		body["reasoning"] = map[string]any{"effort": client.ReasoningEffort}
		body["include"] = []string{"reasoning.encrypted_content"}
	}
	raw, latency, err := client.post(ctx, "/v1/responses", body)
	if err != nil {
		return responsesReply{}, err
	}
	var envelope struct {
		ID     string            `json:"id"`
		Model  string            `json:"model"`
		Status string            `json:"status"`
		Error  any               `json:"error"`
		Output []json.RawMessage `json:"output"`
		Usage  struct {
			InputTokens   int `json:"input_tokens"`
			OutputTokens  int `json:"output_tokens"`
			TotalTokens   int `json:"total_tokens"`
			OutputDetails struct {
				ReasoningTokens int `json:"reasoning_tokens"`
			} `json:"output_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return responsesReply{}, fmt.Errorf("decode Responses output: %w", err)
	}
	if envelope.Status != "completed" {
		return responsesReply{}, fmt.Errorf("Responses status %q: %v", envelope.Status, envelope.Error)
	}
	reply := responsesReply{Output: envelope.Output}
	for _, rawItem := range envelope.Output {
		var item struct {
			Type      string `json:"type"`
			CallID    string `json:"call_id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
			Content   []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(rawItem, &item); err != nil {
			return responsesReply{}, fmt.Errorf("decode Responses item: %w", err)
		}
		switch item.Type {
		case "function_call":
			reply.ToolCalls = append(reply.ToolCalls, responsesToolCall{CallID: item.CallID, Name: item.Name, Arguments: item.Arguments})
		case "message":
			for _, content := range item.Content {
				if content.Type == "output_text" {
					reply.Text += content.Text
				}
			}
		}
	}
	usage := Usage{PromptTokens: envelope.Usage.InputTokens, CompletionTokens: envelope.Usage.OutputTokens, ReasoningTokens: envelope.Usage.OutputDetails.ReasoningTokens, TotalTokens: envelope.Usage.TotalTokens}
	reply.Result = ModelResult{Raw: raw, RequestID: envelope.ID, Model: envelope.Model, Usage: usage, Latency: latency}
	return reply, nil
}

func jsonSchemaTextFormat(name string, schema map[string]any) map[string]any {
	return map[string]any{"format": map[string]any{"type": "json_schema", "name": name, "strict": true, "schema": schema}}
}

func responsesToolDefinitions(tools []*mcp.Tool) []map[string]any {
	definitions := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		definitions = append(definitions, map[string]any{
			"type": "function", "name": tool.Name, "description": tool.Description, "parameters": tool.InputSchema, "strict": false,
		})
	}
	return definitions
}

func (client Client) post(ctx context.Context, path string, body any) ([]byte, time.Duration, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("encode model request: %w", err)
	}
	if client.DryRun {
		return nil, 0, &RequestPreviewError{Body: encoded}
	}
	if strings.TrimSpace(client.Endpoint) == "" {
		return nil, 0, errors.New("model endpoint is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(client.Endpoint, "/")+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, fmt.Errorf("create model request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept-Encoding", "identity")
	apiKey := strings.TrimSpace(client.APIKey)
	if client.Provider == ProviderAnthropic {
		request.Header.Set("anthropic-version", "2023-06-01")
		if apiKey != "" {
			request.Header.Set("x-api-key", apiKey)
		}
	} else if apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+apiKey)
	}
	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Minute}
	}
	started := time.Now()
	response, err := httpClient.Do(request)
	latency := time.Since(started)
	if err != nil {
		return nil, latency, fmt.Errorf("call model endpoint: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, latency, fmt.Errorf("read model response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, latency, &StatusError{StatusCode: response.StatusCode, Status: response.Status, Body: strings.TrimSpace(string(raw))}
	}
	return raw, latency, nil
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func responseSchema() map[string]any {
	stringArray := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	remediationSuggestion := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"intent", "targetEntityIds", "supportingIds"}, "properties": map[string]any{
		"intent": map[string]any{"type": "string", "enum": []string{
			string(remediation.IntentNetworkDeclareIngressIsolation), string(remediation.IntentTransportRequireMutualTLS), string(remediation.IntentGatewayPreventRouteDelivery),
		}},
		"targetEntityIds": map[string]any{"type": "array", "minItems": 1, "maxItems": 1, "items": map[string]any{"type": "string"}},
		"supportingIds":   map[string]any{"type": "array", "minItems": 1, "maxItems": remediation.MaxSupportingIDs, "items": map[string]any{"type": "string"}},
	}}
	claim := map[string]any{"type": "object", "additionalProperties": false, "required": []string{"mode", "text", "supportingIds"}, "properties": map[string]any{
		"mode": map[string]any{"type": "string", "enum": claimModeValues},
		"text": map[string]any{"type": "string"}, "supportingIds": map[string]any{"type": "array", "maxItems": remediation.MaxSupportingIDs, "description": "For candidate_finding, include the selected signal ID, each supporting returned fact object's own id field, and at least one distinct value from each fact's evidenceIds field.", "items": map[string]any{"type": "string"}},
	}}
	assessment := map[string]any{"type": "object", "additionalProperties": false,
		"required": []string{"decision", "category", "severity", "modelUncertainty", "summary", "affectedEntityIds", "claims", "uncertainties", "signalIds", "remediationSuggestions"},
		"properties": map[string]any{
			"decision":         map[string]any{"type": "string", "enum": decisionValues},
			"category":         map[string]any{"type": "string", "enum": categoryValues},
			"severity":         map[string]any{"type": "string", "enum": severityValues},
			"modelUncertainty": map[string]any{"type": "string", "enum": uncertaintyValues},
			"summary":          map[string]any{"type": "string"}, "affectedEntityIds": stringArray,
			"claims": map[string]any{"type": "array", "items": claim}, "uncertainties": stringArray,
			"signalIds":              map[string]any{"type": "array", "description": "For candidate_finding, copy the investigated signal IDs exactly.", "items": map[string]any{"type": "string"}},
			"remediationSuggestions": map[string]any{"type": "array", "maxItems": remediation.MaxSuggestions, "items": remediationSuggestion},
		},
	}
	return map[string]any{"type": "object", "additionalProperties": false, "required": []string{"assessment"}, "properties": map[string]any{"assessment": assessment}}
}

// toolArguments decodes a model's tool-call arguments as a JSON object.
func toolArguments(encoded []byte) (map[string]any, bool) {
	var arguments map[string]any
	if err := json.Unmarshal(encoded, &arguments); err != nil {
		return nil, false
	}
	return arguments, true
}
