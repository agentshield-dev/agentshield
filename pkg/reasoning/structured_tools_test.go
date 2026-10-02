package reasoning

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func searchTool(t *testing.T, calls *int) StructuredTool {
	t.Helper()
	return StructuredTool{Name: "search", InputSchema: map[string]any{"type": "object"}, Execute: func(_ context.Context, args json.RawMessage) (json.RawMessage, error) {
		*calls++
		return json.RawMessage(`{"url":"https://docs.example/egress"}`), nil
	}}
}

func finishTestTool(failures int) StructuredTool {
	return StructuredTool{Name: "finish", Final: true, InputSchema: map[string]any{"type": "object"}, Execute: func(context.Context, json.RawMessage) (json.RawMessage, error) {
		if failures > 0 {
			failures--
			return nil, errors.New("rationale is required")
		}
		return json.RawMessage(`{"finished":true}`), nil
	}}
}

func responsesCall(id, name, arguments string) string {
	encoded, _ := json.Marshal(arguments)
	return `{"type":"function_call","call_id":"` + id + `","name":"` + name + `","arguments":` + string(encoded) + `}`
}

func responsesToolReply(id string, items ...string) []byte {
	return []byte(`{"id":"` + id + `","model":"gpt-test","status":"completed","output":[` + strings.Join(items, ",") + `]}`)
}

func TestToolLoopUsesResponsesAPIRequiresToolsAndReplaysOutputItems(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/responses" || request.Header.Get("Authorization") != "Bearer test-openai-key" {
			t.Errorf("request path=%q Authorization=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		var body struct {
			Model        string            `json:"model"`
			Store        *bool             `json:"store"`
			Instructions string            `json:"instructions"`
			Input        []json.RawMessage `json:"input"`
			Tools        []struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"tools"`
			ToolChoice      json.RawMessage `json:"tool_choice"`
			MaxOutputTokens int             `json:"max_output_tokens"`
			Text            json.RawMessage `json:"text"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != "gpt-test" || body.Store == nil || *body.Store || body.Instructions != "bounded system" || body.MaxOutputTokens != 3000 {
			t.Errorf("Responses request metadata = %#v", body)
		}
		if len(body.Text) != 0 || string(body.ToolChoice) != `"required"` || len(body.Tools) != 2 || body.Tools[0].Name != "search" || body.Tools[1].Name != "finish" {
			t.Errorf("turn %d must require one of both tools without a response format: tools=%#v choice=%s text=%s", requests+1, body.Tools, body.ToolChoice, body.Text)
		}
		requests++
		writer.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			_, _ = writer.Write(responsesToolReply("resp-1", `{"type":"reasoning","id":"rs_1","encrypted_content":"opaque"}`, responsesCall("call-1", "search", `{"query":"egress"}`)))
		case 2:
			var items []map[string]any
			for _, raw := range body.Input {
				var item map[string]any
				if err := json.Unmarshal(raw, &item); err != nil {
					t.Fatal(err)
				}
				items = append(items, item)
			}
			if len(items) != 4 || items[1]["type"] != "reasoning" || items[1]["encrypted_content"] != "opaque" || items[2]["call_id"] != "call-1" ||
				items[3]["type"] != "function_call_output" || !strings.Contains(items[3]["output"].(string), "docs.example") {
				t.Errorf("follow-up did not replay reasoning, call, and output: %#v", items)
			}
			_, _ = writer.Write(responsesToolReply("resp-2", responsesCall("call-2", "finish", `{"rationale":"done"}`)))
		default:
			t.Errorf("unexpected model request %d", requests)
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	calls := 0
	output, err := (Client{Endpoint: server.URL, APIKey: "test-openai-key", Model: "gpt-test", HTTPClient: server.Client()}).GenerateWithTools(
		context.Background(), "bounded system", json.RawMessage(`{"input":true}`), []StructuredTool{searchTool(t, &calls), finishTestTool(0)},
		StructuredToolLimits{MaxTurns: 3, MaxCalls: 2, MaxArgumentBytes: 1024, MaxResultBytes: 1024, MaxTotalResultBytes: 2048},
	)
	if err != nil {
		t.Fatal(err)
	}
	if output.FinalTool != "finish" || string(output.FinalArguments) != `{"rationale":"done"}` || calls != 1 || len(output.Calls) != 2 || requests != 2 {
		t.Fatalf("output=%#v calls=%d requests=%d", output, calls, requests)
	}
}

func TestToolLoopBudgetKeepsFinishAvailableAndForcesItOnTheLastTurn(t *testing.T) {
	requests := 0
	var choices []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Tools      []json.RawMessage `json:"tools"`
			ToolChoice json.RawMessage   `json:"tool_choice"`
			Input      []map[string]any  `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.Tools) != 2 {
			t.Errorf("turn %d tools=%s, want both tools on every turn", requests+1, body.Tools)
		}
		choices = append(choices, string(body.ToolChoice))
		requests++
		writer.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			_, _ = writer.Write(responsesToolReply("resp-1", responsesCall("call-1", "search", `{}`), responsesCall("call-2", "search", `{}`)))
		case 2:
			if last := body.Input[len(body.Input)-1]; !strings.Contains(last["output"].(string), "budget exhausted; call finish to finish") {
				t.Errorf("over-budget call result = %#v", last)
			}
			_, _ = writer.Write(responsesToolReply("resp-2", responsesCall("call-3", "finish", `{}`)))
		default:
			if last := body.Input[len(body.Input)-1]; !strings.Contains(last["output"].(string), "rationale is required") {
				t.Errorf("failed finish result = %#v", last)
			}
			_, _ = writer.Write(responsesToolReply("resp-3", responsesCall("call-4", "finish", `{"ok":true}`), responsesCall("call-5", "search", `{}`)))
		}
	}))
	defer server.Close()
	calls := 0
	output, err := (Client{Endpoint: server.URL, HTTPClient: server.Client()}).GenerateWithTools(
		context.Background(), "prompt", json.RawMessage(`{}`), []StructuredTool{searchTool(t, &calls), finishTestTool(1)},
		StructuredToolLimits{MaxTurns: 3, MaxCalls: 1, MaxArgumentBytes: 1024, MaxResultBytes: 1024, MaxTotalResultBytes: 4096},
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(output.FinalArguments) != `{"ok":true}` || len(output.Calls) != 5 || output.Calls[4].Error != "not executed: the run already finished" {
		t.Fatalf("calls=%d output=%#v", calls, output)
	}
	if len(choices) != 3 || choices[0] != `"required"` || choices[1] != `"required"` || choices[2] != `{"name":"finish","type":"function"}` {
		t.Fatalf("tool choices = %v, want required until the last turn forces finish", choices)
	}
}

func TestToolLoopRejectsMissingToolCallsAndUnfinishedRuns(t *testing.T) {
	for _, test := range []struct {
		name  string
		reply []byte
		want  string
	}{
		{"text instead of a tool call", []byte(`{"id":"r","model":"m","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"{}"}]}]}`), "no tool call"},
		{"never finishes", responsesToolReply("r", responsesCall("call", "search", `{}`)), "did not call finish"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write(test.reply)
			}))
			defer server.Close()
			calls := 0
			_, err := (Client{Endpoint: server.URL, HTTPClient: server.Client()}).GenerateWithTools(
				context.Background(), "prompt", json.RawMessage(`{}`), []StructuredTool{searchTool(t, &calls), finishTestTool(0)},
				StructuredToolLimits{MaxTurns: 2, MaxCalls: 4, MaxArgumentBytes: 1024, MaxResultBytes: 1024, MaxTotalResultBytes: 4096},
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}
	if _, err := (Client{}).GenerateWithTools(context.Background(), "prompt", json.RawMessage(`{}`), []StructuredTool{{Name: "search", InputSchema: map[string]any{}, Execute: func(context.Context, json.RawMessage) (json.RawMessage, error) { return nil, nil }}},
		StructuredToolLimits{MaxTurns: 1, MaxArgumentBytes: 1, MaxResultBytes: 1, MaxTotalResultBytes: 1}); err == nil || !strings.Contains(err.Error(), "final tool") {
		t.Fatalf("tools without a final tool: err=%v", err)
	}
}

func TestAnthropicToolLoopUsesNativeMessagesAPIWithoutOutputFormat(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/v1/messages" || request.Header.Get("x-api-key") != "test-anthropic-key" || request.Header.Get("Authorization") != "" || request.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("Anthropic request path=%q headers=%#v", request.URL.Path, request.Header)
		}
		var body struct {
			Model        string             `json:"model"`
			MaxTokens    int                `json:"max_tokens"`
			System       string             `json:"system"`
			Messages     []anthropicMessage `json:"messages"`
			OutputConfig json.RawMessage    `json:"output_config"`
			ToolChoice   map[string]any     `json:"tool_choice"`
			Tools        []struct {
				Name        string         `json:"name"`
				Strict      bool           `json:"strict"`
				InputSchema map[string]any `json:"input_schema"`
			} `json:"tools"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != anthropicModel || body.MaxTokens != 3000 || body.System != "bounded system" || len(body.OutputConfig) != 0 || body.ToolChoice["type"] != "any" {
			t.Errorf("Anthropic request metadata = %#v", body)
		}
		if len(body.Tools) != 2 || body.Tools[0].Name != "search" || !body.Tools[0].Strict {
			t.Errorf("Anthropic tools = %#v", body.Tools)
		}
		if query := body.Tools[0].InputSchema["properties"].(map[string]any)["query"].(map[string]any); query["maxLength"] != nil {
			t.Errorf("unsupported tool constraint was not moved into the description: %#v", query)
		}
		writer.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			if len(body.Messages) != 1 || body.Messages[0].Role != "user" {
				t.Errorf("initial messages = %#v", body.Messages)
			}
			_, _ = writer.Write([]byte(`{"id":"msg-1","model":"claude-sonnet-4-6","content":[{"type":"tool_use","id":"toolu_search","name":"search","input":{"query":"egress"}}],"stop_reason":"tool_use","usage":{"input_tokens":12,"output_tokens":3}}`))
			return
		}
		last := body.Messages[len(body.Messages)-1]
		if len(body.Messages) != 3 || body.Messages[1].Content[0]["type"] != "tool_use" || last.Content[0]["type"] != "tool_result" || last.Content[0]["tool_use_id"] != "toolu_search" {
			t.Errorf("follow-up conversation history = %#v", body.Messages)
		}
		_, _ = writer.Write([]byte(`{"id":"msg-2","model":"claude-sonnet-4-6","content":[{"type":"tool_use","id":"toolu_finish","name":"finish","input":{"rationale":"done"}}],"stop_reason":"tool_use","usage":{"input_tokens":20,"output_tokens":4}}`))
	}))
	defer server.Close()
	calls := 0
	search := searchTool(t, &calls)
	search.InputSchema = map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string", "maxLength": 20}}, "required": []string{"query"}, "additionalProperties": false}
	output, err := (Client{Endpoint: server.URL, APIKey: "test-anthropic-key", HTTPClient: server.Client(), Provider: ProviderAnthropic}).GenerateWithTools(
		context.Background(), "bounded system", json.RawMessage(`{"input":true}`), []StructuredTool{search, finishTestTool(0)},
		StructuredToolLimits{MaxTurns: 3, MaxCalls: 1, MaxArgumentBytes: 1024, MaxResultBytes: 1024, MaxTotalResultBytes: 2048},
	)
	if err != nil || string(output.FinalArguments) != `{"rationale":"done"}` || calls != 1 || requests != 2 {
		t.Fatalf("output=%#v calls=%d requests=%d err=%v", output, calls, requests, err)
	}
}
