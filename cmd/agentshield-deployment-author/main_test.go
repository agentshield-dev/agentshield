package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/reasoning"
)

func TestDecodeContext(t *testing.T) {
	input := `{"resourceId":"deployment-id","kind":"kubernetes/deployment","name":"payments","namespace":"prod","serviceAccountName":"payments-runtime"}`
	if _, err := decodeContext(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		`{"resourceId":"deployment-id","kind":"kubernetes/pod"}`,
		`{"resourceId":"deployment-id","kind":"kubernetes/deployment","unknown":"field"}`,
		`{"resourceId":"deployment-id","kind":"kubernetes/deployment","labels":{"app":"payments"}}`,
		`{"resourceId":"deployment-id","kind":"kubernetes/deployment"} {}`,
		`not-json`,
	} {
		if _, err := decodeContext(strings.NewReader(invalid)); err == nil {
			t.Fatalf("accepted invalid context %q", invalid)
		}
	}
}

func TestRunCallsAuthorWithoutDatabase(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer test-openai-key" {
			t.Errorf("Authorization = %q, want Bearer test-openai-key", got)
		}
		var body struct {
			Input []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if request.URL.Path != "/v1/responses" || len(body.Input) != 1 || !strings.Contains(body.Input[0].Content, `"kind":"kubernetes/deployment"`) || strings.Contains(body.Input[0].Content, "deployment-id") {
			t.Errorf("unexpected request %s input: %#v", request.URL.Path, body.Input)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"request-1","model":"test","status":"completed","output":[{"type":"function_call","call_id":"finish-1","name":"finish","arguments":"{\"rationale\":\"No supported rule is justified.\"}"}],"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12}}`))
	}))
	defer server.Close()
	input := `{"resourceId":"deployment-id","kind":"kubernetes/deployment","name":"payments","namespace":"prod"}`
	file := t.TempDir() + "/context.json"
	if err := os.WriteFile(file, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := run([]string{"--input", file, "--model-endpoint", server.URL}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"rationale": "No supported rule is justified."`) || !strings.Contains(output.String(), `"rules": []`) {
		t.Fatalf("proposal output = %s", output.String())
	}
}

func TestRunUsesAnthropicMessagesAPI(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/messages" {
			t.Errorf("request path=%q, want /v1/messages", request.URL.Path)
		}
		if request.Header.Get("x-api-key") != "test-anthropic-key" || request.Header.Get("Authorization") != "" || request.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("Anthropic request headers = %#v", request.Header)
		}
		var body struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != "claude-sonnet-4-6" {
			t.Errorf("model=%q, want claude-sonnet-4-6", body.Model)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"msg-1","model":"claude-sonnet-4-6","content":[{"type":"tool_use","id":"toolu_finish","name":"finish","input":{"rationale":"No supported rule is justified."}}],"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":2}}`))
	}))
	defer server.Close()
	input := `{"resourceId":"deployment-id","kind":"kubernetes/deployment","name":"payments","namespace":"prod"}`
	file := t.TempDir() + "/context.json"
	if err := os.WriteFile(file, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := run([]string{"--input", file, "--model-endpoint", server.URL, "--model-provider", "anthropic"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"rules": []`) {
		t.Fatalf("proposal output = %s", output.String())
	}
}

func TestRunDryRunPrintsExactProviderRequestWithoutProviderIO(t *testing.T) {
	t.Setenv("AGENTSHIELD_MODEL_ENDPOINT", "")
	t.Setenv("AGENTSHIELD_MODEL_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	input := `{"resourceId":"deployment-id","kind":"kubernetes/deployment","name":"istiod","namespace":"istio-system","serviceAccountName":"istiod"}`
	file := t.TempDir() + "/context.json"
	if err := os.WriteFile(file, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		provider string
		model    string
		flags    []string
	}{
		{name: "OpenAI", provider: "openai", model: reasoning.Model},
		{name: "Anthropic", provider: "anthropic", model: "claude-sonnet-4-6", flags: []string{"--model-provider", "anthropic"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output strings.Builder
			args := append([]string{"--input", file, "--dry-run"}, test.flags...)
			if err := run(args, &output); err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal([]byte(output.String()), &body); err != nil {
				t.Fatalf("dry-run output is not a request body: %v; output=%s", err, output.String())
			}
			if body["model"] != test.model {
				t.Fatalf("model=%v, want %q", body["model"], test.model)
			}
			if test.provider == "anthropic" {
				if body["system"] == nil || !strings.Contains(body["system"].(string), "Propose up to three security detection rules") {
					t.Errorf("Anthropic request omitted neutral authoring prompt: %#v", body["system"])
				}
				messages, ok := body["messages"].([]any)
				if !ok || len(messages) == 0 {
					t.Fatalf("Anthropic request omitted messages: %#v", body["messages"])
				}
				userMessage := messages[0].(map[string]any)
				content := userMessage["content"].([]any)
				if !strings.Contains(content[0].(map[string]any)["text"].(string), `"serviceAccountName":"istiod"`) {
					t.Errorf("Anthropic request omitted Deployment context")
				}
				if body["output_config"] != nil || body["tool_choice"].(map[string]any)["type"] != "any" {
					t.Errorf("Anthropic request must require a tool call without an output format: %#v %#v", body["output_config"], body["tool_choice"])
				}
			} else {
				if instructions, _ := body["instructions"].(string); !strings.Contains(instructions, "Propose up to three security detection rules") {
					t.Errorf("OpenAI request omitted neutral authoring instructions")
				}
				input, ok := body["input"].([]any)
				if !ok || len(input) != 1 {
					t.Fatalf("OpenAI input=%#v", body["input"])
				}
				userContent, _ := input[0].(map[string]any)["content"].(string)
				if !strings.Contains(userContent, `"serviceAccountName":"istiod"`) || strings.Contains(userContent, "labels") {
					t.Errorf("OpenAI request omitted Deployment context")
				}
				if body["text"] != nil || body["tool_choice"] != "required" {
					t.Errorf("OpenAI request must require a tool call without a response format: %#v %#v", body["text"], body["tool_choice"])
				}
			}
			tools, ok := body["tools"].([]any)
			if !ok || len(tools) == 0 {
				t.Fatalf("request omitted tool definitions: %#v", body["tools"])
			}
			var toolNames []string
			for _, item := range tools {
				toolNames = append(toolNames, item.(map[string]any)["name"].(string))
			}
			if strings.Join(toolNames, ",") != "add_rule,finish" {
				t.Errorf("dry-run tools=%v, want add_rule and finish", toolNames)
			}
			requestBody := output.String()
			if !strings.Contains(requestBody, "destination_ip_class") || !strings.Contains(requestBody, "destination_role") || !strings.Contains(requestBody, "communicates-with") || !strings.Contains(requestBody, "100.64.0.0/10") {
				t.Errorf("provider request omitted generated CEL or graph selector schema")
			}
			if strings.Contains(requestBody, "Cilium") {
				t.Errorf("provider request hardcodes a provider name")
			}
			if strings.Contains(output.String(), "test-openai-key") || strings.Contains(output.String(), "test-anthropic-key") {
				t.Errorf("request body unexpectedly contains credentials")
			}
		})
	}
}

func TestRunRequiresContextAndEndpoint(t *testing.T) {
	if err := run(nil, io.Discard); err == nil {
		t.Fatal("missing context accepted")
	}
	file := t.TempDir() + "/context.json"
	if err := os.WriteFile(file, []byte(`{"resourceId":"d","kind":"kubernetes/deployment"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--input", file, "--model-endpoint="}, io.Discard); err == nil {
		t.Fatal("missing endpoint accepted")
	}
}
