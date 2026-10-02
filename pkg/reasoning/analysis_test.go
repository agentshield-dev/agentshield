package reasoning_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/reasoning/mcpserver"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

func TestAnalyzeCandidateSuppressesWithoutModelCall(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	outcome, err := reasoning.AnalyzeCandidate(context.Background(), reasoning.Client{Endpoint: server.URL}, reasoning.Packet{AnalysisID: "a", HydratedGraphSHA256: "g"}, reasoning.AnalysisConfig{Name: "compact", Compact: true})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || outcome.Promotion.Status != "suppressed" {
		t.Fatalf("calls = %d, outcome = %#v", calls.Load(), outcome)
	}
}

func TestAnalyzeCandidateLetsModelTraverseMCPAndPromotes(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Input []map[string]any `json:"input"`
			Tools []map[string]any `json:"tools"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		index := int(calls.Add(1))
		expectedTools := 6
		if index == 4 {
			expectedTools = 0
		}
		if len(body.Tools) != expectedTools {
			t.Errorf("tool count = %d, want %d", len(body.Tools), expectedTools)
		}
		message := map[string]any{"role": "assistant"}
		switch index {
		case 1:
			if encoded, _ := json.Marshal(body.Input); strings.Contains(string(encoded), "fact-1") {
				t.Error("initial request leaked telemetry")
			}
			message["tool_calls"] = []map[string]any{toolCall("call-1", "r1")}
		case 2:
			message["tool_calls"] = []map[string]any{toolCall("call-2", "r2")}
		case 3:
			response := reasoning.Response{Assessment: reasoning.Assessment{
				Decision: "candidate_finding", Category: "possible_lateral_path", Severity: "high", ModelUncertainty: "low",
				AffectedEntityIDs: []string{"r1", "r2", "r3"}, SignalIDs: []string{"signal-1"},
				Claims: []reasoning.Claim{{Mode: "observed", Text: "bounded path", SupportingIDs: []string{"signal-1", "r2", "evidence-1"}}},
			}}
			encoded, _ := json.Marshal(response)
			message["content"] = string(encoded)
		case 4:
			repairInstruction, _ := body.Input[len(body.Input)-1]["content"].(string)
			for _, required := range []string{"signal-1", "fact-1", "evidence-1"} {
				if !strings.Contains(repairInstruction, required) {
					t.Errorf("repair instruction omitted %q: %s", required, repairInstruction)
				}
			}
			response := reasoning.Response{Assessment: reasoning.Assessment{
				Decision: "candidate_finding", Category: "possible_lateral_path", Severity: "high", ModelUncertainty: "low",
				AffectedEntityIDs: []string{"r1", "r2", "r3"}, SignalIDs: []string{"signal-1"},
				Claims: []reasoning.Claim{{Mode: "observed", Text: "bounded path", SupportingIDs: []string{"signal-1", "fact-1", "evidence-1", "fact-2", "evidence-2"}}},
			}}
			encoded, _ := json.Marshal(response)
			message["content"] = string(encoded)
		default:
			t.Fatalf("unexpected model call %d", index)
		}
		writeModelResponse(writer, message)
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph",
		Resources: []reasoning.Resource{{ID: "r1"}, {ID: "r2"}, {ID: "r3"}},
		Signals:   []detector.InvestigationSignal{{ID: "signal-1", Risk: detector.RiskHigh, AnchorIDs: []string{"r1"}}},
	}
	provider, err := reasoning.NewContextProviderWithTelemetry(packet, reasoning.PinnedTelemetryContext{
		Token: reasoning.AnalysisToken{AnalysisID: "analysis", GraphSHA256: "graph"},
		Telemetry: []reasoning.Telemetry{
			{ID: "fact-1", SubjectID: "r1", ObjectID: "r2", EvidenceIDs: []string{"evidence-1"}},
			{ID: "fact-2", SubjectID: "r2", ObjectID: "r3", EvidenceIDs: []string{"evidence-2"}},
		},
	}, reasoning.DefaultContextLimits())
	if err != nil {
		t.Fatal(err)
	}
	session, closeSession, err := mcpserver.ConnectInMemory(context.Background(), provider)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeSession(); err != nil {
			t.Error(err)
		}
	})
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), reasoning.Client{Endpoint: server.URL}, packet, reasoning.AnalysisConfig{Name: "compact", Compact: true}, session)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 || len(outcome.Retrievals) != 2 || len(outcome.EffectivePacket.Telemetry) != 2 || outcome.Promotion.Status != "promoted" {
		t.Fatalf("calls = %d, outcome = %#v", calls.Load(), outcome)
	}
	if outcome.Usage().TotalTokens != 48 {
		t.Fatalf("total tokens = %d", outcome.Usage().TotalTokens)
	}
	if len(outcome.ModelResults) != 4 || outcome.ModelResults[0].Trace.Stage != "investigation" || outcome.ModelResults[3].Trace.Stage != "repair" {
		t.Fatalf("model traces = %#v", outcome.ModelResults)
	}
	if len(outcome.ModelResults[0].Trace.ToolCalls) != 1 || outcome.ModelResults[0].Trace.ToolCalls[0].Name != "get_telemetry_chain" {
		t.Fatalf("first model trace = %#v", outcome.ModelResults[0].Trace)
	}
	if outcome.ModelResults[3].Trace.Assessment == nil || outcome.ModelResults[3].Trace.Assessment.Decision != "candidate_finding" {
		t.Fatalf("repair trace = %#v", outcome.ModelResults[3].Trace)
	}
}

func TestAnalyzeCandidateExecutesParallelToolCallsWithoutRiskBudget(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		message := map[string]any{"role": "assistant"}
		if calls.Add(1) == 1 {
			message["tool_calls"] = []map[string]any{toolCall("call-1", "r1"), toolCall("call-2", "r1"), toolCall("call-3", "r1")}
		} else {
			if len(body.Tools) != 6 {
				t.Errorf("final request exposed %d tools", len(body.Tools))
			}
			encoded, _ := json.Marshal(validNoFindingResponse())
			message["content"] = string(encoded)
		}
		writeModelResponse(writer, message)
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "r1"}},
		Signals: []detector.InvestigationSignal{{ID: "signal-1", Risk: detector.RiskMedium, AnchorIDs: []string{"r1"}}},
	}
	session, closeSession := contextSession(t, packet, nil, reasoning.DefaultContextLimits())
	defer closeSession()
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), reasoning.Client{Endpoint: server.URL}, packet, reasoning.AnalysisConfig{}, session)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(outcome.Retrievals) != 3 || outcome.Response.Assessment.Decision != "no_finding" {
		t.Fatalf("calls = %d, outcome = %#v", calls.Load(), outcome)
	}
}

func TestAnalyzeCandidateDeterministicallyRetrievesGovernanceThroughTopology(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Input []map[string]any `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(body.Input)
		for _, required := range []string{"governed-by", "network-policy", "policy-targeting"} {
			if !strings.Contains(string(encoded), required) {
				t.Errorf("deterministic context omitted %q", required)
			}
		}
		response, _ := json.Marshal(validNoFindingResponse())
		writeModelResponse(writer, map[string]any{"content": string(response)})
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", SuggestedContextAnchors: []string{"deployment", "service"},
		Resources: []reasoning.Resource{{ID: "deployment"}, {ID: "service"}, {ID: "pod"}, {ID: "network-policy", Kind: "kubernetes/networkpolicy"}},
		Relationships: []reasoning.Relationship{
			{ID: "deploys", SubjectID: "deployment", Predicate: "instantiates", ObjectID: "pod"},
			{ID: "selects", SubjectID: "service", Predicate: graph.PredicateExposes, ObjectID: "pod"},
			{ID: "governance", SubjectID: "pod", Predicate: "governed-by", ObjectID: "network-policy", EvidenceIDs: []string{"evidence"}},
		},
		Facets:  []reasoning.Facet{{ID: "targeting", ResourceID: "network-policy", Kind: "policy-targeting", EvidenceIDs: []string{"evidence"}}},
		Signals: []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskMedium, AnchorIDs: []string{"deployment", "service"}}},
	}
	session, closeSession := contextSession(t, packet, nil, reasoning.DefaultContextLimits())
	defer closeSession()
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), reasoning.Client{Endpoint: server.URL}, packet, reasoning.AnalysisConfig{Compact: true, RetrievalMode: reasoning.RetrievalDeterministic}, session)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Retrievals) != 4 || len(outcome.EffectivePacket.Relationships) != 3 {
		t.Fatalf("retrievals = %d, relationships = %#v", len(outcome.Retrievals), outcome.EffectivePacket.Relationships)
	}
}

func TestAnalyzeCandidateResponsesReplaysReasoningAndFunctionItems(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("Accept-Encoding = %q, want identity", got)
		}
		var body struct {
			Store bool              `json:"store"`
			Input []json.RawMessage `json:"input"`
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Store || len(body.Tools) != 6 {
			t.Fatalf("store = %t, tools = %d", body.Store, len(body.Tools))
		}
		call := calls.Add(1)
		output := []any{}
		if call == 1 {
			output = append(output,
				map[string]any{"type": "reasoning", "id": "reasoning-1", "encrypted_content": "opaque"},
				map[string]any{"type": "function_call", "id": "function-1", "call_id": "call-1", "name": "get_telemetry_chain", "arguments": `{"anchorIds":["r1"]}`},
			)
		} else {
			encodedInput, _ := json.Marshal(body.Input)
			for _, required := range []string{"reasoning-1", "function-1", "function_call_output", "call-1"} {
				if !strings.Contains(string(encodedInput), required) {
					t.Errorf("Responses continuation omitted %q: %s", required, encodedInput)
				}
			}
			response, _ := json.Marshal(validNoFindingResponse())
			output = append(output, map[string]any{"type": "message", "id": "message-1", "role": "assistant", "status": "completed", "content": []map[string]any{{"type": "output_text", "text": string(response)}}})
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"id": "response", "model": "reasoning-model", "status": "completed", "output": output,
			"usage": map[string]any{"input_tokens": 10, "output_tokens": 3, "total_tokens": 13, "output_tokens_details": map[string]any{"reasoning_tokens": 2}},
		})
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "r1"}},
		Signals: []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskMedium, AnchorIDs: []string{"r1"}}},
	}
	session, closeSession := contextSession(t, packet, nil, reasoning.DefaultContextLimits())
	defer closeSession()
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), reasoning.Client{Endpoint: server.URL, Model: "reasoning-model", ReasoningEffort: "low"}, packet, reasoning.AnalysisConfig{}, session)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(outcome.Retrievals) != 1 || outcome.Usage().ReasoningTokens != 4 {
		t.Fatalf("calls = %d, outcome = %#v", calls.Load(), outcome)
	}
}

func TestAnalyzeCandidateCanRecoverFromToolValidationError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Input []map[string]any `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		message := map[string]any{"role": "assistant"}
		if calls.Add(1) == 1 {
			message["tool_calls"] = []map[string]any{toolCall("bad-call", "unknown-anchor")}
		} else {
			encodedMessages, _ := json.Marshal(body.Input)
			if !strings.Contains(string(encodedMessages), "context anchor") {
				t.Fatalf("tool error was not returned to model: %s", encodedMessages)
			}
			encoded, _ := json.Marshal(validNoFindingResponse())
			message["content"] = string(encoded)
		}
		writeModelResponse(writer, message)
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "r1"}},
		Signals: []detector.InvestigationSignal{{ID: "signal-1", Risk: detector.RiskLow, AnchorIDs: []string{"r1"}}},
	}
	session, closeSession := contextSession(t, packet, nil, reasoning.DefaultContextLimits())
	defer closeSession()
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), reasoning.Client{Endpoint: server.URL}, packet, reasoning.AnalysisConfig{}, session)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(outcome.Retrievals) != 0 || outcome.Response.Assessment.Decision != "no_finding" {
		t.Fatalf("calls = %d, outcome = %#v", calls.Load(), outcome)
	}
}

func TestInvestigationToolLoopIsBounded(t *testing.T) {
	var calls atomic.Int32
	var choices []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			ToolChoice string           `json:"tool_choice"`
			Input      []map[string]any `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		choices = append(choices, body.ToolChoice)
		message := map[string]any{"role": "assistant"}
		switch calls.Add(1) {
		case 1:
			message["tool_calls"] = []map[string]any{toolCall("call-1", "r1"), toolCall("call-2", "r1")}
		case 2:
			if last := body.Input[len(body.Input)-1]; !strings.Contains(last["output"].(string), "budget exhausted") {
				t.Errorf("over-budget call result = %#v", last)
			}
			// A model that keeps calling tools.
			message["tool_calls"] = []map[string]any{toolCall("call-3", "r1")}
		default:
			encoded, _ := json.Marshal(validNoFindingResponse())
			message["content"] = string(encoded)
		}
		writeModelResponse(writer, message)
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "r1"}},
		Signals: []detector.InvestigationSignal{{ID: "signal-1", Risk: detector.RiskMedium, AnchorIDs: []string{"r1"}}},
	}
	session, closeSession := contextSession(t, packet, nil, reasoning.DefaultContextLimits())
	defer closeSession()
	client := reasoning.Client{Endpoint: server.URL, InvestigationLimits: reasoning.StructuredToolLimits{
		MaxTurns: 3, MaxCalls: 1, MaxArgumentBytes: 1024, MaxResultBytes: 64 << 10, MaxTotalResultBytes: 128 << 10,
	}}
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), client, packet, reasoning.AnalysisConfig{}, session)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || len(outcome.Retrievals) != 1 || outcome.Response.Assessment.Decision != "no_finding" {
		t.Fatalf("calls=%d retrievals=%d outcome=%#v", calls.Load(), len(outcome.Retrievals), outcome.Response)
	}
	if len(choices) != 3 || choices[0] != "auto" || choices[1] != "auto" || choices[2] != "none" {
		t.Fatalf("tool choices = %v, want the last turn to require an answer", choices)
	}
}

func TestRepairAllowlistMatchesValidationIncludingInitialPacketFacts(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Input []map[string]any `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		message := map[string]any{"role": "assistant"}
		switch calls.Add(1) {
		case 1:
			encoded, _ := json.Marshal(reasoning.Response{Assessment: reasoning.Assessment{
				Decision: "no_finding", Category: "unknown_security_effect", Severity: "none", ModelUncertainty: "low", AffectedEntityIDs: []string{"missing"},
			}})
			message["content"] = string(encoded)
		default:
			instruction, _ := body.Input[len(body.Input)-1]["content"].(string)
			if !strings.Contains(instruction, `"fact-0"`) || !strings.Contains(instruction, `"evidence-0"`) || !strings.Contains(instruction, `"signal-1"`) {
				t.Errorf("repair allowlist omits initial packet facts: %s", instruction)
			}
			encoded, _ := json.Marshal(validNoFindingResponse())
			message["content"] = string(encoded)
		}
		writeModelResponse(writer, message)
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "r1"}, {ID: "r2"}},
		Relationships: []reasoning.Relationship{{ID: "fact-0", SubjectID: "r1", Predicate: "communicates-with", ObjectID: "r2", EvidenceIDs: []string{"evidence-0"}}},
		Signals:       []detector.InvestigationSignal{{ID: "signal-1", Risk: detector.RiskMedium, AnchorIDs: []string{"r1"}}},
	}
	session, closeSession := contextSession(t, packet, nil, reasoning.DefaultContextLimits())
	defer closeSession()
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), reasoning.Client{Endpoint: server.URL}, packet, reasoning.AnalysisConfig{}, session)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || outcome.Validation != "accepted" {
		t.Fatalf("calls=%d outcome=%#v", calls.Load(), outcome)
	}
}

func validNoFindingResponse() reasoning.Response {
	return reasoning.Response{Assessment: reasoning.Assessment{
		Decision: "no_finding", Category: "unknown_security_effect", Severity: "none", ModelUncertainty: "low",
		AffectedEntityIDs: []string{}, Claims: []reasoning.Claim{}, Uncertainties: []string{}, SignalIDs: []string{}, RemediationSuggestions: []remediation.Suggestion{},
	}}
}

func TestAnalyzeCandidateRejectsFindingFromTruncatedContext(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		message := map[string]any{"role": "assistant"}
		if calls.Add(1) == 1 {
			message["tool_calls"] = []map[string]any{toolCall("call-1", "r1")}
		} else {
			encoded, _ := json.Marshal(reasoning.Response{Assessment: reasoning.Assessment{
				Decision: "candidate_finding", Category: "possible_lateral_path", Severity: "high", ModelUncertainty: "low",
				AffectedEntityIDs: []string{"r1"}, SignalIDs: []string{"signal-1"},
				Claims: []reasoning.Claim{{Mode: "observed", Text: "bounded path", SupportingIDs: []string{"signal-1", "fact-1", "evidence-1"}}},
			}})
			message["content"] = string(encoded)
		}
		writeModelResponse(writer, message)
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "r1"}, {ID: "r2"}},
		Signals: []detector.InvestigationSignal{{ID: "signal-1", Risk: detector.RiskLow, AnchorIDs: []string{"r1"}}},
	}
	telemetry := []reasoning.Telemetry{{ID: "fact-1", SubjectID: "r1", ObjectID: "r2", EvidenceIDs: []string{"evidence-1"}}}
	session, closeSession := contextSession(t, packet, telemetry, reasoning.ContextLimits{Resources: 1, Relationships: 10, Facets: 10, Telemetry: 10})
	defer closeSession()
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), reasoning.Client{Endpoint: server.URL}, packet, reasoning.AnalysisConfig{}, session)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Validation != "rejected" || outcome.Promotion.Reason != "candidate_context_truncated" {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestAnalyzeCandidateRejectsRepairedFindingFromTruncatedContext(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		message := map[string]any{"role": "assistant"}
		switch calls.Add(1) {
		case 1:
			message["tool_calls"] = []map[string]any{toolCall("call-1", "r1")}
		case 2:
			encoded, _ := json.Marshal(reasoning.Response{Assessment: reasoning.Assessment{
				Decision: "no_finding", Category: "unknown_security_effect", AffectedEntityIDs: []string{"missing"},
			}})
			message["content"] = string(encoded)
		case 3:
			encoded, _ := json.Marshal(reasoning.Response{Assessment: reasoning.Assessment{
				Decision: "candidate_finding", Category: "possible_lateral_path", Severity: "high", ModelUncertainty: "low",
				AffectedEntityIDs: []string{"r1"}, SignalIDs: []string{"signal-1"},
				Claims: []reasoning.Claim{{Mode: "observed", Text: "bounded path", SupportingIDs: []string{"signal-1", "fact-1", "evidence-1"}}},
			}})
			message["content"] = string(encoded)
		default:
			t.Fatal("unexpected model call")
		}
		writeModelResponse(writer, message)
	}))
	defer server.Close()
	packet := reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "r1"}, {ID: "r2"}},
		Signals: []detector.InvestigationSignal{{ID: "signal-1", Risk: detector.RiskLow, AnchorIDs: []string{"r1"}}},
	}
	telemetry := []reasoning.Telemetry{{ID: "fact-1", SubjectID: "r1", ObjectID: "r2", EvidenceIDs: []string{"evidence-1"}}}
	session, closeSession := contextSession(t, packet, telemetry, reasoning.ContextLimits{Resources: 1, Relationships: 10, Facets: 10, Telemetry: 10})
	defer closeSession()
	outcome, err := reasoning.AnalyzeCandidateWithTools(context.Background(), reasoning.Client{Endpoint: server.URL}, packet, reasoning.AnalysisConfig{}, session)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || outcome.Validation != "rejected" || outcome.Promotion.Reason != "candidate_context_truncated" {
		t.Fatalf("calls = %d, outcome = %#v", calls.Load(), outcome)
	}
}

func contextSession(t *testing.T, packet reasoning.Packet, telemetry []reasoning.Telemetry, limits reasoning.ContextLimits) (*mcp.ClientSession, func()) {
	t.Helper()
	provider, err := reasoning.NewContextProviderWithTelemetry(packet, reasoning.PinnedTelemetryContext{
		Token: reasoning.AnalysisToken{AnalysisID: packet.AnalysisID, GraphSHA256: packet.HydratedGraphSHA256}, Telemetry: telemetry,
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	session, closeSession, err := mcpserver.ConnectInMemory(context.Background(), provider)
	if err != nil {
		t.Fatal(err)
	}
	return session, func() {
		if err := closeSession(); err != nil {
			t.Error(err)
		}
	}
}

func toolCall(id, anchor string) map[string]any {
	arguments, _ := json.Marshal(map[string]any{
		"anchorIds": []string{anchor},
	})
	return map[string]any{
		"id": "function-" + id, "type": "function_call", "call_id": id,
		"name": "get_telemetry_chain", "arguments": string(arguments),
	}
}

func writeModelResponse(writer http.ResponseWriter, message map[string]any) {
	var output any
	if toolCalls, ok := message["tool_calls"]; ok {
		output = toolCalls
	} else {
		output = []map[string]any{{
			"type": "message", "id": "message", "role": "assistant", "status": "completed",
			"content": []map[string]any{{"type": "output_text", "text": message["content"]}},
		}}
	}
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"id": "response", "model": reasoning.Model, "status": "completed", "output": output,
		"usage": map[string]any{"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
	})
}
