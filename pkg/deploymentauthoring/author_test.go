package deploymentauthoring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

func testWorkload() state.DeploymentAuthoringContext {
	return state.DeploymentAuthoringContext{ResourceID: "deployment-id", Kind: "kubernetes/deployment", Name: "payments", Namespace: "prod", ServiceAccountName: "payments-runtime"}
}

func TestBuildProposalAppliesHostOwnedScopeAndMetadata(t *testing.T) {
	proposal, err := buildProposal(testWorkload(), modelDraft{Rationale: "New public destinations are unusual for this workload.", Rules: []modelRule{{
		Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public'", Rationale: "Alert on new public destinations.",
	}}}, detector.CELSelectorNames())
	if err != nil {
		t.Fatal(err)
	}
	want := detector.Rule{
		ID: "deployment/deployment-id/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*", WorkloadResourceID: "deployment-id",
		Type: "relationship", Kind: "communicates-with", Expression: "destination_ip_class == 'public'",
		Risk: draftRisk, Reasons: []string{draftReason}, WindowSeconds: draftWindowSeconds,
	}
	if len(proposal.Rules) != 1 || !reflect.DeepEqual(proposal.Rules[0].Rule, want) {
		t.Fatalf("proposal=%#v, want rule %#v", proposal, want)
	}
}

func TestBuildProposalRejectsInvalidDrafts(t *testing.T) {
	valid := modelRule{Selector: "relationship:communicates-with", Expression: "true", Rationale: "r"}
	for _, test := range []struct {
		name   string
		mutate func(*modelDraft)
	}{
		{"unknown selector", func(draft *modelDraft) { draft.Rules[0].Selector = "resource:kubernetes/deployment" }},
		{"undeclared variable", func(draft *modelDraft) { draft.Rules[0].Expression = "operation == 'egress'" }},
		{"missing rationale", func(draft *modelDraft) { draft.Rules[0].Rationale = "" }},
		{"too many rules", func(draft *modelDraft) {
			for _, expression := range []string{"destination_role == ''", "destination_ip_class == 'public'", "destination_ip_class == 'private'"} {
				draft.Rules = append(draft.Rules, modelRule{Selector: valid.Selector, Expression: expression, Rationale: "r"})
			}
		}},
		{"duplicate rule", func(draft *modelDraft) {
			draft.Rules = append(draft.Rules, modelRule{Selector: valid.Selector, Expression: " " + valid.Expression + " ", Rationale: "other"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			draft := modelDraft{Rules: []modelRule{valid}}
			test.mutate(&draft)
			if _, err := buildProposal(testWorkload(), draft, detector.CELSelectorNames()); err == nil {
				t.Fatal("invalid draft accepted")
			}
		})
	}
}

func TestAddRuleValidatesAgainstSelectorEnvironment(t *testing.T) {
	for _, test := range []struct {
		name  string
		rule  modelRule
		added bool
		error string
	}{
		{"populated relationship fields", modelRule{Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public' && destination_role == ''", Rationale: "r"}, true, ""},
		{"populated telemetry fields", modelRule{Selector: "telemetry:network-flow", Expression: "operation == 'egress' && outcome == 'forwarded'", Rationale: "r"}, true, ""},
		{"process class", modelRule{Selector: "relationship:executes", Expression: "process_class == 'shell'", Rationale: "r"}, true, ""},
		{"field the relationship does not populate", modelRule{Selector: "relationship:communicates-with", Expression: "operation == 'egress'", Rationale: "r"}, false, "undeclared reference to 'operation'"},
		{"unknown selector", modelRule{Selector: "relationship:not-a-predicate", Expression: "true", Rationale: "r"}, false, "unsupported selector"},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector := &ruleCollector{workload: testWorkload(), selectors: detector.CELSelectorNames()}
			result := addRule(t, collector, test.rule)
			if result.Added != test.added || !strings.Contains(result.Error, test.error) || (len(collector.rules) == 1) != test.added {
				t.Fatalf("added=%t error=%q recorded=%d, want added=%t with %q", result.Added, result.Error, len(collector.rules), test.added, test.error)
			}
		})
	}
}

func TestAddRuleRecordsDistinctRulesUpToTheLimit(t *testing.T) {
	var logs bytes.Buffer
	collector := &ruleCollector{workload: testWorkload(), selectors: detector.CELSelectorNames(), logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	rules := []modelRule{
		{Selector: "relationship:executes", Expression: "process_class == 'shell'", Rationale: "Interactive shells are unexpected."},
		{Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public'", Rationale: "Public egress is unexpected."},
		{Selector: "telemetry:network-flow", Expression: "outcome == 'dropped'", Rationale: "Dropped flows indicate probing."},
	}
	if result := addRule(t, collector, rules[0]); !result.Added || result.Remaining != maxDraftRules-1 {
		t.Fatalf("first rule result = %#v", result)
	}
	if result := addRule(t, collector, modelRule{Selector: rules[0].Selector, Expression: rules[0].Expression, Rationale: "again"}); result.Added || !strings.Contains(result.Error, "repeats") {
		t.Fatalf("duplicate rule result = %#v", result)
	}
	if result := addRule(t, collector, modelRule{Selector: "relationship:executes", Expression: "operation == 'x'", Rationale: "r"}); result.Added {
		t.Fatalf("invalid rule result = %#v", result)
	}
	for _, rule := range rules[1:] {
		if result := addRule(t, collector, rule); !result.Added {
			t.Fatalf("rule %#v result = %#v", rule, result)
		}
	}
	if result := addRule(t, collector, modelRule{Selector: "relationship:exposes", Expression: "true", Rationale: "r"}); result.Added || !strings.Contains(result.Error, "3 rules") {
		t.Fatalf("over-limit rule result = %#v", result)
	}
	if !reflect.DeepEqual(collector.rules, rules) {
		t.Fatalf("recorded rules = %#v, want only the accepted rules %#v", collector.rules, rules)
	}
	if added, rejected := strings.Count(logs.String(), "add_rule added rule"), strings.Count(logs.String(), "add_rule rejected rule"); added != 3 || rejected != 3 {
		t.Fatalf("logged %d added and %d rejected rules, want 3 and 3:\n%s", added, rejected, logs.String())
	}
	proposal, err := buildProposal(testWorkload(), modelDraft{Rules: collector.rules}, detector.CELSelectorNames())
	if err != nil {
		t.Fatal(err)
	}
	for index, rule := range proposal.Rules {
		if want := fmt.Sprintf("deployment/deployment-id/rule-%d", index+1); rule.Rule.ID != want || rule.Rule.WorkloadResourceID != "deployment-id" {
			t.Fatalf("rule %d = %#v, want ID %s scoped to the workload", index, rule.Rule, want)
		}
	}
}

func TestFinishRequiresABoundedRationale(t *testing.T) {
	for _, test := range []struct {
		arguments string
		valid     bool
	}{
		{`{"rationale":"No field distinguishes this workload."}`, true},
		{`{"rationale":""}`, false},
		{`{"rationale":"` + strings.Repeat("x", 2049) + `"}`, false},
		{`{}`, false},
		{`{"rationale":"r","rules":[]}`, false},
	} {
		_, err := finishTool().Execute(context.Background(), json.RawMessage(test.arguments))
		if (err == nil) != test.valid {
			t.Fatalf("finish %.40s: err=%v, want valid=%t", test.arguments, err, test.valid)
		}
	}
	if !finishTool().Final {
		t.Fatal("finish must end the tool run")
	}
}

type addRuleResult struct {
	Added     bool   `json:"added"`
	Error     string `json:"error"`
	Remaining int    `json:"remaining"`
}

func addRule(t *testing.T, collector *ruleCollector, rule modelRule) addRuleResult {
	t.Helper()
	arguments, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := collector.addRuleTool().Execute(context.Background(), arguments)
	if err != nil {
		t.Fatal(err)
	}
	var result addRuleResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestModelAuthorSendsMinimalContextAndAppliesHostScope(t *testing.T) {
	rule := modelRule{Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public' && destination_role == ''", Rationale: "Detect new public destinations."}
	toolArguments, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	finishArguments, err := json.Marshal(map[string]string{"rationale": "The workload should not reach unknown public addresses."})
	if err != nil {
		t.Fatal(err)
	}
	responses := [][]byte{
		fmt.Appendf(nil, `{"id":"resp-1","model":"test","status":"completed","output":[{"type":"function_call","call_id":"add-1","name":"add_rule","arguments":%q}]}`, toolArguments),
		fmt.Appendf(nil, `{"id":"resp-2","model":"test","status":"completed","output":[{"type":"function_call","call_id":"finish-1","name":"finish","arguments":%q}]}`, finishArguments),
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Text         json.RawMessage  `json:"text"`
			ToolChoice   string           `json:"tool_choice"`
			Instructions string           `json:"instructions"`
			Input        []map[string]any `json:"input"`
			Tools        []struct {
				Name       string         `json:"name"`
				Parameters map[string]any `json:"parameters"`
			} `json:"tools"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if requests == 0 {
			if len(body.Text) != 0 || body.ToolChoice != "required" {
				t.Errorf("request must require a tool call without a response format: text=%s tool_choice=%q", body.Text, body.ToolChoice)
			}
			if len(body.Tools) != 2 || body.Tools[0].Name != "add_rule" || body.Tools[1].Name != "finish" {
				t.Errorf("offered tools=%#v, want add_rule and finish", body.Tools)
			} else if parameters, _ := json.Marshal(body.Tools[0].Parameters); !strings.Contains(string(parameters), "destination_role") || !strings.Contains(string(parameters), "process_class") {
				t.Errorf("add_rule does not carry the generated rule contract: %s", parameters)
			}
			if strings.Contains(body.Instructions, "CEL") || strings.Contains(body.Instructions, "destination_ip_class") || strings.Contains(body.Instructions, "public") {
				t.Errorf("system prompt discloses the rule contract: %s", body.Instructions)
			}
			var input map[string]any
			if err := json.Unmarshal([]byte(body.Input[0]["content"].(string)), &input); err != nil {
				t.Error(err)
			}
			want := map[string]any{"kind": "kubernetes/deployment", "name": "payments", "namespace": "prod", "serviceAccountName": "payments-runtime"}
			if !reflect.DeepEqual(input, want) {
				t.Errorf("model input=%#v, want %#v", input, want)
			}
		} else if last := body.Input[len(body.Input)-1]; last["type"] != "function_call_output" || !strings.Contains(last["output"].(string), `"added":true`) {
			t.Errorf("follow-up omitted an accepted add_rule result: %#v", last)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(responses[requests])
		requests++
	}))
	defer server.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proposal, err := (ModelAuthor{Client: reasoning.Client{Endpoint: server.URL, HTTPClient: server.Client()}, Logger: logger}).Author(context.Background(), testWorkload())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "add_rule added rule") || !strings.Contains(logs.String(), "add_rule_calls=1 accepted_rules=1") {
		t.Fatalf("debug logs omit the add_rule trace or run summary:\n%s", logs.String())
	}
	if requests != 2 || len(proposal.Rules) != 1 || len(proposal.ToolCalls) != 2 || proposal.Rules[0].Rule.WorkloadResourceID != "deployment-id" ||
		proposal.Rationale != "The workload should not reach unknown public addresses." {
		t.Fatalf("requests=%d proposal=%#v", requests, proposal)
	}
}

func TestRetryDelayCaps(t *testing.T) {
	if got := retryDelay(1); got != time.Second {
		t.Fatalf("first retry delay=%s", got)
	}
	if got := retryDelay(100); got != 256*time.Second {
		t.Fatalf("capped retry delay=%s", got)
	}
}

type authorFunc func(context.Context, state.DeploymentAuthoringContext) (Proposal, error)

func (author authorFunc) Author(ctx context.Context, workload state.DeploymentAuthoringContext) (Proposal, error) {
	return author(ctx, workload)
}

type fakeJobStore struct {
	completed   json.RawMessage
	retried     string
	retryAfter  time.Duration
	terminal    bool
	outcome     state.DeploymentRuleRetry
	claimErr    error
	claims      int
	minAge      time.Duration
	behavior    state.DeploymentBehavior
	behaviorErr error
}

func (store *fakeJobStore) ClaimDeploymentRuleJob(_ context.Context, _ string, _, minAge time.Duration) (state.DeploymentRuleJob, bool, error) {
	store.claims++
	store.minAge = minAge
	if store.claimErr != nil {
		return state.DeploymentRuleJob{}, false, store.claimErr
	}
	return state.DeploymentRuleJob{ID: 42, Context: testWorkload()}, true, nil
}

func (store *fakeJobStore) DeploymentObservedBehavior(context.Context, string) (state.DeploymentBehavior, error) {
	return store.behavior, store.behaviorErr
}

func (store *fakeJobStore) DeploymentRuleQueueStats(context.Context, time.Duration) (state.DeploymentRuleQueueStats, error) {
	return state.DeploymentRuleQueueStats{}, nil
}

func (store *fakeJobStore) RenewDeploymentRuleJob(context.Context, int64, string, time.Duration) (bool, error) {
	return true, nil
}

func (store *fakeJobStore) CompleteDeploymentRuleJob(_ context.Context, _ int64, _ string, proposal json.RawMessage) error {
	store.completed = proposal
	return nil
}

func (store *fakeJobStore) RetryDeploymentRuleJob(_ context.Context, _ int64, _ string, failure string, retryAfter time.Duration, terminal bool) (state.DeploymentRuleRetry, error) {
	store.retried, store.retryAfter, store.terminal = failure, retryAfter, terminal
	return store.outcome, nil
}

func TestNewWorkerRequiresStoreAuthorAndLease(t *testing.T) {
	validStore := &fakeJobStore{}
	validAuthor := authorFunc(func(context.Context, state.DeploymentAuthoringContext) (Proposal, error) { return Proposal{}, nil })
	if _, err := NewWorker(validStore, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: validAuthor}); err != nil {
		t.Fatalf("valid worker config rejected: %v", err)
	}
	for _, config := range []WorkerConfig{
		{ID: "worker", LeaseDuration: 2 * time.Second, Author: validAuthor},
		{ID: "worker", LeaseDuration: 5 * time.Second},
		{ID: "worker", LeaseDuration: 5 * time.Second, Author: validAuthor, BaselineWindow: -time.Second},
		{ID: "worker", LeaseDuration: 5 * time.Second, Author: validAuthor, BaselineWindow: MaxBaselineWindow + time.Second},
	} {
		if _, err := NewWorker(validStore, config); err == nil {
			t.Fatal("invalid worker config accepted")
		}
	}
	if _, err := NewWorker(nil, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: validAuthor}); err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestWorkerAuthorsFromTheCurrentBaselineAndPersistsProposal(t *testing.T) {
	baseline := state.DeploymentBehavior{CollectedTelemetry: []string{"active-probe"}, Requests: []state.ObservedRequest{{Telemetry: "active-probe", Operation: "GET /v1/products", Count: 3}}}
	store := &fakeJobStore{behavior: baseline}
	var seen state.DeploymentAuthoringContext
	worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(_ context.Context, workload state.DeploymentAuthoringContext) (Proposal, error) {
		seen = workload
		return Proposal{Rationale: "No rule is justified.", Rules: []ProposalRule{}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), state.DeploymentRuleJob{ID: 42, Context: testWorkload()}); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(store.completed) || store.retried != "" {
		t.Fatalf("completed=%s retried=%q", store.completed, store.retried)
	}
	if seen.ObservedBehavior == nil || !reflect.DeepEqual(*seen.ObservedBehavior, baseline) || seen.Name != testWorkload().Name {
		t.Fatalf("author context = %#v, want the job identity with the current baseline", seen)
	}
}

func TestWorkerRetriesWhenTheBaselineCannotBeRead(t *testing.T) {
	store := &fakeJobStore{behaviorErr: errors.New("graph not materialized")}
	called := false
	worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(context.Context, state.DeploymentAuthoringContext) (Proposal, error) {
		called = true
		return Proposal{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), state.DeploymentRuleJob{ID: 42, Context: testWorkload()}); err == nil {
		t.Fatal("baseline failure was not reported")
	}
	if called || !strings.Contains(store.retried, "graph not materialized") || len(store.completed) != 0 {
		t.Fatalf("called=%t retried=%q completed=%s", called, store.retried, store.completed)
	}
}

func TestDraftRuleIDsAreScopedToTheTemplateRevision(t *testing.T) {
	workload := testWorkload()
	workload.TemplateSHA256 = strings.Repeat("ab", 32)
	proposal, err := buildProposal(workload, modelDraft{Rationale: "r", Rules: []modelRule{{Selector: "relationship:communicates-with", Expression: "true", Rationale: "r"}}}, detector.CELSelectorNames())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := proposal.Rules[0].Rule.ID, "deployment/deployment-id/template-abababababab/rule-1"; got != want {
		t.Fatalf("rule ID = %q, want %q", got, want)
	}
	workload.TemplateSHA256 = "short"
	if err := ValidateContext(workload); err == nil {
		t.Fatal("a malformed template digest was accepted")
	}
}

func TestWorkerSchedulesRetryAfterAuthorFailure(t *testing.T) {
	store := &fakeJobStore{}
	worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(context.Context, state.DeploymentAuthoringContext) (Proposal, error) {
		return Proposal{}, errors.New("model unavailable")
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), state.DeploymentRuleJob{ID: 42, Context: testWorkload()}); err == nil {
		t.Fatal("author failure was not reported")
	}
	if store.retried != "model unavailable" || len(store.completed) != 0 {
		t.Fatalf("retried=%q completed=%s", store.retried, store.completed)
	}
}

func TestWorkerGivesUpOnRepeatedPermanentAndPanickingFailures(t *testing.T) {
	for _, test := range []struct {
		name         string
		attempt      int
		err          error
		panics       bool
		wantDelay    time.Duration
		wantTerminal bool
		want         string
	}{
		{name: "transient failure", attempt: 1, err: errors.New("model unavailable"), wantDelay: retryDelay(1), want: "model unavailable"},
		{name: "backoff grows", attempt: 4, err: errors.New("model unavailable"), wantDelay: retryDelay(4), want: "model unavailable"},
		{name: "attempts exhausted", attempt: 8, err: errors.New("model unavailable"), wantDelay: retryDelay(8), wantTerminal: true, want: "model unavailable"},
		{name: "invalid request", attempt: 1, err: &reasoning.StatusError{StatusCode: 400, Status: "400 Bad Request"}, wantDelay: retryDelay(1), wantTerminal: true, want: "400"},
		{name: "panic", attempt: 1, panics: true, wantDelay: retryDelay(1), want: "panic: author bug"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeJobStore{}
			worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(context.Context, state.DeploymentAuthoringContext) (Proposal, error) {
				if test.panics {
					panic("author bug")
				}
				return Proposal{}, test.err
			})})
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.process(context.Background(), state.DeploymentRuleJob{ID: 42, AttemptCount: test.attempt, Context: testWorkload()}); err == nil {
				t.Fatal("failure was not reported")
			}
			if !strings.Contains(store.retried, test.want) || store.retryAfter != test.wantDelay || store.terminal != test.wantTerminal || len(store.completed) != 0 {
				t.Fatalf("retried=%q after %s terminal=%t, want %q after %s terminal=%t", store.retried, store.retryAfter, store.terminal, test.want, test.wantDelay, test.wantTerminal)
			}
		})
	}
}

func TestWorkerDropsSupersededJobWithoutReportingFailure(t *testing.T) {
	store := &fakeJobStore{outcome: state.DeploymentRuleRetrySuperseded}
	worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(context.Context, state.DeploymentAuthoringContext) (Proposal, error) {
		return Proposal{}, errors.New("model unavailable")
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), state.DeploymentRuleJob{ID: 42, AttemptCount: 1, Context: testWorkload()}); err != nil {
		t.Fatalf("superseded job reported %v", err)
	}
	if store.retried == "" {
		t.Fatal("failure was not recorded")
	}
}

func TestWorkerReportsQueueReadFailuresAndKeepsRunning(t *testing.T) {
	store := &fakeJobStore{claimErr: errors.New("database unavailable")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reported := false
	worker, err := NewWorker(store, WorkerConfig{
		ID: "worker", PollInterval: time.Hour, LeaseDuration: 5 * time.Second, BaselineWindow: 6 * time.Hour,
		Author:      authorFunc(func(context.Context, state.DeploymentAuthoringContext) (Proposal, error) { return Proposal{}, nil }),
		ReportError: func(error) { reported = true; cancel() },
	})
	if err != nil {
		t.Fatal(err)
	}
	worker.Run(ctx)
	if !reported || store.claims != 1 || store.minAge != 6*time.Hour {
		t.Fatalf("reported=%t claims=%d minAge=%s", reported, store.claims, store.minAge)
	}
}

func TestModelAuthorSelectorAllowlist(t *testing.T) {
	selectors, err := ModelAuthor{Selectors: []string{"telemetry:active-probe", "relationship:communicates-with"}}.selectors()
	if err != nil || len(selectors) != 2 {
		t.Fatalf("selectors=%v err=%v", selectors, err)
	}
	if all, err := (ModelAuthor{}).selectors(); err != nil || len(all) != len(detector.CELSelectorNames()) {
		t.Fatalf("default selectors=%v err=%v", all, err)
	}
	if _, err := (ModelAuthor{Selectors: []string{"telemetry:unknown"}}).selectors(); err == nil {
		t.Fatal("unknown selector accepted")
	}
	schema := modelRuleSchema(selectors)["properties"].(map[string]any)["selector"].(map[string]any)
	if enum := schema["enum"].([]string); len(enum) != 2 || strings.Contains(schema["description"].(string), "network-flow") {
		t.Fatalf("selector schema offers more than the allowlist: %v", schema)
	}
	draft := modelDraft{Rationale: "r", Rules: []modelRule{{Selector: "telemetry:network-flow", Expression: "outcome == 'dropped'", Rationale: "r"}}}
	if _, err := buildProposal(testWorkload(), draft, selectors); err == nil {
		t.Fatal("a selector outside the allowlist was accepted")
	}
	collector := &ruleCollector{workload: testWorkload(), selectors: selectors}
	if result := addRule(t, collector, draft.Rules[0]); result.Added || len(collector.rules) != 0 {
		t.Fatalf("add_rule accepted a selector outside the allowlist: %#v", result)
	}
}

func TestModelAuthorSendsObservedBehaviorAndValidatesItsLimits(t *testing.T) {
	var input map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Input []map[string]any `json:"input"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if err := json.Unmarshal([]byte(body.Input[0]["content"].(string)), &input); err != nil {
			t.Error(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"id":"resp-1","model":"test","status":"completed","output":[{"type":"function_call","call_id":"finish-1","name":"finish","arguments":%q}]}`, `{"rationale":"none"}`)
	}))
	defer server.Close()
	workload := testWorkload()
	workload.TemplateSHA256 = strings.Repeat("ab", 32)
	workload.ObservedBehavior = &state.DeploymentBehavior{Requests: []state.ObservedRequest{}}
	if _, err := (ModelAuthor{Client: reasoning.Client{Endpoint: server.URL, HTTPClient: server.Client()}}).Author(context.Background(), workload); err != nil {
		t.Fatal(err)
	}
	if behavior, ok := input["observedBehavior"].(map[string]any); !ok || !reflect.DeepEqual(behavior["requests"], []any{}) {
		t.Fatalf("an empty baseline was not sent as an empty request list: %#v", input)
	}
	if _, sent := input["templateSha256"]; sent {
		t.Fatalf("the template digest was sent to the model: %#v", input)
	}

	workload.ObservedBehavior.Requests = make([]state.ObservedRequest, state.MaxObservedRequests+1)
	if err := ValidateContext(workload); err == nil {
		t.Fatal("observed behavior over the request limit was accepted")
	}
	workload.ObservedBehavior.Requests = []state.ObservedRequest{{Operation: strings.Repeat("a", 257)}}
	if err := ValidateContext(workload); err == nil {
		t.Fatal("observed operation over the field limit was accepted")
	}
	workload.ObservedBehavior.Requests = nil
	workload.ObservedBehavior.CollectedTelemetry = make([]string, state.MaxCollectedTelemetry+1)
	if err := ValidateContext(workload); err == nil {
		t.Fatal("collected telemetry over the kind limit was accepted")
	}
}
