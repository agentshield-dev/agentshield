package resourceauthoring

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

func testWorkload() state.ResourceAuthoringContext {
	return state.ResourceAuthoringContext{
		ResourceID: "deployment-id", Kind: "kubernetes/deployment", Name: "payments", Namespace: "prod",
		ContextSHA256: strings.Repeat("a", 64), Context: json.RawMessage(`{"workload":{"serviceAccountName":"payments-runtime"}}`),
	}
}

func TestBuildProposalAppliesHostOwnedScopeAndMetadata(t *testing.T) {
	proposal, err := buildProposal(testWorkload(), modelDraft{Rationale: "New public destinations are unusual for this resource.", Rules: []modelRule{{Risk: detector.RiskMedium,
		Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public'", Rationale: "Alert on new public destinations.",
	}}}, detector.CELSelectorNames())
	if err != nil {
		t.Fatal(err)
	}
	want := detector.Rule{
		ID: "deployment/1a6e56990dae2f0b7bfff93dc0e91948/v-aaaaaaaaaaaa/r-1653ce7b06c875e78ad70e7d21895fc22d06531c4637a8c1f0218a781a6ccaf6", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*", ScopeResourceID: "deployment-id",
		Type: "relationship", Kind: "communicates-with", Expression: "destination_ip_class == 'public'",
		Risk: detector.RiskMedium, Reasons: []string{draftReason}, WindowSeconds: draftWindowSeconds,
	}
	if len(proposal.Rules) != 1 || !reflect.DeepEqual(proposal.Rules[0].Rule, want) {
		t.Fatalf("proposal=%#v, want rule %#v", proposal, want)
	}
}

func TestBuildProposalRejectsInvalidDrafts(t *testing.T) {
	valid := modelRule{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "true", Rationale: "r"}
	for _, test := range []struct {
		name   string
		mutate func(*modelDraft)
	}{
		{"unknown selector", func(draft *modelDraft) { draft.Rules[0].Selector = "resource:kubernetes/deployment" }},
		{"undeclared variable", func(draft *modelDraft) { draft.Rules[0].Expression = "operation == 'egress'" }},
		{"invalid risk", func(draft *modelDraft) { draft.Rules[0].Risk = "urgent" }},
		{"missing rationale", func(draft *modelDraft) { draft.Rules[0].Rationale = "" }},
		{"too many rules", func(draft *modelDraft) {
			for _, expression := range []string{"destination_role == ''", "destination_ip_class == 'public'", "destination_ip_class == 'private'"} {
				draft.Rules = append(draft.Rules, modelRule{Risk: detector.RiskMedium, Selector: valid.Selector, Expression: expression, Rationale: "r"})
			}
		}},
		{"duplicate rule", func(draft *modelDraft) {
			draft.Rules = append(draft.Rules, modelRule{Risk: detector.RiskMedium, Selector: valid.Selector, Expression: " " + valid.Expression + " ", Rationale: "other"})
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
		{"populated relationship fields", modelRule{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public' && destination_role == ''", Rationale: "r"}, true, ""},
		{"populated telemetry fields", modelRule{Risk: detector.RiskMedium, Selector: "telemetry:network-flow", Expression: "operation == 'egress' && outcome == 'forwarded'", Rationale: "r"}, true, ""},
		{"process class", modelRule{Risk: detector.RiskMedium, Selector: "relationship:executes", Expression: "process_class == 'shell'", Rationale: "r"}, true, ""},
		{"field the relationship does not populate", modelRule{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "operation == 'egress'", Rationale: "r"}, false, "undeclared reference to 'operation'"},
		{"unknown selector", modelRule{Risk: detector.RiskMedium, Selector: "relationship:not-a-predicate", Expression: "true", Rationale: "r"}, false, "unsupported selector"},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector := &ruleCollector{resource: testWorkload(), selectors: detector.CELSelectorNames()}
			result := addRule(t, collector, test.rule)
			if result.Added != test.added || !strings.Contains(result.Error, test.error) || (len(collector.rules) == 1) != test.added {
				t.Fatalf("added=%t error=%q recorded=%d, want added=%t with %q", result.Added, result.Error, len(collector.rules), test.added, test.error)
			}
		})
	}
}

func TestAddRuleRecordsDistinctRulesUpToTheLimit(t *testing.T) {
	var logs bytes.Buffer
	collector := &ruleCollector{resource: testWorkload(), selectors: detector.CELSelectorNames(), logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	rules := []modelRule{
		{Risk: detector.RiskHigh, Selector: "relationship:executes", Expression: "process_class == 'shell'", Rationale: "Interactive shells are unexpected."},
		{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public'", Rationale: "Public egress is unexpected."},
		{Risk: detector.RiskLow, Selector: "telemetry:network-flow", Expression: "outcome == 'dropped'", Rationale: "Dropped flows indicate probing."},
	}
	if result := addRule(t, collector, rules[0]); !result.Added || result.Remaining != maxDraftRules-1 {
		t.Fatalf("first rule result = %#v", result)
	}
	if result := addRule(t, collector, modelRule{Risk: detector.RiskMedium, Selector: rules[0].Selector, Expression: rules[0].Expression, Rationale: "again"}); result.Added || !strings.Contains(result.Error, "repeats") {
		t.Fatalf("duplicate rule result = %#v", result)
	}
	if result := addRule(t, collector, modelRule{Risk: detector.RiskMedium, Selector: "relationship:executes", Expression: "operation == 'x'", Rationale: "r"}); result.Added {
		t.Fatalf("invalid rule result = %#v", result)
	}
	for _, rule := range rules[1:] {
		if result := addRule(t, collector, rule); !result.Added {
			t.Fatalf("rule %#v result = %#v", rule, result)
		}
	}
	if result := addRule(t, collector, modelRule{Risk: detector.RiskMedium, Selector: "relationship:exposes", Expression: "true", Rationale: "r"}); result.Added || !strings.Contains(result.Error, "3 rules") {
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
	wantPrefix := "deployment/1a6e56990dae2f0b7bfff93dc0e91948/v-aaaaaaaaaaaa/r-"
	for index, rule := range proposal.Rules {
		if !strings.HasPrefix(rule.Rule.ID, wantPrefix) || rule.Rule.ScopeResourceID != "deployment-id" || rule.Rule.Risk != rules[index].Risk {
			t.Fatalf("rule %d = %#v, want revision-scoped ID with prefix %s", index, rule.Rule, wantPrefix)
		}
	}
}

func TestFinishRequiresABoundedRationale(t *testing.T) {
	for _, test := range []struct {
		arguments string
		valid     bool
	}{
		{`{"rationale":"No field distinguishes this resource."}`, true},
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

func TestModelAuthorSendsResourceContextAndAppliesHostScope(t *testing.T) {
	resource := testWorkload()
	resource.Kind = "kubernetes/clusterrolebinding"
	resource.Name, resource.Namespace = "lab-admin", ""
	resource.Context = json.RawMessage(`{}`)
	resource.Attributes = map[string]string{"kubernetes/rbac-role-ref-kind": "ClusterRole", "kubernetes/rbac-role-ref-name": "cluster-admin"}
	rule := modelRule{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public' && destination_role == ''", Rationale: "Detect new public destinations."}
	toolArguments, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	finishArguments, err := json.Marshal(map[string]string{"rationale": "The resource should not reach unknown public addresses."})
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
			want := map[string]any{
				"kind": "kubernetes/clusterrolebinding", "name": "lab-admin", "context": map[string]any{},
				"attributes": map[string]any{"kubernetes/rbac-role-ref-kind": "ClusterRole", "kubernetes/rbac-role-ref-name": "cluster-admin"},
			}
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
	proposal, err := (ModelAuthor{Client: reasoning.Client{Endpoint: server.URL, HTTPClient: server.Client()}, Logger: logger}).Author(context.Background(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "add_rule added rule") || !strings.Contains(logs.String(), "add_rule_calls=1 accepted_rules=1") {
		t.Fatalf("debug logs omit the add_rule trace or run summary:\n%s", logs.String())
	}
	if requests != 2 || len(proposal.Rules) != 1 || len(proposal.ToolCalls) != 2 || proposal.Rules[0].Rule.ScopeResourceID != "deployment-id" || !bytes.Equal(proposal.Context, resource.Context) || !reflect.DeepEqual(proposal.Attributes, resource.Attributes) ||
		proposal.Rationale != "The resource should not reach unknown public addresses." {
		t.Fatalf("requests=%d proposal=%#v", requests, proposal)
	}
}

func TestModelAuthorBoundsEncodedInput(t *testing.T) {
	resource := testWorkload()
	resource.ObservedBehavior = &state.WorkloadBehavior{Requests: make([]state.ObservedRequest, state.MaxObservedRequests)}
	for index := range resource.ObservedBehavior.Requests {
		resource.ObservedBehavior.Requests[index] = state.ObservedRequest{
			Telemetry: strings.Repeat("\x00", 128), Destination: strings.Repeat("\x00", 507), DestinationKind: strings.Repeat("\x00", 128),
			DestinationResourceID: strings.Repeat("\x00", 128), DestinationRole: strings.Repeat("\x00", 64), Operation: strings.Repeat("\x00", 256), Outcome: strings.Repeat("\x00", 64),
		}
	}
	if _, err := (ModelAuthor{}).Author(context.Background(), resource); err == nil || !strings.Contains(err.Error(), fmt.Sprint(ModelAuthorInputMaxBytes)) {
		t.Fatalf("encoded input limit was not enforced: %v", err)
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

type authorFunc func(context.Context, state.ResourceAuthoringContext) (Proposal, error)

func (author authorFunc) Author(ctx context.Context, resource state.ResourceAuthoringContext) (Proposal, error) {
	return author(ctx, resource)
}

type fakeJobStore struct {
	completed   json.RawMessage
	retried     string
	retryAfter  time.Duration
	terminal    bool
	outcome     state.ResourceRuleRetry
	claimErr    error
	claims      int
	minAge      time.Duration
	behavior    state.WorkloadBehavior
	behaviorErr error
}

func (store *fakeJobStore) ClaimResourceRuleJob(_ context.Context, _ string, _, minAge time.Duration) (state.ResourceRuleJob, bool, error) {
	store.claims++
	store.minAge = minAge
	if store.claimErr != nil {
		return state.ResourceRuleJob{}, false, store.claimErr
	}
	return state.ResourceRuleJob{ID: 42, Context: testWorkload()}, true, nil
}

func (store *fakeJobStore) WorkloadObservedBehavior(context.Context, string) (state.WorkloadBehavior, error) {
	return store.behavior, store.behaviorErr
}

func (store *fakeJobStore) ResourceRuleQueueStats(context.Context, time.Duration) (state.ResourceRuleQueueStats, error) {
	return state.ResourceRuleQueueStats{}, nil
}

func (store *fakeJobStore) RenewResourceRuleJob(context.Context, int64, string, time.Duration) (bool, error) {
	return true, nil
}

func (store *fakeJobStore) CompleteResourceRuleJob(_ context.Context, _ int64, _ string, proposal json.RawMessage) error {
	store.completed = proposal
	return nil
}

func (store *fakeJobStore) RetryResourceRuleJob(_ context.Context, _ int64, _ string, failure string, retryAfter time.Duration, terminal bool) (state.ResourceRuleRetry, error) {
	store.retried, store.retryAfter, store.terminal = failure, retryAfter, terminal
	return store.outcome, nil
}

func TestNewWorkerRequiresStoreAuthorAndLease(t *testing.T) {
	validStore := &fakeJobStore{}
	validAuthor := authorFunc(func(context.Context, state.ResourceAuthoringContext) (Proposal, error) { return Proposal{}, nil })
	if _, err := NewWorker(validStore, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: validAuthor}); err != nil {
		t.Fatalf("valid worker config rejected: %v", err)
	}
	for _, config := range []WorkerConfig{
		{ID: "worker", LeaseDuration: 2 * time.Second, Author: validAuthor},
		{ID: "worker", LeaseDuration: 5 * time.Second},
		{ID: "worker", LeaseDuration: 5 * time.Second, Author: validAuthor, StabilizationWindow: -time.Second},
		{ID: "worker", LeaseDuration: 5 * time.Second, Author: validAuthor, StabilizationWindow: MaxStabilizationWindow + time.Second},
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
	baseline := state.WorkloadBehavior{CollectedTelemetry: []string{"active-probe"}, Requests: []state.ObservedRequest{{Telemetry: "active-probe", Operation: "GET /v1/products", Count: 3}}}
	store := &fakeJobStore{behavior: baseline}
	var seen state.ResourceAuthoringContext
	worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(_ context.Context, resource state.ResourceAuthoringContext) (Proposal, error) {
		seen = resource
		return Proposal{Rationale: "No rule is justified.", Rules: []ProposalRule{}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), state.ResourceRuleJob{ID: 42, Context: testWorkload()}); err != nil {
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
	worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(context.Context, state.ResourceAuthoringContext) (Proposal, error) {
		called = true
		return Proposal{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), state.ResourceRuleJob{ID: 42, Context: testWorkload()}); err == nil {
		t.Fatal("baseline failure was not reported")
	}
	if called || !strings.Contains(store.retried, "graph not materialized") || len(store.completed) != 0 {
		t.Fatalf("called=%t retried=%q completed=%s", called, store.retried, store.completed)
	}
}

func TestDraftRuleIDsAreScopedToTheContextRevision(t *testing.T) {
	resource := testWorkload()
	resource.ContextSHA256 = strings.Repeat("ab", 32)
	proposal, err := buildProposal(resource, modelDraft{Rationale: "r", Rules: []modelRule{{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "true", Rationale: "r"}}}, detector.CELSelectorNames())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := proposal.Rules[0].Rule.ID, "deployment/1a6e56990dae2f0b7bfff93dc0e91948/v-abababababab/r-42e0b61c24c44c92d2c59b7192473f5eaeb68590df3247befd4c09569dc6f247"; got != want {
		t.Fatalf("rule ID = %q, want %q", got, want)
	}
	for _, kind := range []string{"kubernetes/statefulset", "kubernetes/daemonset"} {
		resource.Kind = kind
		proposal, err = buildProposal(resource, modelDraft{Rationale: "r", Rules: []modelRule{{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "true", Rationale: "r"}}}, detector.CELSelectorNames())
		if err != nil {
			t.Fatal(err)
		}
		if got, want := proposal.Rules[0].Rule.ID, strings.TrimPrefix(kind, "kubernetes/")+"/1a6e56990dae2f0b7bfff93dc0e91948/v-abababababab/r-42e0b61c24c44c92d2c59b7192473f5eaeb68590df3247befd4c09569dc6f247"; got != want {
			t.Fatalf("rule ID = %q, want %q", got, want)
		}
	}
	resource.Kind = "kubernetes/statefulset"
	resource.ResourceID = strings.Repeat("x", 128)
	proposal, err = buildProposal(resource, modelDraft{Rationale: "r", Rules: []modelRule{{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "true", Rationale: "r"}}}, detector.CELSelectorNames())
	if err != nil || len(proposal.Rules[0].Rule.ID) > 128 {
		t.Fatalf("maximum resource ID produced invalid rule identity: %#v err=%v", proposal, err)
	}
	resource.Kind = "kubernetes/job"
	if err := ValidateContext(resource); err != nil {
		t.Fatalf("generic resource context was rejected: %v", err)
	}
	resource.Kind = "kubernetes/deployment"
	resource.ContextSHA256 = "short"
	if err := ValidateContext(resource); err == nil {
		t.Fatal("a malformed context revision was accepted")
	}
}

func TestDraftRuleIDsFollowLogicAcrossReordering(t *testing.T) {
	first := modelRule{Risk: detector.RiskMedium, Selector: "relationship:communicates-with", Expression: "destination_ip_class == 'public'", Rationale: "r"}
	second := modelRule{Risk: detector.RiskMedium, Selector: "relationship:executes", Expression: "process_class == 'shell'", Rationale: "r"}
	proposal, err := buildProposal(testWorkload(), modelDraft{Rules: []modelRule{first, second}}, detector.CELSelectorNames())
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := buildProposal(testWorkload(), modelDraft{Rules: []modelRule{second, first}}, detector.CELSelectorNames())
	if err != nil {
		t.Fatal(err)
	}
	if proposal.Rules[0].Rule.ID != reordered.Rules[1].Rule.ID || proposal.Rules[1].Rule.ID != reordered.Rules[0].Rule.ID {
		t.Fatalf("rule IDs changed after reorder: %#v %#v", proposal.Rules, reordered.Rules)
	}
	changed := first
	changed.Expression = "destination_ip_class == 'private'"
	changedProposal, err := buildProposal(testWorkload(), modelDraft{Rules: []modelRule{changed}}, detector.CELSelectorNames())
	if err != nil {
		t.Fatal(err)
	}
	if changedProposal.Rules[0].Rule.ID == proposal.Rules[0].Rule.ID {
		t.Fatalf("changed logic reused rule ID %q", proposal.Rules[0].Rule.ID)
	}
	base := proposal.Rules[0].Rule
	baseID, err := ruleID(testWorkload(), base)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*detector.Rule)
	}{
		{name: "risk", mutate: func(rule *detector.Rule) { rule.Risk = detector.RiskHigh }},
		{name: "reasons", mutate: func(rule *detector.Rule) { rule.Reasons = []string{"different_reason"} }},
		{name: "window", mutate: func(rule *detector.Rule) { rule.WindowSeconds++ }},
		{name: "plugin", mutate: func(rule *detector.Rule) { rule.PluginID = "kubernetes" }},
		{name: "input version", mutate: func(rule *detector.Rule) { rule.InputVersion = "v2" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			changedID, err := ruleID(testWorkload(), changed)
			if err != nil {
				t.Fatal(err)
			}
			if changedID == baseID {
				t.Fatalf("changed %s reused rule ID %q", test.name, baseID)
			}
		})
	}
	base.ID, base.Revision = "ignored", 99
	if got, err := ruleID(testWorkload(), base); err != nil || got != baseID {
		t.Fatalf("ID or revision affected behavior identity: got=%q want=%q err=%v", got, baseID, err)
	}
}

func TestWorkerSchedulesRetryAfterAuthorFailure(t *testing.T) {
	store := &fakeJobStore{}
	worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(context.Context, state.ResourceAuthoringContext) (Proposal, error) {
		return Proposal{}, errors.New("model unavailable")
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), state.ResourceRuleJob{ID: 42, Context: testWorkload()}); err == nil {
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
			worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(context.Context, state.ResourceAuthoringContext) (Proposal, error) {
				if test.panics {
					panic("author bug")
				}
				return Proposal{}, test.err
			})})
			if err != nil {
				t.Fatal(err)
			}
			if err := worker.process(context.Background(), state.ResourceRuleJob{ID: 42, AttemptCount: test.attempt, Context: testWorkload()}); err == nil {
				t.Fatal("failure was not reported")
			}
			if !strings.Contains(store.retried, test.want) || store.retryAfter != test.wantDelay || store.terminal != test.wantTerminal || len(store.completed) != 0 {
				t.Fatalf("retried=%q after %s terminal=%t, want %q after %s terminal=%t", store.retried, store.retryAfter, store.terminal, test.want, test.wantDelay, test.wantTerminal)
			}
		})
	}
}

func TestWorkerDropsSupersededJobWithoutReportingFailure(t *testing.T) {
	store := &fakeJobStore{outcome: state.ResourceRuleRetrySuperseded}
	worker, err := NewWorker(store, WorkerConfig{ID: "worker", LeaseDuration: 5 * time.Second, Author: authorFunc(func(context.Context, state.ResourceAuthoringContext) (Proposal, error) {
		return Proposal{}, errors.New("model unavailable")
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.process(context.Background(), state.ResourceRuleJob{ID: 42, AttemptCount: 1, Context: testWorkload()}); err != nil {
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
		ID: "worker", PollInterval: time.Hour, LeaseDuration: 5 * time.Second, StabilizationWindow: 6 * time.Hour,
		Author:      authorFunc(func(context.Context, state.ResourceAuthoringContext) (Proposal, error) { return Proposal{}, nil }),
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
	selectors, err := ModelAuthor{Selectors: []string{"telemetry:active-probe", "relationship:communicates-with"}}.selectors(testWorkload())
	if err != nil || len(selectors) != 2 {
		t.Fatalf("selectors=%v err=%v", selectors, err)
	}
	if all, err := (ModelAuthor{}).selectors(testWorkload()); err != nil || len(all) != len(detector.CELSelectorNames())+1 || all[len(all)-1] != "resource:kubernetes/deployment" {
		t.Fatalf("default selectors=%v err=%v", all, err)
	}
	if _, err := (ModelAuthor{Selectors: []string{"telemetry:unknown"}}).selectors(testWorkload()); err == nil {
		t.Fatal("unknown selector accepted")
	}
	schema := modelRuleSchema(selectors)["properties"].(map[string]any)["selector"].(map[string]any)
	if enum := schema["enum"].([]string); len(enum) != 2 || strings.Contains(schema["description"].(string), "network-flow") {
		t.Fatalf("selector schema offers more than the allowlist: %v", schema)
	}
	draft := modelDraft{Rationale: "r", Rules: []modelRule{{Risk: detector.RiskMedium, Selector: "telemetry:network-flow", Expression: "outcome == 'dropped'", Rationale: "r"}}}
	if _, err := buildProposal(testWorkload(), draft, selectors); err == nil {
		t.Fatal("a selector outside the allowlist was accepted")
	}
	collector := &ruleCollector{resource: testWorkload(), selectors: selectors}
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
	resource := testWorkload()
	resource.ContextSHA256 = strings.Repeat("ab", 32)
	resource.ObservedBehavior = &state.WorkloadBehavior{Requests: []state.ObservedRequest{}}
	if _, err := (ModelAuthor{Client: reasoning.Client{Endpoint: server.URL, HTTPClient: server.Client()}}).Author(context.Background(), resource); err != nil {
		t.Fatal(err)
	}
	if behavior, ok := input["observedBehavior"].(map[string]any); !ok || !reflect.DeepEqual(behavior["requests"], []any{}) {
		t.Fatalf("an empty baseline was not sent as an empty request list: %#v", input)
	}
	if _, sent := input["contextSha256"]; sent {
		t.Fatalf("the template digest was sent to the model: %#v", input)
	}

	resource.ObservedBehavior.Requests = make([]state.ObservedRequest, state.MaxObservedRequests+1)
	if err := ValidateContext(resource); err == nil {
		t.Fatal("observed behavior over the request limit was accepted")
	}
	resource.ObservedBehavior.Requests = []state.ObservedRequest{{Operation: strings.Repeat("a", 257)}}
	if err := ValidateContext(resource); err == nil {
		t.Fatal("observed operation over the field limit was accepted")
	}
	resource.ObservedBehavior.Requests = nil
	resource.ObservedBehavior.CollectedTelemetry = make([]string, state.MaxCollectedTelemetry+1)
	if err := ValidateContext(resource); err == nil {
		t.Fatal("collected telemetry over the kind limit was accepted")
	}
}
