package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

var testScheme = graph.IdentityScheme{Group: "test.example.io", Version: "v1", Kind: "Object"}

const testGraphSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const testActionID = "test-action/v1"

func TestProposalIDIsDeterministic(t *testing.T) {
	suggestion := Suggestion{Intent: IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"signal", "evidence"}}
	target := Target{EntityID: "target", Identity: graph.IdentityClaim{Scheme: testScheme, AuthorityID: "cluster", ImmutableKey: "v1/pod/uid"}, Kind: "kubernetes/pod"}
	first, err := NewProposal("finding", "analysis", testGraphSHA256, suggestion, target, []string{"signal", "evidence", "signal"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewProposal("finding", "analysis", testGraphSHA256, suggestion, target, []string{"evidence", "signal"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || len(first.EvidenceIDs) != 2 {
		t.Fatalf("proposal IDs differ: %q and %q", first.ID, second.ID)
	}
}

func TestSuggestionSupportingIDsAreBoundedAndUnique(t *testing.T) {
	tooMany := make([]string, MaxSupportingIDs+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("support-%d", index)
	}
	tests := []struct {
		name       string
		supporting []string
		want       string
	}{
		{name: "duplicate", supporting: []string{"signal", "signal"}, want: "duplicate"},
		{name: "over bound", supporting: tooMany, want: "exceeds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			suggestion := Suggestion{Intent: IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: test.supporting}
			if err := suggestion.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestProposalValidationRejectsRecomputedMalformedJSONBeforeRouting(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	graphReads := 0
	executor, err := NewExecutor(registry, func(context.Context) (GraphView, error) {
		graphReads++
		return testGraphView(testGraphSHA256, "cluster"), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*Proposal)
	}{
		{name: "empty finding", mutate: func(proposal *Proposal) { proposal.FindingID = "" }},
		{name: "empty analysis", mutate: func(proposal *Proposal) { proposal.AnalysisID = "" }},
		{name: "malformed graph digest", mutate: func(proposal *Proposal) { proposal.GraphSHA256 = "graph" }},
		{name: "empty support", mutate: func(proposal *Proposal) { proposal.SupportingIDs = nil }},
		{name: "empty evidence", mutate: func(proposal *Proposal) { proposal.EvidenceIDs = nil }},
		{name: "invalid intent", mutate: func(proposal *Proposal) { proposal.Intent = "unknown" }},
		{name: "empty target", mutate: func(proposal *Proposal) { proposal.Target.EntityID = "" }},
		{name: "noncanonical target", mutate: func(proposal *Proposal) { proposal.Target.EntityID = " target " }},
		{name: "malformed identity", mutate: func(proposal *Proposal) { proposal.Target.Identity.ImmutableKey = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proposal := testProposal(t, testGraphSHA256, "cluster")
			test.mutate(&proposal)
			proposal.ID = ""
			proposal.ID = canonicalID("proposal", proposal)

			if _, err := registry.Candidates(proposal); err == nil {
				t.Fatal("candidate enumeration accepted malformed proposal")
			}
			if _, _, err := registry.Provider(proposal, provider.id, testActionID); err == nil {
				t.Fatal("provider routing accepted malformed proposal")
			}
			if _, err := executor.Plan(context.Background(), proposal, provider.id, testActionID); err == nil {
				t.Fatal("executor planning accepted malformed proposal")
			}
		})
	}
	if graphReads != 0 {
		t.Fatalf("graph reads = %d, want 0", graphReads)
	}
}

func TestRegistryEnumeratesOverlappingProvidersStablyAndRequiresSelection(t *testing.T) {
	first := &testProvider{id: "z-provider", authority: "cluster"}
	second := &testProvider{id: "a-provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(first), testRegistration(second))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	candidates, err := registry.Candidates(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].ProviderID != "a-provider" || candidates[1].ProviderID != "z-provider" {
		t.Fatalf("candidates = %#v", candidates)
	}
	if _, _, err := registry.Provider(proposal, "", ""); err == nil || !strings.Contains(err.Error(), "explicit provider") {
		t.Fatalf("ambiguous provider error = %v", err)
	}
	if provider, _, err := registry.Provider(proposal, "z-provider", testActionID); err != nil || provider != first {
		t.Fatalf("selected provider = %#v, err = %v", provider, err)
	}
	if _, _, err := registry.Provider(testProposal(t, "graph", "other"), "z-provider", testActionID); err == nil {
		t.Fatal("registry routed a different authority")
	}
}

func TestRegistryRejectsDuplicateProviderIDsAndActions(t *testing.T) {
	if _, err := NewRegistry(testRegistration(&testProvider{id: "same", authority: "cluster"}), testRegistration(&testProvider{id: "same", authority: "other"})); err == nil {
		t.Fatal("registry accepted duplicate provider IDs")
	}
	provider := &testProvider{id: "duplicate-action", authority: "cluster", duplicateAction: true}
	if _, err := NewRegistry(testRegistration(provider)); err == nil {
		t.Fatal("registry accepted duplicate actions in one trusted ownership context")
	}
}

func TestRegistryAllowsSameProviderAndRouteAcrossSourcesAndAuthorities(t *testing.T) {
	first := &testProvider{id: "same", sourceID: "one", authority: "cluster-one"}
	second := &testProvider{id: "same", sourceID: "two", authority: "cluster-two"}
	registry, err := NewRegistry(testRegistration(first), testRegistration(second))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		authority string
		sourceID  string
	}{{authority: "cluster-one", sourceID: "one"}, {authority: "cluster-two", sourceID: "two"}} {
		candidates, err := registry.Candidates(testProposal(t, "graph", test.authority))
		if err != nil {
			t.Fatal(err)
		}
		if len(candidates) != 1 || candidates[0].ProviderID != "same" || candidates[0].SourceID != test.sourceID || candidates[0].ActionID != testActionID {
			t.Fatalf("candidates for %s = %#v", test.authority, candidates)
		}
	}
}

func TestRegistryAllowsMultipleActionsForSameContract(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster", actions: []Action{
		{ID: "z-mechanism/v2", Intent: IntentNetworkDeclareIngressIsolation, TargetKind: "kubernetes/pod", Scheme: testScheme, AuthorityID: "cluster", Mode: ModeExecutable},
		{ID: "a-mechanism/v1", Intent: IntentNetworkDeclareIngressIsolation, TargetKind: "kubernetes/pod", Scheme: testScheme, AuthorityID: "cluster", Mode: ModeExecutable},
	}}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	candidates, err := registry.Candidates(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].ActionID != "a-mechanism/v1" || candidates[1].ActionID != "z-mechanism/v2" {
		t.Fatalf("candidates = %#v", candidates)
	}
	if _, action, err := registry.Provider(proposal, provider.id, "z-mechanism/v2"); err != nil || action.ID != "z-mechanism/v2" {
		t.Fatalf("selected action = %#v, err = %v", action, err)
	}
}

func TestRegistryValidatesVersionedActionIDs(t *testing.T) {
	tests := []struct {
		name     string
		actionID string
		valid    bool
	}{
		{name: "valid", actionID: "network-policy/v1", valid: true},
		{name: "valid hyphen and digits", actionID: "action-2-review/v12", valid: true},
		{name: "missing mechanism", actionID: "/v1"},
		{name: "missing version", actionID: "network-policy/v"},
		{name: "zero version", actionID: "network-policy/v0"},
		{name: "leading zero", actionID: "network-policy/v01"},
		{name: "uppercase mechanism", actionID: "Network-policy/v1"},
		{name: "underscore mechanism", actionID: "network_policy/v1"},
		{name: "non-numeric version", actionID: "network-policy/vone"},
		{name: "extra segment", actionID: "network-policy/v1/preview"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &testProvider{id: "provider", authority: "cluster", actions: []Action{{
				ID: test.actionID, Intent: IntentNetworkDeclareIngressIsolation, TargetKind: "kubernetes/pod", Scheme: testScheme, AuthorityID: "cluster", Mode: ModeExecutable,
			}}}
			_, err := NewRegistry(testRegistration(provider))
			if (err == nil) != test.valid {
				t.Fatalf("NewRegistry() error = %v, valid = %t", err, test.valid)
			}
		})
	}
}

func TestRegistryAcceptsRegisteredProviderWithNoActiveActions(t *testing.T) {
	provider := &testProvider{id: "inactive", authority: "cluster", inactive: true}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := registry.Candidates(testProposal(t, "graph", "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("inactive provider candidates = %#v", candidates)
	}
}

func TestExecutorAdvisoryProviderPlansButRejectsOperations(t *testing.T) {
	provider := &testProvider{id: "advisory", authority: "cluster", mode: ModeAdvisoryOnly}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return "graph" }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	plan, err := executor.Plan(context.Background(), proposal, provider.id, testActionID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != ModeAdvisoryOnly || plan.Advisory == "" {
		t.Fatalf("plan = %#v", plan)
	}
	_, err = executor.Prepare(context.Background(), proposal, plan)
	var advisoryErr *AdvisoryOnlyError
	if !errors.As(err, &advisoryErr) {
		t.Fatalf("dry-run error = %v", err)
	}
}

func TestExecutorRejectsProviderPlanRedirectBeforePreparation(t *testing.T) {
	redirecting := &testProvider{id: "provider-a", authority: "cluster", planProviderID: "provider-b"}
	other := &testProvider{id: "provider-b", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(redirecting), testRegistration(other))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return "graph" }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	if _, err := executor.Plan(context.Background(), proposal, redirecting.id, testActionID); err == nil || !strings.Contains(err.Error(), "does not match proposal and provider") {
		t.Fatalf("redirected plan error = %v", err)
	}
	if redirecting.preparations != 0 || other.preparations != 0 {
		t.Fatalf("preparation calls = provider-a:%d provider-b:%d, want zero", redirecting.preparations, other.preparations)
	}
}

func TestExecutorRejectsProviderPlanSourceRedirectBeforePreparation(t *testing.T) {
	provider := &testProvider{id: "provider", sourceID: "trusted", planSourceID: "spoofed", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return "graph" }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Plan(context.Background(), testProposal(t, "graph", "cluster"), provider.id, "trusted", testActionID); err == nil || !strings.Contains(err.Error(), "does not match proposal and provider") {
		t.Fatalf("source-spoofed plan error = %v", err)
	}
}

func TestExecutorRequiresPreparationAndAllowsUnrelatedGraphChange(t *testing.T) {
	current := "graph"
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return current }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, current, "cluster")
	plan, err := executor.Plan(context.Background(), proposal, provider.id, testActionID)
	if err != nil {
		t.Fatal(err)
	}
	fabricated, _ := NewPreparation(plan, true, nil)
	if _, err := executor.Execute(context.Background(), proposal, plan, fabricated, plan.ID); err == nil || !strings.Contains(err.Error(), "recorded") {
		t.Fatalf("execute without recorded preparation err = %v", err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, ""); err == nil || !strings.Contains(err.Error(), "explicit approval") {
		t.Fatalf("execute without approval err = %v", err)
	}
	if provider.executions != 0 {
		t.Fatalf("provider executed without approval: %d", provider.executions)
	}
	current = "changed"
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
	if provider.executions != 1 {
		t.Fatalf("provider executions = %d, want 1", provider.executions)
	}
}

func TestExecutorRejectsMutatedCanonicalObjects(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return "graph" }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	proposal.Target.Kind = "kubernetes/service"
	proposal.ID = ""
	proposal.ID = canonicalID("proposal", proposal)
	if _, err := executor.Plan(context.Background(), proposal, provider.id, testActionID); err == nil || !strings.Contains(err.Error(), "no remediation provider") {
		t.Fatalf("unsupported target routing error = %v", err)
	}
}

func TestKnownIntentUnsupportedTargetIsValidButHasNoCandidates(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	proposal.Target.Kind = "kubernetes/service"
	proposal.ID = ""
	proposal.ID = canonicalID("proposal", proposal)
	if err := proposal.Validate(); err != nil {
		t.Fatalf("provider-neutral proposal validation failed: %v", err)
	}
	candidates, err := registry.Candidates(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("unsupported target candidates = %#v", candidates)
	}
}

func TestExecutorAllowsUnrelatedGraphChange(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, func(context.Context) (GraphView, error) {
		return testGraphView("current-graph", "cluster"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "analyzed-graph", "cluster")
	plan, err := executor.Plan(context.Background(), proposal, provider.id, testActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
}

func TestExecutorRejectsMeaningfullyStaleTarget(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")

	tests := []struct {
		name string
		view GraphView
		want string
	}{
		{name: "fabricated target", view: GraphView{SHA256: canonicalTestGraphSHA256("graph")}, want: "absent"},
		{name: "kind mismatch", view: GraphView{SHA256: canonicalTestGraphSHA256("graph"), Snapshot: graph.Snapshot{Resources: []graph.Resource{{ID: proposal.Target.EntityID, Kind: "kubernetes/service", Identity: proposal.Target.Identity}}}}, want: "changed kind"},
		{name: "kind conflict", view: GraphView{SHA256: canonicalTestGraphSHA256("graph"), Snapshot: graph.Snapshot{Conflicts: []graph.AssertionConflict{{ResourceID: proposal.Target.EntityID, Kinds: []string{"kubernetes/pod", "kubernetes/service"}}}}}, want: "conflicting kinds"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor, err := NewExecutor(registry, func(context.Context) (GraphView, error) { return test.view, nil })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.Plan(context.Background(), proposal, provider.id, testActionID); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("plan error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestExecutorAcceptsMultiplyAssertedCanonicalTarget(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	view := testGraphView("graph", "cluster")
	view.Snapshot.Resources[0].Assertions = []graph.ResourceAssertion{
		{Claim: view.Snapshot.Resources[0].Identity, Kind: "kubernetes/pod", PluginID: "kubernetes", SourceID: "source-a"},
		{Claim: view.Snapshot.Resources[0].Identity, Kind: "kubernetes/pod", PluginID: "istio", SourceID: "source-b"},
	}
	executor, err := NewExecutor(registry, func(context.Context) (GraphView, error) { return view, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Plan(context.Background(), testProposal(t, "graph", "cluster"), provider.id, testActionID); err != nil {
		t.Fatal(err)
	}
}

func TestExecutorRejectsCrossPlanPreparationReplay(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return "graph" }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	firstPlan, err := executor.Plan(context.Background(), proposal, provider.id, testActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	secondPlan, err := NewPlan(proposal, provider.id, provider.source(), testActionID, "different-desired-state")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, secondPlan, preparation, secondPlan.ID); err == nil || !strings.Contains(err.Error(), "successful matching preparation") {
		t.Fatalf("cross-plan preparation replay error = %v", err)
	}
	if provider.executions != 0 {
		t.Fatalf("provider executions = %d, want 0", provider.executions)
	}
}

func TestExecutorConcurrentExecuteCallsProviderOnceAndCachesResult(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return "graph" }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	plan, err := executor.Plan(context.Background(), proposal, provider.id, testActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 16
	results := make(chan ExecutionResult, callers)
	errors := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, executionErr := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID)
			results <- result
			errors <- executionErr
		}()
	}
	wait.Wait()
	close(results)
	close(errors)
	for executionErr := range errors {
		if executionErr != nil {
			t.Fatal(executionErr)
		}
	}
	var first ExecutionResult
	for result := range results {
		if first.ID == "" {
			first = result
		}
		if result.ID != first.ID {
			t.Fatalf("concurrent apply result = %#v, want %#v", result, first)
		}
	}
	if provider.executions != 1 {
		t.Fatalf("provider executions = %d, want 1", provider.executions)
	}
}

func TestExecutorWaiterRechecksRemovedTargetAfterFailedExecution(t *testing.T) {
	var targetPresent atomic.Bool
	targetPresent.Store(true)
	started := make(chan struct{})
	release := make(chan struct{})
	provider := &blockingFailProvider{testProvider: testProvider{id: "provider", authority: "cluster"}, started: started, release: release}
	registry, err := NewRegistry(Registration{ProviderID: provider.id, SourceID: provider.source(), Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, func(context.Context) (GraphView, error) {
		if !targetPresent.Load() {
			return GraphView{SHA256: canonicalTestGraphSHA256("changed")}, nil
		}
		return testGraphView("graph", "cluster"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	plan, err := executor.Plan(context.Background(), proposal, provider.id, testActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)
	go func() {
		_, executionErr := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID)
		firstErr <- executionErr
	}()
	<-started
	go func() {
		_, executionErr := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID)
		secondErr <- executionErr
	}()
	targetPresent.Store(false)
	close(release)
	if err := <-firstErr; err == nil || !strings.Contains(err.Error(), "blocked execute failed") {
		t.Fatalf("first apply error = %v", err)
	}
	if err := <-secondErr; err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("waiting apply error = %v", err)
	}
	if provider.executions != 1 {
		t.Fatalf("provider executions = %d, want 1", provider.executions)
	}
}

func TestExecutorVerifyRequiresRecordedSuccessfulExecution(t *testing.T) {
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return "graph" }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, "graph", "cluster")
	plan, err := executor.Plan(context.Background(), proposal, provider.id, testActionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Verify(context.Background(), proposal, plan); err == nil || !strings.Contains(err.Error(), "recorded by this executor") {
		t.Fatalf("verify-before-execution error = %v", err)
	}
}

func TestExecutorVerifyAllowsGraphChangeAfterExecution(t *testing.T) {
	current := "graph"
	provider := &testProvider{id: "provider", authority: "cluster"}
	registry, err := NewRegistry(testRegistration(provider))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(registry, testGraphSource(func() string { return current }, "cluster"))
	if err != nil {
		t.Fatal(err)
	}
	proposal := testProposal(t, current, "cluster")
	plan, err := executor.Plan(context.Background(), proposal, provider.id, testActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
	current = "graph-after-provider-write"
	verification, err := executor.Verify(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Satisfied {
		t.Fatal("provider postcondition did not verify after graph changed")
	}
}

type blockingFailProvider struct {
	testProvider
	started chan struct{}
	release chan struct{}
}

func (provider *blockingFailProvider) Execute(_ context.Context, _ Proposal, _ Plan, _ Preparation) (ExecutionResult, error) {
	provider.executions++
	close(provider.started)
	<-provider.release
	return ExecutionResult{}, errors.New("blocked execute failed")
}

type testProvider struct {
	id              string
	sourceID        string
	planSourceID    string
	authority       string
	mode            Mode
	planProviderID  string
	duplicateAction bool
	inactive        bool
	actions         []Action
	preparations    int
	executions      int
}

func (provider *testProvider) RemediationDescriptor() Descriptor {
	mode := provider.mode
	if mode == "" {
		mode = ModeExecutable
	}
	actions := []Action{{
		ID: testActionID, Intent: IntentNetworkDeclareIngressIsolation, Scheme: testScheme, AuthorityID: provider.authority,
		TargetKind: "kubernetes/pod", Mode: mode,
	}}
	if provider.inactive {
		actions = nil
	}
	if provider.duplicateAction {
		actions = append(actions, actions[0])
	}
	if provider.actions != nil {
		actions = provider.actions
	}
	return Descriptor{Actions: actions}
}

func (provider *testProvider) Plan(_ context.Context, proposal Proposal, actionID string) (Plan, error) {
	if actionID == "" {
		return Plan{}, fmt.Errorf("unsupported action %q", actionID)
	}
	if provider.mode == ModeAdvisoryOnly {
		return NewAdvisoryPlan(proposal, provider.id, provider.source(), actionID, "Review the route attachment and detach it through the owning gateway configuration.")
	}
	providerID := provider.id
	if provider.planProviderID != "" {
		providerID = provider.planProviderID
	}
	sourceID := provider.source()
	if provider.planSourceID != "" {
		sourceID = provider.planSourceID
	}
	return NewPlan(proposal, providerID, sourceID, actionID, "desired")
}

func (provider *testProvider) Prepare(_ context.Context, _ Proposal, plan Plan) (Preparation, error) {
	provider.preparations++
	return NewPreparation(plan, true, nil)
}

func (provider *testProvider) Execute(_ context.Context, _ Proposal, plan Plan, preparation Preparation) (ExecutionResult, error) {
	provider.executions++
	return NewExecutionResult(plan, preparation, true, nil)
}

func (provider *testProvider) Verify(_ context.Context, _ Proposal, plan Plan, result ExecutionResult) (Verification, error) {
	return Verification{PlanID: plan.ID, ProviderID: provider.id, SourceID: provider.source(), ActionID: plan.ActionID, ExecutionResultID: result.ID, Satisfied: provider.executions > 0}, nil
}

func testRegistration(provider *testProvider) Registration {
	return Registration{ProviderID: provider.id, SourceID: provider.source(), Provider: provider}
}

func (provider *testProvider) source() string {
	if provider.sourceID == "" {
		return "source"
	}
	return provider.sourceID
}

func testProposal(t *testing.T, graphSHA256, authority string) Proposal {
	t.Helper()
	proposal, err := NewProposal("finding", "analysis", canonicalTestGraphSHA256(graphSHA256),
		Suggestion{Intent: IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}},
		Target{EntityID: "target", Identity: graph.IdentityClaim{Scheme: testScheme, AuthorityID: authority, ImmutableKey: "v1/pod/uid"}, Kind: "kubernetes/pod"},
		[]string{"evidence"})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func testGraphSource(digest func() string, authority string) GraphSourceFunc {
	return func(context.Context) (GraphView, error) {
		return testGraphView(digest(), authority), nil
	}
}

func testGraphView(digest, authority string) GraphView {
	identity := graph.IdentityClaim{Scheme: testScheme, AuthorityID: authority, ImmutableKey: "v1/pod/uid"}
	return GraphView{SHA256: canonicalTestGraphSHA256(digest), Snapshot: graph.Snapshot{Resources: []graph.Resource{{
		ID: "target", Kind: "kubernetes/pod", Identity: identity,
	}}}}
}

func canonicalTestGraphSHA256(value string) string {
	if len(value) == sha256.Size*2 {
		if _, err := hex.DecodeString(value); err == nil && strings.ToLower(value) == value {
			return value
		}
	}
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
