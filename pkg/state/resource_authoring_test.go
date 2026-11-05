package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func mustAuthoringContext(context any, attributes map[string]string) string {
	authoringContext, err := graph.NewResourceAuthoringContext(context, attributes)
	if err != nil {
		panic(err)
	}
	encoded, err := json.Marshal(authoringContext)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func authoringContextSHA256(resource ResourceAuthoringContext) string {
	digest, err := resourceAuthoringContextSHA256(resource)
	if err != nil {
		panic(err)
	}
	return digest
}

func decodedAuthoringContext(encoded string) graph.ResourceAuthoringContext {
	authoringContext, err := graph.DecodeResourceAuthoringContext(encoded)
	if err != nil {
		panic(err)
	}
	return authoringContext
}

func TestResourceAuthoringContextUsesBoundedPluginContext(t *testing.T) {
	encoded := mustAuthoringContext(map[string]any{"roleClass": "admin"}, map[string]string{"authorization_class": "admin"})
	resource := graph.Resource{ID: "statefulset-id", Kind: "kubernetes/statefulset", Assertions: []graph.ResourceAssertion{
		{PluginID: "untrusted-plugin", RuleID: "untrusted.resource", Attributes: map[string]string{"kubernetes/name": "spoofed"}},
		{PluginID: "kubernetes", RuleID: "kubernetes.resource.authoring-context", Attributes: map[string]string{
			"kubernetes/name": "ledger", "kubernetes/namespace": "payments",
			graph.ResourceAuthoringContextAttribute: encoded,
		}}}}
	authoringContext := ResourceAuthoringContextFor(resource)
	want := ResourceAuthoringContext{
		ResourceID: "statefulset-id", Kind: "kubernetes/statefulset", Name: "ledger", Namespace: "payments",
		Context: json.RawMessage(`{"roleClass":"admin"}`), Attributes: map[string]string{"authorization_class": "admin"},
	}
	want.ContextSHA256 = authoringContextSHA256(want)
	if !reflect.DeepEqual(authoringContext, want) {
		t.Fatalf("context=%#v, want %#v", authoringContext, want)
	}
	resource.Assertions[1].Attributes[graph.ResourceAuthoringContextAttribute] = `{"schemaVersion":"v1","context":{},"rawManifest":{}}`
	if context := ResourceAuthoringContextFor(resource); context.ContextSHA256 != "" {
		t.Fatalf("an invalid context remained eligible for authoring: %#v", context)
	}
}

func TestResourceAuthoringContextSelectsValidContextAfterMalformedAssertion(t *testing.T) {
	encoded := mustAuthoringContext(map[string]any{"hostPID": true}, nil)
	v1 := graph.ResourceAssertion{PluginID: "kubernetes", RuleID: "kubernetes.resource.authoring-context", Attributes: map[string]string{
		"kubernetes/name": "current", "kubernetes/namespace": "payments",
		graph.ResourceAuthoringContextAttribute: encoded,
	}}
	malformed := graph.ResourceAssertion{PluginID: "kubernetes", RuleID: "kubernetes.resource.authoring-context", Attributes: map[string]string{
		graph.ResourceAuthoringContextAttribute: `{"schemaVersion":"v1","context":[]}`,
	}}
	want := ResourceAuthoringContext{ResourceID: "deployment-id", Kind: "kubernetes/deployment", Name: "current", Namespace: "payments", Context: json.RawMessage(`{"hostPID":true}`)}
	want.ContextSHA256 = authoringContextSHA256(want)
	resource := graph.Resource{ID: "deployment-id", Kind: "kubernetes/deployment", Assertions: []graph.ResourceAssertion{malformed, v1}}
	if got := ResourceAuthoringContextFor(resource); !reflect.DeepEqual(got, want) {
		t.Fatalf("context=%#v, want %#v", got, want)
	}
}

func TestResourceAuthoringContextRevisionIncludesModelVisibleIdentity(t *testing.T) {
	encoded := mustAuthoringContext(map[string]any{"hostPID": true}, nil)
	assertion := graph.ResourceAssertion{PluginID: "kubernetes", RuleID: "kubernetes.resource.authoring-context", Attributes: map[string]string{
		"kubernetes/name": "current", "kubernetes/namespace": "payments", graph.ResourceAuthoringContextAttribute: encoded,
	}}
	first := ResourceAuthoringContextFor(graph.Resource{ID: "deployment-id", Kind: "kubernetes/deployment", Assertions: []graph.ResourceAssertion{assertion}})
	assertion.Attributes["kubernetes/name"] = "renamed"
	second := ResourceAuthoringContextFor(graph.Resource{ID: "deployment-id", Kind: "kubernetes/deployment", Assertions: []graph.ResourceAssertion{assertion}})
	if first.ContextSHA256 == second.ContextSHA256 {
		t.Fatal("a model-visible name change retained the same authoring revision")
	}
}

func TestResourceAuthoringContextRejectsConflictingValidContexts(t *testing.T) {
	authoringAssertion := func(hostPID bool) graph.ResourceAssertion {
		return graph.ResourceAssertion{PluginID: "kubernetes", RuleID: "kubernetes.resource.authoring-context", Attributes: map[string]string{
			"kubernetes/name": "payments", "kubernetes/namespace": "payments",
			graph.ResourceAuthoringContextAttribute: mustAuthoringContext(map[string]any{"hostPID": hostPID}, nil),
		}}
	}
	resource := graph.Resource{ID: "deployment-id", Kind: "kubernetes/deployment", Assertions: []graph.ResourceAssertion{authoringAssertion(false), authoringAssertion(true)}}
	want := ResourceAuthoringContext{ResourceID: "deployment-id", Kind: "kubernetes/deployment"}
	if got := ResourceAuthoringContextFor(resource); !reflect.DeepEqual(got, want) {
		t.Fatalf("context=%#v, want %#v", got, want)
	}
}

func TestNormalizeObservedOperation(t *testing.T) {
	for operation, want := range map[string]string{
		"GET /v1/products?page=1":                                   "GET /v1/products",
		"GET /v1/cart/session-123#top":                              "GET /v1/cart/session-123",
		"DELETE /api/v1/items/42":                                   "DELETE /api/v1/items/{id}",
		"GET /v1/orders/0f8fad5b-d9cb-469f-a165-70867728950e/lines": "GET /v1/orders/{id}/lines",
		"GET /v1/facade-decaf-bead":                                 "GET /v1/facade-decaf-bead",
		"GET /":                                                     "GET /",
		"":                                                          "",
	} {
		if got := NormalizeObservedOperation(operation); got != want {
			t.Errorf("NormalizeObservedOperation(%q) = %q, want %q", operation, got, want)
		}
	}
	if got := NormalizeObservedOperation("GET /" + strings.Repeat("a", 400)); len(got) != maxObservedOperationLength {
		t.Errorf("normalized operation length = %d, want %d", len(got), maxObservedOperationLength)
	}
}

func TestWorkloadBehaviorForSummarizesTheDeploymentsOutboundTelemetry(t *testing.T) {
	named := func(id, kind, name string, attributes map[string]string) graph.Resource {
		if attributes == nil {
			attributes = map[string]string{}
		}
		if name != "" {
			attributes["kubernetes/name"], attributes["kubernetes/namespace"] = name, "shop"
		}
		return graph.Resource{ID: id, Kind: kind, Assertions: []graph.ResourceAssertion{{Attributes: attributes}}}
	}
	snapshot := graph.Snapshot{
		Resources: []graph.Resource{
			named("frontend", "kubernetes/deployment", "frontend", nil),
			named("frontend-rs", "kubernetes/replicaset", "frontend-abc", nil),
			named("frontend-pod", "kubernetes/pod", "frontend-abc", nil),
			named("catalog", "kubernetes/service", "catalog-api", nil),
			named("apiserver", "network/destination", "", map[string]string{"network/role": graph.NetworkRoleControlPlaneAPI}),
		},
		Relationships: []graph.Relationship{
			{SubjectID: "frontend", Predicate: graph.PredicateInstantiates, ObjectID: "frontend-rs"},
			{SubjectID: "frontend-rs", Predicate: graph.PredicateInstantiates, ObjectID: "frontend-pod"},
			{SubjectID: "frontend-rs", Predicate: graph.PredicateInstantiates, ObjectID: "frontend"},
		},
		Telemetry: []graph.TelemetryEvent{
			{SubjectID: "frontend-pod", ObjectID: "catalog", Kind: "active-probe", Operation: "GET /v1/products?page=1", Outcome: "allowed", Count: 2},
			{SubjectID: "frontend", ObjectID: "catalog", Kind: "active-probe", Operation: "GET /v1/products?page=2", Outcome: "allowed", Count: 3},
			{SubjectID: "frontend", ObjectID: "apiserver", Kind: "network-flow", Operation: "egress", Outcome: "forwarded", Count: 1},
			{SubjectID: "catalog", ObjectID: "frontend", Kind: "active-probe", Operation: "GET /", Outcome: "allowed", Count: 9},
		},
	}
	want := WorkloadBehavior{CollectedTelemetry: []string{"active-probe", "network-flow"}, Requests: []ObservedRequest{
		{Telemetry: "network-flow", DestinationResourceID: "apiserver", DestinationKind: "network/destination", DestinationRole: graph.NetworkRoleControlPlaneAPI, Operation: "egress", Outcome: "forwarded", Count: 1},
		{Telemetry: "active-probe", Destination: "shop/catalog-api", DestinationResourceID: "catalog", DestinationKind: "kubernetes/service", Operation: "GET /v1/products", Outcome: "allowed", Count: 5},
	}}
	if got := WorkloadBehaviorFor(snapshot, "frontend"); !reflect.DeepEqual(got, want) {
		t.Fatalf("behavior = %#v, want %#v", got, want)
	}
	if got := WorkloadBehaviorFor(snapshot, "missing"); got.Requests == nil || len(got.Requests) != 0 || got.Truncated || len(got.CollectedTelemetry) != 2 {
		t.Fatalf("a Deployment without telemetry = %#v, want an empty, non-nil request list and the collected kinds", got)
	}

	if got := WorkloadBehaviorFor(graph.Snapshot{}, "frontend"); got.CollectedTelemetry == nil || got.Requests == nil {
		t.Fatalf("an empty graph = %#v, want empty, non-nil lists", got)
	}
	snapshot.Telemetry = nil
	for index := range MaxObservedRequests + 1 {
		snapshot.Telemetry = append(snapshot.Telemetry, graph.TelemetryEvent{
			SubjectID: "frontend", ObjectID: "catalog", Kind: "active-probe", Operation: fmt.Sprintf("GET /v1/path-%02d", index), Count: uint64(index + 1),
		})
	}
	truncated := WorkloadBehaviorFor(snapshot, "frontend")
	if !truncated.Truncated || len(truncated.Requests) != MaxObservedRequests || truncated.Requests[0].Operation != "GET /v1/path-01" {
		t.Fatalf("truncation did not keep the most frequent requests in sorted order: %#v", truncated)
	}
}

func deploymentContribution(name string, generation uint64, uid, label string) Contribution {
	return Contribution{
		PluginID: "kubernetes", SourceID: "cluster/local", Name: name, Generation: generation,
		Ready: true, SourceHealth: "healthy", SourceObservedAt: time.Now().UTC(),
		Input: graph.Input{Resources: []graph.ResourceAssertion{{
			Claim: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster", ImmutableKey: "apps/v1/deployment/" + uid},
			Kind:  "kubernetes/deployment", DisplayName: "prod/payments",
			Attributes: map[string]string{
				"kubernetes/name": "payments", "kubernetes/namespace": "prod", "kubernetes/label/app": label,
				graph.ResourceAuthoringContextAttribute: mustAuthoringContext(map[string]any{"label": label}, map[string]string{"kubernetes/label/app": label}),
			},
			PluginID: "kubernetes", SourceID: "cluster/local", RuleID: "kubernetes.resource.authoring-context",
		}}},
	}
}

func TestPostgreSQLResourceAuthoringJobCreatedOncePerGraphIdentity(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	first := deploymentContribution("deployments", 1, "deployment-uid", "payments")
	if _, err := store.ReplaceContribution(ctx, first); err != nil {
		t.Fatal(err)
	}
	var resourceID string
	if err := store.pool.QueryRow(ctx, `SELECT resource_id::text FROM current_resources WHERE kind='kubernetes/deployment'`).Scan(&resourceID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_rule_jobs WHERE resource_id=$1`, resourceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("job count=%d err=%v", count, err)
	}
	first.Generation = 2
	first.Input.Resources[0].Attributes["kubernetes/label/app"] = "payments-v2"
	first.SourceObservedAt = time.Now().UTC()
	if _, err := store.ReplaceContribution(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_rule_jobs WHERE resource_id=$1`, resourceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("after update job count=%d err=%v", count, err)
	}
	second := deploymentContribution("semantic-deployment-assertion", 1, "deployment-uid", "payments")
	second.PluginID, second.SourceID = "test-observer", "observer/local"
	second.Input.Resources[0].PluginID, second.Input.Resources[0].SourceID = second.PluginID, second.SourceID
	if _, err := store.ReplaceContribution(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_rule_jobs WHERE resource_id=$1`, resourceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("after second assertion job count=%d err=%v", count, err)
	}
	third := deploymentContribution("another-deployment", 1, "other-uid", "ledger")
	if _, err := store.ReplaceContribution(ctx, third); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_rule_jobs`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("total job count=%d err=%v", count, err)
	}
}

func TestPostgreSQLResourceAuthoringQueuesEveryProjectedResourceKind(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	for index, kind := range []string{"statefulset", "daemonset", "job"} {
		contribution := deploymentContribution(kind, uint64(index+1), kind+"-uid", kind)
		contribution.Name = kind
		contribution.Input.Resources[0].Claim.ImmutableKey = "apps/v1/" + kind + "/" + kind + "-uid"
		contribution.Input.Resources[0].Kind = "kubernetes/" + kind
		if _, err := store.ReplaceContribution(ctx, contribution); err != nil {
			t.Fatal(err)
		}
	}
	var kinds []string
	rows, err := store.pool.Query(ctx, `SELECT r.kind FROM resource_rule_jobs j JOIN current_resources r ON r.resource_id=j.resource_id ORDER BY r.kind`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, kind)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"kubernetes/daemonset", "kubernetes/job", "kubernetes/statefulset"}; !reflect.DeepEqual(kinds, want) {
		t.Fatalf("queued kinds=%v, want %v", kinds, want)
	}
}

// revisionContribution is a resource authoring assertion for one revision.
func revisionContribution(generation uint64, revision string) Contribution {
	contribution := deploymentContribution("deployments", generation, "deployment-uid", "payments")
	contribution.SourceObservedAt = time.Now().UTC()
	contribution.Input.Resources[0].Attributes[graph.ResourceAuthoringContextAttribute] = mustAuthoringContext(map[string]any{"revision": revision, "hostPID": true}, nil)
	return contribution
}

func TestPostgreSQLResourceAuthoringJobPerContextRevision(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	revisions := func() []string {
		t.Helper()
		rows, err := store.pool.Query(ctx, `SELECT context_sha256 || ':' || status FROM resource_rule_jobs ORDER BY job_id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var result []string
		for rows.Next() {
			var revision string
			if err := rows.Scan(&revision); err != nil {
				t.Fatal(err)
			}
			result = append(result, revision)
		}
		return result
	}
	publish := func(generation uint64, template string) {
		t.Helper()
		if _, err := store.ReplaceContribution(ctx, revisionContribution(generation, template)); err != nil {
			t.Fatal(err)
		}
	}
	revision := func(value string) string {
		contribution := revisionContribution(1, value)
		assertion := contribution.Input.Resources[0]
		context := decodedAuthoringContext(assertion.Attributes[graph.ResourceAuthoringContextAttribute])
		resource := ResourceAuthoringContext{
			Kind: assertion.Kind, Name: assertion.Attributes["kubernetes/name"], Namespace: assertion.Attributes["kubernetes/namespace"],
			Context: context.Context, Attributes: context.Attributes,
		}
		return authoringContextSHA256(resource)
	}
	publish(1, "a")
	if got := revisions(); !reflect.DeepEqual(got, []string{revision("a") + ":queued"}) {
		t.Fatalf("after first revision jobs=%v", got)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker", time.Minute, time.Hour)
	if err != nil || claimed {
		t.Fatalf("a job inside its stabilization window was claimed: job=%#v err=%v", job, err)
	}
	if job, claimed, err = store.ClaimResourceRuleJob(ctx, "worker", time.Minute, 0); err != nil || !claimed || job.Context.ContextSHA256 != revision("a") || !bytes.Contains(job.Context.Context, []byte(`"hostPID": true`)) {
		t.Fatalf("job=%#v claimed=%t err=%v", job, claimed, err)
	}
	if err := store.CompleteResourceRuleJob(ctx, job.ID, "worker", json.RawMessage(`{"rationale":"r","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	publish(2, "b")
	publish(3, "c")
	if got := revisions(); !reflect.DeepEqual(got, []string{revision("a") + ":completed", revision("c") + ":queued"}) {
		t.Fatalf("a queued revision was not superseded: jobs=%v", got)
	}
	publish(4, "a")
	if got := revisions(); !reflect.DeepEqual(got, []string{revision("a") + ":completed"}) {
		t.Fatalf("returning to an authored revision: jobs=%v", got)
	}
	status, found, err := store.ResourceRuleJobStatus(ctx, job.ID)
	if err != nil || !found || status.ContextSHA256 != revision("a") {
		t.Fatalf("status=%#v found=%t err=%v", status, found, err)
	}
}

func TestPostgreSQLResourceRuleRevisionsFollowTheCurrentContext(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	generation := uint64(0)
	ruleIDs := map[int64]string{}
	publish := func(template string) {
		t.Helper()
		generation++
		if _, err := store.ReplaceContribution(ctx, revisionContribution(generation, template)); err != nil {
			t.Fatal(err)
		}
	}
	author := func(template string) int64 {
		t.Helper()
		publish(template)
		job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker", time.Minute, 0)
		if err != nil || !claimed {
			t.Fatalf("claimed=%t err=%v", claimed, err)
		}
		rule := detector.Rule{
			ID: "deployment/" + job.Context.ResourceID + "/template-" + template + "/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*",
			ScopeResourceID: job.Context.ResourceID, Type: "relationship", Kind: "communicates-with",
			Expression: "true", Risk: detector.RiskMedium, Reasons: []string{"resource_rule_match"}, WindowSeconds: 300,
		}
		proposal, err := json.Marshal(map[string]any{"rationale": "r", "rules": []map[string]any{{"rule": rule, "rationale": "r"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CompleteResourceRuleJob(ctx, job.ID, "worker", proposal); err != nil {
			t.Fatal(err)
		}
		ruleIDs[job.ID] = rule.ID
		return job.ID
	}
	review := func(jobID int64, decision string) {
		t.Helper()
		selected := []string(nil)
		if decision == ResourceRuleReviewApproved {
			selected = []string{ruleIDs[jobID]}
		}
		if err := store.ReviewResourceRuleJobRules(ctx, jobID, decision, "operator", selected); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(step string, want map[string]detector.RuleMode) {
		t.Helper()
		rules, err := store.ReadResourceRules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := detector.ValidateResourceRules(rules); err != nil {
			t.Fatal(err)
		}
		got := map[string]detector.RuleMode{}
		for _, rule := range rules {
			got[rule.Rule.ID[strings.Index(rule.Rule.ID, "template-")+9:][:1]] = rule.Mode
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: loaded=%v, want %v", step, got, want)
		}
	}
	first := author("a")
	review(first, ResourceRuleReviewApproved)
	expect("approved revision", map[string]detector.RuleMode{"a": detector.RuleModeActive})
	second := author("b")
	expect("new revision pending", map[string]detector.RuleMode{"a": detector.RuleModeActive, "b": detector.RuleModeShadow})
	review(second, ResourceRuleReviewRejected)
	expect("new revision rejected", map[string]detector.RuleMode{"a": detector.RuleModeActive})
	third := author("c")
	review(third, ResourceRuleReviewApproved)
	expect("newer revision approved", map[string]detector.RuleMode{"c": detector.RuleModeActive})
	publish("a")
	expect("rollback to an approved revision", map[string]detector.RuleMode{"a": detector.RuleModeActive})
	publish("b")
	expect("rollback to a rejected revision", map[string]detector.RuleMode{"c": detector.RuleModeActive})
	publish("c")
	expect("roll forward", map[string]detector.RuleMode{"c": detector.RuleModeActive})
	if err := store.ReviewResourceRuleJobRules(ctx, second, ResourceRuleReviewApproved, "operator", []string{ruleIDs[second]}); !errors.Is(err, ErrResourceRuleJobNotReviewable) {
		t.Fatalf("historical revision approval error = %v", err)
	}
	var current int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_rule_jobs WHERE current_revision`).Scan(&current); err != nil || current != 1 {
		t.Fatalf("current revisions=%d err=%v", current, err)
	}
}

func TestPostgreSQLReadResourceRulesBoundsAfterActiveRules(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	for index := range 4 {
		name := fmt.Sprintf("deployments-%d", index)
		if _, err := store.ReplaceContribution(ctx, deploymentContribution(name, 1, name+"-uid", name)); err != nil {
			t.Fatal(err)
		}
	}
	var newest ResourceRuleJob
	var oldest ResourceRuleJob
	ruleIDs := map[int64]string{}
	for index := range 4 {
		job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker", time.Minute, 0)
		if err != nil || !claimed {
			t.Fatalf("claimed=%t err=%v", claimed, err)
		}
		rule := detector.Rule{
			ID: fmt.Sprintf("resource/rule-%d", 4-index), Revision: 1, InputVersion: detector.InputVersion, PluginID: "*", ScopeResourceID: job.Context.ResourceID,
			Type: "resource", Kind: job.Context.Kind, Expression: "true", Risk: detector.RiskMedium, Reasons: []string{"resource_rule_match"},
		}
		proposal, err := json.Marshal(map[string]any{"rationale": "r", "rules": []map[string]any{{"rule": rule, "rationale": "r"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CompleteResourceRuleJob(ctx, job.ID, "worker", proposal); err != nil {
			t.Fatal(err)
		}
		ruleIDs[job.ID] = rule.ID
		if job.ID > newest.ID {
			newest = job
		}
		if oldest.ID == 0 || job.ID < oldest.ID {
			oldest = job
		}
	}
	if err := store.ReviewResourceRuleJobRules(ctx, newest.ID, ResourceRuleReviewApproved, "operator", []string{ruleIDs[newest.ID]}); err != nil {
		t.Fatal(err)
	}
	allRules, err := store.ReadResourceRules(ctx)
	if err != nil || len(allRules) != 4 {
		t.Fatalf("complete rule inventory=%#v err=%v", allRules, err)
	}
	invalidRule := detector.Rule{
		ID: ruleIDs[oldest.ID], Revision: 1, InputVersion: detector.InputVersion, PluginID: "*", ScopeResourceID: oldest.Context.ResourceID,
		Type: "resource", Kind: oldest.Context.Kind, Expression: "missing_field == true", Risk: detector.RiskMedium, Reasons: []string{"resource_rule_match"},
	}
	invalidProposal, err := json.Marshal(map[string]any{"rules": []map[string]any{{"rule": invalidRule}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE resource_rule_jobs SET proposal=$2 WHERE job_id=$1`, oldest.ID, invalidProposal); err != nil {
		t.Fatal(err)
	}
	rules, err := store.readResourceRules(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	shadowRuleIDs := make([]string, 0, 2)
	for jobID, ruleID := range ruleIDs {
		if jobID != oldest.ID && jobID != newest.ID {
			shadowRuleIDs = append(shadowRuleIDs, ruleID)
		}
	}
	slices.Sort(shadowRuleIDs)
	if len(rules) != 2 || rules[0].Mode != detector.RuleModeActive || rules[0].Rule.ID != ruleIDs[newest.ID] || rules[1].Rule.ID != shadowRuleIDs[0] {
		t.Fatalf("bounded rules=%#v, want newest approved rule before shadow overflow", rules)
	}
	if err := detector.ValidateResourceRules(rules); err != nil {
		t.Fatalf("bounded rules included a corrupt rule before later valid rules: %v", err)
	}
}

func TestPostgreSQLRemovingResourceUnloadsApprovedResourceRules(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	contribution := revisionContribution(1, "a")
	if _, err := store.ReplaceContribution(ctx, contribution); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	rule := detector.Rule{
		ID: "resource/opt-out/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*", ScopeResourceID: job.Context.ResourceID,
		Type: "resource", Kind: job.Context.Kind, Expression: "true", Risk: detector.RiskMedium, Reasons: []string{"resource_rule_match"},
	}
	proposal, err := json.Marshal(map[string]any{"rationale": "r", "rules": []map[string]any{{"rule": rule, "rationale": "r"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteResourceRuleJob(ctx, job.ID, "worker", proposal); err != nil {
		t.Fatal(err)
	}
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewApproved, "operator", []string{rule.ID}); err != nil {
		t.Fatal(err)
	}
	removed := revisionContribution(2, "a")
	removed.Input = graph.Input{}
	if _, err := store.ReplaceContribution(ctx, removed); err != nil {
		t.Fatal(err)
	}
	if rules, err := store.ReadResourceRules(ctx); err != nil || len(rules) != 0 {
		t.Fatalf("opted-out resource rules=%#v err=%v", rules, err)
	}
	var current int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_rule_jobs WHERE resource_id=$1 AND current_revision`, job.Context.ResourceID).Scan(&current); err != nil || current != 0 {
		t.Fatalf("current revisions=%d err=%v", current, err)
	}
	if _, err := store.RequestResourceRuleJob(ctx, job.Context.ResourceID, "operator"); !errors.Is(err, ErrResourceRuleJobNotFound) {
		t.Fatalf("removed resource regeneration error = %v", err)
	}
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewApproved, "operator", []string{rule.ID}); !errors.Is(err, ErrResourceRuleJobNotReviewable) {
		t.Fatalf("removed resource approval error = %v", err)
	}
}

func TestPostgreSQLDeploymentJobClaimLeaseRetryAndCompletion(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, deploymentContribution("deployments", 1, "deployment-uid", "payments")); err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err := store.pool.QueryRow(ctx, `SELECT job_id FROM resource_rule_jobs`).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	claims := make(chan bool, 2)
	errorsChannel := make(chan error, 2)
	for _, owner := range []string{"worker/a", "worker/b"} {
		wait.Add(1)
		go func(owner string) {
			defer wait.Done()
			_, claimed, err := store.ClaimResourceRuleJob(ctx, owner, time.Minute, 0)
			claims <- claimed
			errorsChannel <- err
		}(owner)
	}
	wait.Wait()
	close(claims)
	close(errorsChannel)
	claimedCount := 0
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	for claimed := range claims {
		if claimed {
			claimedCount++
		}
	}
	if claimedCount != 1 {
		t.Fatalf("concurrent claims=%d, want 1", claimedCount)
	}
	var owner string
	if err := store.pool.QueryRow(ctx, `SELECT lease_owner FROM resource_rule_jobs WHERE job_id=$1`, jobID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if renewed, err := store.RenewResourceRuleJob(ctx, jobID, owner, time.Minute); err != nil || !renewed {
		t.Fatalf("renewed=%t err=%v", renewed, err)
	}
	if outcome, err := store.RetryResourceRuleJob(ctx, jobID, owner, "temporary failure", time.Second, false); err != nil || outcome != ResourceRuleRetryScheduled {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if _, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/retry", time.Minute, 0); err != nil || claimed {
		t.Fatalf("early retry claimed=%t err=%v", claimed, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE resource_rule_jobs SET available_at=now()-interval '1 second' WHERE job_id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/retry", time.Minute, 0)
	if err != nil || !claimed || job.AttemptCount != 2 {
		t.Fatalf("job=%#v claimed=%t err=%v", job, claimed, err)
	}
	invalidRule := detector.Rule{
		ID: "resource/invalid/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*", ScopeResourceID: job.Context.ResourceID,
		Type: "resource", Kind: job.Context.Kind, Expression: "missing_field == true", Risk: detector.RiskMedium, Reasons: []string{"resource_rule_match"},
	}
	invalidProposal, err := json.Marshal(map[string]any{"rules": []map[string]any{{"rule": invalidRule}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteResourceRuleJob(ctx, jobID, "worker/retry", invalidProposal); err == nil {
		t.Fatal("invalid resource rule proposal completed")
	}
	proposal := json.RawMessage(`{"jobId":1,"rules":[]}`)
	if err := store.CompleteResourceRuleJob(ctx, jobID, "worker/other", proposal); err == nil {
		t.Fatal("non-owner completed job")
	}
	if err := store.CompleteResourceRuleJob(ctx, jobID, "worker/retry", proposal); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/third", time.Minute, 0); err != nil || claimed {
		t.Fatalf("completed job reclaimed=%t err=%v", claimed, err)
	}
	stored, found, err := store.ResourceRuleProposal(ctx, jobID)
	if err != nil || !found || !json.Valid(stored) {
		t.Fatalf("proposal=%s found=%t err=%v", stored, found, err)
	}
	status, found, err := store.ResourceRuleJobStatus(ctx, jobID)
	if err != nil || !found || status.Status != "completed" || status.AttemptCount != 2 {
		t.Fatalf("status=%#v found=%t err=%v", status, found, err)
	}
	if _, _, err := store.ClaimResourceRuleJob(ctx, "", time.Minute, 0); err == nil {
		t.Fatal("empty worker ID accepted")
	}
	if _, _, err := store.ClaimResourceRuleJob(ctx, "worker", 0, 0); err == nil {
		t.Fatal("empty lease accepted")
	}
	if _, err := store.RetryResourceRuleJob(ctx, jobID, "worker/retry", "stale", time.Second, false); err == nil {
		t.Fatal("stale lease retried job")
	}
	if err := store.CompleteResourceRuleJob(ctx, jobID, "worker/retry", json.RawMessage(`not-json`)); err == nil {
		t.Fatal("invalid proposal accepted")
	}
}

func TestPostgreSQLDeploymentJobLeaseReclaimAfterCrash(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, deploymentContribution("deployments", 1, "deployment-uid", "payments")); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/crashed", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("job=%#v claimed=%t err=%v", job, claimed, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE resource_rule_jobs SET lease_expires_at=now()-interval '1 second' WHERE job_id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/restarted", time.Minute, 0)
	if err != nil || !claimed || reclaimed.ID != job.ID || reclaimed.AttemptCount != 2 {
		t.Fatalf("job=%#v claimed=%t err=%v", reclaimed, claimed, err)
	}
	if renewed, err := store.RenewResourceRuleJob(ctx, job.ID, "worker/crashed", time.Minute); err != nil || renewed {
		t.Fatalf("stale worker renewed=%t err=%v", renewed, err)
	}
}

func TestPostgreSQLResourceRuleReviewControlsResourceRuleMode(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	contribution := deploymentContribution("deployments", 1, "deployment-uid", "payments")
	if _, err := store.ReplaceContribution(ctx, contribution); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/a", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewApproved, "operator/reviewer", []string{"not-completed"}); err == nil {
		t.Fatal("review accepted before the proposal completed")
	}
	rule := detector.Rule{
		ID: "deployment/" + job.Context.ResourceID + "/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*",
		ScopeResourceID: job.Context.ResourceID, Type: "relationship", Kind: "communicates-with",
		Expression: "destination_ip_class == 'public'", Risk: detector.RiskMedium, Reasons: []string{"resource_rule_match"}, WindowSeconds: 300,
	}
	ruleTwo := rule
	ruleTwo.ID = "deployment/" + job.Context.ResourceID + "/rule-2"
	ruleTwo.Expression = "destination_role == 'database'"
	proposal, err := json.Marshal(map[string]any{"rationale": "test", "rules": []map[string]any{{"rule": rule, "rationale": "public egress"}, {"rule": ruleTwo, "rationale": "database access"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteResourceRuleJob(ctx, job.ID, "worker/a", proposal); err != nil {
		t.Fatal(err)
	}
	assertModes := func(want map[string]detector.RuleMode) {
		t.Helper()
		rules, err := store.ReadResourceRules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := make(map[string]detector.RuleMode, len(rules))
		for _, loaded := range rules {
			got[loaded.Rule.ID] = loaded.Mode
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("rules=%#v, want %v", rules, want)
		}
		if err := detector.ValidateResourceRules(rules); err != nil {
			t.Fatal(err)
		}
	}
	assertModes(map[string]detector.RuleMode{rule.ID: detector.RuleModeShadow, ruleTwo.ID: detector.RuleModeShadow})
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, "pending", "operator/reviewer", nil); err == nil {
		t.Fatal("invalid review decision accepted")
	}
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewApproved, "operator/reviewer", []string{}); !errors.Is(err, ErrResourceRuleSelectionInvalid) {
		t.Fatalf("empty rule selection error = %v", err)
	}
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewApproved, "operator/reviewer", []string{"unknown"}); !errors.Is(err, ErrResourceRuleSelectionInvalid) {
		t.Fatalf("unknown rule selection error = %v", err)
	}
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewApproved, "operator/reviewer", []string{ruleTwo.ID}); err != nil {
		t.Fatal(err)
	}
	assertModes(map[string]detector.RuleMode{ruleTwo.ID: detector.RuleModeActive})
	stored, found, err := store.ResourceRuleProposal(ctx, job.ID)
	if err != nil || !found || !bytes.Contains(stored, []byte(rule.ID)) || !bytes.Contains(stored, []byte(ruleTwo.ID)) || !bytes.Contains(stored, []byte(`"approvedRuleIds"`)) {
		t.Fatalf("selective approval did not retain the proposal: found=%t proposal=%s err=%v", found, stored, err)
	}
	status, found, err := store.ResourceRuleJobStatus(ctx, job.ID)
	if err != nil || !found || status.ReviewStatus != ResourceRuleReviewApproved || status.ReviewedBy != "operator/reviewer" || status.ReviewedAt == nil {
		t.Fatalf("status=%#v found=%t err=%v", status, found, err)
	}
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewRejected, "operator/reviewer", nil); err != nil {
		t.Fatal(err)
	}
	assertModes(map[string]detector.RuleMode{})
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewApproved, "operator/reviewer", []string{rule.ID, ruleTwo.ID}); err != nil {
		t.Fatal(err)
	}
	assertModes(map[string]detector.RuleMode{rule.ID: detector.RuleModeActive, ruleTwo.ID: detector.RuleModeActive})
	if _, err := store.RetireContribution(ctx, contribution.PluginID, contribution.SourceID, contribution.Name, 2, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	assertModes(map[string]detector.RuleMode{})
}

func TestPostgreSQLRequestResourceRuleJobReauthorsTheCurrentRevision(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	contribution := deploymentContribution("deployments", 1, "deployment-uid", "payments")
	contribution.Input.Resources[0].Attributes[graph.ResourceAuthoringContextAttribute] = mustAuthoringContext(map[string]any{"serviceAccountName": "payments"}, nil)
	if _, err := store.ReplaceContribution(ctx, contribution); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.ListResourceRuleJobs(ctx, 10, "")
	if err != nil || len(jobs) != 1 || !jobs[0].CurrentRevision {
		t.Fatalf("jobs=%#v err=%v", jobs, err)
	}
	resourceID := jobs[0].ResourceID
	if stats, err := store.ResourceRuleQueueStats(ctx, 6*time.Hour); err != nil || stats.WaitingForStabilization != 1 || stats.Ready != 0 || stats.NextEligibleAt == nil {
		t.Fatalf("queue before the baseline = %#v err=%v", stats, err)
	}
	if _, claimed, err := store.ClaimResourceRuleJob(ctx, "worker", time.Minute, 6*time.Hour); err != nil || claimed {
		t.Fatalf("claimed a queued job inside its stabilization window: claimed=%t err=%v", claimed, err)
	}
	// Requesting a queued job wakes it: it skips the stabilization wait.
	woken, err := store.RequestResourceRuleJob(ctx, resourceID, "operator/ui")
	if err != nil || woken.ID != jobs[0].ID || woken.Status != "queued" || woken.RequestedBy != "operator/ui" {
		t.Fatalf("wake queued job: job=%#v err=%v", woken, err)
	}
	if stats, err := store.ResourceRuleQueueStats(ctx, 6*time.Hour); err != nil || stats.WaitingForStabilization != 0 || stats.Ready != 1 {
		t.Fatalf("queue after waking = %#v err=%v", stats, err)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker", time.Minute, 6*time.Hour)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if running, err := store.RequestResourceRuleJob(ctx, resourceID, "operator/ui"); !errors.Is(err, ErrResourceRuleJobInProgress) || running.Status != "running" {
		t.Fatalf("request for a running job: job=%#v err=%v", running, err)
	}
	rule := detector.Rule{
		ID: "a", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*", ScopeResourceID: job.Context.ResourceID,
		Type: "resource", Kind: job.Context.Kind, Expression: "true", Risk: detector.RiskMedium, Reasons: []string{"resource_rule_match"},
	}
	ruleTwo := rule
	ruleTwo.ID = "b"
	proposal, err := json.Marshal(map[string]any{"rationale": "r", "rules": []map[string]any{{"rule": rule, "rationale": "x"}, {"rule": ruleTwo, "rationale": "y"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteResourceRuleJob(ctx, job.ID, "worker", proposal); err != nil {
		t.Fatal(err)
	}
	if err := store.ReviewResourceRuleJobRules(ctx, job.ID, ResourceRuleReviewApproved, "operator/reviewer", []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	if status, _, err := store.ResourceRuleJobStatus(ctx, job.ID); err != nil || status.RuleCount != 2 || status.ReviewStatus != ResourceRuleReviewApproved {
		t.Fatalf("completed status=%#v err=%v", status, err)
	}
	refreshed := deploymentContribution("deployments", 2, "deployment-uid", "payments")
	refreshed.Input.Resources[0].Attributes[graph.ResourceAuthoringContextAttribute] = mustAuthoringContext(map[string]any{"serviceAccountName": "payments"}, nil)
	if _, err := store.ReplaceContribution(ctx, refreshed); err != nil {
		t.Fatal(err)
	}
	if jobs, err := store.ListResourceRuleJobs(ctx, 10, resourceID); err != nil || len(jobs) != 1 || jobs[0].Status != "completed" || jobs[0].ReviewStatus != ResourceRuleReviewApproved {
		t.Fatalf("context refresh changed job execution state: jobs=%#v err=%v", jobs, err)
	}

	requested, err := store.RequestResourceRuleJob(ctx, resourceID, "operator/ui")
	if err != nil {
		t.Fatal(err)
	}
	if requested.ID != job.ID || requested.Status != "queued" || requested.ReviewStatus != ResourceRuleReviewPending ||
		requested.RuleCount != 0 || requested.RequestedBy != "operator/ui" || requested.RequestedAt == nil || requested.CompletedAt != nil {
		t.Fatalf("requested job = %#v", requested)
	}
	if _, found, err := store.ResourceRuleProposal(ctx, job.ID); err != nil || found {
		t.Fatalf("the reset job kept its proposal: found=%t err=%v", found, err)
	}
	if rules, err := store.ReadResourceRules(ctx); err != nil || len(rules) != 0 {
		t.Fatalf("the reset job's rules are still loaded: %#v err=%v", rules, err)
	}
	// A requested job skips the stabilization wait.
	if reclaimed, claimed, err := store.ClaimResourceRuleJob(ctx, "worker", time.Minute, 6*time.Hour); err != nil || !claimed || reclaimed.ID != job.ID || !bytes.Contains(reclaimed.Context.Context, []byte(`"serviceAccountName": "payments"`)) {
		t.Fatalf("requested job did not use refreshed context: job=%#v claimed=%t err=%v", reclaimed, claimed, err)
	}
	if _, err := store.RequestResourceRuleJob(ctx, "00000000-0000-0000-0000-000000000000", "operator/ui"); !errors.Is(err, ErrResourceRuleJobNotFound) {
		t.Fatalf("request for an unknown Deployment: err=%v", err)
	}
	if _, err := store.RequestResourceRuleJob(ctx, resourceID, ""); err == nil {
		t.Fatal("request without an actor was accepted")
	}
}

func TestPostgreSQLReadResourceRulesSkipsMisScopedProposal(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, deploymentContribution("deployments", 1, "deployment-uid", "payments")); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/a", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	rule := detector.Rule{
		ID: "deployment/other/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*",
		ScopeResourceID: "00000000-0000-0000-0000-000000000000", Type: "relationship", Kind: "communicates-with",
		Expression: "destination_ip_class == 'public'", Risk: detector.RiskMedium, Reasons: []string{"resource_rule_match"}, WindowSeconds: 300,
	}
	proposal, err := json.Marshal(map[string]any{"rationale": "test", "rules": []map[string]any{{"rule": rule, "rationale": "wrong scope"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteResourceRuleJob(ctx, job.ID, "worker/a", proposal); err == nil {
		t.Fatal("completed a proposal containing a rule scoped to another resource")
	}
	if _, err := store.pool.Exec(ctx, `UPDATE resource_rule_jobs SET status='completed', proposal=$2, lease_owner=NULL, lease_expires_at=NULL, completed_at=now() WHERE job_id=$1`, job.ID, proposal); err != nil {
		t.Fatal(err)
	}
	if rules, err := store.ReadResourceRules(ctx); err != nil || len(rules) != 0 {
		t.Fatalf("rules=%#v err=%v, want none and no error", rules, err)
	}
}

func TestPostgreSQLResourceRuleJobFailsTerminallyUntilRequested(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, revisionContribution(1, "a")); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/a", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if outcome, err := store.RetryResourceRuleJob(ctx, job.ID, "worker/a", "400 Bad Request", time.Second, true); err != nil || outcome != ResourceRuleRetryFailed {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE resource_rule_jobs SET available_at=now()-interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/b", time.Minute, 0); err != nil || claimed {
		t.Fatalf("failed job reclaimed=%t err=%v", claimed, err)
	}
	status, found, err := store.ResourceRuleJobStatus(ctx, job.ID)
	if err != nil || !found || status.Status != "failed" || status.LastError != "400 Bad Request" {
		t.Fatalf("status=%#v found=%t err=%v", status, found, err)
	}
	if stats, err := store.ResourceRuleQueueStats(ctx, 0); err != nil || stats.Failed != 1 || stats.Ready != 0 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	// An operator request queues it again with a fresh attempt count.
	requested, err := store.RequestResourceRuleJob(ctx, job.Context.ResourceID, "operator/ui")
	if err != nil || requested.Status != "queued" || requested.AttemptCount != 0 {
		t.Fatalf("requested=%#v err=%v", requested, err)
	}
	if reclaimed, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/b", time.Minute, 0); err != nil || !claimed || reclaimed.ID != job.ID {
		t.Fatalf("requested job claimed=%t err=%v", claimed, err)
	}
}

func TestPostgreSQLStaleResourceRuleJobsAreDropped(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, revisionContribution(1, "a")); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/a", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	// A new Pod template revision arrives while revision a is being authored.
	if _, err := store.ReplaceContribution(ctx, revisionContribution(2, "b")); err != nil {
		t.Fatal(err)
	}
	if renewed, err := store.RenewResourceRuleJob(ctx, job.ID, "worker/a", time.Minute); err != nil || renewed {
		t.Fatalf("superseded lease renewed=%t err=%v", renewed, err)
	}
	if err := store.CompleteResourceRuleJob(ctx, job.ID, "worker/a", json.RawMessage(`{"rationale":"stale","rules":[]}`)); err == nil {
		t.Fatal("superseded job completed")
	}
	if outcome, err := store.RetryResourceRuleJob(ctx, job.ID, "worker/a", "model unavailable", time.Second, false); err != nil || outcome != ResourceRuleRetrySuperseded {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if _, found, err := store.ResourceRuleJobStatus(ctx, job.ID); err != nil || found {
		t.Fatalf("superseded job kept: found=%t err=%v", found, err)
	}
	// The Deployment leaves the graph before revision b is claimed: the claim
	// drops b instead of authoring a Deployment that no longer exists.
	gone := revisionContribution(3, "b")
	gone.Input = graph.Input{}
	if _, err := store.ReplaceContribution(ctx, gone); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := store.ClaimResourceRuleJob(ctx, "worker/a", time.Minute, 0); err != nil || claimed {
		t.Fatalf("job for a deleted Deployment claimed=%t err=%v", claimed, err)
	}
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM resource_rule_jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("jobs left=%d err=%v", count, err)
	}
}
