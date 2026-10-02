package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestDeploymentAuthoringContextUsesOnlyKubernetesProjection(t *testing.T) {
	resource := graph.Resource{ID: "deployment-id", Kind: "kubernetes/deployment", Assertions: []graph.ResourceAssertion{
		{PluginID: "untrusted-plugin", RuleID: "kubernetes.deployment.authoring-context", Attributes: map[string]string{"kubernetes/name": "spoofed"}},
		{PluginID: "kubernetes", RuleID: "kubernetes.deployment.authoring-context", Attributes: map[string]string{
			"kubernetes/name": "istiod", "kubernetes/namespace": "istio-system", "kubernetes/service-account-name": "istiod",
		}}}}
	authoringContext := DeploymentAuthoringContextFor(resource)
	want := DeploymentAuthoringContext{ResourceID: "deployment-id", Kind: "kubernetes/deployment", Name: "istiod", Namespace: "istio-system", ServiceAccountName: "istiod"}
	if authoringContext != want {
		t.Fatalf("context=%#v, want %#v", authoringContext, want)
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

func TestDeploymentBehaviorForSummarizesTheDeploymentsOutboundTelemetry(t *testing.T) {
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
			named("catalog", "kubernetes/service", "catalog-api", nil),
			named("apiserver", "network/destination", "", map[string]string{"network/role": graph.NetworkRoleControlPlaneAPI}),
		},
		Telemetry: []graph.TelemetryEvent{
			{SubjectID: "frontend", ObjectID: "catalog", Kind: "active-probe", Operation: "GET /v1/products?page=1", Outcome: "allowed", Count: 2},
			{SubjectID: "frontend", ObjectID: "catalog", Kind: "active-probe", Operation: "GET /v1/products?page=2", Outcome: "allowed", Count: 3},
			{SubjectID: "frontend", ObjectID: "apiserver", Kind: "network-flow", Operation: "egress", Outcome: "forwarded", Count: 1},
			{SubjectID: "catalog", ObjectID: "frontend", Kind: "active-probe", Operation: "GET /", Outcome: "allowed", Count: 9},
		},
	}
	want := DeploymentBehavior{CollectedTelemetry: []string{"active-probe", "network-flow"}, Requests: []ObservedRequest{
		{Telemetry: "network-flow", DestinationKind: "network/destination", DestinationRole: graph.NetworkRoleControlPlaneAPI, Operation: "egress", Outcome: "forwarded", Count: 1},
		{Telemetry: "active-probe", Destination: "shop/catalog-api", DestinationKind: "kubernetes/service", Operation: "GET /v1/products", Outcome: "allowed", Count: 5},
	}}
	if got := DeploymentBehaviorFor(snapshot, "frontend"); !reflect.DeepEqual(got, want) {
		t.Fatalf("behavior = %#v, want %#v", got, want)
	}
	if got := DeploymentBehaviorFor(snapshot, "missing"); got.Requests == nil || len(got.Requests) != 0 || got.Truncated || len(got.CollectedTelemetry) != 2 {
		t.Fatalf("a Deployment without telemetry = %#v, want an empty, non-nil request list and the collected kinds", got)
	}

	if got := DeploymentBehaviorFor(graph.Snapshot{}, "frontend"); got.CollectedTelemetry == nil || got.Requests == nil {
		t.Fatalf("an empty graph = %#v, want empty, non-nil lists", got)
	}
	snapshot.Telemetry = nil
	for index := range MaxObservedRequests + 1 {
		snapshot.Telemetry = append(snapshot.Telemetry, graph.TelemetryEvent{
			SubjectID: "frontend", ObjectID: "catalog", Kind: "active-probe", Operation: fmt.Sprintf("GET /v1/path-%02d", index), Count: uint64(index + 1),
		})
	}
	truncated := DeploymentBehaviorFor(snapshot, "frontend")
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
			Attributes: map[string]string{"kubernetes/name": "payments", "kubernetes/namespace": "prod", "kubernetes/label/app": label},
			PluginID:   "kubernetes", SourceID: "cluster/local", RuleID: "test.deployment",
		}}},
	}
}

func TestPostgreSQLDeploymentAuthoringJobCreatedOncePerGraphIdentity(t *testing.T) {
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
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM deployment_rule_jobs WHERE resource_id=$1`, resourceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("job count=%d err=%v", count, err)
	}
	first.Generation = 2
	first.Input.Resources[0].Attributes["kubernetes/label/app"] = "payments-v2"
	first.SourceObservedAt = time.Now().UTC()
	if _, err := store.ReplaceContribution(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM deployment_rule_jobs WHERE resource_id=$1`, resourceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("after update job count=%d err=%v", count, err)
	}
	second := deploymentContribution("semantic-deployment-assertion", 1, "deployment-uid", "payments")
	second.PluginID, second.SourceID = "test-observer", "observer/local"
	second.Input.Resources[0].PluginID, second.Input.Resources[0].SourceID = second.PluginID, second.SourceID
	if _, err := store.ReplaceContribution(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM deployment_rule_jobs WHERE resource_id=$1`, resourceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("after second assertion job count=%d err=%v", count, err)
	}
	third := deploymentContribution("another-deployment", 1, "other-uid", "ledger")
	if _, err := store.ReplaceContribution(ctx, third); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM deployment_rule_jobs`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("total job count=%d err=%v", count, err)
	}
}

// revisionContribution is a Kubernetes authoring-context assertion for one
// Deployment Pod template revision.
func revisionContribution(generation uint64, template string) Contribution {
	contribution := deploymentContribution("deployments", generation, "deployment-uid", "payments")
	contribution.SourceObservedAt = time.Now().UTC()
	contribution.Input.Resources[0].RuleID = "kubernetes.deployment.authoring-context"
	contribution.Input.Resources[0].Attributes["kubernetes/pod-template-sha256"] = strings.Repeat(template, 64)
	return contribution
}

func TestPostgreSQLDeploymentAuthoringJobPerTemplateRevision(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	revisions := func() []string {
		t.Helper()
		rows, err := store.pool.Query(ctx, `SELECT left(template_sha256, 1) || ':' || status FROM deployment_rule_jobs ORDER BY job_id`)
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
	publish(1, "a")
	if got := revisions(); !reflect.DeepEqual(got, []string{"a:queued"}) {
		t.Fatalf("after first revision jobs=%v", got)
	}
	job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker", time.Minute, time.Hour)
	if err != nil || claimed {
		t.Fatalf("a job inside its baseline window was claimed: job=%#v err=%v", job, err)
	}
	if job, claimed, err = store.ClaimDeploymentRuleJob(ctx, "worker", time.Minute, 0); err != nil || !claimed || job.Context.TemplateSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("job=%#v claimed=%t err=%v", job, claimed, err)
	}
	if err := store.CompleteDeploymentRuleJob(ctx, job.ID, "worker", json.RawMessage(`{"rationale":"r","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	publish(2, "b")
	publish(3, "c")
	if got := revisions(); !reflect.DeepEqual(got, []string{"a:completed", "c:queued"}) {
		t.Fatalf("a queued revision was not superseded: jobs=%v", got)
	}
	publish(4, "a")
	if got := revisions(); !reflect.DeepEqual(got, []string{"a:completed"}) {
		t.Fatalf("returning to an authored revision: jobs=%v", got)
	}
	status, found, err := store.DeploymentRuleJobStatus(ctx, job.ID)
	if err != nil || !found || status.TemplateSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("status=%#v found=%t err=%v", status, found, err)
	}
}

func TestPostgreSQLDeploymentRuleRevisionsFollowTheCurrentTemplate(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	generation := uint64(0)
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
		job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker", time.Minute, 0)
		if err != nil || !claimed {
			t.Fatalf("claimed=%t err=%v", claimed, err)
		}
		rule := detector.Rule{
			ID: "deployment/" + job.Context.ResourceID + "/template-" + template + "/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*",
			WorkloadResourceID: job.Context.ResourceID, Type: "relationship", Kind: "communicates-with",
			Expression: "true", Risk: detector.RiskMedium, Reasons: []string{"workload_rule_match"}, WindowSeconds: 300,
		}
		proposal, err := json.Marshal(map[string]any{"rationale": "r", "rules": []map[string]any{{"rule": rule, "rationale": "r"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.CompleteDeploymentRuleJob(ctx, job.ID, "worker", proposal); err != nil {
			t.Fatal(err)
		}
		return job.ID
	}
	review := func(jobID int64, decision string) {
		t.Helper()
		if err := store.ReviewDeploymentRuleJob(ctx, jobID, decision, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(step string, want map[string]detector.RuleMode) {
		t.Helper()
		rules, err := store.ReadWorkloadRules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := detector.ValidateWorkloadRules(rules); err != nil {
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
	review(first, DeploymentRuleReviewApproved)
	expect("approved revision", map[string]detector.RuleMode{"a": detector.RuleModeActive})
	second := author("b")
	expect("new revision pending", map[string]detector.RuleMode{"a": detector.RuleModeActive, "b": detector.RuleModeShadow})
	review(second, DeploymentRuleReviewRejected)
	expect("new revision rejected", map[string]detector.RuleMode{"a": detector.RuleModeActive})
	third := author("c")
	review(third, DeploymentRuleReviewApproved)
	expect("newer revision approved", map[string]detector.RuleMode{"c": detector.RuleModeActive})
	publish("a")
	expect("rollback to an approved revision", map[string]detector.RuleMode{"a": detector.RuleModeActive})
	publish("b")
	expect("rollback to a rejected revision", map[string]detector.RuleMode{"c": detector.RuleModeActive})
	publish("c")
	expect("roll forward", map[string]detector.RuleMode{"c": detector.RuleModeActive})
	var current int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM deployment_rule_jobs WHERE current_revision`).Scan(&current); err != nil || current != 1 {
		t.Fatalf("current revisions=%d err=%v", current, err)
	}
}

func TestPostgreSQLDeploymentJobClaimLeaseRetryAndCompletion(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, deploymentContribution("deployments", 1, "deployment-uid", "payments")); err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err := store.pool.QueryRow(ctx, `SELECT job_id FROM deployment_rule_jobs`).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	claims := make(chan bool, 2)
	errorsChannel := make(chan error, 2)
	for _, owner := range []string{"worker/a", "worker/b"} {
		wait.Add(1)
		go func(owner string) {
			defer wait.Done()
			_, claimed, err := store.ClaimDeploymentRuleJob(ctx, owner, time.Minute, 0)
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
	if err := store.pool.QueryRow(ctx, `SELECT lease_owner FROM deployment_rule_jobs WHERE job_id=$1`, jobID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if renewed, err := store.RenewDeploymentRuleJob(ctx, jobID, owner, time.Minute); err != nil || !renewed {
		t.Fatalf("renewed=%t err=%v", renewed, err)
	}
	if outcome, err := store.RetryDeploymentRuleJob(ctx, jobID, owner, "temporary failure", time.Second, false); err != nil || outcome != DeploymentRuleRetryScheduled {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if _, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/retry", time.Minute, 0); err != nil || claimed {
		t.Fatalf("early retry claimed=%t err=%v", claimed, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deployment_rule_jobs SET available_at=now()-interval '1 second' WHERE job_id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/retry", time.Minute, 0)
	if err != nil || !claimed || job.AttemptCount != 2 {
		t.Fatalf("job=%#v claimed=%t err=%v", job, claimed, err)
	}
	proposal := json.RawMessage(`{"jobId":1,"rules":[]}`)
	if err := store.CompleteDeploymentRuleJob(ctx, jobID, "worker/other", proposal); err == nil {
		t.Fatal("non-owner completed job")
	}
	if err := store.CompleteDeploymentRuleJob(ctx, jobID, "worker/retry", proposal); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/third", time.Minute, 0); err != nil || claimed {
		t.Fatalf("completed job reclaimed=%t err=%v", claimed, err)
	}
	stored, found, err := store.DeploymentRuleProposal(ctx, jobID)
	if err != nil || !found || !json.Valid(stored) {
		t.Fatalf("proposal=%s found=%t err=%v", stored, found, err)
	}
	status, found, err := store.DeploymentRuleJobStatus(ctx, jobID)
	if err != nil || !found || status.Status != "completed" || status.AttemptCount != 2 {
		t.Fatalf("status=%#v found=%t err=%v", status, found, err)
	}
	if _, _, err := store.ClaimDeploymentRuleJob(ctx, "", time.Minute, 0); err == nil {
		t.Fatal("empty worker ID accepted")
	}
	if _, _, err := store.ClaimDeploymentRuleJob(ctx, "worker", 0, 0); err == nil {
		t.Fatal("empty lease accepted")
	}
	if _, err := store.RetryDeploymentRuleJob(ctx, jobID, "worker/retry", "stale", time.Second, false); err == nil {
		t.Fatal("stale lease retried job")
	}
	if err := store.CompleteDeploymentRuleJob(ctx, jobID, "worker/retry", json.RawMessage(`not-json`)); err == nil {
		t.Fatal("invalid proposal accepted")
	}
}

func TestPostgreSQLDeploymentJobLeaseReclaimAfterCrash(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, deploymentContribution("deployments", 1, "deployment-uid", "payments")); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/crashed", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("job=%#v claimed=%t err=%v", job, claimed, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deployment_rule_jobs SET lease_expires_at=now()-interval '1 second' WHERE job_id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/restarted", time.Minute, 0)
	if err != nil || !claimed || reclaimed.ID != job.ID || reclaimed.AttemptCount != 2 {
		t.Fatalf("job=%#v claimed=%t err=%v", reclaimed, claimed, err)
	}
	if renewed, err := store.RenewDeploymentRuleJob(ctx, job.ID, "worker/crashed", time.Minute); err != nil || renewed {
		t.Fatalf("stale worker renewed=%t err=%v", renewed, err)
	}
}

func TestPostgreSQLDeploymentRuleReviewControlsWorkloadRuleMode(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	contribution := deploymentContribution("deployments", 1, "deployment-uid", "payments")
	if _, err := store.ReplaceContribution(ctx, contribution); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/a", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if err := store.ReviewDeploymentRuleJob(ctx, job.ID, DeploymentRuleReviewApproved, "operator/reviewer"); err == nil {
		t.Fatal("review accepted before the proposal completed")
	}
	rule := detector.Rule{
		ID: "deployment/" + job.Context.ResourceID + "/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*",
		WorkloadResourceID: job.Context.ResourceID, Type: "relationship", Kind: "communicates-with",
		Expression: "destination_ip_class == 'public'", Risk: detector.RiskMedium, Reasons: []string{"workload_rule_match"}, WindowSeconds: 300,
	}
	proposal, err := json.Marshal(map[string]any{"rationale": "test", "rules": []map[string]any{{"rule": rule, "rationale": "public egress"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteDeploymentRuleJob(ctx, job.ID, "worker/a", proposal); err != nil {
		t.Fatal(err)
	}
	assertMode := func(want detector.RuleMode) {
		t.Helper()
		rules, err := store.ReadWorkloadRules(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if want == "" {
			if len(rules) != 0 {
				t.Fatalf("rules=%#v, want none", rules)
			}
			return
		}
		if len(rules) != 1 || rules[0].Mode != want || rules[0].Rule.ID != rule.ID {
			t.Fatalf("rules=%#v, want one %s rule", rules, want)
		}
		if err := detector.ValidateWorkloadRules(rules); err != nil {
			t.Fatal(err)
		}
	}
	assertMode(detector.RuleModeShadow)
	if err := store.ReviewDeploymentRuleJob(ctx, job.ID, "pending", "operator/reviewer"); err == nil {
		t.Fatal("invalid review decision accepted")
	}
	if err := store.ReviewDeploymentRuleJob(ctx, job.ID, DeploymentRuleReviewApproved, "operator/reviewer"); err != nil {
		t.Fatal(err)
	}
	assertMode(detector.RuleModeActive)
	status, found, err := store.DeploymentRuleJobStatus(ctx, job.ID)
	if err != nil || !found || status.ReviewStatus != DeploymentRuleReviewApproved || status.ReviewedBy != "operator/reviewer" || status.ReviewedAt == nil {
		t.Fatalf("status=%#v found=%t err=%v", status, found, err)
	}
	if err := store.ReviewDeploymentRuleJob(ctx, job.ID, DeploymentRuleReviewRejected, "operator/reviewer"); err != nil {
		t.Fatal(err)
	}
	assertMode("")
	if err := store.ReviewDeploymentRuleJob(ctx, job.ID, DeploymentRuleReviewApproved, "operator/reviewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RetireContribution(ctx, contribution.PluginID, contribution.SourceID, contribution.Name, 2, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	assertMode("")
}

func TestPostgreSQLRequestDeploymentRuleJobReauthorsTheCurrentRevision(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, deploymentContribution("deployments", 1, "deployment-uid", "payments")); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.ListDeploymentRuleJobs(ctx, 10)
	if err != nil || len(jobs) != 1 || !jobs[0].CurrentRevision {
		t.Fatalf("jobs=%#v err=%v", jobs, err)
	}
	resourceID := jobs[0].ResourceID
	if stats, err := store.DeploymentRuleQueueStats(ctx, 6*time.Hour); err != nil || stats.WaitingForBaseline != 1 || stats.Ready != 0 || stats.NextEligibleAt == nil {
		t.Fatalf("queue before the baseline = %#v err=%v", stats, err)
	}
	if _, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker", time.Minute, 6*time.Hour); err != nil || claimed {
		t.Fatalf("claimed a queued job inside its baseline window: claimed=%t err=%v", claimed, err)
	}
	// Requesting a queued job wakes it: it skips the baseline wait.
	woken, err := store.RequestDeploymentRuleJob(ctx, resourceID, "operator/ui")
	if err != nil || woken.ID != jobs[0].ID || woken.Status != "queued" || woken.RequestedBy != "operator/ui" {
		t.Fatalf("wake queued job: job=%#v err=%v", woken, err)
	}
	if stats, err := store.DeploymentRuleQueueStats(ctx, 6*time.Hour); err != nil || stats.WaitingForBaseline != 0 || stats.Ready != 1 {
		t.Fatalf("queue after waking = %#v err=%v", stats, err)
	}
	job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker", time.Minute, 6*time.Hour)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if running, err := store.RequestDeploymentRuleJob(ctx, resourceID, "operator/ui"); !errors.Is(err, ErrDeploymentRuleJobInProgress) || running.Status != "running" {
		t.Fatalf("request for a running job: job=%#v err=%v", running, err)
	}
	proposal := json.RawMessage(`{"rationale":"r","rules":[{"rule":{"id":"a"},"rationale":"x"},{"rule":{"id":"b"},"rationale":"y"}]}`)
	if err := store.CompleteDeploymentRuleJob(ctx, job.ID, "worker", proposal); err != nil {
		t.Fatal(err)
	}
	if err := store.ReviewDeploymentRuleJob(ctx, job.ID, DeploymentRuleReviewApproved, "operator/reviewer"); err != nil {
		t.Fatal(err)
	}
	if status, _, err := store.DeploymentRuleJobStatus(ctx, job.ID); err != nil || status.RuleCount != 2 || status.ReviewStatus != DeploymentRuleReviewApproved {
		t.Fatalf("completed status=%#v err=%v", status, err)
	}

	requested, err := store.RequestDeploymentRuleJob(ctx, resourceID, "operator/ui")
	if err != nil {
		t.Fatal(err)
	}
	if requested.ID != job.ID || requested.Status != "queued" || requested.ReviewStatus != DeploymentRuleReviewPending ||
		requested.RuleCount != 0 || requested.RequestedBy != "operator/ui" || requested.RequestedAt == nil || requested.CompletedAt != nil {
		t.Fatalf("requested job = %#v", requested)
	}
	if _, found, err := store.DeploymentRuleProposal(ctx, job.ID); err != nil || found {
		t.Fatalf("the reset job kept its proposal: found=%t err=%v", found, err)
	}
	if rules, err := store.ReadWorkloadRules(ctx); err != nil || len(rules) != 0 {
		t.Fatalf("the reset job's rules are still loaded: %#v err=%v", rules, err)
	}
	// A requested job skips the baseline wait.
	if reclaimed, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker", time.Minute, 6*time.Hour); err != nil || !claimed || reclaimed.ID != job.ID {
		t.Fatalf("requested job was not claimable before the baseline window: claimed=%t err=%v", claimed, err)
	}
	if _, err := store.RequestDeploymentRuleJob(ctx, "00000000-0000-0000-0000-000000000000", "operator/ui"); !errors.Is(err, ErrDeploymentRuleJobNotFound) {
		t.Fatalf("request for an unknown Deployment: err=%v", err)
	}
	if _, err := store.RequestDeploymentRuleJob(ctx, resourceID, ""); err == nil {
		t.Fatal("request without an actor was accepted")
	}
}

func TestPostgreSQLReadWorkloadRulesSkipsMisScopedProposal(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, deploymentContribution("deployments", 1, "deployment-uid", "payments")); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/a", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	rule := detector.Rule{
		ID: "deployment/other/rule-1", Revision: 1, InputVersion: detector.InputVersion, PluginID: "*",
		WorkloadResourceID: "00000000-0000-0000-0000-000000000000", Type: "relationship", Kind: "communicates-with",
		Expression: "destination_ip_class == 'public'", Risk: detector.RiskMedium, Reasons: []string{"workload_rule_match"}, WindowSeconds: 300,
	}
	proposal, err := json.Marshal(map[string]any{"rationale": "test", "rules": []map[string]any{{"rule": rule, "rationale": "wrong scope"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteDeploymentRuleJob(ctx, job.ID, "worker/a", proposal); err != nil {
		t.Fatal(err)
	}
	// One bad proposal is skipped instead of failing every detector reload.
	if rules, err := store.ReadWorkloadRules(ctx); err != nil || len(rules) != 0 {
		t.Fatalf("rules=%#v err=%v, want none and no error", rules, err)
	}
}

func TestPostgreSQLDeploymentRuleJobFailsTerminallyUntilRequested(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, revisionContribution(1, "a")); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/a", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if outcome, err := store.RetryDeploymentRuleJob(ctx, job.ID, "worker/a", "400 Bad Request", time.Second, true); err != nil || outcome != DeploymentRuleRetryFailed {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE deployment_rule_jobs SET available_at=now()-interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/b", time.Minute, 0); err != nil || claimed {
		t.Fatalf("failed job reclaimed=%t err=%v", claimed, err)
	}
	status, found, err := store.DeploymentRuleJobStatus(ctx, job.ID)
	if err != nil || !found || status.Status != "failed" || status.LastError != "400 Bad Request" {
		t.Fatalf("status=%#v found=%t err=%v", status, found, err)
	}
	if stats, err := store.DeploymentRuleQueueStats(ctx, 0); err != nil || stats.Failed != 1 || stats.Ready != 0 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	// An operator request queues it again with a fresh attempt count.
	requested, err := store.RequestDeploymentRuleJob(ctx, job.Context.ResourceID, "operator/ui")
	if err != nil || requested.Status != "queued" || requested.AttemptCount != 0 {
		t.Fatalf("requested=%#v err=%v", requested, err)
	}
	if reclaimed, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/b", time.Minute, 0); err != nil || !claimed || reclaimed.ID != job.ID {
		t.Fatalf("requested job claimed=%t err=%v", claimed, err)
	}
}

func TestPostgreSQLStaleDeploymentRuleJobsAreDropped(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, err := store.ReplaceContribution(ctx, revisionContribution(1, "a")); err != nil {
		t.Fatal(err)
	}
	job, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/a", time.Minute, 0)
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	// A new Pod template revision arrives while revision a is being authored.
	if _, err := store.ReplaceContribution(ctx, revisionContribution(2, "b")); err != nil {
		t.Fatal(err)
	}
	if outcome, err := store.RetryDeploymentRuleJob(ctx, job.ID, "worker/a", "model unavailable", time.Second, false); err != nil || outcome != DeploymentRuleRetrySuperseded {
		t.Fatalf("outcome=%v err=%v", outcome, err)
	}
	if _, found, err := store.DeploymentRuleJobStatus(ctx, job.ID); err != nil || found {
		t.Fatalf("superseded job kept: found=%t err=%v", found, err)
	}
	// The Deployment leaves the graph before revision b is claimed: the claim
	// drops b instead of authoring a Deployment that no longer exists.
	gone := revisionContribution(3, "b")
	gone.Input = graph.Input{}
	if _, err := store.ReplaceContribution(ctx, gone); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := store.ClaimDeploymentRuleJob(ctx, "worker/a", time.Minute, 0); err != nil || claimed {
		t.Fatalf("job for a deleted Deployment claimed=%t err=%v", claimed, err)
	}
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM deployment_rule_jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("jobs left=%d err=%v", count, err)
	}
}
