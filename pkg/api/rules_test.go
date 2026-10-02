package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

type fakeRuleStore struct {
	activation detector.Activation
	active     bool
	workload   []detector.WorkloadRule
	jobs       map[int64]state.DeploymentRuleJobSummary
	proposals  map[int64]json.RawMessage
	reviews    []string
	requested  []string
}

func (store *fakeRuleStore) ReadActiveDetectorRuleset(context.Context) (detector.Activation, error) {
	if !store.active {
		return detector.Activation{}, detector.ErrNoActiveRuleset
	}
	return store.activation, nil
}

func (store *fakeRuleStore) ReadWorkloadRules(context.Context) ([]detector.WorkloadRule, error) {
	return store.workload, nil
}

func (store *fakeRuleStore) ListDeploymentRuleJobs(context.Context, int) ([]state.DeploymentRuleJobSummary, error) {
	var jobs []state.DeploymentRuleJobSummary
	for _, job := range store.jobs {
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (store *fakeRuleStore) DeploymentRuleJobStatus(_ context.Context, id int64) (state.DeploymentRuleJobSummary, bool, error) {
	job, found := store.jobs[id]
	return job, found, nil
}

func (store *fakeRuleStore) DeploymentRuleProposal(_ context.Context, id int64) (json.RawMessage, bool, error) {
	proposal, found := store.proposals[id]
	return proposal, found, nil
}

func (store *fakeRuleStore) ReviewDeploymentRuleJob(_ context.Context, id int64, decision, actor string) error {
	job := store.jobs[id]
	if job.Status != "completed" {
		return state.ErrDeploymentRuleJobNotReviewable
	}
	job.ReviewStatus, job.ReviewedBy = decision, actor
	store.jobs[id] = job
	store.reviews = append(store.reviews, decision)
	return nil
}

func (store *fakeRuleStore) RequestDeploymentRuleJob(_ context.Context, resourceID, actor string) (state.DeploymentRuleJobSummary, error) {
	for id, job := range store.jobs {
		if job.ResourceID != resourceID || !job.CurrentRevision {
			continue
		}
		if job.Status == "running" {
			return job, state.ErrDeploymentRuleJobInProgress
		}
		now := time.Now()
		job.Status, job.ReviewStatus, job.RuleCount, job.RequestedBy, job.RequestedAt = "queued", state.DeploymentRuleReviewPending, 0, actor, &now
		store.jobs[id] = job
		store.requested = append(store.requested, resourceID)
		return job, nil
	}
	return state.DeploymentRuleJobSummary{}, state.ErrDeploymentRuleJobNotFound
}

func ruleTestServer(t *testing.T, store *fakeRuleStore, writable bool) http.Handler {
	t.Helper()
	server, err := NewServer(&fakeStateStore{}, nil, WithRules(store, writable))
	if err != nil {
		t.Fatal(err)
	}
	return server.Handler()
}

func newRuleStore() *fakeRuleStore {
	return &fakeRuleStore{
		jobs: map[int64]state.DeploymentRuleJobSummary{
			1: {ID: 1, ResourceID: "deployment-a", Status: "completed", ReviewStatus: state.DeploymentRuleReviewPending, RuleCount: 1, CurrentRevision: true},
			2: {ID: 2, ResourceID: "deployment-b", Status: "running", ReviewStatus: state.DeploymentRuleReviewPending, CurrentRevision: true},
		},
		proposals: map[int64]json.RawMessage{1: json.RawMessage(`{"rationale":"r","rules":[{"rule":{"id":"deployment/deployment-a/rule-1"},"rationale":"x"}]}`)},
	}
}

func serveRuleRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestRulesRouteReportsMissingActivationAndWorkloadRules(t *testing.T) {
	store := newRuleStore()
	store.workload = []detector.WorkloadRule{{Rule: detector.Rule{ID: "deployment/deployment-a/rule-1", WorkloadResourceID: "deployment-a"}, Mode: detector.RuleModeShadow}}
	response := serveRuleRequest(ruleTestServer(t, store, false), http.MethodGet, "/api/v1/rules", "")
	var body rulesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s err=%v", response.Code, response.Body, err)
	}
	if body.Activation != nil || len(body.Rules) != 0 || len(body.WorkloadRules) != 1 || body.WorkloadRules[0].Mode != detector.RuleModeShadow {
		t.Fatalf("rules response = %#v", body)
	}
	store.active, store.activation = true, detector.Activation{Revision: 3, Ruleset: detector.Ruleset{ID: "security/v2", Rules: []detector.Rule{{ID: "global"}}}}
	response = serveRuleRequest(ruleTestServer(t, store, false), http.MethodGet, "/api/v1/rules", "")
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Activation == nil || body.Activation.Revision != 3 || body.Activation.RulesetID != "security/v2" || len(body.Rules) != 1 {
		t.Fatalf("active rules response = %s err=%v", response.Body, err)
	}
}

func TestRuleDraftRoutesReturnSummariesAndProposals(t *testing.T) {
	handler := ruleTestServer(t, newRuleStore(), false)
	response := serveRuleRequest(handler, http.MethodGet, "/api/v1/rule-drafts", "")
	var list ruleDraftsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil || len(list.Drafts) != 2 {
		t.Fatalf("drafts=%s err=%v", response.Body, err)
	}
	response = serveRuleRequest(handler, http.MethodGet, "/api/v1/rule-drafts/1", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"proposal":{"rationale":"r"`) {
		t.Fatalf("completed draft = %d %s", response.Code, response.Body)
	}
	response = serveRuleRequest(handler, http.MethodGet, "/api/v1/rule-drafts/2", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"proposal":null`) {
		t.Fatalf("running draft = %d %s", response.Code, response.Body)
	}
	for path, want := range map[string]int{"/api/v1/rule-drafts/9": http.StatusNotFound, "/api/v1/rule-drafts/x": http.StatusBadRequest} {
		if response := serveRuleRequest(handler, http.MethodGet, path, ""); response.Code != want {
			t.Fatalf("%s status = %d, want %d", path, response.Code, want)
		}
	}
}

func TestRuleWriteRoutesRequireWritesAndMapStateErrors(t *testing.T) {
	store := newRuleStore()
	readOnly := ruleTestServer(t, store, false)
	for _, path := range []string{"/api/v1/rule-drafts/1/review", "/api/v1/workloads/deployment-a/rule-drafts"} {
		if response := serveRuleRequest(readOnly, http.MethodPost, path, `{"decision":"approved"}`); response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "--rule-review-api") {
			t.Fatalf("read-only %s = %d %s", path, response.Code, response.Body)
		}
	}
	if len(store.reviews) != 0 || len(store.requested) != 0 {
		t.Fatal("a read-only server changed rule state")
	}

	handler := ruleTestServer(t, store, true)
	if response := serveRuleRequest(handler, http.MethodPost, "/api/v1/rule-drafts/1/review", `{"decision":"pending"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid decision = %d", response.Code)
	}
	response := serveRuleRequest(handler, http.MethodPost, "/api/v1/rule-drafts/1/review", `{"decision":"approved"}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"reviewStatus":"approved"`) || store.jobs[1].ReviewedBy != ruleActor {
		t.Fatalf("approve = %d %s", response.Code, response.Body)
	}
	if response := serveRuleRequest(handler, http.MethodPost, "/api/v1/rule-drafts/2/review", `{"decision":"approved"}`); response.Code != http.StatusConflict {
		t.Fatalf("review of a running draft = %d", response.Code)
	}

	response = serveRuleRequest(handler, http.MethodPost, "/api/v1/workloads/deployment-a/rule-drafts", "{}")
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"status":"queued"`) {
		t.Fatalf("regenerate = %d %s", response.Code, response.Body)
	}
	response = serveRuleRequest(handler, http.MethodPost, "/api/v1/workloads/deployment-b/rule-drafts", "{}")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"draft":{"id":2`) {
		t.Fatalf("regenerate in progress = %d %s", response.Code, response.Body)
	}
	if response := serveRuleRequest(handler, http.MethodPost, "/api/v1/workloads/unknown/rule-drafts", "{}"); response.Code != http.StatusNotFound {
		t.Fatalf("regenerate unknown = %d", response.Code)
	}
	// A form post from another origin is not JSON, so it never reaches the store.
	formPost := httptest.NewRequest(http.MethodPost, "/api/v1/workloads/deployment-a/rule-drafts", strings.NewReader("x=1"))
	formPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, formPost)
	if recorder.Code != http.StatusBadRequest || len(store.requested) != 1 {
		t.Fatalf("form post regenerate = %d, requests=%d", recorder.Code, len(store.requested))
	}
}

func TestRuleRoutesWithoutARuleStoreAreUnavailable(t *testing.T) {
	server, err := NewServer(&fakeStateStore{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response := serveRuleRequest(server.Handler(), http.MethodGet, "/api/v1/rules", ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("rules without a store = %d", response.Code)
	}
}
