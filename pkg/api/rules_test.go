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
	workload   []detector.ResourceRule
	jobs       map[int64]state.ResourceRuleJobSummary
	proposals  map[int64]json.RawMessage
	reviews    []string
	selections [][]string
	requested  []string
	listedFor  string
}

func (store *fakeRuleStore) ReadActiveDetectorRuleset(context.Context) (detector.Activation, error) {
	if !store.active {
		return detector.Activation{}, detector.ErrNoActiveRuleset
	}
	return store.activation, nil
}

func (store *fakeRuleStore) ReadResourceRulesForDetector(context.Context) ([]detector.ResourceRule, error) {
	return store.workload, nil
}

func (store *fakeRuleStore) ListResourceRuleJobs(_ context.Context, _ int, resourceID string) ([]state.ResourceRuleJobSummary, error) {
	store.listedFor = resourceID
	var jobs []state.ResourceRuleJobSummary
	for _, job := range store.jobs {
		if resourceID != "" && job.ResourceID != resourceID {
			continue
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func TestRulesRouteReportsDetectorRuleTruncation(t *testing.T) {
	store := newRuleStore()
	store.workload = make([]detector.ResourceRule, detector.MaxResourceRules+1)
	response := serveRuleRequest(ruleTestServer(t, store, false), http.MethodGet, "/api/v1/rules", "")
	var body rulesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.ResourceRules) != detector.MaxResourceRules || !body.ResourceRulesTruncated {
		t.Fatalf("rules=%d truncated=%t err=%v", len(body.ResourceRules), body.ResourceRulesTruncated, err)
	}
}

func (store *fakeRuleStore) ResourceRuleJobStatus(_ context.Context, id int64) (state.ResourceRuleJobSummary, bool, error) {
	job, found := store.jobs[id]
	return job, found, nil
}

func (store *fakeRuleStore) ResourceRuleProposal(_ context.Context, id int64) (json.RawMessage, bool, error) {
	proposal, found := store.proposals[id]
	return proposal, found, nil
}

func (store *fakeRuleStore) ReviewResourceRuleJobRules(_ context.Context, id int64, decision, actor string, selectedRuleIDs []string) error {
	job := store.jobs[id]
	if job.Status != "completed" {
		return state.ErrResourceRuleJobNotReviewable
	}
	if decision == state.ResourceRuleReviewApproved && len(selectedRuleIDs) == 0 {
		return state.ErrResourceRuleSelectionInvalid
	}
	job.ReviewStatus, job.ReviewedBy = decision, actor
	store.jobs[id] = job
	store.reviews = append(store.reviews, decision)
	store.selections = append(store.selections, selectedRuleIDs)
	return nil
}

func (store *fakeRuleStore) RequestResourceRuleJob(_ context.Context, resourceID, actor string) (state.ResourceRuleJobSummary, error) {
	for id, job := range store.jobs {
		if job.ResourceID != resourceID || !job.CurrentRevision {
			continue
		}
		if job.Status == "running" {
			return job, state.ErrResourceRuleJobInProgress
		}
		now := time.Now()
		job.Status, job.ReviewStatus, job.RuleCount, job.RequestedBy, job.RequestedAt = "queued", state.ResourceRuleReviewPending, 0, actor, &now
		store.jobs[id] = job
		store.requested = append(store.requested, resourceID)
		return job, nil
	}
	return state.ResourceRuleJobSummary{}, state.ErrResourceRuleJobNotFound
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
		jobs: map[int64]state.ResourceRuleJobSummary{
			1: {ID: 1, ResourceID: "deployment-a", Status: "completed", ReviewStatus: state.ResourceRuleReviewPending, RuleCount: 1, CurrentRevision: true},
			2: {ID: 2, ResourceID: "deployment-b", Status: "running", ReviewStatus: state.ResourceRuleReviewPending, CurrentRevision: true},
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

func TestRulesRouteReportsMissingActivationAndResourceRules(t *testing.T) {
	store := newRuleStore()
	store.workload = []detector.ResourceRule{{Rule: detector.Rule{ID: "deployment/deployment-a/rule-1", ScopeResourceID: "deployment-a"}, Mode: detector.RuleModeShadow}}
	response := serveRuleRequest(ruleTestServer(t, store, false), http.MethodGet, "/api/v1/rules", "")
	var body rulesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s err=%v", response.Code, response.Body, err)
	}
	if body.Activation != nil || len(body.Rules) != 0 || len(body.ResourceRules) != 1 || body.ResourceRules[0].Mode != detector.RuleModeShadow {
		t.Fatalf("rules response = %#v", body)
	}
	store.active, store.activation = true, detector.Activation{Revision: 3, Ruleset: detector.Ruleset{ID: "security/v2", Rules: []detector.Rule{{ID: "global"}}}}
	response = serveRuleRequest(ruleTestServer(t, store, false), http.MethodGet, "/api/v1/rules", "")
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Activation == nil || body.Activation.Revision != 3 || body.Activation.RulesetID != "security/v2" || len(body.Rules) != 1 {
		t.Fatalf("active rules response = %s err=%v", response.Body, err)
	}
}

func TestRuleDraftRoutesReturnSummariesAndProposals(t *testing.T) {
	store := newRuleStore()
	handler := ruleTestServer(t, store, false)
	response := serveRuleRequest(handler, http.MethodGet, "/api/v1/rule-drafts", "")
	var list ruleDraftsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil || len(list.Drafts) != 2 {
		t.Fatalf("drafts=%s err=%v", response.Body, err)
	}
	response = serveRuleRequest(handler, http.MethodGet, "/api/v1/rule-drafts?resourceId=deployment-a", "")
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil || len(list.Drafts) != 1 || store.listedFor != "deployment-a" {
		t.Fatalf("resource drafts=%s listedFor=%q err=%v", response.Body, store.listedFor, err)
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
	for _, path := range []string{"/api/v1/rule-drafts/1/review", "/api/v1/resources/deployment-a/rule-drafts"} {
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
	if response := serveRuleRequest(handler, http.MethodPost, "/api/v1/rule-drafts/1/review", `{"decision":"approved","ruleIds":[]}`); response.Code != http.StatusBadRequest {
		t.Fatalf("empty rule selection = %d", response.Code)
	}
	response := serveRuleRequest(handler, http.MethodPost, "/api/v1/rule-drafts/1/review", `{"decision":"approved"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("omitted rule selection = %d %s", response.Code, response.Body)
	}
	response = serveRuleRequest(handler, http.MethodPost, "/api/v1/rule-drafts/1/review", `{"decision":"approved","ruleIds":["deployment/deployment-a/rule-1"]}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"reviewStatus":"approved"`) || store.jobs[1].ReviewedBy != ruleActor || len(store.selections) != 1 || len(store.selections[0]) != 1 || store.selections[0][0] != "deployment/deployment-a/rule-1" {
		t.Fatalf("selective approve = %d selections=%v", response.Code, store.selections)
	}
	if response := serveRuleRequest(handler, http.MethodPost, "/api/v1/rule-drafts/2/review", `{"decision":"approved"}`); response.Code != http.StatusConflict {
		t.Fatalf("review of a running draft = %d", response.Code)
	}

	response = serveRuleRequest(handler, http.MethodPost, "/api/v1/resources/deployment-a/rule-drafts", "{}")
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"status":"queued"`) {
		t.Fatalf("regenerate = %d %s", response.Code, response.Body)
	}
	response = serveRuleRequest(handler, http.MethodPost, "/api/v1/resources/deployment-b/rule-drafts", "{}")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"draft":{"id":2`) {
		t.Fatalf("regenerate in progress = %d %s", response.Code, response.Body)
	}
	if response := serveRuleRequest(handler, http.MethodPost, "/api/v1/resources/unknown/rule-drafts", "{}"); response.Code != http.StatusNotFound {
		t.Fatalf("regenerate unknown = %d", response.Code)
	}
	// A form post from another origin is not JSON, so it never reaches the store.
	formPost := httptest.NewRequest(http.MethodPost, "/api/v1/resources/deployment-a/rule-drafts", strings.NewReader("x=1"))
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
