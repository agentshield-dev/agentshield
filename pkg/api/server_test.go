package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

type fakeStateStore struct {
	pingError      error
	latestError    error
	revisionError  error
	latestCalls    int
	record         state.GraphView
	manifest       state.GraphManifest
	manifestErrors []error
	manifestCalls  int
	depth          int
	direction      string
	limit          int
	findings       []state.Finding
	findingQuery   state.FindingQuery
	findingHasMore bool
	findingTotal   int
}

func (store *fakeStateStore) Ping(context.Context) error { return store.pingError }

func (store *fakeStateStore) CurrentGraph(context.Context) (state.GraphView, error) {
	store.latestCalls++
	return store.record, store.latestError
}

func (store *fakeStateStore) QueryResources(_ context.Context, query state.ResourceQuery) (state.ResourcePage, error) {
	if store.latestError != nil {
		return state.ResourcePage{}, store.latestError
	}
	page := state.ResourcePage{GraphSHA256: store.record.SHA256}
	for _, resource := range store.record.Snapshot.Resources {
		if query.Kind != "" && resource.Kind != query.Kind || query.Namespace != "" && resourceNamespace(resource) != query.Namespace || query.After != "" && resource.ID <= query.After {
			continue
		}
		if query.Search != "" && !strings.Contains(strings.ToLower(resourceSearchText(resource)), strings.ToLower(query.Search)) {
			continue
		}
		page.Resources = append(page.Resources, resource)
	}
	if query.Limit > 0 && len(page.Resources) > query.Limit {
		page.Next = page.Resources[query.Limit-1].ID
		page.Resources = page.Resources[:query.Limit]
	}
	return page, nil
}

func (store *fakeStateStore) GetResourceDetail(_ context.Context, id string) (state.ResourceDetail, error) {
	resource, found := findResource(store.record.Snapshot.Resources, id)
	if !found {
		return state.ResourceDetail{}, state.ErrGraphEntityNotFound
	}
	detail := state.ResourceDetail{GraphSHA256: store.record.SHA256, Resource: resource}
	for _, relationship := range store.record.Snapshot.Relationships {
		if relationship.SubjectID == id || relationship.ObjectID == id {
			detail.Relationships = append(detail.Relationships, relationship)
		}
	}
	for _, facet := range store.record.Snapshot.Facets {
		if facet.ResourceID == id {
			detail.Facets = append(detail.Facets, facet)
		}
	}
	return detail, nil
}

func (store *fakeStateStore) QueryRelationships(_ context.Context, query state.RelationshipQuery) (state.RelationshipPage, error) {
	if store.latestError != nil {
		return state.RelationshipPage{}, store.latestError
	}
	page := state.RelationshipPage{GraphSHA256: store.record.SHA256}
	for _, relationship := range store.record.Snapshot.Relationships {
		if query.Predicate != "" && string(relationship.Predicate) != query.Predicate || query.ResourceID != "" && relationship.SubjectID != query.ResourceID && relationship.ObjectID != query.ResourceID || query.After != "" && relationship.ID <= query.After {
			continue
		}
		page.Relationships = append(page.Relationships, relationship)
	}
	if query.Limit > 0 && len(page.Relationships) > query.Limit {
		page.Next = page.Relationships[query.Limit-1].ID
		page.Relationships = page.Relationships[:query.Limit]
	}
	return page, nil
}

func (store *fakeStateStore) GetRelationshipDetail(_ context.Context, id string) (state.RelationshipDetail, error) {
	for _, relationship := range store.record.Snapshot.Relationships {
		if relationship.ID == id {
			subject, subjectFound := findResource(store.record.Snapshot.Resources, relationship.SubjectID)
			object, objectFound := findResource(store.record.Snapshot.Resources, relationship.ObjectID)
			if !subjectFound || !objectFound {
				return state.RelationshipDetail{}, errors.New("relationship endpoint is unresolved")
			}
			return state.RelationshipDetail{GraphSHA256: store.record.SHA256, Relationship: relationship, Subject: subject, Object: object}, nil
		}
	}
	return state.RelationshipDetail{}, state.ErrGraphEntityNotFound
}

func (store *fakeStateStore) GraphRevision(context.Context) (string, error) {
	return store.record.SHA256, store.revisionError
}

func (store *fakeStateStore) CreateManifest(context.Context) (state.GraphManifest, error) {
	store.manifestCalls++
	if len(store.manifestErrors) > 0 {
		err := store.manifestErrors[0]
		store.manifestErrors = store.manifestErrors[1:]
		return state.GraphManifest{}, err
	}
	return store.manifest, nil
}

func (store *fakeStateStore) Neighborhood(_ context.Context, _ string, depth int, direction string, limit int) (state.Neighborhood, error) {
	store.depth = depth
	store.direction = direction
	store.limit = limit
	return state.Neighborhood{SHA256: store.record.SHA256}, nil
}

func (store *fakeStateStore) GetFinding(_ context.Context, findingID string) (state.Finding, error) {
	for _, finding := range store.findings {
		if finding.ID == findingID {
			return finding, nil
		}
	}
	return state.Finding{}, state.ErrFindingNotFound
}

func (store *fakeStateStore) QueryFindings(_ context.Context, query state.FindingQuery) (state.FindingPage, error) {
	store.findingQuery = query
	total := store.findingTotal
	if total == 0 {
		total = len(store.findings)
	}
	if query.Limit < len(store.findings) {
		return state.FindingPage{Findings: store.findings[:query.Limit], HasMore: true, Total: total}, nil
	}
	return state.FindingPage{Findings: store.findings, HasMore: store.findingHasMore, Total: total}, nil
}

func TestHealthAndReadinessStates(t *testing.T) {
	// Readiness does not wait for a published graph: graph routes return 503
	// on their own until one exists.
	store := &fakeStateStore{latestError: state.ErrNotMaterialized}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	assertStatus(t, handler, "/healthz", http.StatusNoContent)
	assertStatus(t, handler, "/readyz", http.StatusNoContent)
	store.pingError = errors.New("database unavailable")
	assertStatus(t, handler, "/healthz", http.StatusNoContent)
	assertStatus(t, handler, "/readyz", http.StatusServiceUnavailable)
	store.pingError = nil
	store.revisionError = errors.New("relation contribution_heads does not exist")
	assertStatus(t, handler, "/readyz", http.StatusServiceUnavailable)
	store.revisionError = nil
	store.latestError = nil
	store.record = testRecord()
	assertStatus(t, handler, "/readyz", http.StatusNoContent)
	if store.latestCalls != 0 {
		t.Fatalf("/readyz compiled the graph %d times, want 0", store.latestCalls)
	}
}

func TestGraphExplorerAndManifestParity(t *testing.T) {
	record := testRecord()
	store := &fakeStateStore{record: record, manifest: state.GraphManifest{ID: "manifest-1", Digest: "def456"}}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.assets = fstest.MapFS{"index.html": {Data: []byte("<title>AgentShield</title>")}}
	handler := server.Handler()

	graphResponse := httptest.NewRecorder()
	handler.ServeHTTP(graphResponse, httptest.NewRequest(http.MethodGet, "/api/v1/graph", nil))
	if graphResponse.Code != http.StatusOK || graphResponse.Header().Get("ETag") != `"abc123"` || !strings.Contains(graphResponse.Body.String(), `"sha256":"abc123"`) {
		t.Fatalf("unexpected graph response: code=%d headers=%v body=%s", graphResponse.Code, graphResponse.Header(), graphResponse.Body.String())
	}
	manifestResponse := httptest.NewRecorder()
	handler.ServeHTTP(manifestResponse, httptest.NewRequest(http.MethodGet, "/api/v1/manifest", nil))
	if manifestResponse.Code != http.StatusOK || !strings.Contains(manifestResponse.Body.String(), `"id":"manifest-1"`) {
		t.Fatalf("unexpected manifest response: code=%d body=%s", manifestResponse.Code, manifestResponse.Body.String())
	}
	neighborhoodResponse := httptest.NewRecorder()
	handler.ServeHTTP(neighborhoodResponse, httptest.NewRequest(http.MethodGet, "/api/v1/neighborhood?resourceId=00000000-0000-0000-0000-000000000001", nil))
	if neighborhoodResponse.Code != http.StatusOK || !strings.Contains(neighborhoodResponse.Body.String(), `"sha256":"abc123"`) {
		t.Fatalf("unexpected neighborhood response: code=%d body=%s", neighborhoodResponse.Code, neighborhoodResponse.Body.String())
	}
	if store.depth != 2 || store.direction != "both" || store.limit != 500 {
		t.Fatalf("neighborhood defaults = depth %d, direction %q, limit %d", store.depth, store.direction, store.limit)
	}
	explorerResponse := httptest.NewRecorder()
	handler.ServeHTTP(explorerResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	if explorerResponse.Code != http.StatusOK || !strings.Contains(explorerResponse.Body.String(), "AgentShield") {
		t.Fatalf("unexpected explorer response: code=%d body=%s", explorerResponse.Code, explorerResponse.Body.String())
	}
}

func TestOverviewRetriesConcurrentManifestUpdate(t *testing.T) {
	store := &fakeStateStore{
		record:   testRecord(),
		manifest: state.GraphManifest{ID: "manifest-1", Digest: "def456"},
		manifestErrors: []error{
			&pgconn.PgError{Code: "40001", Message: "could not serialize access due to concurrent update"},
			&pgconn.PgError{Code: "23505", Message: "duplicate manifest"},
		},
	}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := serveJSON(t, server.Handler(), http.MethodGet, "/api/v1/overview", "")
	if response.Code != http.StatusOK || store.manifestCalls != 3 {
		t.Fatalf("overview retry: code=%d calls=%d body=%s", response.Code, store.manifestCalls, response.Body.String())
	}
}

func TestWebUIServesBuiltAssets(t *testing.T) {
	server, err := NewServer(&fakeStateStore{record: testRecord()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.assets = fstest.MapFS{
		"index.html":    {Data: []byte("<title>AgentShield</title>")},
		"assets/app.js": {Data: []byte("console.log('ui')")},
	}
	handler := server.Handler()

	index := httptest.NewRecorder()
	handler.ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/", nil))
	if index.Code != http.StatusOK || !strings.HasPrefix(index.Header().Get("Content-Type"), "text/html") || index.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("unexpected index response: code=%d headers=%v", index.Code, index.Header())
	}
	script := httptest.NewRecorder()
	handler.ServeHTTP(script, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if script.Code != http.StatusOK || !strings.Contains(script.Header().Get("Content-Type"), "javascript") || script.Body.String() != "console.log('ui')" {
		t.Fatalf("unexpected asset response: code=%d headers=%v body=%q", script.Code, script.Header(), script.Body.String())
	}
	for _, path := range []string{"/assets/missing.js", "/index.html", "/unknown"} {
		assertStatus(t, handler, path, http.StatusNotFound)
	}
}

func TestWebUIReportsMissingBuild(t *testing.T) {
	server, err := NewServer(&fakeStateStore{record: testRecord()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.assets = fstest.MapFS{}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "make ui") {
		t.Fatalf("unexpected missing-build response: code=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGraphBackedProductQueries(t *testing.T) {
	semantics, err := graph.EncodeSecuritySemantics(graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
		State: graph.SecurityStateObserved, Effect: "external-addressable", Scope: "external", Direction: "egress", Coverage: "unknown",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStateStore{
		record: state.GraphView{GeneratedAt: time.Now().UTC(), SHA256: "graph", Snapshot: graph.Snapshot{
			Resources: []graph.Resource{
				{ID: "a", Kind: "kubernetes/pod", Identity: graph.IdentityClaim{AuthorityID: "cluster", ImmutableKey: "v1/pod/a"}, Assertions: []graph.ResourceAssertion{{DisplayName: "worker", Attributes: map[string]string{"namespace": "team-a"}}}},
				{ID: "b", Kind: "network/destination", Identity: graph.IdentityClaim{AuthorityID: "cluster", ImmutableKey: "metadata"}},
			},
			Relationships: []graph.Relationship{{ID: "edge", SubjectID: "a", Predicate: graph.PredicateExposes, ObjectID: "b", Assertions: []graph.RelationshipAssertion{
				{Properties: map[string]string{graph.SecuritySemanticsAttribute: semantics}, PluginID: "istio", SourceID: "mesh", RuleID: "exposure", EvidenceIDs: []string{"evidence"}},
			}}},
		}},
		manifest: state.GraphManifest{ID: "manifest", Digest: "graph"},
		findings: []state.Finding{{ID: "finding", Status: state.FindingStatusActive, AffectedEntityIDs: []string{"a"}}},
	}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	checks := map[string][]string{
		"/api/v1/overview":                        {`"resources":2`, `"activeFindings":[{"id":"finding"`},
		"/api/v1/resources?q=worker":              {`"id":"a"`, `"id":"b"`},
		"/api/v1/resources?namespace=team-a":      {`"id":"a"`},
		"/api/v1/resources/a":                     {`"resource":{"id":"a"`, `"relationships":[{"id":"edge"`, `"findings":[{"id":"finding"`},
		"/api/v1/relationships?predicate=exposes": {`"id":"edge"`},
		"/api/v1/relationships/edge":              {`"subject":{"id":"a"`, `"object":{"id":"b"`},
		"/api/v1/exposures?state=observed":        {`"ownerType":"relationship"`, `"coverage":"unknown"`, `"evidenceIds":["evidence"]`},
	}
	for path, fragments := range checks {
		response := serveJSON(t, handler, http.MethodGet, path, "")
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s: code=%d body=%s", path, response.Code, response.Body.String())
		}
		for index, fragment := range fragments {
			contains := strings.Contains(response.Body.String(), fragment)
			if path == "/api/v1/resources?q=worker" && index == 1 {
				contains = !contains
			}
			if !contains {
				t.Fatalf("GET %s body=%s, check %q", path, response.Body.String(), fragment)
			}
		}
	}
	if response := serveJSON(t, handler, http.MethodGet, "/api/v1/resources?cursor=%25%25%25", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid resource cursor: code=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveJSON(t, handler, http.MethodGet, "/api/v1/exposures?coverage=assumed", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid exposure coverage: code=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveJSON(t, handler, http.MethodGet, "/api/v1/exposures?state=effective", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid exposure state filter: code=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGraphSSEPublishesLatestHash(t *testing.T) {
	store := &fakeStateStore{record: testRecord()}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.Handler().ServeHTTP(response, request)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "event: graph") || !strings.Contains(response.Body.String(), `"sha256":"abc123"`) {
		t.Fatalf("unexpected SSE response: code=%d body=%s", response.Code, response.Body.String())
	}
}

// streamingStateStore lets a test publish while a stream polls concurrently.
type streamingStateStore struct {
	fakeStateStore
	mu          sync.Mutex
	revision    string
	latestCalls int
}

func (store *streamingStateStore) GraphRevision(context.Context) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.revision, nil
}

func (store *streamingStateStore) CurrentGraph(context.Context) (state.GraphView, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.latestCalls++
	return store.record, nil
}

func (store *streamingStateStore) publish(revision, digest string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revision = revision
	store.record.SHA256 = digest
}

func (store *streamingStateStore) loads() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.latestCalls
}

// openEventStream serves server over a real listener, so the http.Server's
// WriteTimeout applies, and returns the stream's lines.
func openEventStream(t *testing.T, server *Server, writeTimeout time.Duration) <-chan string {
	t.Helper()
	listener := httptest.NewUnstartedServer(server.Handler())
	listener.Config.WriteTimeout = writeTimeout
	listener.Start()
	t.Cleanup(listener.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, listener.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := listener.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("event stream status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(response.Body)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	return lines
}

func awaitLine(t *testing.T, lines <-chan string, want string) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("event stream closed before %q", want)
			}
			if strings.Contains(line, want) {
				return
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func TestGraphSSEOutlivesServerWriteTimeout(t *testing.T) {
	store := &streamingStateStore{fakeStateStore: fakeStateStore{record: testRecord()}, revision: "1"}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.eventPollInterval = 10 * time.Millisecond
	lines := openEventStream(t, server, 100*time.Millisecond)
	awaitLine(t, lines, `"sha256":"abc123"`)
	time.Sleep(300 * time.Millisecond)
	store.publish("2", "def456")
	awaitLine(t, lines, `"sha256":"def456"`)
}

func TestGraphSSESendsKeepAliveComments(t *testing.T) {
	store := &streamingStateStore{fakeStateStore: fakeStateStore{record: testRecord()}, revision: "1"}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.eventKeepAliveInterval = 20 * time.Millisecond
	lines := openEventStream(t, server, time.Minute)
	awaitLine(t, lines, `"sha256":"abc123"`)
	awaitLine(t, lines, ": keepalive")
}

func TestGraphSSELoadsGraphOnlyWhenRevisionChanges(t *testing.T) {
	store := &streamingStateStore{fakeStateStore: fakeStateStore{record: testRecord()}, revision: "1"}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.eventPollInterval = 5 * time.Millisecond
	lines := openEventStream(t, server, time.Minute)
	awaitLine(t, lines, `"sha256":"abc123"`)
	time.Sleep(100 * time.Millisecond)
	if loads := store.loads(); loads != 1 {
		t.Fatalf("Latest called %d times with an unchanged revision, want 1", loads)
	}
	// A new revision with the same digest reloads the graph but sends nothing.
	store.publish("2", "abc123")
	store.publish("3", "def456")
	awaitLine(t, lines, `"sha256":"def456"`)
	if loads := store.loads(); loads < 2 || loads > 3 {
		t.Fatalf("Latest called %d times across two revisions, want 2 or 3", loads)
	}
}

func TestCloseStreamsLetsShutdownFinish(t *testing.T) {
	store := &streamingStateStore{fakeStateStore: fakeStateStore{record: testRecord()}, revision: "1"}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(server.Handler())
	listener.Config.RegisterOnShutdown(server.CloseStreams)
	listener.Start()
	t.Cleanup(listener.Close)
	response, err := listener.Client().Get(listener.URL + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := bufio.NewReader(response.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := listener.Config.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown with an open event stream: %v", err)
	}
}

func TestServerErrorsHideInternalDetails(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	internal := errors.New(`pq: relation "contribution_heads" does not exist`)
	store := &fakeStateStore{record: testRecord(), manifestErrors: []error{internal}}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := serveJSON(t, server.Handler(), http.MethodGet, "/api/v1/manifest", "")
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInternalServerError || body.Error != "create graph manifest: internal server error; see the server log" {
		t.Fatalf("manifest failure: code=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(logs.String(), "contribution_heads") {
		t.Fatalf("server log does not carry the internal error: %s", logs.String())
	}

	store.latestError = state.ErrNotMaterialized
	response = serveJSON(t, server.Handler(), http.MethodGet, "/api/v1/graph", "")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"load graph: graph is not materialized"`) {
		t.Fatalf("not materialized: code=%d body=%s", response.Code, response.Body.String())
	}
	proposal := testRemediationProposal(t)
	store.findings = []state.Finding{{ID: proposal.FindingID, Remediations: []remediation.Proposal{proposal}, Status: state.FindingStatusActive}}
	response = serveJSON(t, server.Handler(), http.MethodPost, "/api/v1/findings/"+proposal.FindingID+"/remediations/"+proposal.ID+"/prepare", `{}`)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "live remediation is unavailable") {
		t.Fatalf("remediation unavailable: code=%d body=%s", response.Code, response.Body.String())
	}
	response = serveJSON(t, server.Handler(), http.MethodGet, "/api/v1/neighborhood?resourceId=not-a-uuid", "")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "resource ID must be a UUID") {
		t.Fatalf("neighborhood validation: code=%d body=%s", response.Code, response.Body.String())
	}
}

func TestOTLPLogsEndpointUsesRegisteredHandler(t *testing.T) {
	called := false
	otlp := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called = true
		if request.URL.Path != "/v1/logs" {
			t.Fatalf("unexpected OTLP path %q", request.URL.Path)
		}
		writer.WriteHeader(http.StatusAccepted)
	})
	server, err := NewServer(&fakeStateStore{}, otlp)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/logs", nil))
	if response.Code != http.StatusAccepted || !called {
		t.Fatalf("OTLP handler called=%t status=%d", called, response.Code)
	}
}

func TestFindingsAPIQueriesAndPaginates(t *testing.T) {
	createdAt := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	store := &fakeStateStore{
		findings:       []state.Finding{{ID: "finding:one", CreatedAt: createdAt}},
		findingHasMore: true,
		findingTotal:   7,
	}
	server, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := serveJSON(t, server.Handler(), http.MethodGet, "/api/v1/findings?status=active&severity=high&category=new_exposure&affectedEntityId=target&limit=1", "")
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("findings response: code=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if store.findingQuery.Status != state.FindingStatusActive || store.findingQuery.Severity != "high" || store.findingQuery.Category != "new_exposure" || store.findingQuery.AffectedEntityID != "target" || store.findingQuery.Limit != 1 {
		t.Fatalf("finding query = %#v", store.findingQuery)
	}
	var body findingsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 7 {
		t.Fatalf("finding total = %d", body.Total)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/findings?cursor="+body.NextCursor, nil)
	query, err := parseFindingQuery(request)
	if err != nil || query.BeforeCreatedAt == nil || !query.BeforeCreatedAt.Equal(createdAt) || query.BeforeFindingID != "finding:one" {
		t.Fatalf("cursor query = %#v, err = %v", query, err)
	}
	for _, path := range []string{"/api/v1/findings?status=closed", "/api/v1/findings?limit=many", "/api/v1/findings?cursor=invalid"} {
		if invalid := serveJSON(t, server.Handler(), http.MethodGet, path, ""); invalid.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %q: code=%d body=%s", path, invalid.Code, invalid.Body.String())
		}
	}
}

func TestFindingRemediationRequiresPreparedExactPlanApproval(t *testing.T) {
	proposal := testRemediationProposal(t)
	store := &fakeStateStore{findings: []state.Finding{{
		ID: proposal.FindingID, AnalysisID: proposal.AnalysisID, GraphSHA256: proposal.GraphSHA256,
		Category: "new_exposure", Severity: "high",
		ModelUncertainty: "low", Summary: "Unexpected ingress", SignalIDs: []string{"signal"},
		Remediations: []remediation.Proposal{proposal}, Status: state.FindingStatusActive, CreatedAt: time.Now().UTC(),
	}}}
	executor := &fakeRemediationExecutor{proposal: proposal}
	server, err := NewServerWithRemediations(store, nil, executor)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()

	findings := serveJSON(t, handler, http.MethodGet, "/api/v1/findings", "")
	if findings.Code != http.StatusOK || !strings.Contains(findings.Body.String(), `"remediations":[{"id":"`+proposal.ID) {
		t.Fatalf("findings response: code=%d body=%s", findings.Code, findings.Body.String())
	}
	basePath := "/api/v1/findings/" + proposal.FindingID + "/remediations/" + proposal.ID
	candidates := serveJSON(t, handler, http.MethodGet, basePath+"/candidates", "")
	if candidates.Code != http.StatusOK || !strings.Contains(candidates.Body.String(), `"actionId":"network-policy/v1"`) {
		t.Fatalf("candidates response: code=%d body=%s", candidates.Code, candidates.Body.String())
	}
	prepare := serveJSON(t, handler, http.MethodPost, basePath+"/prepare", `{"providerId":"kubernetes","sourceId":"cluster","actionId":"network-policy/v1"}`)
	if prepare.Code != http.StatusOK || executor.prepareCalls != 1 || !strings.Contains(prepare.Body.String(), `"preparation"`) {
		t.Fatalf("prepare response: calls=%d code=%d body=%s", executor.prepareCalls, prepare.Code, prepare.Body.String())
	}
	wrong := serveJSON(t, handler, http.MethodPost, basePath+"/approve", `{"planId":"plan:wrong"}`)
	if wrong.Code != http.StatusConflict || executor.executeCalls != 0 {
		t.Fatalf("wrong approval: calls=%d code=%d body=%s", executor.executeCalls, wrong.Code, wrong.Body.String())
	}
	approve := serveJSON(t, handler, http.MethodPost, basePath+"/approve", `{"planId":"`+executor.plan.ID+`"}`)
	if approve.Code != http.StatusOK || executor.executeCalls != 1 || !strings.Contains(approve.Body.String(), `"satisfied":true`) {
		t.Fatalf("approval response: calls=%d code=%d body=%s", executor.executeCalls, approve.Code, approve.Body.String())
	}
	retry := serveJSON(t, handler, http.MethodPost, basePath+"/approve", `{"planId":"`+executor.plan.ID+`"}`)
	if retry.Code != http.StatusOK || executor.executeCalls != 1 || retry.Body.String() != approve.Body.String() {
		t.Fatalf("approval retry: calls=%d code=%d body=%s", executor.executeCalls, retry.Code, retry.Body.String())
	}
	store.findings[0].Status = state.FindingStatusInvalidated
	invalidated := serveJSON(t, handler, http.MethodGet, basePath+"/candidates", "")
	if invalidated.Code != http.StatusConflict {
		t.Fatalf("invalidated finding remediation: code=%d body=%s", invalidated.Code, invalidated.Body.String())
	}
}

// An approval whose client disconnects still executes and verifies, and an
// execution whose verification fails is reported as applied, recorded, and
// never executed again.
func TestFindingRemediationApprovalOutlivesRequestAndReportsUnverifiedExecution(t *testing.T) {
	proposal := testRemediationProposal(t)
	store := &fakeStateStore{findings: []state.Finding{{
		ID: proposal.FindingID, AnalysisID: proposal.AnalysisID, GraphSHA256: proposal.GraphSHA256,
		Category: "new_exposure", Severity: "high", ModelUncertainty: "low", Summary: "Unexpected ingress",
		SignalIDs: []string{"signal"}, Remediations: []remediation.Proposal{proposal}, Status: state.FindingStatusActive, CreatedAt: time.Now().UTC(),
	}}}
	executor := &fakeRemediationExecutor{proposal: proposal, verifyErr: errors.New("provider read failed")}
	server, err := NewServerWithRemediations(store, nil, executor)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	basePath := "/api/v1/findings/" + proposal.FindingID + "/remediations/" + proposal.ID
	if prepare := serveJSON(t, handler, http.MethodPost, basePath+"/prepare", `{"providerId":"kubernetes","sourceId":"cluster","actionId":"network-policy/v1"}`); prepare.Code != http.StatusOK {
		t.Fatalf("prepare response: code=%d body=%s", prepare.Code, prepare.Body.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, basePath+"/approve", strings.NewReader(`{"planId":"`+executor.plan.ID+`"}`)).WithContext(ctx)
	request.Host = "localhost:8088"
	request.Header.Set("Content-Type", "application/json")
	approve := httptest.NewRecorder()
	handler.ServeHTTP(approve, request)
	if executor.executeCalls != 1 || executor.executeCtx != nil || executor.verifyCtx != nil {
		t.Fatalf("approval ran on the request context: calls=%d executeCtx=%v verifyCtx=%v", executor.executeCalls, executor.executeCtx, executor.verifyCtx)
	}
	if approve.Code != http.StatusOK || !strings.Contains(approve.Body.String(), `"satisfied":false`) ||
		!strings.Contains(approve.Body.String(), `"verificationError":"verify remediation: provider read failed"`) ||
		!strings.Contains(approve.Body.String(), `"id":"`+executor.result.ID+`"`) {
		t.Fatalf("unverified approval response: code=%d body=%s", approve.Code, approve.Body.String())
	}
	executor.verifyErr = nil
	retry := serveJSON(t, handler, http.MethodPost, basePath+"/approve", `{"planId":"`+executor.plan.ID+`"}`)
	if retry.Code != http.StatusOK || executor.executeCalls != 1 || executor.verifyCalls != 2 || !strings.Contains(retry.Body.String(), `"satisfied":true`) || strings.Contains(retry.Body.String(), "verificationError") {
		t.Fatalf("approval retry: execute=%d verify=%d code=%d body=%s", executor.executeCalls, executor.verifyCalls, retry.Code, retry.Body.String())
	}
	again := serveJSON(t, handler, http.MethodPost, basePath+"/approve", `{"planId":"`+executor.plan.ID+`"}`)
	if again.Code != http.StatusOK || executor.executeCalls != 1 || executor.verifyCalls != 2 || again.Body.String() != retry.Body.String() {
		t.Fatalf("verified approval retry: execute=%d verify=%d code=%d body=%s", executor.executeCalls, executor.verifyCalls, again.Code, again.Body.String())
	}
}

func TestLoopbackHostCheck(t *testing.T) {
	proposal := testRemediationProposal(t)
	store := &fakeStateStore{record: testRecord(), findings: []state.Finding{{
		ID: proposal.FindingID, AnalysisID: proposal.AnalysisID, GraphSHA256: proposal.GraphSHA256,
		Category: "new_exposure", Severity: "high", ModelUncertainty: "low", Summary: "Unexpected ingress",
		SignalIDs: []string{"signal"}, Remediations: []remediation.Proposal{proposal}, Status: state.FindingStatusActive, CreatedAt: time.Now().UTC(),
	}}}
	executor := &fakeRemediationExecutor{proposal: proposal}
	remediating, err := NewServerWithRemediations(store, nil, executor)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := NewServer(store, nil, WithLoopbackHostCheck(true))
	if err != nil {
		t.Fatal(err)
	}
	unchecked, err := NewServer(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	optedOut, err := NewServerWithRemediations(store, nil, executor, WithLoopbackHostCheck(false))
	if err != nil {
		t.Fatal(err)
	}
	serve := func(handler http.Handler, method, path, host, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Host = host
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	for _, host := range []string{"localhost", "localhost:5173", "LocalHost:8088", "127.0.0.1", "127.0.0.1:8088", "127.0.0.2:8088", "[::1]", "[::1]:8088"} {
		for name, server := range map[string]*Server{"remediating": remediating, "checked": checked} {
			if response := serve(server.Handler(), http.MethodGet, "/healthz", host, ""); response.Code != http.StatusNoContent {
				t.Fatalf("%s server rejected loopback host %q: code=%d body=%s", name, host, response.Code, response.Body.String())
			}
		}
	}
	approvePath := "/api/v1/findings/" + proposal.FindingID + "/remediations/" + proposal.ID + "/approve"
	for _, host := range []string{"", "example.com", "attacker.example:8088", "localhost.attacker.example", "127.0.0.1.attacker.example", "0.0.0.0:8088", "10.0.0.1:8088", "[::]:8088"} {
		for name, server := range map[string]*Server{"remediating": remediating, "checked": checked} {
			for _, request := range []struct{ method, path, body string }{
				{http.MethodGet, "/healthz", ""},
				{http.MethodGet, "/api/v1/graph", ""},
				{http.MethodPost, approvePath, `{"planId":"plan"}`},
			} {
				response := serve(server.Handler(), request.method, request.path, host, request.body)
				if response.Code != http.StatusForbidden || response.Header().Get("Content-Security-Policy") == "" {
					t.Fatalf("%s server %s %s with host %q: code=%d body=%s", name, request.method, request.path, host, response.Code, response.Body.String())
				}
			}
		}
	}
	if executor.executeCalls != 0 {
		t.Fatalf("rejected approvals executed %d times", executor.executeCalls)
	}
	for name, server := range map[string]*Server{"unchecked": unchecked, "opted out": optedOut} {
		if response := serve(server.Handler(), http.MethodGet, "/api/v1/graph", "agentshield.example:8088", ""); response.Code != http.StatusOK {
			t.Fatalf("%s server rejected non-loopback host: code=%d body=%s", name, response.Code, response.Body.String())
		}
	}
}

func TestDecodeRemediationApprovalRequest(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"planId":"plan"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	var approval remediationApprovalRequest
	if err := decodeJSONRequest(response, request, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.PlanID != "plan" {
		t.Fatalf("approval = %#v", approval)
	}
}

type fakeRemediationExecutor struct {
	proposal     remediation.Proposal
	plan         remediation.Plan
	preparation  remediation.Preparation
	result       remediation.ExecutionResult
	prepareCalls int
	executeCalls int
	verifyCalls  int
	verifyErr    error
	executeCtx   error
	verifyCtx    error
}

func (executor *fakeRemediationExecutor) Candidates(proposal remediation.Proposal) ([]remediation.Candidate, error) {
	if proposal.ID != executor.proposal.ID {
		return nil, errors.New("unexpected proposal")
	}
	return []remediation.Candidate{{ProviderID: "kubernetes", SourceID: "cluster", ActionID: "network-policy/v1", Mode: remediation.ModeExecutable}}, nil
}

func (executor *fakeRemediationExecutor) Plan(_ context.Context, proposal remediation.Proposal, providerID string, selection ...string) (remediation.Plan, error) {
	if proposal.ID != executor.proposal.ID || providerID != "kubernetes" || len(selection) != 2 || selection[0] != "cluster" || selection[1] != "network-policy/v1" {
		return remediation.Plan{}, errors.New("unexpected selection")
	}
	plan, err := remediation.NewPlan(proposal, providerID, selection[0], selection[1], strings.Repeat("b", 64))
	executor.plan = plan
	return plan, err
}

func (executor *fakeRemediationExecutor) Prepare(_ context.Context, _ remediation.Proposal, plan remediation.Plan) (remediation.Preparation, error) {
	executor.prepareCalls++
	preparation, err := remediation.NewPreparation(plan, true, nil)
	executor.preparation = preparation
	return preparation, err
}

func (executor *fakeRemediationExecutor) Execute(ctx context.Context, _ remediation.Proposal, plan remediation.Plan, preparation remediation.Preparation, approval string) (remediation.ExecutionResult, error) {
	if approval != plan.ID || preparation.ID != executor.preparation.ID {
		return remediation.ExecutionResult{}, errors.New("approval mismatch")
	}
	executor.executeCalls++
	executor.executeCtx = ctx.Err()
	result, err := remediation.NewExecutionResult(plan, preparation, true, nil)
	executor.result = result
	return result, err
}

func (executor *fakeRemediationExecutor) Verify(ctx context.Context, _ remediation.Proposal, plan remediation.Plan) (remediation.Verification, error) {
	executor.verifyCalls++
	executor.verifyCtx = ctx.Err()
	if executor.verifyErr != nil {
		return remediation.Verification{}, executor.verifyErr
	}
	return remediation.Verification{
		PlanID: plan.ID, ProviderID: plan.ProviderID, SourceID: plan.SourceID, ActionID: plan.ActionID,
		ExecutionResultID: executor.result.ID, Satisfied: true,
	}, nil
}

func serveJSON(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Host = "localhost:8088"
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func testRemediationProposal(t *testing.T) remediation.Proposal {
	t.Helper()
	proposal, err := remediation.NewProposal(
		"finding:test", "analysis:test", strings.Repeat("a", 64),
		remediation.Suggestion{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}},
		remediation.Target{EntityID: "target", Kind: "kubernetes/pod", Identity: graph.IdentityClaim{
			Scheme: graph.IdentityScheme{Group: "kubernetes.io", Version: "v1", Kind: "Object"}, AuthorityID: "cluster", ImmutableKey: "v1/pod/uid",
		}},
		[]string{"evidence"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func assertStatus(t *testing.T, handler http.Handler, path string, want int) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != want {
		t.Fatalf("GET %s status=%d, want %d; body=%s", path, response.Code, want, response.Body.String())
	}
}

func testRecord() state.GraphView {
	return state.GraphView{
		GeneratedAt: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), SHA256: "abc123",
		Snapshot: graph.Snapshot{Resources: []graph.Resource{}, Facets: []graph.Facet{}, Relationships: []graph.Relationship{}, Telemetry: []graph.TelemetryEvent{}},
	}
}
