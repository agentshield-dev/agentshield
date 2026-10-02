package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/state"
	"github.com/agentshield-dev/agentshield/ui"
)

// StateStore is the read model the API serves. *state.Store implements it.
// CreateManifest is the only method that writes; it records an idempotent,
// content-addressed manifest row and never changes the graph.
type StateStore interface {
	Ping(context.Context) error
	CurrentGraph(context.Context) (state.GraphView, error)
	GraphRevision(context.Context) (string, error)
	QueryResources(context.Context, state.ResourceQuery) (state.ResourcePage, error)
	GetResourceDetail(context.Context, string) (state.ResourceDetail, error)
	QueryRelationships(context.Context, state.RelationshipQuery) (state.RelationshipPage, error)
	GetRelationshipDetail(context.Context, string) (state.RelationshipDetail, error)
	CreateManifest(context.Context) (state.GraphManifest, error)
	Neighborhood(context.Context, string, int, string, int) (state.Neighborhood, error)
	GetFinding(context.Context, string) (state.Finding, error)
	QueryFindings(context.Context, state.FindingQuery) (state.FindingPage, error)
}

// RemediationExecutor drives the remediation lifecycle.
// *remediation.Executor implements it.
type RemediationExecutor interface {
	Candidates(remediation.Proposal) ([]remediation.Candidate, error)
	Plan(context.Context, remediation.Proposal, string, ...string) (remediation.Plan, error)
	Prepare(context.Context, remediation.Proposal, remediation.Plan) (remediation.Preparation, error)
	Execute(context.Context, remediation.Proposal, remediation.Plan, remediation.Preparation, string) (remediation.ExecutionResult, error)
	Verify(context.Context, remediation.Proposal, remediation.Plan) (remediation.Verification, error)
}

// Server is the AgentShield HTTP API. Remediation preparation sessions are
// held in memory and are lost on restart.
type Server struct {
	store        StateStore
	otlp         http.Handler
	assets       fs.FS
	remediations RemediationExecutor
	sessionsMu   sync.Mutex
	sessions     map[string]preparedRemediation
	loopbackOnly bool
	// rules serves the detection rule routes; rulesWritable enables review and regeneration.
	rules         RuleStore
	rulesWritable bool
	// Tests shorten these; see handleEvents.
	eventPollInterval      time.Duration
	eventKeepAliveInterval time.Duration
	// streamsClosed ends every graph event stream; see CloseStreams.
	streamsClosed    chan struct{}
	closeStreamsOnce sync.Once
}

// Graph event stream timing. The keepalive interval stays under the common
// 30 to 60 second proxy idle timeouts.
const (
	eventPollInterval      = 500 * time.Millisecond
	eventKeepAliveInterval = 25 * time.Second
	eventWriteTimeout      = 30 * time.Second
)

// Option configures a [Server].
type Option func(*Server)

// WithLoopbackHostCheck controls whether the server rejects requests whose
// Host header is not "localhost" or a loopback IP literal, on any port, with
// 403 Forbidden.
//
// Enable it whenever the server listens only on loopback. Binding to loopback
// keeps remote hosts out, but a page from another site can use DNS rebinding
// to resolve its own name to 127.0.0.1 and then call the API as a same-origin
// request. The browser still sends the attacker's name in Host, so checking
// Host closes that path. Do not enable it behind a proxy that forwards a
// non-loopback Host.
func WithLoopbackHostCheck(enabled bool) Option {
	return func(server *Server) { server.loopbackOnly = enabled }
}

// NewServer returns a server without live remediation. otlp may be nil. The
// server does not know its listen address, so the loopback Host check is off
// unless enabled with [WithLoopbackHostCheck].
func NewServer(store StateStore, otlp http.Handler, options ...Option) (*Server, error) {
	if store == nil {
		return nil, errors.New("state store is required")
	}
	server := &Server{
		store: store, otlp: otlp, assets: ui.Assets(),
		eventPollInterval: eventPollInterval, eventKeepAliveInterval: eventKeepAliveInterval,
		streamsClosed: make(chan struct{}),
	}
	for _, option := range options {
		option(server)
	}
	return server, nil
}

// NewServerWithRemediations returns a server whose remediation routes can
// plan, prepare, and execute actions through executor. Callers must serve it
// only on a loopback listener. The loopback Host check is therefore on by
// default; options are applied after that default.
func NewServerWithRemediations(store StateStore, otlp http.Handler, executor RemediationExecutor, options ...Option) (*Server, error) {
	if executor == nil {
		return nil, errors.New("remediation executor is required")
	}
	server, err := NewServer(store, otlp, append([]Option{WithLoopbackHostCheck(true)}, options...)...)
	if err != nil {
		return nil, err
	}
	server.remediations = executor
	server.sessions = make(map[string]preparedRemediation)
	return server, nil
}

// Handler returns the routed handler with security headers and, when enabled,
// the loopback Host check applied to every route. See the package
// documentation for the route list.
func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", server.handleReady)
	mux.HandleFunc("GET /api/v1/graph", server.handleGraph)
	mux.HandleFunc("GET /api/v1/manifest", server.handleManifest)
	mux.HandleFunc("GET /api/v1/neighborhood", server.handleNeighborhood)
	mux.HandleFunc("GET /api/v1/overview", server.handleOverview)
	mux.HandleFunc("GET /api/v1/resources", server.handleResources)
	mux.HandleFunc("GET /api/v1/resources/{resourceID}", server.handleResource)
	mux.HandleFunc("GET /api/v1/relationships", server.handleRelationships)
	mux.HandleFunc("GET /api/v1/relationships/{relationshipID}", server.handleRelationship)
	mux.HandleFunc("GET /api/v1/exposures", server.handleExposures)
	mux.HandleFunc("GET /api/v1/events", server.handleEvents)
	mux.HandleFunc("GET /api/v1/findings", server.handleFindings)
	mux.HandleFunc("GET /api/v1/findings/{findingID}", server.handleFinding)
	mux.HandleFunc("GET /api/v1/rules", server.handleRules)
	mux.HandleFunc("GET /api/v1/rule-drafts", server.handleRuleDrafts)
	mux.HandleFunc("GET /api/v1/rule-drafts/{jobID}", server.handleRuleDraft)
	mux.HandleFunc("POST /api/v1/rule-drafts/{jobID}/review", server.handleRuleDraftReview)
	mux.HandleFunc("POST /api/v1/workloads/{resourceID}/rule-drafts", server.handleRuleDraftRequest)
	mux.HandleFunc("GET /api/v1/findings/{findingID}/remediations/{proposalID}/candidates", server.handleRemediationCandidates)
	mux.HandleFunc("POST /api/v1/findings/{findingID}/remediations/{proposalID}/prepare", server.handleRemediationPrepare)
	mux.HandleFunc("POST /api/v1/findings/{findingID}/remediations/{proposalID}/approve", server.handleRemediationApprove)
	if server.otlp != nil {
		mux.Handle("POST /v1/logs", server.otlp)
	}
	mux.Handle("GET /assets/", http.FileServerFS(server.assets))
	mux.HandleFunc("GET /{$}", server.handleIndex)
	var handler http.Handler = mux
	if server.loopbackOnly {
		handler = loopbackHostOnly(handler)
	}
	return securityHeaders(handler)
}

// loopbackHostOnly runs before routing so a rebinding page cannot reach any
// route, including read-only graph data.
func loopbackHostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !loopbackHost(request.Host) {
			writeError(writer, http.StatusForbidden, "validate Host header", errors.New("this listener accepts only localhost or loopback IP hosts"))
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func loopbackHost(hostport string) bool {
	host := hostport
	if splitHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = splitHost
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (server *Server) handleIndex(writer http.ResponseWriter, _ *http.Request) {
	data, err := fs.ReadFile(server.assets, "index.html")
	if err != nil {
		http.Error(writer, `web UI is not built; run "make ui" and rebuild`, http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = writer.Write(data)
}

// CloseStreams ends every open and future graph event stream so
// [http.Server.Shutdown] does not wait for them. Register it with
// [http.Server.RegisterOnShutdown]. It is safe to call more than once.
func (server *Server) CloseStreams() {
	server.closeStreamsOnce.Do(func() { close(server.streamsClosed) })
}

// handleReady reports whether the server can serve requests: PostgreSQL
// answers and the schema is readable. It reads only the cheap graph revision
// and never compiles the graph, so it stays fast as the graph grows. Graph
// publication and discovery progress are separate states; graph routes return
// 503 until a graph is published.
func (server *Server) handleReady(writer http.ResponseWriter, request *http.Request) {
	if err := server.store.Ping(request.Context()); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "database is unavailable", err)
		return
	}
	if _, err := server.store.GraphRevision(request.Context()); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "read graph revision", err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) handleGraph(writer http.ResponseWriter, request *http.Request) {
	record, err := server.store.CurrentGraph(request.Context())
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, state.ErrNotMaterialized) {
			status = http.StatusServiceUnavailable
		}
		writeError(writer, status, "load graph", err)
		return
	}
	writer.Header().Set("ETag", fmt.Sprintf(`"%s"`, record.SHA256))
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, record)
}

func (server *Server) handleManifest(writer http.ResponseWriter, request *http.Request) {
	manifest, err := server.createManifest(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "create graph manifest", err)
		return
	}
	writeJSON(writer, http.StatusOK, manifest)
}

// createManifest records and returns the manifest for the current contribution
// versions. Writing on a GET is deliberate: the stored row gives the manifest
// its stable creation time and parent link, and CreateManifest is idempotent
// for an unchanged graph (see the package documentation). Serialization failures and unique
// violations, which concurrent creation of the same manifest can cause, are
// retried with short exponential backoff.
func (server *Server) createManifest(ctx context.Context) (state.GraphManifest, error) {
	const attempts = 5
	var err error
	for attempt := range attempts {
		var manifest state.GraphManifest
		manifest, err = server.store.CreateManifest(ctx)
		if err == nil {
			return manifest, nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || (pgErr.Code != "40001" && pgErr.Code != "23505") || attempt == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return state.GraphManifest{}, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 25 * time.Millisecond):
		}
	}
	return state.GraphManifest{}, err
}

func (server *Server) handleNeighborhood(writer http.ResponseWriter, request *http.Request) {
	depth, _ := strconv.Atoi(request.URL.Query().Get("depth"))
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	direction := request.URL.Query().Get("direction")
	if depth == 0 {
		depth = 2
	}
	if limit == 0 {
		limit = 500
	}
	if direction == "" {
		direction = "both"
	}
	resourceID := request.URL.Query().Get("resourceId")
	if err := state.ValidateNeighborhoodQuery(resourceID, depth, direction); err != nil {
		writeError(writer, http.StatusBadRequest, "query graph neighborhood", err)
		return
	}
	result, err := server.store.Neighborhood(request.Context(), resourceID, depth, direction, limit)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, state.ErrNotMaterialized) {
			status = http.StatusServiceUnavailable
		}
		writeError(writer, status, "query graph neighborhood", err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

// handleEvents streams a "graph" event with the graph digest on connect and
// whenever the digest changes, and a comment line as a keepalive so proxies do
// not close an idle stream. EventSource ignores comments.
//
// Each connection polls [StateStore.GraphRevision] every eventPollInterval and
// reads the revision-validated cached graph only when the revision changes. A
// stream ends when the client disconnects or [Server.CloseStreams] is called.
func (server *Server) handleEvents(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	controller := http.NewResponseController(writer)
	// The server's WriteTimeout bounds a whole response, which would cut the
	// stream. Bound each write instead so a stalled client is still dropped.
	send := func(message string) bool {
		if err := controller.SetWriteDeadline(time.Now().Add(eventWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := io.WriteString(writer, message); err != nil {
			return false
		}
		return controller.Flush() == nil
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	if err := controller.Flush(); errors.Is(err, http.ErrNotSupported) {
		writeError(writer, http.StatusInternalServerError, "stream graph changes", errStreamingUnsupported)
		return
	}
	var lastRevision, lastHash string
	check := func() bool {
		revision, err := server.store.GraphRevision(ctx)
		if err != nil || revision == lastRevision {
			return true
		}
		record, err := server.store.CurrentGraph(ctx)
		if err != nil && !errors.Is(err, state.ErrNotMaterialized) {
			return true
		}
		lastRevision = revision
		if err != nil || record.SHA256 == lastHash {
			return true
		}
		payload, _ := json.Marshal(map[string]any{"sha256": record.SHA256, "generatedAt": record.GeneratedAt})
		if !send("event: graph\ndata: " + string(payload) + "\n\n") {
			return false
		}
		lastHash = record.SHA256
		return true
	}
	poll := time.NewTicker(server.eventPollInterval)
	defer poll.Stop()
	keepAlive := time.NewTicker(server.eventKeepAliveInterval)
	defer keepAlive.Stop()
	if !check() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-server.streamsClosed:
			return
		case <-keepAlive.C:
			if !send(": keepalive\n\n") {
				return
			}
		case <-poll.C:
			if !check() {
				return
			}
		}
	}
}

// securityHeaders applies a same-origin CSP to every response, including
// errors. The UI must not rely on inline scripts or styles or other origins.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

// writeError writes {"error": "<action>: <reason>"}. A 4xx reason describes
// the request and is returned as is. A 5xx reason can carry database or
// provider text, so it is logged and replaced with the status text unless err
// is a [clientError] or [state.ErrNotMaterialized].
func writeError(writer http.ResponseWriter, status int, action string, err error) {
	reason := err.Error()
	if status >= http.StatusInternalServerError {
		var public clientError
		switch {
		case errors.As(err, &public):
			reason = public.Error()
		case errors.Is(err, state.ErrNotMaterialized):
			reason = state.ErrNotMaterialized.Error()
		default:
			if !errors.Is(err, context.Canceled) {
				slog.Error("API request failed", "action", action, "status", status, "error", err)
			}
			reason = strings.ToLower(http.StatusText(status)) + "; see the server log"
		}
	}
	writeJSON(writer, status, map[string]string{"error": action + ": " + reason})
}

// clientError is an error message written for API clients. writeError returns
// it even on a 5xx status.
type clientError string

func (err clientError) Error() string { return string(err) }

const (
	errStreamingUnsupported   clientError = "streaming is unsupported"
	errRemediationUnavailable clientError = "live remediation is unavailable"
)
