package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	collectorlogsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func admissionEvent(id string) Event {
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	return Event{EventID: id, ObservedAt: time.Unix(10, 0).UTC(), Kind: "request", Subject: claim, Object: claim, PluginID: "test", SourceID: "test"}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestPipelineIngestIsAllOrNothing(t *testing.T) {
	pipeline, err := NewPipeline(PipelineConfig{QueueCapacity: 3, MaxBatch: 1}, &collectingSink{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := pipeline.Ingest(ctx, admissionEvent("a"), admissionEvent("b"), admissionEvent("c"), admissionEvent("d")); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("oversized request error = %v, want ErrRequestTooLarge", err)
	}
	if err := pipeline.Ingest(ctx, admissionEvent("a"), admissionEvent("b")); err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Ingest(ctx, admissionEvent("c"), admissionEvent("d")); !errors.Is(err, ErrPipelineOverloaded) {
		t.Fatalf("overflowing request error = %v, want ErrPipelineOverloaded", err)
	}
	if got := len(pipeline.queue); got != 2 {
		t.Fatalf("queued = %d after rejected request, want 2 (nothing partial)", got)
	}
	// A validation failure part way through enqueues nothing.
	invalid := admissionEvent("")
	if err := pipeline.Ingest(ctx, admissionEvent("e"), invalid); err == nil || len(pipeline.queue) != 2 {
		t.Fatalf("invalid request error = %v, queued = %d", err, len(pipeline.queue))
	}
}

func TestPipelineIngestFailsOnceRunHasStopped(t *testing.T) {
	sink := &collectingSink{}
	pipeline, err := NewPipeline(PipelineConfig{QueueCapacity: 10, MaxBatch: 2, FlushInterval: time.Hour}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Ingest(context.Background(), admissionEvent("a")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pipeline.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Ingest(context.Background(), admissionEvent("b")); !errors.Is(err, ErrPipelineClosed) {
		t.Fatalf("ingest after drain = %v, want ErrPipelineClosed", err)
	}
	if sink.total != 1 {
		t.Fatalf("drained %d events, want 1", sink.total)
	}
}

func TestPipelineRetriesFailedCommitWithoutResendingBatch(t *testing.T) {
	var mu sync.Mutex
	var calls [][]Event
	committed := make(chan struct{})
	pipeline, err := NewPipeline(PipelineConfig{
		QueueCapacity: 10, MaxBatch: 1, FlushInterval: time.Hour, RetryMinimum: time.Millisecond, RetryMaximum: time.Millisecond, Logger: quietLogger(),
	}, &collectingSink{}, func(_ context.Context, events []Event) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, slices.Clone(events))
		if len(calls) < 3 {
			return errors.New("database failover")
		}
		close(committed)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pipeline.Run(ctx) }()
	if err := pipeline.Ingest(ctx, admissionEvent("a")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("commit was not retried to success")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v, want nil after a transient commit failure", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls[0]) != 1 || len(calls[1]) != 0 || len(calls[2]) != 0 {
		t.Fatalf("commit calls = %v, want the batch once and then nil retries", calls)
	}
}

func TestPipelineBoundsHungAndPersistentCommitFailures(t *testing.T) {
	attempts := 0
	pipeline, err := NewPipeline(PipelineConfig{
		QueueCapacity: 10, MaxBatch: 1, FlushInterval: time.Hour, RetryMinimum: time.Millisecond, RetryMaximum: time.Millisecond,
		CommitTimeout: 5 * time.Millisecond, CommitRetryLimit: 50 * time.Millisecond, Logger: quietLogger(),
	}, &collectingSink{}, func(ctx context.Context, _ []Event) error {
		attempts++
		<-ctx.Done() // A hung query ends at the per-attempt deadline.
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Ingest(context.Background(), admissionEvent("a")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pipeline.Run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || attempts < 2 {
			t.Fatalf("Run = %v after %d attempts, want deadline error after retries", err, attempts)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("persistent commit failure did not end Run")
	}
	if err := pipeline.Ingest(context.Background(), admissionEvent("b")); !errors.Is(err, ErrPipelineClosed) {
		t.Fatalf("ingest after Run failed = %v, want ErrPipelineClosed", err)
	}
}

func TestPipelineRunReturnsPanicAsError(t *testing.T) {
	pipeline, err := NewPipeline(PipelineConfig{QueueCapacity: 10, MaxBatch: 1, FlushInterval: time.Hour}, &collectingSink{}, func(context.Context, []Event) error {
		panic("projector bug")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Ingest(context.Background(), admissionEvent("a")); err != nil {
		t.Fatal(err)
	}
	err = pipeline.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "projector bug") || !strings.Contains(err.Error(), "goroutine") {
		t.Fatalf("Run = %v, want panic error with stack", err)
	}
}

func TestRollupPublisherRetriesBatchAfterGraphLoadFailure(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	target := &fakeRollupTarget{}
	failLoad := true
	publisher, err := NewRollupPublisher(RollupPublisherConfig{
		Rollup: NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 100}),
		Snapshot: func(context.Context) (graph.Snapshot, error) {
			if failLoad {
				return graph.Snapshot{}, errors.New("database unavailable")
			}
			return publisherGraph, nil
		},
		Target: target,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("one", "cilium", "hubble", now)}); err == nil {
		t.Fatal("commit succeeded without a graph")
	}
	failLoad = false
	if err := publisher.Commit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"cilium/hubble@1:1"}; !slices.Equal(got, want) {
		t.Fatalf("retry published %v, want %v", got, want)
	}
}

func TestRollupPublisherRereadsGenerationAfterAmbiguousFailure(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	target := &fakeRollupTarget{durable: map[string]uint64{}}
	publisher := newTestRollupPublisher(t, target, &now)
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("one", "cilium", "hubble", now)}); err != nil {
		t.Fatal(err)
	}
	target.summary()
	// The write at generation 2 committed but reported failure.
	target.fail = errors.New("connection reset")
	target.durable["cilium/hubble"] = 2
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("two", "cilium", "hubble", now)}); err == nil {
		t.Fatal("commit did not report the failure")
	}
	target.fail = nil
	if err := publisher.Commit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"cilium/hubble@3:1"}; !slices.Equal(got, want) {
		t.Fatalf("retry published %v, want %v", got, want)
	}
}

func TestRollupIgnoresFutureEventsForExpiry(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	rollup := NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 10, Now: func() time.Time { return now }})
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	live := Event{EventID: "live", ObservedAt: now.Add(-time.Minute), Kind: "network-flow", Subject: claim, Object: claim, PluginID: "test", SourceID: "test", Count: 1}
	if skipped := rollup.ObserveBatch([]Event{live}); skipped != 0 {
		t.Fatalf("skipped = %d", skipped)
	}
	future := live
	future.EventID = "future"
	future.ObservedAt = now.Add(24 * time.Hour)
	if skipped := rollup.ObserveBatch([]Event{future}); skipped != 1 {
		t.Fatalf("skipped = %d, want the future event", skipped)
	}
	// Within the skew bound, expiry still runs no later than the clock.
	nearFuture := live
	nearFuture.EventID = "near"
	nearFuture.ObservedAt = now.Add(time.Minute)
	rollup.ObserveBatch([]Event{nearFuture})
	input := rollup.Input()
	if len(input.Telemetry) != 2 || len(input.Relationships) != 1 {
		t.Fatalf("rollup after skewed events = %d series, %d leases; want live state kept", len(input.Telemetry), len(input.Relationships))
	}
}

func TestRollupHoldsUnboundDestinationUntilBindingOrGrace(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	rollup := NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 100, UnresolvedGrace: 5 * time.Minute})
	client := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster", ImmutableKey: "pod/client"}
	server := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster", ImmutableKey: "pod/new"}
	newAddress, _ := graph.NetworkDestinationClaim("network", "ip/10.0.0.9")
	otherAddress, _ := graph.NetworkDestinationClaim("network", "ip/10.0.0.10")
	flow := func(id string, object graph.IdentityClaim) Event {
		return Event{EventID: id, ObservedAt: now, Kind: "network-flow", Subject: client, Object: object, PluginID: "test", SourceID: "test", Count: 1, EvidenceIDs: []string{id}}
	}
	before := graph.Snapshot{Resources: []graph.Resource{{Identity: client}}}
	rollup.ObserveResolved([]Event{flow("one", newAddress), flow("two", otherAddress)}, before, now)
	for _, series := range rollup.Input().Telemetry {
		if series.Object != newAddress && series.Object != otherAddress {
			t.Fatalf("unbound destination collapsed before grace: %v", series.Object)
		}
	}

	// The Pod is published with its address binding inside the grace window.
	after := graph.Snapshot{
		Resources: []graph.Resource{{Identity: client}, {Identity: server}},
		Relationships: []graph.Relationship{{Predicate: graph.PredicateExposes, Assertions: []graph.RelationshipAssertion{{
			Subject: server, Predicate: graph.PredicateExposes, Object: newAddress,
		}}}},
	}
	changed, _ := rollup.ObserveResolved(nil, after, now.Add(time.Minute))
	if !changed {
		t.Fatal("binding the held address reported no change")
	}
	objects := map[string]uint64{}
	for _, series := range rollup.Input().Telemetry {
		objects[series.Object.ImmutableKey] = series.Count
	}
	if objects["pod/new"] != 1 || objects["ip/10.0.0.10"] != 1 {
		t.Fatalf("series objects = %v, want the bound Pod and the still-held address", objects)
	}

	// After the grace window the remaining address collapses to its peer class.
	rollup.ObserveResolved(nil, after, now.Add(6*time.Minute))
	objects = map[string]uint64{}
	for _, series := range rollup.Input().Telemetry {
		objects[series.Object.ImmutableKey] = series.Count
	}
	if objects["pod/new"] != 1 || objects["private-ip"] != 1 || len(objects) != 2 {
		t.Fatalf("series objects = %v, want the Pod and the private-ip class", objects)
	}
}

func TestOTLPReceiverRejectsOverloadWithRetryAfter(t *testing.T) {
	registry, err := NewMappingRegistry(Mapping{PluginID: "test", SourceID: "test", Mapper: MapperFuncs{
		MatchFunc: func(LogRecord) bool { return true },
		MapFunc:   func(context.Context, LogRecord) ([]Event, error) { return []Event{admissionEvent("a")}, nil },
	}})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewOTLPReceiver(OTLPReceiverConfig{Logger: quietLogger()}, registry, ingestorFunc(func(context.Context, ...Event) error {
		return ErrPipelineOverloaded
	}))
	if err != nil {
		t.Fatal(err)
	}
	response := serveOTLP(receiver, &collectorlogsv1.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: []*logsv1.LogRecord{{}}}}}}})
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d, Retry-After = %q", response.Code, response.Header().Get("Retry-After"))
	}
}

func TestOTLPReceiverLimitsConcurrentRequests(t *testing.T) {
	registry, err := NewMappingRegistry()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewOTLPReceiver(OTLPReceiverConfig{MaxConcurrentRequests: 1}, registry, &recordingEventIngestor{})
	if err != nil {
		t.Fatal(err)
	}
	receiver.inFlight <- struct{}{} // One request is already being handled.
	response := serveOTLP(receiver, &collectorlogsv1.ExportLogsServiceRequest{})
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d, want 429 with Retry-After", response.Code)
	}
	<-receiver.inFlight
	if response := serveOTLP(receiver, &collectorlogsv1.ExportLogsServiceRequest{}); response.Code != http.StatusOK {
		t.Fatalf("status after release = %d", response.Code)
	}
}

func TestOTLPReceiverDoesNotRejectSkippedRecords(t *testing.T) {
	registry, err := NewMappingRegistry(Mapping{PluginID: "test", SourceID: "test", Mapper: MapperFuncs{
		MatchFunc: func(LogRecord) bool { return true },
		MapFunc:   func(context.Context, LogRecord) ([]Event, error) { return nil, ErrSkipRecord },
	}})
	if err != nil {
		t.Fatal(err)
	}
	ingestor := &recordingEventIngestor{}
	receiver, err := NewOTLPReceiver(OTLPReceiverConfig{}, registry, ingestor)
	if err != nil {
		t.Fatal(err)
	}
	response := serveOTLP(receiver, &collectorlogsv1.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: []*logsv1.LogRecord{{}}}}}}})
	var exportResponse collectorlogsv1.ExportLogsServiceResponse
	if err := proto.Unmarshal(response.Body.Bytes(), &exportResponse); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || exportResponse.PartialSuccess != nil || len(ingestor.events) != 0 {
		t.Fatalf("status = %d, partial success = %v, events = %d", response.Code, exportResponse.PartialSuccess, len(ingestor.events))
	}
}

func TestClickHouseSinkSendsStableDeduplicationToken(t *testing.T) {
	var tokens []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query, _ := url.ParseQuery(request.URL.RawQuery)
		tokens = append(tokens, query.Get("insert_deduplication_token"))
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sink, err := NewClickHouseSink(ClickHouseConfig{Endpoint: server.URL, Database: "agentshield", Table: "telemetry_events"})
	if err != nil {
		t.Fatal(err)
	}
	batch := []Event{admissionEvent("a"), admissionEvent("b")}
	other := admissionEvent("a")
	other.PluginID = "other"
	for _, events := range [][]Event{batch, batch, {other, admissionEvent("b")}} {
		if err := sink.WriteBatch(context.Background(), events); err != nil {
			t.Fatal(err)
		}
	}
	if tokens[0] == "" || tokens[0] != tokens[1] || tokens[0] == tokens[2] {
		t.Fatalf("tokens = %v, want equal for a retry and distinct per plugin", tokens)
	}
}

type ingestorFunc func(context.Context, ...Event) error

func (function ingestorFunc) Ingest(ctx context.Context, events ...Event) error {
	return function(ctx, events...)
}

func serveOTLP(receiver *OTLPReceiver, exportRequest *collectorlogsv1.ExportLogsServiceRequest) *httptest.ResponseRecorder {
	payload, _ := proto.Marshal(exportRequest)
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-protobuf")
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, request)
	return response
}

func TestIngestWaitingRetriesOverloadUntilAccepted(t *testing.T) {
	ingestor := &overloadedIngestor{remaining: 2}
	if err := IngestWaiting(context.Background(), ingestor, Event{}); err != nil || ingestor.calls != 3 {
		t.Fatalf("err = %v, calls = %d", err, ingestor.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := IngestWaiting(ctx, &overloadedIngestor{remaining: 1 << 30}, Event{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if err := IngestWaiting(context.Background(), &overloadedIngestor{err: ErrPipelineClosed}, Event{}); !errors.Is(err, ErrPipelineClosed) {
		t.Fatalf("err = %v, want ErrPipelineClosed", err)
	}
}

type overloadedIngestor struct {
	remaining int
	calls     int
	err       error
}

func (ingestor *overloadedIngestor) Ingest(context.Context, ...Event) error {
	ingestor.calls++
	if ingestor.err != nil {
		return ingestor.err
	}
	if ingestor.remaining > 0 {
		ingestor.remaining--
		return ErrPipelineOverloaded
	}
	return nil
}
