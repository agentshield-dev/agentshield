package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/progress"
)

// Ingest admission errors. Receivers map ErrPipelineOverloaded to a retryable
// "slow down" response (HTTP 429), ErrPipelineClosed to 503, and
// ErrRequestTooLarge to a non-retryable rejection.
var (
	ErrPipelineOverloaded = errors.New("telemetry queue cannot accept the request now")
	ErrPipelineClosed     = errors.New("telemetry pipeline is not accepting events")
	ErrRequestTooLarge    = errors.New("telemetry request exceeds queue capacity")
)

// CommitFunc projects a sink-acknowledged batch into graph state. It is called
// with a nil batch on lifecycle ticks so time-based rollup changes, such as
// lease expiry, are published while traffic is quiet.
//
// An error means the batch was accepted but its projection is not yet
// published. Run retries by calling CommitFunc again with a nil batch, so a
// CommitFunc must keep a batch it failed to publish and publish it on the
// next call. Each call runs under PipelineConfig.CommitTimeout.
type CommitFunc func(context.Context, []Event) error

// PipelineConfig tunes a Pipeline. Zero values select the defaults noted.
type PipelineConfig struct {
	// QueueCapacity bounds queued, not-yet-flushed events. Default 100,000.
	QueueCapacity int
	// MaxBatch flushes as soon as a batch reaches this size. Default 5,000.
	MaxBatch int
	// FlushInterval flushes a partial batch. Default 250ms.
	FlushInterval time.Duration
	// LifecycleInterval, when positive, calls CommitFunc on a timer even with
	// no traffic. Zero disables lifecycle ticks.
	LifecycleInterval time.Duration
	// RetryMinimum and RetryMaximum bound the exponential sink and commit
	// retry delay. Defaults 100ms and 10s.
	RetryMinimum time.Duration
	RetryMaximum time.Duration
	// CommitTimeout bounds one CommitFunc attempt, so a hung query cannot
	// stall the pipeline forever. Default 30s.
	CommitTimeout time.Duration
	// CommitRetryLimit is how long consecutive CommitFunc failures are
	// retried before Run gives up and returns the error. Default 5 minutes.
	CommitRetryLimit time.Duration
	// Logger receives sink and commit failure and recovery messages. Default
	// slog.Default().
	Logger *slog.Logger
}

// sinkFailureLogInterval limits how often a persistently failing sink or
// commit is logged.
const sinkFailureLogInterval = time.Minute

// Pipeline batches events from many producers into one sink and then one
// commit callback. Ingest is safe for concurrent use; Run must be called
// exactly once and owns all batching, so the sink and CommitFunc are never
// called concurrently.
type Pipeline struct {
	config   PipelineConfig
	sink     Sink
	commit   CommitFunc
	queue    chan Event
	progress *progress.Reporter

	// admission serializes enqueueing and closing. Only Ingest sends to queue,
	// and only while holding admission after checking capacity, so a send
	// never blocks and a request is enqueued whole or not at all.
	admission sync.Mutex
	closed    bool
}

// NewPipeline returns a pipeline writing to sink. commit may be nil when no
// graph projection is wanted.
func NewPipeline(config PipelineConfig, sink Sink, commit CommitFunc) (*Pipeline, error) {
	if sink == nil {
		return nil, errors.New("telemetry sink is required")
	}
	if config.QueueCapacity <= 0 {
		config.QueueCapacity = 100_000
	}
	if config.MaxBatch <= 0 {
		config.MaxBatch = 5_000
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = 250 * time.Millisecond
	}
	if config.RetryMinimum <= 0 {
		config.RetryMinimum = 100 * time.Millisecond
	}
	if config.RetryMaximum <= 0 {
		config.RetryMaximum = 10 * time.Second
	}
	if config.CommitTimeout <= 0 {
		config.CommitTimeout = 30 * time.Second
	}
	if config.CommitRetryLimit <= 0 {
		config.CommitRetryLimit = 5 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MaxBatch > config.QueueCapacity {
		return nil, errors.New("telemetry batch cannot exceed queue capacity")
	}
	return &Pipeline{
		config: config, sink: sink, commit: commit, queue: make(chan Event, config.QueueCapacity),
		progress: progress.New("telemetry pipeline"),
	}, nil
}

// IngestWaiting submits events like Ingest but waits while the queue is
// full instead of returning ErrPipelineOverloaded. It is for in-process
// producers that read a stream and have no client to push back on; HTTP
// receivers return 429 instead. It returns when the events are accepted,
// on any other error, or when ctx ends.
func IngestWaiting(ctx context.Context, ingestor EventIngestor, events ...Event) error {
	const wait = 50 * time.Millisecond
	for {
		err := ingestor.Ingest(ctx, events...)
		if !errors.Is(err, ErrPipelineOverloaded) {
			return err
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Ingest validates events and enqueues them all or none. It never blocks on
// a full queue and never drops an event: when the queue cannot take the whole
// request it returns ErrPipelineOverloaded and enqueues nothing, which is the
// pipeline's explicit backpressure. Producers retry the whole request later,
// and stable event IDs keep that retry idempotent in the raw store. A request
// larger than the whole queue returns ErrRequestTooLarge. Once Run starts
// draining or has returned, Ingest returns ErrPipelineClosed, so no event is
// accepted that nothing will drain.
func (pipeline *Pipeline) Ingest(ctx context.Context, events ...Event) error {
	for index := range events {
		if err := events[index].normalize(); err != nil {
			return fmt.Errorf("telemetry event %d: %w", index, err)
		}
	}
	if len(events) > cap(pipeline.queue) {
		return ErrRequestTooLarge
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pipeline.admission.Lock()
	defer pipeline.admission.Unlock()
	if pipeline.closed {
		return ErrPipelineClosed
	}
	if len(pipeline.queue)+len(events) > cap(pipeline.queue) {
		pipeline.progress.Add("overloaded", 1)
		return ErrPipelineOverloaded
	}
	for index := range events {
		pipeline.queue <- events[index]
	}
	pipeline.progress.Add("accepted", int64(len(events)))
	return nil
}

// close stops admission. Run drains every event enqueued before it returns.
func (pipeline *Pipeline) close() {
	pipeline.admission.Lock()
	pipeline.closed = true
	pipeline.admission.Unlock()
}

// Run drains the queue until ctx ends or a commit fails persistently.
//
// Each flush writes the batch to the sink, retrying with exponential backoff
// until it succeeds or ctx ends, and only then passes it to CommitFunc. A
// batch is therefore never projected before it is durable, and a failing sink
// stalls the pipeline (and, once the queue is full, rejects producers)
// instead of dropping data. A failed CommitFunc is retried with the same
// backoff, each attempt under CommitTimeout; Run returns the error only after
// CommitRetryLimit of consecutive failures.
//
// On cancellation Run stops admission and drains everything still queued in
// MaxBatch-sized flushes under a fresh 10-second deadline, since ctx is
// already done. Events still queued when that deadline expires are lost with
// the process. Admission also stops when Run returns for any reason. A panic
// inside Run is returned as an error with its stack.
func (pipeline *Pipeline) Run(ctx context.Context) (err error) {
	defer pipeline.close()
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("telemetry pipeline panic: %v\n%s", recovered, debug.Stack())
		}
	}()
	return pipeline.run(ctx)
}

func (pipeline *Pipeline) run(ctx context.Context) error {
	ticker := time.NewTicker(pipeline.config.FlushInterval)
	defer ticker.Stop()
	var lifecycle <-chan time.Time
	var lifecycleTicker *time.Ticker
	if pipeline.config.LifecycleInterval > 0 {
		lifecycleTicker = time.NewTicker(pipeline.config.LifecycleInterval)
		lifecycle = lifecycleTicker.C
		defer lifecycleTicker.Stop()
	}
	batch := make([]Event, 0, pipeline.config.MaxBatch)
	flush := func(flushContext context.Context) error {
		if len(batch) == 0 {
			return nil
		}
		// Clone so the commit callback may retain the slice after batch is reused.
		committed := slices.Clone(batch)
		// Persist high-volume raw events before exposing any bounded graph rollup
		// produced by the commit callback.
		if err := pipeline.writeWithRetry(flushContext, committed); err != nil {
			return err
		}
		if err := pipeline.commitWithRetry(flushContext, committed); err != nil {
			return fmt.Errorf("commit telemetry projection: %w", err)
		}
		pipeline.progress.Add("written", int64(len(committed)))
		pipeline.progress.Add("batches", 1)
		batch = batch[:0]
		return nil
	}
	status := func() []any {
		return []any{"queued", len(pipeline.queue), "queue_capacity", cap(pipeline.queue)}
	}
	for {
		select {
		case event := <-pipeline.queue:
			batch = append(batch, event)
			if len(batch) >= pipeline.config.MaxBatch {
				if err := flush(ctx); err != nil {
					return err
				}
			}
		case <-ticker.C:
			if err := flush(ctx); err != nil {
				return err
			}
			pipeline.progress.Tick(ctx, status)
		case <-lifecycle:
			if len(batch) > 0 {
				if err := flush(ctx); err != nil {
					return err
				}
			} else if err := pipeline.commitWithRetry(ctx, nil); err != nil {
				return fmt.Errorf("commit telemetry lifecycle: %w", err)
			}
		case <-ctx.Done():
			// Stop admission first so the drain below sees every accepted event.
			pipeline.close()
			shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for {
				for len(batch) < pipeline.config.MaxBatch {
					select {
					case event := <-pipeline.queue:
						batch = append(batch, event)
					default:
						return flush(shutdownContext)
					}
				}
				if err := flush(shutdownContext); err != nil {
					return err
				}
			}
		}
	}
}

// writeWithRetry retries the sink until it succeeds or ctx ends. Sink errors
// are not returned; the only failure is ctx's error. A permanently failing
// sink (bad credentials, schema mismatch) therefore stalls ingestion rather
// than failing it. Failures are logged on the first attempt and then at most
// once per sinkFailureLogInterval, and a success after failures is logged
// once. Logs carry counts and the sink error, never event content.
func (pipeline *Pipeline) writeWithRetry(ctx context.Context, events []Event) error {
	logger := pipeline.config.Logger
	delay := pipeline.config.RetryMinimum
	var failedSince, lastLogged time.Time
	for attempt := 1; ; attempt++ {
		err := pipeline.sink.WriteBatch(ctx, events)
		if err == nil {
			if attempt > 1 {
				logger.Info("telemetry sink write succeeded after retries",
					"attempts", attempt, "events", len(events), "failing_for", time.Since(failedSince).Round(time.Millisecond))
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		now := time.Now()
		if attempt == 1 {
			failedSince = now
		}
		if attempt == 1 || now.Sub(lastLogged) >= sinkFailureLogInterval {
			lastLogged = now
			logger.Warn("telemetry sink write failed; retrying",
				"attempt", attempt, "events", len(events), "retry_in", delay, "error", err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
		delay = min(delay*2, pipeline.config.RetryMaximum)
	}
}

// commitWithRetry calls CommitFunc with each attempt under CommitTimeout.
// After a failure it retries with a nil batch, which the CommitFunc contract
// treats as "publish what was already accepted", backing off like the sink.
// It returns ctx's error on cancellation, or the last commit error once
// failures have lasted CommitRetryLimit. Logging follows writeWithRetry and
// never includes event content.
func (pipeline *Pipeline) commitWithRetry(ctx context.Context, events []Event) error {
	if pipeline.commit == nil {
		return nil
	}
	logger := pipeline.config.Logger
	delay := pipeline.config.RetryMinimum
	var failedSince, lastLogged time.Time
	batch := events
	for attempt := 1; ; attempt++ {
		attemptContext, cancel := context.WithTimeout(ctx, pipeline.config.CommitTimeout)
		err := pipeline.commit(attemptContext, batch)
		cancel()
		if err == nil {
			if attempt > 1 {
				logger.Info("telemetry commit succeeded after retries",
					"attempts", attempt, "events", len(events), "failing_for", time.Since(failedSince).Round(time.Millisecond))
			}
			return nil
		}
		// The CommitFunc kept the batch; later attempts only republish.
		batch = nil
		if ctx.Err() != nil {
			return ctx.Err()
		}
		now := time.Now()
		if attempt == 1 {
			failedSince = now
		}
		if now.Sub(failedSince) >= pipeline.config.CommitRetryLimit {
			return err
		}
		if attempt == 1 || now.Sub(lastLogged) >= sinkFailureLogInterval {
			lastLogged = now
			logger.Warn("telemetry commit failed; retrying",
				"attempt", attempt, "events", len(events), "retry_in", delay, "error", err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
		delay = min(delay*2, pipeline.config.RetryMaximum)
	}
}
