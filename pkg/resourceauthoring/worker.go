package resourceauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"runtime/debug"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/progress"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// JobStore is the durable authoring queue and the graph the baseline is read
// from. *state.Store implements it. Only the current lease owner may renew,
// complete, or retry a job.
type JobStore interface {
	BaselineSource
	// ClaimResourceRuleJob claims a job at least minAge old.
	ClaimResourceRuleJob(ctx context.Context, workerID string, lease, minAge time.Duration) (state.ResourceRuleJob, bool, error)
	RenewResourceRuleJob(context.Context, int64, string, time.Duration) (bool, error)
	CompleteResourceRuleJob(context.Context, int64, string, json.RawMessage) error
	RetryResourceRuleJob(context.Context, int64, string, string, time.Duration, bool) (state.ResourceRuleRetry, error)
	// ResourceRuleQueueStats feeds the worker's periodic status line.
	ResourceRuleQueueStats(context.Context, time.Duration) (state.ResourceRuleQueueStats, error)
}

// WorkerConfig configures a [Worker]. The lease is renewed every third of
// LeaseDuration while the author runs.
type WorkerConfig struct {
	ID            string
	PollInterval  time.Duration
	LeaseDuration time.Duration
	// StabilizationWindow is how long a job waits after its resource revision
	// appears, so the graph can collect the telemetry the draft is based on.
	StabilizationWindow time.Duration
	// MaxAttempts bounds authoring attempts, retried with exponential backoff;
	// zero uses 8. After the last one, or after a request the model endpoint
	// rejected as invalid, the job fails until an operator requests it again.
	MaxAttempts int
	Author      Author
	ReportError func(error)
}

// MaxStabilizationWindow bounds [WorkerConfig.StabilizationWindow] by the telemetry
// rollup retention: older telemetry has already left the graph.
const MaxStabilizationWindow = 24 * time.Hour

// Worker processes resource rule authoring jobs one at a time. It logs each
// claimed and finished job and a bounded status line with the queue.
type Worker struct {
	store    JobStore
	config   WorkerConfig
	progress *progress.Reporter
}

// NewWorker validates config and returns a worker. LeaseDuration must be
// between 3 seconds and 24 hours.
func NewWorker(store JobStore, config WorkerConfig) (*Worker, error) {
	if store == nil {
		return nil, errors.New("resource authoring job store is required")
	}
	if config.ID == "" || len(config.ID) > 128 {
		return nil, errors.New("resource authoring worker ID must contain 1-128 bytes")
	}
	if config.PollInterval <= 0 {
		config.PollInterval = time.Second
	}
	if config.LeaseDuration < 3*time.Second || config.LeaseDuration > 24*time.Hour {
		return nil, errors.New("resource authoring lease must be between 3 seconds and 24 hours")
	}
	if config.Author == nil {
		return nil, errors.New("resource rule author is required")
	}
	if config.StabilizationWindow < 0 || config.StabilizationWindow > MaxStabilizationWindow {
		return nil, fmt.Errorf("resource rule stabilization window must be between 0 and %s", MaxStabilizationWindow)
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 8
	}
	if config.MaxAttempts < 1 {
		return nil, errors.New("resource authoring max attempts must be positive")
	}
	return &Worker{store: store, config: config, progress: progress.New("Resource rule authoring worker", "worker", config.ID)}, nil
}

// Run polls until ctx is cancelled; claim and job failures are reported and retried.
func (worker *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(worker.config.PollInterval)
	defer ticker.Stop()
	for {
		job, found, err := worker.store.ClaimResourceRuleJob(ctx, worker.config.ID, worker.config.LeaseDuration, worker.config.StabilizationWindow)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			worker.report(fmt.Errorf("claim resource rule authoring job: %w", err))
		} else if found {
			if err := worker.process(ctx, job); ctx.Err() == nil {
				if err != nil {
					worker.progress.Add("failed", 1)
				}
				worker.report(err)
			}
			continue
		}
		worker.progress.Tick(ctx, func() []any { return worker.queueStatus(ctx) })
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (worker *Worker) report(err error) {
	if err != nil && worker.config.ReportError != nil {
		worker.config.ReportError(err)
	}
}

// queueStatus describes what the queue waits for, for the status line.
func (worker *Worker) queueStatus(ctx context.Context) []any {
	stats, err := worker.store.ResourceRuleQueueStats(ctx, worker.config.StabilizationWindow)
	if err != nil {
		return []any{"queue_error", err.Error()}
	}
	attrs := []any{"ready", stats.Ready, "running", stats.Running, "retrying", stats.Retrying, "failed", stats.Failed,
		"waiting_for_stabilization", stats.WaitingForStabilization, "stabilization_window", worker.config.StabilizationWindow.String()}
	if stats.NextEligibleAt != nil {
		attrs = append(attrs, "next_stabilization_ends_in", time.Until(*stats.NextEligibleAt).Round(time.Second).String())
	}
	return attrs
}

// process authors one claimed job. If the lease is lost, or cannot be renewed
// before it expires, the author call is cancelled and nothing is written,
// because another worker may now own the job.
func (worker *Worker) process(ctx context.Context, job state.ResourceRuleJob) error {
	started := time.Now()
	slog.InfoContext(ctx, "authoring resource rules", "worker", worker.config.ID, "job", job.ID,
		"resource", job.Context.Namespace+"/"+job.Context.Name, "kind", job.Context.Kind, "attempt", job.AttemptCount)
	authorContext, cancel := context.WithCancel(ctx)
	defer cancel()
	leaseResult := make(chan error, 1)
	go func() {
		err := reasoning.KeepLease(authorContext, worker.config.LeaseDuration, func(ctx context.Context) (bool, error) {
			return worker.store.RenewResourceRuleJob(ctx, job.ID, worker.config.ID, worker.config.LeaseDuration)
		})
		if err != nil {
			cancel()
		}
		leaseResult <- err
	}()
	proposal, authorErr := worker.author(authorContext, job)
	cancel()
	if err := <-leaseResult; err != nil {
		return fmt.Errorf("renew resource authoring lease: %w", err)
	}
	if authorErr != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		retryAfter := retryDelay(job.AttemptCount)
		terminal := job.AttemptCount >= worker.config.MaxAttempts || reasoning.IsPermanentModelError(authorErr)
		outcome, err := worker.store.RetryResourceRuleJob(ctx, job.ID, worker.config.ID, authorErr.Error(), retryAfter, terminal)
		if err != nil {
			return fmt.Errorf("record resource authoring retry after %w: %w", authorErr, err)
		}
		switch outcome {
		case state.ResourceRuleRetrySuperseded:
			// A newer revision, or the resource's removal, made this draft
			// moot; the newer revision has its own job.
			worker.progress.Add("superseded", 1)
			slog.InfoContext(ctx, "dropped stale resource authoring job", "worker", worker.config.ID, "job", job.ID,
				"resource", job.Context.Namespace+"/"+job.Context.Name, "kind", job.Context.Kind)
			return nil
		case state.ResourceRuleRetryFailed:
			worker.progress.Add("failed", 1)
			return fmt.Errorf("resource authoring job %d failed after %d attempt(s); request it again to retry: %w", job.ID, job.AttemptCount, authorErr)
		}
		return fmt.Errorf("resource authoring job %d failed (retry in %s): %w", job.ID, retryAfter, authorErr)
	}
	encoded, err := json.Marshal(proposal)
	if err != nil {
		return fmt.Errorf("encode resource rule proposal %d: %w", job.ID, err)
	}
	if err := worker.store.CompleteResourceRuleJob(ctx, job.ID, worker.config.ID, encoded); err != nil {
		return fmt.Errorf("persist resource rule proposal %d: %w", job.ID, err)
	}
	worker.progress.Add("completed", 1)
	slog.InfoContext(ctx, "drafted resource rules", "worker", worker.config.ID, "job", job.ID,
		"resource", job.Context.Namespace+"/"+job.Context.Name, "kind", job.Context.Kind, "rules", len(proposal.Rules),
		"duration", time.Since(started).Round(100*time.Millisecond).String())
	return nil
}

// author reads the baseline and drafts the proposal. A panic is returned as
// an error with its stack, so one bad job cannot crash the process.
func (worker *Worker) author(ctx context.Context, job state.ResourceRuleJob) (proposal Proposal, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("resource authoring panic: %v\n%s", recovered, debug.Stack())
		}
	}()
	resource, err := WithObservedBehavior(ctx, worker.store, job.Context)
	if err != nil {
		return Proposal{}, fmt.Errorf("read resource baseline: %w", err)
	}
	return worker.config.Author.Author(ctx, resource)
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := min(attempt-1, 8)
	seconds := min(int64(1)<<shift, int64(300))
	if seconds > math.MaxInt64/int64(time.Second) {
		return 5 * time.Minute
	}
	return time.Duration(seconds) * time.Second
}
