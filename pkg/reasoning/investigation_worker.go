package reasoning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/progress"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// InvestigationJobStore is the durable investigation queue plus the graph and
// finding state an investigation reads and writes.
type InvestigationJobStore interface {
	ChangeReader
	FindingStore
	ClaimInvestigationJob(context.Context, string, time.Duration) (state.InvestigationJob, bool, error)
	AdmitInvestigationJob(context.Context, int64, string, state.InvestigationAdmission) (string, error)
	SkipInvestigationJob(context.Context, int64, string, string) error
	RenewInvestigationJob(context.Context, int64, string, time.Duration) (bool, error)
	CompleteInvestigationJob(context.Context, int64, string, json.RawMessage) error
	RetryInvestigationJob(context.Context, int64, string, string, time.Duration, bool) error
	PruneInvestigationJobs(context.Context, time.Time) (int64, error)
}

// Investigation job skip reasons decided by the worker; admission adds duplicate and budget.
const (
	InvestigationSkipStale   = "stale"
	InvestigationSkipSampled = "sampled"
)

type InvestigationWorkerConfig struct {
	ID            string
	PollInterval  time.Duration
	LeaseDuration time.Duration
	// MaxAttempts bounds failed investigations of one job before it fails permanently.
	MaxAttempts int
	// JobTimeout bounds one investigation attempt, including every model turn
	// and tool call; zero uses 15 minutes. A timed-out attempt is retried.
	JobTimeout time.Duration
	Sampling   SamplingPolicy
	// Retention prunes finished jobs; zero keeps them.
	Retention   time.Duration
	Clock       func() time.Time
	ReportError func(error)
}

// InvestigationWorker drains the investigation queue. A model failure retries the
// job with backoff and never blocks detection.
type InvestigationWorker struct {
	store        InvestigationJobStore
	investigator *Investigator
	findings     *FindingSink
	config       InvestigationWorkerConfig
	lastPruned   time.Time
	progress     *progress.Reporter
}

// InvestigationOutcome summarizes a completed job.
type InvestigationOutcome struct {
	AnalysisID         string   `json:"analysisId"`
	HydratedAtSequence uint64   `json:"hydratedAtSequence"`
	Promotion          string   `json:"promotion"`
	Reason             string   `json:"reason"`
	FindingID          string   `json:"findingId,omitempty"`
	SignalIDs          []string `json:"signalIds"`
	Attempts           int      `json:"attempts"`
	Usage              Usage    `json:"usage"`
	LatencyMillis      int64    `json:"latencyMillis"`
}

func NewInvestigationWorker(store InvestigationJobStore, investigator *Investigator, config InvestigationWorkerConfig) (*InvestigationWorker, error) {
	if store == nil || investigator == nil {
		return nil, errors.New("investigation worker requires a store and an investigator")
	}
	if config.ID == "" || len(config.ID) > 128 {
		return nil, errors.New("investigation worker ID must contain 1-128 bytes")
	}
	if config.PollInterval <= 0 {
		config.PollInterval = time.Second
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = 30 * time.Second
	}
	if config.LeaseDuration < 3*time.Second || config.LeaseDuration > 24*time.Hour {
		return nil, errors.New("investigation lease must be between 3 seconds and 24 hours")
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 5
	}
	if config.JobTimeout == 0 {
		config.JobTimeout = 15 * time.Minute
	}
	if config.MaxAttempts < 1 || config.Retention < 0 || config.JobTimeout < 0 {
		return nil, errors.New("investigation max attempts must be positive, and retention and job timeout must not be negative")
	}
	if err := config.Sampling.validate(); err != nil {
		return nil, err
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	findings, err := NewFindingSink(store, config.Clock)
	if err != nil {
		return nil, err
	}
	return &InvestigationWorker{
		store: store, investigator: investigator, findings: findings, config: config,
		progress: progress.New("investigation worker", "worker", config.ID),
	}, nil
}

// Run polls until ctx is cancelled; failures are reported and retried.
func (worker *InvestigationWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(worker.config.PollInterval)
	defer ticker.Stop()
	for {
		worker.prune(ctx)
		job, found, err := worker.store.ClaimInvestigationJob(ctx, worker.config.ID, worker.config.LeaseDuration)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			worker.report(fmt.Errorf("claim investigation job: %w", err))
		} else if found {
			started := time.Now()
			slog.InfoContext(ctx, "investigating", "worker", worker.config.ID, "job", job.ID, "attempt", job.AttemptCount)
			err := worker.processSafely(ctx, job)
			if ctx.Err() == nil {
				if err != nil {
					worker.progress.Add("failed", 1)
				} else {
					worker.progress.Add("processed", 1)
					slog.InfoContext(ctx, "investigation job finished", "worker", worker.config.ID, "job", job.ID,
						"duration", time.Since(started).Round(100*time.Millisecond).String())
				}
				worker.report(err)
			}
			continue
		}
		worker.progress.Tick(ctx, nil)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// processSafely is Process with a panic recorded as the job's failure, so one
// bad job cannot crash the process.
func (worker *InvestigationWorker) processSafely(ctx context.Context, job state.InvestigationJob) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = worker.fail(ctx, job, panicError(recovered, debug.Stack()), true)
		}
	}()
	return worker.Process(ctx, job)
}

// Process handles one claimed job: staleness, sampling, admission, then investigation.
func (worker *InvestigationWorker) Process(ctx context.Context, job state.InvestigationJob) error {
	request, err := DecodeInvestigationRequest(job.Request)
	if err != nil {
		return worker.fail(ctx, job, err, true)
	}
	checkpoint, err := worker.store.ReadGraphCheckpoint(ctx)
	if err != nil {
		return worker.fail(ctx, job, fmt.Errorf("read graph checkpoint: %w", err), false)
	}
	request = request.RetainPresentAnchors(checkpoint)
	if !slices.ContainsFunc(request.Signals, InvestigationEligible) {
		return worker.store.SkipInvestigationJob(ctx, job.ID, worker.config.ID, InvestigationSkipStale)
	}
	if !job.Admitted {
		if !worker.config.Sampling.Sampled(request) {
			return worker.store.SkipInvestigationJob(ctx, job.ID, worker.config.ID, InvestigationSkipSampled)
		}
		decision, err := worker.store.AdmitInvestigationJob(ctx, job.ID, worker.config.ID, worker.config.Sampling.admission())
		if err != nil {
			return fmt.Errorf("admit investigation job %d: %w", job.ID, err)
		}
		if decision != state.InvestigationAdmitted {
			return nil
		}
	}
	events, err := worker.readEvents(ctx, request)
	if err != nil {
		return worker.fail(ctx, job, err, job.AttemptCount+1 >= worker.config.MaxAttempts)
	}
	run, err := worker.investigate(ctx, job, request, events, checkpoint)
	if err != nil {
		// A request the model endpoint rejected as invalid fails the same way on every retry.
		return worker.fail(ctx, job, err, job.AttemptCount+1 >= worker.config.MaxAttempts || IsPermanentModelError(err))
	}
	outcome := run.Analysis.Outcome
	findingID, err := worker.findings.RecordInvestigation(ctx, outcome)
	if err != nil {
		return worker.fail(ctx, job, fmt.Errorf("record investigation finding: %w", err), job.AttemptCount+1 >= worker.config.MaxAttempts)
	}
	if findingID != "" {
		if err := worker.reconcile(ctx, run.Packet.HydratedAtSequence, outcome.Response.Assessment.AffectedEntityIDs); err != nil {
			worker.report(fmt.Errorf("reconcile finding %s: %w", findingID, err))
		}
	}
	summary, err := json.Marshal(InvestigationOutcome{
		AnalysisID: run.Packet.AnalysisID, HydratedAtSequence: run.Packet.HydratedAtSequence,
		Promotion: outcome.Promotion.Status, Reason: outcome.Promotion.Reason, FindingID: findingID,
		SignalIDs: signalIDs(run.Packet), Attempts: run.Analysis.Attempts, Usage: outcome.Usage(), LatencyMillis: outcome.Latency(),
	})
	if err != nil {
		return err
	}
	return worker.store.CompleteInvestigationJob(ctx, job.ID, worker.config.ID, summary)
}

func signalIDs(packet Packet) []string {
	ids := make([]string, 0, len(packet.Signals))
	for _, signal := range packet.Signals {
		ids = append(ids, signal.ID)
	}
	return ids
}

func (worker *InvestigationWorker) readEvents(ctx context.Context, request InvestigationRequest) ([]state.ContributionChangeEvent, error) {
	span := request.LastSequence - request.FirstSequence + 1
	if span > maxInvestigationSpan {
		return nil, fmt.Errorf("investigation change range %d-%d exceeds %d changes", request.FirstSequence, request.LastSequence, maxInvestigationSpan)
	}
	events, err := worker.store.ReadContributionChanges(ctx, request.FirstSequence-1, int(span))
	if err != nil {
		return nil, fmt.Errorf("read investigation changes: %w", err)
	}
	if uint64(len(events)) != span || events[0].Sequence != request.FirstSequence || events[len(events)-1].Sequence != request.LastSequence {
		return nil, fmt.Errorf("investigation change range %d-%d is unavailable", request.FirstSequence, request.LastSequence)
	}
	return events, nil
}

// investigate runs the model within the job timeout while renewing the job
// lease; losing the lease cancels it.
func (worker *InvestigationWorker) investigate(ctx context.Context, job state.InvestigationJob, request InvestigationRequest, events []state.ContributionChangeEvent, checkpoint state.GraphCheckpoint) (InvestigationRun, error) {
	runContext, cancelRun := context.WithTimeout(ctx, worker.config.JobTimeout)
	defer cancelRun()
	// Renewal has its own context so stopping it after a finished run is never mistaken for lease loss.
	renewContext, stopRenewal := context.WithCancel(ctx)
	defer stopRenewal()
	var leaseErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		leaseErr = KeepLease(renewContext, worker.config.LeaseDuration, func(ctx context.Context) (bool, error) {
			return worker.store.RenewInvestigationJob(ctx, job.ID, worker.config.ID, worker.config.LeaseDuration)
		})
		if leaseErr != nil {
			cancelRun()
		}
	}()
	run, err := worker.investigator.Investigate(runContext, request, events, checkpoint, worker.config.Clock().UTC())
	stopRenewal()
	<-done
	if leaseErr != nil {
		return InvestigationRun{}, fmt.Errorf("renew investigation lease: %w", leaseErr)
	}
	if err != nil && ctx.Err() == nil && errors.Is(runContext.Err(), context.DeadlineExceeded) {
		return InvestigationRun{}, fmt.Errorf("investigation exceeded the %s job timeout: %w", worker.config.JobTimeout, err)
	}
	return run, err
}

// reconcile invalidates a new finding when changes committed after its hydrated
// graph, while the model ran, already touched its entities.
func (worker *InvestigationWorker) reconcile(ctx context.Context, hydratedAt uint64, affected []string) error {
	events, err := worker.store.ReadContributionChanges(ctx, hydratedAt, 1000)
	if err != nil || len(events) == 0 {
		return err
	}
	changed := changedEntityIDs(events)
	if len(events) == 1000 {
		changed = slices.Clone(affected)
	}
	if len(changed) == 0 {
		return nil
	}
	checkpoint, err := worker.store.ReadGraphCheckpoint(ctx)
	if err != nil {
		return err
	}
	return worker.store.InvalidateFindings(ctx, checkpoint.View.SHA256, checkpoint.ThroughSequence, changed, worker.config.Clock().UTC())
}

func (worker *InvestigationWorker) fail(ctx context.Context, job state.InvestigationJob, cause error, terminal bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	delay := retryBackoff(job.AttemptCount + 1)
	if err := worker.store.RetryInvestigationJob(ctx, job.ID, worker.config.ID, cause.Error(), delay, terminal); err != nil {
		return fmt.Errorf("record investigation failure after %w: %w", cause, err)
	}
	if terminal {
		return fmt.Errorf("investigation job %d failed permanently: %w", job.ID, cause)
	}
	return fmt.Errorf("investigation job %d failed (retry in %s): %w", job.ID, delay, cause)
}

func retryBackoff(attempt int) time.Duration {
	shift := min(max(attempt, 1)-1, 8)
	return min(time.Duration(1<<shift)*5*time.Second, 10*time.Minute)
}

func (worker *InvestigationWorker) prune(ctx context.Context) {
	if worker.config.Retention <= 0 {
		return
	}
	now := worker.config.Clock().UTC()
	if now.Sub(worker.lastPruned) < time.Hour {
		return
	}
	if _, err := worker.store.PruneInvestigationJobs(ctx, now.Add(-worker.config.Retention)); err != nil {
		worker.report(fmt.Errorf("prune investigation jobs: %w", err))
		return
	}
	worker.lastPruned = now
}

func (worker *InvestigationWorker) report(err error) {
	if err != nil && worker.config.ReportError != nil {
		worker.config.ReportError(err)
	}
}
