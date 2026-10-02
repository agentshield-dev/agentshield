package reasoning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/progress"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// Rebase reasons recorded on [Evaluation]. These values are persisted; do not
// rename them.
const (
	// RebaseChangeWindowUnavailable means the outbox could not supply a
	// contiguous window ending at the checkpoint.
	RebaseChangeWindowUnavailable = "change_window_unavailable"
	// RebaseStartupWithoutHistory means the consumer started with no cursor,
	// or behind the checkpoint, and no historical snapshot to diff against.
	RebaseStartupWithoutHistory = "startup_without_historical_snapshot"
)

// CursorStore is the durable state the service needs: the change outbox,
// graph checkpoints, and a per-consumer cursor. *state.Store implements it.
type CursorStore interface {
	ChangeReader
	ReadReasoningCursor(context.Context, string) (state.ReasoningCursor, bool, error)
	AdvanceReasoningCursor(context.Context, state.ReasoningCursor) error
}

// AnalysisRun is an [Analyzer] result. Errors holds failed attempts that
// preceded the returned outcome.
type AnalysisRun struct {
	Outcome  AnalysisOutcome
	Attempts int
	Errors   []string
}

// Analyzer investigates one packet that has at least one signal. Policy
// rejections belong on the returned outcome; an error means the analysis could
// not be completed and stops the service.
type Analyzer interface {
	Analyze(context.Context, Packet, *ContextProvider) (AnalysisRun, error)
}

// AnalyzerFunc adapts a function to [Analyzer].
type AnalyzerFunc func(context.Context, Packet, *ContextProvider) (AnalysisRun, error)

// Analyze calls analyze.
func (analyze AnalyzerFunc) Analyze(ctx context.Context, packet Packet, provider *ContextProvider) (AnalysisRun, error) {
	return analyze(ctx, packet, provider)
}

// Investigation states for an evaluated change window.
const (
	// InvestigationInvestigated means the window was investigated inline (EvaluateWindow).
	InvestigationInvestigated = "investigated"
	// InvestigationQueued means the window's request was handed to the investigation queue.
	InvestigationQueued = "queued"
	// InvestigationBelowThreshold means no signal could support promotion, so no agent ran.
	InvestigationBelowThreshold = "below_threshold"
	// InvestigationDisabled means an eligible signal existed but agentic investigation is disabled.
	InvestigationDisabled = "disabled"
)

// Evaluation is the complete result of processing one change window: the
// window, detector output and ruleset identity, the packet, the investigation
// state, and any inline analysis. A rebase evaluation carries only the window
// and RebaseReason.
type Evaluation struct {
	Window ChangeWindow
	// Signals are built-in novelty signals, the only input to agentic investigation.
	// RuleSignals come from active detection rules and become findings directly.
	// ShadowSignals come from unreviewed workload rules and are recorded only.
	Signals             []detector.InvestigationSignal
	RuleSignals         []detector.InvestigationSignal
	ShadowSignals       []detector.InvestigationSignal
	RulesetID           string
	RulesetDigest       string
	RulesetRevision     uint64
	WorkloadRulesDigest string
	// Investigation describes agentic investigation of Signals; it is empty for windows
	// without detection (no events, rebase, baseline, or a detection failure).
	Investigation string
	// Request is the investigation request for a queued or inline-investigated window.
	Request *InvestigationRequest
	// Packet is built only for a window with an investigation-eligible signal.
	Packet       Packet
	Analysis     AnalysisRun
	Rebased      bool
	RebaseReason string
	// DetectionOmitted counts detector inputs and signals left out to stay
	// within the detector's bounds; see [detector.Result.Omitted].
	DetectionOmitted map[string]int
	// DetectionError is set when detection failed for this window. The window
	// carries no signals and is not investigated, but its changes still
	// invalidate stale findings and the cursor moves past it.
	DetectionError string
}

// ResultSink records an evaluation before the service advances its cursor.
// It must be idempotent: the cursor and the sink are not committed atomically,
// so the same evaluation or finding can be recorded more than once.
type ResultSink interface {
	RecordReasoningEvaluation(context.Context, Evaluation) error
}

// ResultSinkFunc adapts a function to [ResultSink].
type ResultSinkFunc func(context.Context, Evaluation) error

// RecordReasoningEvaluation calls record.
func (record ResultSinkFunc) RecordReasoningEvaluation(ctx context.Context, evaluation Evaluation) error {
	return record(ctx, evaluation)
}

// ServiceConfig configures a [Service]. Zero fields take the defaults from
// [DefaultServiceConfig]; a nil Detection uses the built-in detector with the
// empty default ruleset.
type ServiceConfig struct {
	ConsumerID   string
	PollInterval time.Duration
	// ChangeLimit caps events per window, 1-1000. A backlog larger than this
	// rebases instead of being analyzed in pieces; see [ReadChangeWindow].
	ChangeLimit   int
	PacketLimits  Limits
	ContextLimits ContextLimits
	Detection     detector.Detector
	// QueueInvestigations makes Run attach an investigation request to each eligible
	// window for a queue sink; Run never calls a model itself.
	QueueInvestigations bool
	Clock               func() time.Time
}

// DefaultServiceConfig returns the values [NewService] substitutes for zero
// [ServiceConfig] fields. The agentshield command starts from them.
func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		ConsumerID: "reasoning/default", PollInterval: time.Second, ChangeLimit: 1000,
		PacketLimits: DefaultLimits(), ContextLimits: DefaultContextLimits(),
		Clock: time.Now,
	}
}

// Service is the continuous reasoning consumer. It is not safe for
// concurrent use: incident history is updated in place by each evaluation.
type Service struct {
	store               CursorStore
	detector            detector.Detector
	investigator        *Investigator
	sink                ResultSink
	config              ServiceConfig
	incidentHistory     *IncidentHistory
	incidentInitialized bool
}

// NewService validates config and returns the detection service. analyzer is
// used only by the inline EvaluateWindow methods; Run never calls a model. sink
// may be nil to discard results.
func NewService(store CursorStore, analyzer Analyzer, sink ResultSink, config ServiceConfig) (*Service, error) {
	if store == nil {
		return nil, errors.New("reasoning cursor store is required")
	}
	defaults := DefaultServiceConfig()
	if config.ConsumerID == "" {
		config.ConsumerID = defaults.ConsumerID
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaults.PollInterval
	}
	if config.ChangeLimit == 0 {
		config.ChangeLimit = defaults.ChangeLimit
	}
	if config.PacketLimits == (Limits{}) {
		config.PacketLimits = defaults.PacketLimits
	}
	if config.ContextLimits == (ContextLimits{}) {
		config.ContextLimits = defaults.ContextLimits
	}
	if config.Clock == nil {
		config.Clock = defaults.Clock
	}
	if config.ChangeLimit < 1 || config.ChangeLimit > 1000 {
		return nil, errors.New("reasoning change limit must be between 1 and 1000")
	}
	detection := config.Detection
	if detection == nil {
		var err error
		detection, err = detector.New(detector.DefaultConfig(), detector.DefaultRuleset())
		if err != nil {
			return nil, fmt.Errorf("initialize detector: %w", err)
		}
	}
	history, err := NewIncidentHistory(config.ConsumerID)
	if err != nil {
		return nil, err
	}
	var investigator *Investigator
	if analyzer != nil {
		if investigator, err = NewInvestigator(analyzer, config.PacketLimits, config.ContextLimits); err != nil {
			return nil, err
		}
	}
	return &Service{store: store, detector: detection, investigator: investigator, sink: sink, config: config, incidentHistory: history}, nil
}

// EvaluateWindow evaluates the window after afterSequence against previous,
// the snapshot the cursor was last advanced to, using the service's own
// incident history, and investigates an eligible window inline with the
// service's analyzer through the same investigator as the queue worker. It
// does not record results or move the cursor.
func (service *Service) EvaluateWindow(ctx context.Context, previous *graph.Snapshot, afterSequence uint64) (Evaluation, error) {
	return service.evaluateWindow(ctx, previous, afterSequence, evaluateInline, IncidentContext{})
}

// EvaluateWindowWithIncident is [Service.EvaluateWindow] with caller-supplied
// incident context instead of the service's history. Evals use it so they
// share every production stage after incident construction.
func (service *Service) EvaluateWindowWithIncident(ctx context.Context, previous *graph.Snapshot, afterSequence uint64, incident IncidentContext) (Evaluation, error) {
	return service.evaluateWindow(ctx, previous, afterSequence, evaluateInlineWithIncident, incident)
}

// evaluationMode is how one window is evaluated. Each public entry point uses one.
type evaluationMode int

const (
	// evaluateForQueue is [Service.Run]: the service's incident history, and an
	// eligible window is handed to the investigation queue, never to a model.
	evaluateForQueue evaluationMode = iota
	// evaluateInline is [Service.EvaluateWindow]: the service's incident
	// history, and an eligible window is investigated inline.
	evaluateInline
	// evaluateInlineWithIncident is [Service.EvaluateWindowWithIncident]: a
	// caller-supplied incident, and an eligible window is investigated inline.
	evaluateInlineWithIncident
)

// windowError is a failure confined to one window's detection, as opposed to
// a store failure. [Service.Run] records it on the window and moves on.
type windowError struct {
	err    error
	window ChangeWindow
}

func (failure *windowError) Error() string { return failure.err.Error() }
func (failure *windowError) Unwrap() error { return failure.err }

func (service *Service) evaluateWindow(ctx context.Context, previous *graph.Snapshot, afterSequence uint64, mode evaluationMode, incident IncidentContext) (_ Evaluation, err error) {
	window, err := ReadChangeWindow(ctx, service.store, afterSequence, service.config.ChangeLimit)
	if err != nil {
		return Evaluation{}, err
	}
	defer func() {
		var failure *windowError
		if errors.As(err, &failure) {
			failure.window = window
		}
	}()
	evaluation := Evaluation{Window: window}
	if window.RecoveredGap {
		evaluation.Rebased = true
		evaluation.RebaseReason = RebaseChangeWindowUnavailable
		return evaluation, nil
	}
	if len(window.Events) == 0 {
		return evaluation, nil
	}
	now := service.config.Clock().UTC()
	if mode != evaluateInlineWithIncident {
		if incident, err = service.observeIncident(previous, window, now); err != nil {
			return Evaluation{}, err
		}
	}
	if err := service.detectWindow(ctx, previous, now, &evaluation); err != nil {
		return Evaluation{}, err
	}
	evaluation.Investigation = service.investigationFor(mode, previous == nil, slices.ContainsFunc(evaluation.Signals, InvestigationEligible))
	switch evaluation.Investigation {
	case InvestigationQueued:
		return service.queueWindow(previous, incident, now, evaluation)
	case InvestigationInvestigated:
		return service.investigateWindow(ctx, previous, incident, now, evaluation)
	case InvestigationDisabled:
		return service.disabledWindow(previous, now, evaluation)
	default:
		return uninvestigatedWindow(previous, evaluation), nil
	}
}

// observeIncident records the window in the service's incident history and
// returns the incident context as of now.
func (service *Service) observeIncident(previous *graph.Snapshot, window ChangeWindow, now time.Time) (IncidentContext, error) {
	if !service.incidentInitialized && previous != nil {
		service.incidentHistory.ObserveBaseline(*previous)
		service.incidentHistory.ObservePhase("baseline", *previous)
		service.incidentInitialized = true
	}
	service.incidentHistory.ObservePhase(fmt.Sprintf("window-%d", window.Checkpoint.ThroughSequence), window.Checkpoint.View.Snapshot)
	return service.incidentHistory.Context(now)
}

// detectWindow runs the detectors and sorts their signals onto evaluation.
// Without a previous snapshot there is nothing to diff against, so the window
// is a baseline and nothing is detected. A detector error or panic is a
// [windowError]; cancellation is returned as is.
func (service *Service) detectWindow(ctx context.Context, previous *graph.Snapshot, now time.Time, evaluation *Evaluation) (err error) {
	if previous == nil {
		return nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &windowError{err: fmt.Errorf("detect changes: %w", panicError(recovered, debug.Stack()))}
		}
	}()
	// Signal windows are centered on the latest durable source observation
	// in the window, not on when reasoning happened to poll.
	var observedAt time.Time
	for _, event := range evaluation.Window.Events {
		if event.Contribution.SourceObservedAt.After(observedAt) {
			observedAt = event.Contribution.SourceObservedAt
		}
	}
	if observedAt.IsZero() {
		observedAt = now
	}
	result, err := service.detector.Detect(ctx, *previous, evaluation.Window.Checkpoint.View.Snapshot, observedAt)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &windowError{err: fmt.Errorf("detect changes: %w", err)}
	}
	for _, signal := range result.Signals {
		switch {
		case signal.RuleMode == detector.RuleModeShadow:
			evaluation.ShadowSignals = append(evaluation.ShadowSignals, signal)
		case signal.RuleID != "":
			evaluation.RuleSignals = append(evaluation.RuleSignals, signal)
		default:
			evaluation.Signals = append(evaluation.Signals, signal)
		}
	}
	evaluation.RulesetID, evaluation.RulesetDigest, evaluation.RulesetRevision = result.RulesetID, result.RulesetDigest, result.ActivationRevision
	evaluation.WorkloadRulesDigest, evaluation.DetectionOmitted = result.WorkloadRulesDigest, result.Omitted
	return nil
}

// investigationFor decides what happens to a window's novelty signals in mode.
// It returns empty for a baseline window, which is never investigated.
func (service *Service) investigationFor(mode evaluationMode, baseline, eligible bool) string {
	switch {
	case baseline:
		return ""
	case !eligible:
		return InvestigationBelowThreshold
	case mode == evaluateForQueue && service.config.QueueInvestigations:
		return InvestigationQueued
	case mode != evaluateForQueue && service.investigator != nil:
		return InvestigationInvestigated
	default:
		return InvestigationDisabled
	}
}

// uninvestigatedWindow completes a baseline or below-threshold window. No
// packet is built: promotion needs only the baseline flag and the signals.
func uninvestigatedWindow(previous *graph.Snapshot, evaluation Evaluation) Evaluation {
	header := Packet{SchemaVersion: SchemaVersion, Baseline: previous == nil, Signals: evaluation.Signals}
	evaluation.Analysis = notInvestigated(header)
	return evaluation
}

// disabledWindow completes an eligible window that no investigator will see.
func (service *Service) disabledWindow(previous *graph.Snapshot, now time.Time, evaluation Evaluation) (Evaluation, error) {
	packet, err := service.windowPacket(previous, now, evaluation)
	if err != nil {
		return Evaluation{}, err
	}
	evaluation.Packet, evaluation.Analysis = packet, notInvestigated(packet)
	return evaluation, nil
}

// queueWindow attaches an investigation request for the queue sink.
func (service *Service) queueWindow(previous *graph.Snapshot, incident IncidentContext, now time.Time, evaluation Evaluation) (Evaluation, error) {
	packet, err := service.windowPacket(previous, now, evaluation)
	if err != nil {
		return Evaluation{}, err
	}
	request, err := NewInvestigationRequest(evaluation.Window, packet.TopologyChange, evaluation.Signals, incident, now)
	if err != nil {
		return Evaluation{}, &windowError{err: err}
	}
	evaluation.Request, evaluation.Packet, evaluation.Analysis = &request, packet, notInvestigated(packet)
	return evaluation, nil
}

// investigateWindow investigates an eligible window inline. The investigator
// builds its own packet against the window's checkpoint.
func (service *Service) investigateWindow(ctx context.Context, previous *graph.Snapshot, incident IncidentContext, now time.Time, evaluation Evaluation) (Evaluation, error) {
	window := evaluation.Window
	request, err := NewInvestigationRequest(window, topologyChange(previous, window.Checkpoint.View.Snapshot, false), evaluation.Signals, incident, now)
	if err != nil {
		return Evaluation{}, err
	}
	evaluation.Request = &request
	result, err := service.investigator.Investigate(ctx, request, window.Events, window.Checkpoint, now)
	if err != nil {
		return Evaluation{}, err
	}
	evaluation.Packet, evaluation.Analysis = result.Packet, result.Analysis
	return evaluation, nil
}

// windowPacket builds the packet of an eligible, non-baseline window. A
// failure is confined to the window.
func (service *Service) windowPacket(previous *graph.Snapshot, now time.Time, evaluation Evaluation) (Packet, error) {
	window := evaluation.Window
	topology := topologyChange(previous, window.Checkpoint.View.Snapshot, false)
	packet, _, err := buildPacket(window.Events, window.Checkpoint, topology, false, evaluation.Signals, now, service.config.PacketLimits)
	if err != nil {
		return Packet{}, &windowError{err: fmt.Errorf("build packet: %w", err)}
	}
	return packet, nil
}

func notInvestigated(packet Packet) AnalysisRun {
	return AnalysisRun{Outcome: AnalysisOutcome{
		InitialPacket: packet, EffectivePacket: packet, Validation: ValidationNotApplicable, Promotion: Promote(packet, Response{}),
	}}
}

// Run consumes the change outbox until ctx is cancelled, then returns nil.
//
// Startup waits for the graph to materialize, then rebases to the current
// checkpoint if the cursor is missing or behind it. The state API cannot
// materialize an arbitrary historical snapshot, so changes made while the
// consumer was down cannot be diffed and are not claimed as analyzed.
//
// Each poll evaluates at most one window. The sink records the evaluation
// before the cursor advances, so the cursor never claims a window whose results
// were not stored. Finding persistence and the cursor are not committed
// atomically: a crash in between leaves the cursor behind, the next start
// rebases, and deterministic finding IDs keep any re-recorded finding
// idempotent.
//
// A detection failure confined to one window, such as a CEL runtime error, a
// packet that cannot be built, or a detector panic, does not stop the loop:
// the window is recorded with DetectionError and no signals, logged, and the
// cursor moves past it, so one bad window cannot stop detection. Rule
// matches in that window are lost, and the error says so.
//
// A store, sink, or cursor error is returned and ends the loop. Run never
// calls a model: agentic investigation runs in InvestigationWorker, which
// retries its own failures, so a model outage cannot stop detection. A store
// error has no safe in-process recovery: retrying would repeat the failure
// indefinitely, and skipping would silently claim the window was recorded.
// Because the cursor has not advanced, the next start finds it behind the
// checkpoint and records an explicit rebase, which invalidates agentic
// findings from older digests. The production command treats this error as
// fatal. A panic is returned as an error with its stack.
func (service *Service) Run(ctx context.Context) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("detection service: %w", panicError(recovered, debug.Stack()))
		}
	}()
	var previous graph.Snapshot
	var cursor uint64
	status := progress.New("detection service", "consumer", service.config.ConsumerID)
	// An empty window carries no ruleset identity, so the status line keeps the last one seen.
	ruleset := ""
	for {
		var err error
		previous, cursor, err = service.initialize(ctx)
		if err == nil {
			break
		}
		// No graph has been published yet; wait instead of failing startup.
		if !errors.Is(err, state.ErrNotMaterialized) {
			return err
		}
		status.Tick(ctx, func() []any { return []any{"state", "waiting for the first published graph"} })
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(service.config.PollInterval):
		}
	}
	slog.InfoContext(ctx, "detection service started", "consumer", service.config.ConsumerID, "cursor", cursor)
	ticker := time.NewTicker(service.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			evaluation, err := service.evaluateWindow(ctx, &previous, cursor, evaluateForQueue, IncidentContext{})
			if ctx.Err() != nil {
				return nil
			}
			var failure *windowError
			if errors.As(err, &failure) {
				evaluation, err = service.failedWindow(ctx, failure), nil
			}
			if err != nil {
				return err
			}
			// An empty, non-rebase window changes nothing; skip the write.
			if len(evaluation.Window.Events) == 0 && !evaluation.Rebased {
				status.Tick(ctx, func() []any { return []any{"cursor", cursor, "ruleset", ruleset} })
				continue
			}
			if evaluation.RulesetID != "" {
				ruleset = evaluation.RulesetID
			}
			status.Add("windows", 1)
			status.Add("changes", int64(len(evaluation.Window.Events)))
			status.Add("novelty_signals", int64(len(evaluation.Signals)))
			status.Add("rule_signals", int64(len(evaluation.RuleSignals)))
			status.Add("shadow_signals", int64(len(evaluation.ShadowSignals)))
			if evaluation.DetectionError != "" {
				status.Add("failed_windows", 1)
			}
			if len(evaluation.DetectionOmitted) > 0 {
				slog.WarnContext(ctx, "detection window exceeded detector bounds; the rest was not evaluated", "consumer", service.config.ConsumerID,
					"through_sequence", evaluation.Window.Checkpoint.ThroughSequence, "omitted", evaluation.DetectionOmitted)
			}
			if len(evaluation.RuleSignals) > 0 || len(evaluation.ShadowSignals) > 0 {
				slog.InfoContext(ctx, "detection rules matched", "consumer", service.config.ConsumerID,
					"through_sequence", evaluation.Window.Checkpoint.ThroughSequence,
					"rule_signals", len(evaluation.RuleSignals), "shadow_signals", len(evaluation.ShadowSignals))
			}
			if service.sink != nil {
				if err := service.sink.RecordReasoningEvaluation(ctx, evaluation); err != nil {
					return fmt.Errorf("record reasoning evaluation: %w", err)
				}
			}
			checkpoint := evaluation.Window.Checkpoint
			if err := service.advance(ctx, checkpoint); err != nil {
				return err
			}
			previous = checkpoint.View.Snapshot
			cursor = checkpoint.ThroughSequence
			status.Tick(ctx, func() []any { return []any{"cursor", cursor, "ruleset", ruleset} })
		}
	}
}

// failedWindow records a window whose detection failed, so it can be
// recorded and skipped.
func (service *Service) failedWindow(ctx context.Context, failure *windowError) Evaluation {
	slog.ErrorContext(ctx, "detection failed for a change window; recording it and continuing", "consumer", service.config.ConsumerID,
		"through_sequence", failure.window.Checkpoint.ThroughSequence, "error", failure.err)
	return Evaluation{Window: failure.window, DetectionError: failure.Error()}
}

func (service *Service) initialize(ctx context.Context) (graph.Snapshot, uint64, error) {
	checkpoint, err := service.store.ReadGraphCheckpoint(ctx)
	if err != nil {
		return graph.Snapshot{}, 0, err
	}
	cursor, found, err := service.store.ReadReasoningCursor(ctx, service.config.ConsumerID)
	if err != nil {
		return graph.Snapshot{}, 0, err
	}
	if found && cursor.ThroughSequence > checkpoint.ThroughSequence {
		return graph.Snapshot{}, 0, fmt.Errorf("reasoning cursor %d exceeds graph checkpoint %d", cursor.ThroughSequence, checkpoint.ThroughSequence)
	}
	if !found || cursor.ThroughSequence < checkpoint.ThroughSequence {
		evaluation := Evaluation{
			Window:  ChangeWindow{Checkpoint: checkpoint, NextCursor: checkpoint.ThroughSequence},
			Rebased: true, RebaseReason: RebaseStartupWithoutHistory,
		}
		if service.sink != nil {
			if err := service.sink.RecordReasoningEvaluation(ctx, evaluation); err != nil {
				return graph.Snapshot{}, 0, fmt.Errorf("record reasoning rebase: %w", err)
			}
		}
		if err := service.advance(ctx, checkpoint); err != nil {
			return graph.Snapshot{}, 0, err
		}
	}
	return checkpoint.View.Snapshot, checkpoint.ThroughSequence, nil
}

func (service *Service) advance(ctx context.Context, checkpoint state.GraphCheckpoint) error {
	return service.store.AdvanceReasoningCursor(ctx, state.ReasoningCursor{
		ConsumerID: service.config.ConsumerID, ThroughSequence: checkpoint.ThroughSequence,
		GraphSHA256: checkpoint.View.SHA256, UpdatedAt: service.config.Clock().UTC(),
	})
}
