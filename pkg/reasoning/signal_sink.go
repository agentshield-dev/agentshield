package reasoning

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/state"
)

// SignalStore persists detection signals.
type SignalStore interface {
	RecordDetectionSignals(context.Context, []state.DetectionSignal) error
	PruneDetectionSignals(context.Context, time.Time) (int64, error)
}

// SignalSink records every signal of an evaluated window with its investigation
// outcome, so signals stay visible whether or not an agent investigated them.
type SignalSink struct {
	store     SignalStore
	retention time.Duration
	clock     func() time.Time

	mutex      sync.Mutex
	lastPruned time.Time
}

// NewSignalSink keeps signals for retention; pruning runs at most hourly.
func NewSignalSink(store SignalStore, retention time.Duration, clock func() time.Time) (*SignalSink, error) {
	if store == nil {
		return nil, errors.New("signal store is required")
	}
	if retention < time.Hour {
		return nil, errors.New("detection signal retention must be at least one hour")
	}
	if clock == nil {
		clock = time.Now
	}
	return &SignalSink{store: store, retention: retention, clock: clock}, nil
}

func (sink *SignalSink) RecordReasoningEvaluation(ctx context.Context, evaluation Evaluation) error {
	if evaluation.Rebased || len(evaluation.Signals)+len(evaluation.RuleSignals)+len(evaluation.ShadowSignals) == 0 {
		return nil
	}
	checkpoint := evaluation.Window.Checkpoint
	records := make([]state.DetectionSignal, 0, len(evaluation.Signals)+len(evaluation.RuleSignals)+len(evaluation.ShadowSignals))
	for _, signal := range evaluation.Signals {
		records = append(records, state.DetectionSignal{
			Signal: signal, ThroughSequence: checkpoint.ThroughSequence, GraphSHA256: checkpoint.View.SHA256,
			Investigation: signalInvestigation(evaluation.Investigation),
		})
	}
	for _, signal := range evaluation.RuleSignals {
		records = append(records, state.DetectionSignal{
			Signal: signal, ThroughSequence: checkpoint.ThroughSequence, GraphSHA256: checkpoint.View.SHA256,
			Investigation: state.InvestigationRuleFinding,
		})
	}
	for _, signal := range evaluation.ShadowSignals {
		records = append(records, state.DetectionSignal{
			Signal: signal, ThroughSequence: checkpoint.ThroughSequence, GraphSHA256: checkpoint.View.SHA256,
			Investigation: state.InvestigationShadow,
		})
	}
	for chunk := range slices.Chunk(records, 1000) {
		if err := sink.store.RecordDetectionSignals(ctx, chunk); err != nil {
			return err
		}
	}
	return sink.prune(ctx)
}

func signalInvestigation(investigation string) string {
	switch investigation {
	case InvestigationInvestigated:
		return state.InvestigationInvestigated
	case InvestigationQueued:
		return state.InvestigationQueued
	case InvestigationDisabled:
		return state.InvestigationDisabled
	default:
		return state.InvestigationBelowThreshold
	}
}

func (sink *SignalSink) prune(ctx context.Context) error {
	sink.mutex.Lock()
	defer sink.mutex.Unlock()
	now := sink.clock().UTC()
	if now.Sub(sink.lastPruned) < time.Hour {
		return nil
	}
	if _, err := sink.store.PruneDetectionSignals(ctx, now.Add(-sink.retention)); err != nil {
		return err
	}
	sink.lastPruned = now
	return nil
}

// ResultSinks records an evaluation in each sink in order, stopping at the first error.
func ResultSinks(sinks ...ResultSink) ResultSink {
	return ResultSinkFunc(func(ctx context.Context, evaluation Evaluation) error {
		for _, sink := range sinks {
			if sink == nil {
				continue
			}
			if err := sink.RecordReasoningEvaluation(ctx, evaluation); err != nil {
				return err
			}
		}
		return nil
	})
}

// InvestigationQueueStore persists investigation requests for the investigation worker.
type InvestigationQueueStore interface {
	EnqueueInvestigationJob(context.Context, state.InvestigationJobRecord, time.Duration, func(state.InvestigationJobRecord) (state.InvestigationJobRecord, bool, error)) (int64, bool, error)
}

// InvestigationQueue hands each queued window's request to the investigation
// worker. Requests that share an anchor coalesce while their batch window is open.
type InvestigationQueue struct {
	store       InvestigationQueueStore
	batchWindow time.Duration
}

func NewInvestigationQueue(store InvestigationQueueStore, batchWindow time.Duration) (*InvestigationQueue, error) {
	if store == nil {
		return nil, errors.New("investigation queue store is required")
	}
	if batchWindow < 0 || batchWindow > time.Hour {
		return nil, errors.New("investigation batch window must be between zero and one hour")
	}
	return &InvestigationQueue{store: store, batchWindow: batchWindow}, nil
}

func (queue *InvestigationQueue) RecordReasoningEvaluation(ctx context.Context, evaluation Evaluation) error {
	if evaluation.Investigation != InvestigationQueued || evaluation.Request == nil {
		return nil
	}
	request := *evaluation.Request
	record, err := request.Record()
	if err != nil {
		return err
	}
	_, _, err = queue.store.EnqueueInvestigationJob(ctx, record, queue.batchWindow, func(existing state.InvestigationJobRecord) (state.InvestigationJobRecord, bool, error) {
		previous, err := DecodeInvestigationRequest(existing.Request)
		if err != nil {
			return state.InvestigationJobRecord{}, false, err
		}
		merged, accepted := MergeInvestigationRequests(previous, request)
		if !accepted {
			return state.InvestigationJobRecord{}, false, nil
		}
		mergedRecord, err := merged.Record()
		return mergedRecord, err == nil, err
	})
	if err != nil {
		return fmt.Errorf("enqueue investigation: %w", err)
	}
	return nil
}
