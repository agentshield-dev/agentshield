package reasoning

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// FindingStore persists findings and invalidates stale ones. *state.Store
// implements it.
type FindingStore interface {
	PutFinding(context.Context, state.Finding) error
	InvalidateFindings(context.Context, string, uint64, []string, time.Time) error
}

// FindingSink is the production [ResultSink]. It turns each recorded
// [Evaluation] into finding invalidations and at most one new finding.
type FindingSink struct {
	store FindingStore
	clock func() time.Time
}

// NewFindingSink returns a sink writing to store. A nil clock uses time.Now.
func NewFindingSink(store FindingStore, clock func() time.Time) (*FindingSink, error) {
	if store == nil {
		return nil, errors.New("finding store is required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &FindingSink{store: store, clock: clock}, nil
}

// RecordReasoningEvaluation applies one evaluation in this order:
//
//  1. A rebase invalidates every active finding grounded in a different graph
//     digest, because the missed changes are unknown and any of them could
//     have affected those findings.
//  2. Otherwise, active findings from a different digest that name an entity
//     touched by the window's changes are invalidated. Unrelated graph churn
//     leaves findings active.
//  3. A promoted, accepted outcome is persisted as an active finding with
//     every hydrated remediation proposal, including a finding with none.
//
// Invalidated findings remain stored for audit and cannot launch remediation.
// Finding IDs are deterministic, so recording the same evaluation again after
// a crash before the cursor advanced is idempotent.
func (sink *FindingSink) RecordReasoningEvaluation(ctx context.Context, evaluation Evaluation) error {
	if evaluation.Rebased {
		return sink.store.InvalidateFindings(ctx, evaluation.Window.Checkpoint.View.SHA256, evaluation.Window.Checkpoint.ThroughSequence, nil, sink.clock().UTC())
	}
	now := sink.clock().UTC()
	if len(evaluation.Window.Events) > 0 {
		if err := sink.store.InvalidateFindings(ctx, evaluation.Window.Checkpoint.View.SHA256, evaluation.Window.Checkpoint.ThroughSequence, changedEntityIDs(evaluation.Window.Events), now); err != nil {
			return err
		}
	}
	for _, finding := range RuleFindings(evaluation, now) {
		if err := sink.store.PutFinding(ctx, finding); err != nil {
			return err
		}
	}
	_, err := sink.RecordInvestigation(ctx, evaluation.Analysis.Outcome)
	return err
}

// RecordInvestigation persists the finding promoted by an agentic investigation and
// returns its ID, or an empty ID when the outcome did not promote a finding.
func (sink *FindingSink) RecordInvestigation(ctx context.Context, outcome AnalysisOutcome) (string, error) {
	now := sink.clock().UTC()
	promotion := outcome.Promotion
	if outcome.Validation != ValidationAccepted || promotion.Status != PromotionPromoted || promotion.FindingID == "" {
		return "", nil
	}
	var remediations = outcome.Promotion.Remediations
	var proposals = make([]remediation.Proposal, 0, len(remediations))
	if len(remediations) > 0 {
		hydrated, err := NewRemediationProposals(outcome)
		if err != nil {
			return "", err
		}
		proposals = append(proposals, hydrated...)
	}
	assessment := outcome.Response.Assessment
	return promotion.FindingID, sink.store.PutFinding(ctx, state.Finding{
		ID: promotion.FindingID, Origin: state.FindingOriginAgenticInvestigation, AnalysisID: outcome.EffectivePacket.AnalysisID,
		GraphSHA256: outcome.EffectivePacket.HydratedGraphSHA256,
		Category:    assessment.Category, Severity: assessment.Severity,
		ModelUncertainty: assessment.ModelUncertainty, Summary: assessment.Summary,
		SignalIDs: append([]string(nil), promotion.SignalIDs...), AffectedEntityIDs: append([]string(nil), assessment.AffectedEntityIDs...),
		Remediations: proposals, Status: state.FindingStatusActive, CreatedAt: now,
	})
}

func changedEntityIDs(events []state.ContributionChangeEvent) []string {
	ids := make(map[string]struct{})
	for _, event := range events {
		for _, changes := range [][]state.AssertionChange{event.Added, event.Retracted} {
			for _, change := range changes {
				for _, id := range []string{change.Entity.ID, change.Entity.ResourceID, change.Entity.SubjectID, change.Entity.ObjectID} {
					if id != "" {
						ids[id] = struct{}{}
					}
				}
			}
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	slices.Sort(result)
	return result
}
