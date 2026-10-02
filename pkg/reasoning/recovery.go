package reasoning

import (
	"context"
	"errors"
	"fmt"

	"github.com/agentshield-dev/agentshield/pkg/state"
)

// ChangeReader reads the contribution change outbox and a coherent graph
// checkpoint. *state.Store implements it.
type ChangeReader interface {
	ReadContributionChanges(context.Context, uint64, int) ([]state.ContributionChangeEvent, error)
	ReadGraphCheckpoint(context.Context) (state.GraphCheckpoint, error)
}

// ChangeWindow is one of: a contiguous batch of events ending exactly at
// Checkpoint.ThroughSequence; an empty window when nothing changed; or a
// rebase (RecoveredGap) with no events. NextCursor is the sequence a consumer
// records after handling the window.
type ChangeWindow struct {
	Events         []state.ContributionChangeEvent
	Checkpoint     state.GraphCheckpoint
	RecoveredGap   bool
	PreviousCursor uint64
	NextCursor     uint64
}

// ReadChangeWindow either returns one contiguous batch and its coherent current
// checkpoint, or explicitly rebases the cursor to a checkpoint after a gap.
//
// The checkpoint is read first, and events past it are discarded, so the batch
// never describes changes the checkpoint does not contain. The window is a
// rebase when:
//
//   - there are no readable events after afterSequence but the checkpoint is
//     ahead, meaning the outbox no longer holds them;
//   - the events are not contiguous from afterSequence+1, meaning some were
//     pruned or are missing; or
//   - the batch stops before the checkpoint, typically because limit was
//     reached. Analyzing a prefix against a later checkpoint would attribute
//     later state to earlier changes.
//
// A rebase never infers which changes were missed. Callers analyze nothing
// for it and treat findings from older digests as stale.
func ReadChangeWindow(ctx context.Context, reader ChangeReader, afterSequence uint64, limit int) (ChangeWindow, error) {
	if reader == nil {
		return ChangeWindow{}, errors.New("change reader is required")
	}
	checkpoint, err := reader.ReadGraphCheckpoint(ctx)
	if err != nil {
		return ChangeWindow{}, err
	}
	if afterSequence > checkpoint.ThroughSequence {
		return ChangeWindow{}, fmt.Errorf("change cursor %d exceeds checkpoint position %d", afterSequence, checkpoint.ThroughSequence)
	}
	events, err := reader.ReadContributionChanges(ctx, afterSequence, limit)
	if err != nil {
		return ChangeWindow{}, err
	}
	for len(events) > 0 && events[len(events)-1].Sequence > checkpoint.ThroughSequence {
		events = events[:len(events)-1]
	}
	window := ChangeWindow{Events: events, Checkpoint: checkpoint, PreviousCursor: afterSequence, NextCursor: afterSequence}
	if len(events) == 0 {
		if afterSequence < checkpoint.ThroughSequence {
			window.RecoveredGap = true
			window.NextCursor = checkpoint.ThroughSequence
		}
		return window, nil
	}
	expected := afterSequence + 1
	for _, event := range events {
		if event.Sequence != expected {
			window.Events = nil
			window.RecoveredGap = true
			window.NextCursor = checkpoint.ThroughSequence
			return window, nil
		}
		expected++
	}
	window.NextCursor = events[len(events)-1].Sequence
	if window.NextCursor < checkpoint.ThroughSequence {
		window.Events = nil
		window.RecoveredGap = true
		window.NextCursor = checkpoint.ThroughSequence
		return window, nil
	}
	return window, nil
}
