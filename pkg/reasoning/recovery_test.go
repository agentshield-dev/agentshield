package reasoning

import (
	"context"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/state"
)

type recoveryReader struct {
	events     []state.ContributionChangeEvent
	checkpoint state.GraphCheckpoint
}

func (reader recoveryReader) ReadContributionChanges(context.Context, uint64, int) ([]state.ContributionChangeEvent, error) {
	return reader.events, nil
}

func (reader recoveryReader) ReadGraphCheckpoint(context.Context) (state.GraphCheckpoint, error) {
	return reader.checkpoint, nil
}

func TestReadChangeWindowAcceptsContiguousPositions(t *testing.T) {
	window, err := ReadChangeWindow(context.Background(), recoveryReader{
		events:     []state.ContributionChangeEvent{{Sequence: 4}, {Sequence: 5}},
		checkpoint: state.GraphCheckpoint{ThroughSequence: 5},
	}, 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if window.RecoveredGap || window.NextCursor != 5 || len(window.Events) != 2 {
		t.Fatalf("window = %#v", window)
	}
}

func TestReadChangeWindowRebasesWhenBoundedReadCannotReachCheckpoint(t *testing.T) {
	window, err := ReadChangeWindow(context.Background(), recoveryReader{
		events:     []state.ContributionChangeEvent{{Sequence: 4}, {Sequence: 5}},
		checkpoint: state.GraphCheckpoint{ThroughSequence: 6},
	}, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !window.RecoveredGap || window.NextCursor != 6 || len(window.Events) != 0 {
		t.Fatalf("window = %#v", window)
	}
}

func TestReadChangeWindowRebasesExplicitlyAfterGap(t *testing.T) {
	window, err := ReadChangeWindow(context.Background(), recoveryReader{
		events:     []state.ContributionChangeEvent{{Sequence: 7}},
		checkpoint: state.GraphCheckpoint{ThroughSequence: 9},
	}, 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !window.RecoveredGap || window.NextCursor != 9 || len(window.Events) != 0 {
		t.Fatalf("window = %#v", window)
	}
}

func TestReadChangeWindowRebasesWhenRetainedWindowIsEmpty(t *testing.T) {
	window, err := ReadChangeWindow(context.Background(), recoveryReader{
		checkpoint: state.GraphCheckpoint{ThroughSequence: 9},
	}, 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !window.RecoveredGap || window.NextCursor != 9 {
		t.Fatalf("window = %#v", window)
	}
}

func TestReadChangeWindowRejectsCursorAheadOfCheckpoint(t *testing.T) {
	_, err := ReadChangeWindow(context.Background(), recoveryReader{
		checkpoint: state.GraphCheckpoint{ThroughSequence: 2},
	}, 3, 10)
	if err == nil {
		t.Fatal("cursor ahead of checkpoint was accepted")
	}
}
