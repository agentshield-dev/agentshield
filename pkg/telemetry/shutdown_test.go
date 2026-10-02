package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestPipelineShutdownDrainsMoreThanOneBatch(t *testing.T) {
	sink := &collectingSink{}
	pipeline, err := NewPipeline(PipelineConfig{QueueCapacity: 10, MaxBatch: 2, FlushInterval: time.Hour}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	observedAt := time.Unix(10, 0).UTC()
	for index := 0; index < 5; index++ {
		if err := pipeline.Ingest(context.Background(), Event{EventID: string(rune('a' + index)), ObservedAt: observedAt, Kind: "request", Subject: claim, Object: claim, SourceID: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pipeline.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if sink.total != 5 || sink.batches < 3 {
		t.Fatalf("shutdown wrote %d events in %d batches, want 5 events in at least 3 batches", sink.total, sink.batches)
	}
}

type collectingSink struct {
	mu      sync.Mutex
	total   int
	batches int
}

func (sink *collectingSink) WriteBatch(_ context.Context, events []Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.total += len(events)
	sink.batches++
	return nil
}
