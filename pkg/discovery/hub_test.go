package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSubscriberReceivesStableReplayThenLiveChanges(t *testing.T) {
	hub := NewHub()
	publish := func(key string, operation Operation, generation uint64) {
		t.Helper()
		change := Change{EventID: "event-" + key, PluginID: "source", SourceID: "cluster", Collection: "objects", Key: key, Generation: generation, Operation: operation}
		if operation == OperationUpsert {
			change.Payload = json.RawMessage(`{"name":"` + key + `"}`)
		}
		if err := hub.Publish(context.Background(), change); err != nil {
			t.Fatal(err)
		}
	}
	publish("b", OperationUpsert, 1)
	publish("a", OperationUpsert, 1)
	if err := hub.Publish(context.Background(), Change{PluginID: "source", SourceID: "cluster", Collection: "objects", Key: "sync", Generation: 1, Operation: OperationSync}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := hub.Subscribe(ctx, "cluster", "objects")
	if err != nil {
		t.Fatal(err)
	}
	for index, expected := range []struct {
		key       string
		operation Operation
	}{{"a", OperationUpsert}, {"b", OperationUpsert}, {"sync", OperationSync}} {
		change := <-changes
		if change.Key != expected.key || change.Operation != expected.operation || !change.Initial {
			t.Fatalf("replay[%d] = %+v", index, change)
		}
	}

	publish("a", OperationDelete, 2)
	change := <-changes
	if change.Key != "a" || change.Operation != OperationDelete || change.Initial {
		t.Fatalf("live change = %+v", change)
	}

	replayContext, replayCancel := context.WithCancel(context.Background())
	defer replayCancel()
	replay, err := hub.Subscribe(replayContext, "cluster", "objects")
	if err != nil {
		t.Fatal(err)
	}
	first := <-replay
	if first.Key != "b" || first.Operation != OperationUpsert {
		t.Fatalf("deleted key remained in replay: %+v", first)
	}
}

func TestHubScopesReplayAndLiveChangesBySource(t *testing.T) {
	hub := NewHub()
	for _, sourceID := range []string{"one", "two"} {
		change := Change{EventID: "event-" + sourceID, PluginID: "plugin", SourceID: sourceID, Collection: "objects", Key: "shared", Generation: 1, Operation: OperationUpsert, Payload: json.RawMessage(`{"source":"` + sourceID + `"}`)}
		if err := hub.Publish(context.Background(), change); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := hub.Subscribe(ctx, "one", "objects")
	if err != nil {
		t.Fatal(err)
	}
	if change := <-changes; change.SourceID != "one" || change.Key != "shared" {
		t.Fatalf("source-scoped replay = %+v", change)
	}
	if err := hub.Publish(context.Background(), Change{EventID: "event-two-live", PluginID: "plugin", SourceID: "two", Collection: "objects", Key: "other", Generation: 2, Operation: OperationUpsert, Payload: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	select {
	case change := <-changes:
		t.Fatalf("cross-source live change = %+v", change)
	default:
	}
}

// newLagTestHub returns a hub with a small live buffer whose lag logs go to
// output, or nowhere when output is nil.
func newLagTestHub(buffer int, output io.Writer) *Hub {
	hub := NewHub()
	hub.buffer = buffer
	hub.logger = slog.New(slog.DiscardHandler)
	if output != nil {
		hub.logger = slog.New(slog.NewTextHandler(output, nil))
	}
	return hub
}

func lagTestChange(key string, operation Operation, generation uint64, value int) Change {
	change := Change{EventID: fmt.Sprintf("event-%s-%d", key, value), PluginID: "source", SourceID: "cluster", Collection: "objects", Key: key, Generation: generation, Operation: operation}
	switch operation {
	case OperationUpsert:
		change.Payload = json.RawMessage(strconv.Itoa(value))
	case OperationSync:
		change.EventID = ""
		change.Key = "sync"
	}
	return change
}

// TestLaggingSubscriberConvergesToCollectionState drives random upserts,
// deletes, and sync markers through a tiny buffer while the consumer reads
// slowly. Publish must never fail, every sync marker the consumer sees must
// follow exactly the collection state at that marker, and its final cache must
// equal the collection, deletes included.
func TestLaggingSubscriberConvergesToCollectionState(t *testing.T) {
	const operations = 2000
	const finalGeneration = operations + 1
	for seed := int64(1); seed <= 20; seed++ {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			var logs strings.Builder
			hub := newLagTestHub(2, &logs)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changes, err := hub.Subscribe(ctx, "cluster", "objects")
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				atSync map[uint64]map[string]string
				err    error
			}
			done := make(chan result, 1)
			go func() {
				atSync, err := consumeUntilSync(changes, finalGeneration, seed)
				done <- result{atSync: atSync, err: err}
			}()

			random := rand.New(rand.NewSource(seed))
			state := make(map[string]string)
			want := make(map[uint64]map[string]string)
			var generation uint64
			publish := func(change Change) {
				t.Helper()
				if err := hub.Publish(context.Background(), change); err != nil {
					t.Fatalf("publish %+v: %v", change, err)
				}
			}
			for index := range operations {
				key := fmt.Sprintf("key-%d", random.Intn(12))
				switch roll := random.Intn(10); {
				case roll < 5:
					state[key] = strconv.Itoa(index)
					publish(lagTestChange(key, OperationUpsert, generation+1, index))
				case roll < 8:
					delete(state, key)
					publish(lagTestChange(key, OperationDelete, generation+1, index))
				default:
					generation++
					want[generation] = maps.Clone(state)
					publish(lagTestChange("", OperationSync, generation, index))
				}
			}
			want[finalGeneration] = maps.Clone(state)
			publish(lagTestChange("", OperationSync, finalGeneration, operations))

			var got result
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("subscriber did not catch up")
			}
			if got.err != nil {
				t.Fatal(got.err)
			}
			for generation, cache := range got.atSync {
				if !maps.Equal(cache, want[generation]) {
					t.Fatalf("cache at sync %d = %v, want %v", generation, cache, want[generation])
				}
			}
			if !maps.Equal(got.atSync[finalGeneration], state) {
				t.Fatalf("final cache = %v, want %v", got.atSync[finalGeneration], state)
			}
			hub.mu.Lock()
			lagged := strings.Contains(logs.String(), "is lagging")
			hub.mu.Unlock()
			if !lagged {
				t.Fatal("subscriber never lagged; the test did not exercise the backlog")
			}
		})
	}
}

// consumeUntilSync applies changes to a cache with occasional pauses and
// records the cache at every sync marker until it sees finalGeneration.
func consumeUntilSync(changes <-chan Change, finalGeneration uint64, seed int64) (map[uint64]map[string]string, error) {
	random := rand.New(rand.NewSource(seed))
	cache := make(map[string]string)
	atSync := make(map[uint64]map[string]string)
	var lastGeneration uint64
	for change := range changes {
		if random.Intn(20) == 0 {
			time.Sleep(100 * time.Microsecond)
		}
		switch change.Operation {
		case OperationUpsert:
			cache[change.Key] = string(change.Payload)
		case OperationDelete:
			delete(cache, change.Key)
		case OperationSync:
			if change.Generation <= lastGeneration {
				return nil, fmt.Errorf("sync generation %d after %d", change.Generation, lastGeneration)
			}
			lastGeneration = change.Generation
			atSync[change.Generation] = maps.Clone(cache)
			if change.Generation == finalGeneration {
				return atSync, nil
			}
		}
	}
	return nil, errors.New("subscription closed before the final sync marker")
}

func TestLaggingSubscriberDoesNotAffectOthers(t *testing.T) {
	hub := newLagTestHub(1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slow, err := hub.Subscribe(ctx, "cluster", "objects")
	if err != nil {
		t.Fatal(err)
	}
	fast, err := hub.Subscribe(ctx, "cluster", "objects")
	if err != nil {
		t.Fatal(err)
	}
	for index := range 10 {
		key := fmt.Sprintf("key-%d", index%3)
		if err := hub.Publish(context.Background(), lagTestChange(key, OperationUpsert, 1, index)); err != nil {
			t.Fatal(err)
		}
		if change := <-fast; change.Key != key || string(change.Payload) != strconv.Itoa(index) {
			t.Fatalf("fast subscriber change %d = %+v", index, change)
		}
	}
	if err := hub.Publish(context.Background(), lagTestChange("key-0", OperationDelete, 1, 10)); err != nil {
		t.Fatal(err)
	}
	if change := <-fast; change.Operation != OperationDelete {
		t.Fatalf("fast subscriber delete = %+v", change)
	}

	if err := hub.Publish(context.Background(), lagTestChange("", OperationSync, 1, 11)); err != nil {
		t.Fatal(err)
	}
	if change := <-fast; change.Operation != OperationSync {
		t.Fatalf("fast subscriber sync = %+v", change)
	}

	atSync, err := consumeUntilSync(slow, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"key-1": "7", "key-2": "8"}; !maps.Equal(atSync[1], want) {
		t.Fatalf("slow subscriber cache = %v, want %v", atSync[1], want)
	}
}

func TestBacklogKeepsNewestSyncAndOrdersAroundIt(t *testing.T) {
	pending := newBacklog()
	for _, change := range []Change{
		lagTestChange("a", OperationUpsert, 1, 1),
		lagTestChange("", OperationSync, 1, 2),
		lagTestChange("a", OperationDelete, 2, 3),
		lagTestChange("b", OperationUpsert, 2, 4),
		lagTestChange("", OperationSync, 2, 5),
		lagTestChange("c", OperationUpsert, 3, 6),
		lagTestChange("b", OperationDelete, 3, 7),
	} {
		pending.add(change)
	}
	var got []string
	for _, change := range pending.take() {
		got = append(got, fmt.Sprintf("%s:%s:%d", change.Operation, change.Key, change.Generation))
	}
	want := []string{"delete:a:2", "upsert:b:2", "sync:sync:2", "delete:b:3", "upsert:c:3"}
	if !slices.Equal(got, want) {
		t.Fatalf("backlog = %v, want %v", got, want)
	}
	if !pending.empty() {
		t.Fatal("take did not reset the backlog")
	}
}

func TestCancelledLaggingSubscriberCloses(t *testing.T) {
	for range 50 {
		hub := newLagTestHub(1, nil)
		ctx, cancel := context.WithCancel(context.Background())
		changes, err := hub.Subscribe(ctx, "cluster", "objects")
		if err != nil {
			t.Fatal(err)
		}
		for index := range 5 {
			if err := hub.Publish(context.Background(), lagTestChange(fmt.Sprintf("key-%d", index), OperationUpsert, 1, index)); err != nil {
				t.Fatal(err)
			}
		}
		cancel()
		timeout := time.After(5 * time.Second)
	drain:
		for {
			select {
			case _, ok := <-changes:
				if !ok {
					break drain
				}
			case <-timeout:
				t.Fatal("cancelled subscription did not close")
			}
		}
		// Publishing after the subscription ended must not reach it.
		if err := hub.Publish(context.Background(), lagTestChange("late", OperationUpsert, 1, 9)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLagEpisodeIsLoggedOnceWithSubscriber(t *testing.T) {
	var output strings.Builder
	hub := newLagTestHub(1, &output)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := hub.subscribe(ctx, "cluster", "objects", "istio")
	if err != nil {
		t.Fatal(err)
	}
	for index := range 5 {
		if err := hub.Publish(context.Background(), lagTestChange(fmt.Sprintf("key-%d", index), OperationUpsert, 1, index)); err != nil {
			t.Fatal(err)
		}
	}
	if err := hub.Publish(context.Background(), lagTestChange("", OperationSync, 1, 5)); err != nil {
		t.Fatal(err)
	}
	if _, err := consumeUntilSync(changes, 1, 1); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		hub.mu.Lock()
		logs := output.String()
		hub.mu.Unlock()
		if strings.Contains(logs, "caught up") {
			if strings.Count(logs, "is lagging") != 1 || !strings.Contains(logs, "subscriber=istio") || !strings.Contains(logs, "collection=objects") || !strings.Contains(logs, "source=cluster") {
				t.Fatalf("lag logs = %q", logs)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no catch-up log: %q", logs)
		}
		time.Sleep(time.Millisecond)
	}
}
