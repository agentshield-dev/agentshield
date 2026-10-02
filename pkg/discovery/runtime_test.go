package discovery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// fakeStore keeps native events and contribution heads in memory.
type fakeStore struct {
	mu            sync.Mutex
	native        map[string]state.NativeEvent
	contributions []state.Contribution
	generation    uint64
}

func newFakeStore() *fakeStore {
	return &fakeStore{native: make(map[string]state.NativeEvent)}
}

func (s *fakeStore) RecordNative(_ context.Context, event state.NativeEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.native[event.EventID] = event
	return nil
}

func (s *fakeStore) ReplaceContribution(_ context.Context, contribution state.Contribution) (state.GraphView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if contribution.Generation <= s.generation {
		return state.GraphView{}, errors.New("stale generation")
	}
	s.generation = contribution.Generation
	s.contributions = append(s.contributions, contribution)
	return state.GraphView{}, nil
}

func (s *fakeStore) ContributionGeneration(context.Context, string, string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation, nil
}

func (s *fakeStore) history() []state.Contribution {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]state.Contribution(nil), s.contributions...)
}

// flakyPlugin publishes keys a and b and fails on its first attempt, panics on
// its second, and on its third publishes only key a and then runs until
// cancelled.
type flakyPlugin struct {
	attempts atomic.Int32
	running  chan struct{}
}

func (p *flakyPlugin) Descriptor() Descriptor {
	return Descriptor{ID: "flaky", Version: "1", Publishes: []string{"objects"}}
}

func (p *flakyPlugin) SourceID() string { return "source" }

func (p *flakyPlugin) Run(ctx context.Context, runtime Runtime) error {
	attempt := p.attempts.Add(1)
	if attempt == 2 {
		panic("boom")
	}
	generation, err := runtime.ContributionGeneration(ctx, "flaky", "source")
	if err != nil {
		return err
	}
	generation++
	keys := []string{"a", "b"}
	if attempt == 3 {
		keys = []string{"a"}
	}
	for _, key := range keys {
		if err := runtime.Publish(ctx, Change{
			EventID: "flaky:objects:" + key + ":1:upsert", PluginID: "flaky", SourceID: "source", Collection: "objects",
			Key: key, Revision: "1", Generation: generation, Operation: OperationUpsert, Payload: []byte(`{}`),
		}); err != nil {
			return err
		}
	}
	if err := runtime.ReplaceContribution(ctx, "flaky", "source", ContributionOutput{
		Name: "inventory", Generation: generation, Input: graph.Input{}, Ready: true, SourceHealth: "healthy",
	}); err != nil {
		return err
	}
	if err := runtime.MarkReady(ctx, "flaky", "source", "objects", generation); err != nil {
		return err
	}
	if attempt == 1 {
		return errors.New("provider unavailable")
	}
	close(p.running)
	<-ctx.Done()
	return ctx.Err()
}

// steadyPlugin counts its starts and runs until cancelled.
type steadyPlugin struct {
	starts atomic.Int32
}

func (p *steadyPlugin) Descriptor() Descriptor { return Descriptor{ID: "steady", Version: "1"} }
func (p *steadyPlugin) SourceID() string       { return "source" }
func (p *steadyPlugin) Run(ctx context.Context, _ Runtime) error {
	p.starts.Add(1)
	<-ctx.Done()
	return nil
}

func TestManagerRestartsOnlyTheFailedInstanceAndDegradesItsContribution(t *testing.T) {
	store := newFakeStore()
	runtime := &RuntimeService{hub: NewHub(), store: store}
	flaky := &flakyPlugin{running: make(chan struct{})}
	steady := &steadyPlugin{}
	manager, err := NewManager(runtime, flaky, steady)
	if err != nil {
		t.Fatal(err)
	}
	manager.restartBackoff = time.Millisecond
	manager.maxRestartBackoff = 4 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := runtime.hub.Subscribe(ctx, "source", "objects")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- manager.Run(ctx) }()
	select {
	case <-flaky.running:
	case err := <-result:
		t.Fatalf("manager stopped: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("flaky plugin was not restarted")
	}

	if got := flaky.attempts.Load(); got != 3 {
		t.Fatalf("flaky attempts = %d, want 3", got)
	}
	if got := steady.starts.Load(); got != 1 {
		t.Fatalf("steady plugin started %d times, want 1", got)
	}
	var health []string
	var generations []uint64
	for _, contribution := range store.history() {
		health = append(health, contribution.SourceHealth)
		generations = append(generations, contribution.Generation)
	}
	// Attempt 1 publishes healthy, its failure republishes degraded, the
	// panicking attempt 2 publishes nothing, and attempt 3 is healthy again.
	if strings.Join(health, ",") != "healthy,degraded,healthy" || generations[0] != 1 || generations[1] != 2 || generations[2] != 3 {
		t.Fatalf("contribution history = %v at %v", health, generations)
	}

	// Key b was not republished after the restart, so it is deleted before
	// the restarted instance's sync marker.
	var seen []string
	for change := range changes {
		seen = append(seen, string(change.Operation)+":"+change.Key)
		if change.Operation == OperationSync && change.Generation == 3 {
			break
		}
	}
	want := "upsert:a,upsert:b,sync:sync,upsert:a,delete:b,sync:sync"
	if strings.Join(seen, ",") != want {
		t.Fatalf("collection changes = %v, want %s", seen, want)
	}
	store.mu.Lock()
	_, recorded := store.native["flaky:objects:b:1:delete"]
	store.mu.Unlock()
	if !recorded {
		t.Fatal("stale delete was not recorded as a native event")
	}

	cancel()
	if err := <-result; err != nil {
		t.Fatalf("Run after cancellation = %v", err)
	}
}

func TestManagerReportsWhenEveryInstanceFinishes(t *testing.T) {
	manager, err := NewManager(&RuntimeService{hub: NewHub(), store: newFakeStore()}, descriptorPlugin{sourceID: "source", descriptor: Descriptor{ID: "done", Version: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Run(context.Background()); err == nil {
		t.Fatal("Run returned nil after every plugin finished")
	}
}

func TestRunInstanceRecoversPanicWithStack(t *testing.T) {
	err := runInstance(context.Background(), panicPlugin{}, nil)
	if err == nil || !strings.Contains(err.Error(), "plugin panicked: kaboom") || !strings.Contains(err.Error(), "runtime_test.go") {
		t.Fatalf("runInstance error = %v", err)
	}
}

type panicPlugin struct{}

func (panicPlugin) Descriptor() Descriptor             { return Descriptor{ID: "panic", Version: "1"} }
func (panicPlugin) Run(context.Context, Runtime) error { panic("kaboom") }
