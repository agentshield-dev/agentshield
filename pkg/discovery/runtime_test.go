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
	deltas        []state.ContributionDelta
	heads         map[string]uint64
	deltaErr      error
}

func newFakeStore() *fakeStore {
	return &fakeStore{native: make(map[string]state.NativeEvent), heads: make(map[string]uint64)}
}

func contributionKey(pluginID, sourceID, name string) string {
	return pluginID + "\x00" + sourceID + "\x00" + name
}

func (s *fakeStore) RecordNative(_ context.Context, event state.NativeEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.native[event.EventID] = event
	return nil
}

func (s *fakeStore) ReplaceContribution(_ context.Context, contribution state.Contribution) (state.Publication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := contributionKey(contribution.PluginID, contribution.SourceID, contribution.Name)
	if contribution.Generation <= s.heads[key] {
		return state.Publication{}, errors.New("stale generation")
	}
	s.heads[key] = contribution.Generation
	s.contributions = append(s.contributions, contribution)
	return state.Publication{}, nil
}

func (s *fakeStore) ApplyContributionDelta(_ context.Context, delta state.ContributionDelta) (state.Publication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deltaErr != nil {
		err := s.deltaErr
		s.deltaErr = nil
		return state.Publication{}, err
	}
	key := contributionKey(delta.PluginID, delta.SourceID, delta.Name)
	if delta.BaseGeneration != s.heads[key] {
		return state.Publication{}, state.ErrContributionDeltaBaseMismatch
	}
	if delta.Generation <= s.heads[key] {
		return state.Publication{}, errors.New("stale generation")
	}
	s.heads[key] = delta.Generation
	s.deltas = append(s.deltas, delta)
	return state.Publication{}, nil
}

func (s *fakeStore) ContributionGeneration(_ context.Context, pluginID, sourceID string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var generation uint64
	prefix := pluginID + "\x00" + sourceID + "\x00"
	for key, current := range s.heads {
		if strings.HasPrefix(key, prefix) {
			generation = max(generation, current)
		}
	}
	return generation, nil
}

func (s *fakeStore) NormalizeIdentityClaim(claim graph.IdentityClaim) (graph.IdentityClaim, error) {
	return claim, nil
}

func (s *fakeStore) history() []state.Contribution {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]state.Contribution(nil), s.contributions...)
}

func TestRuntimeUsesDeltasBetweenAuthoritativeCheckpointsAndRecoversDrift(t *testing.T) {
	store := newFakeStore()
	runtime := &RuntimeService{
		hub: NewHub(), store: store,
		config: RuntimeConfig{CheckpointInterval: time.Hour, CheckpointDeltas: 2},
	}
	session := newPublicationSession()
	publish := func(generation uint64, key string) error {
		_, err := runtime.publishContribution(context.Background(), "test", "source", ContributionOutput{
			Name: "inventory", Generation: generation, Ready: true, SourceHealth: state.SourceHealthHealthy,
			Input: graph.Input{Resources: []graph.ResourceAssertion{{
				Claim: graph.IdentityClaim{AuthorityID: "source", ImmutableKey: key},
				Kind:  "test/resource", PluginID: "test", SourceID: "source", RuleID: "test.resource",
			}}},
		}, session)
		return err
	}
	if err := publish(1, "a"); err != nil {
		t.Fatal(err)
	}
	if err := publish(2, "b"); err != nil {
		t.Fatal(err)
	}
	if err := publish(3, "c"); err != nil {
		t.Fatal(err)
	}
	if err := publish(4, "d"); err != nil {
		t.Fatal(err)
	}
	if len(store.contributions) != 2 || store.contributions[0].Generation != 1 || store.contributions[1].Generation != 4 {
		t.Fatalf("authoritative publications = %+v, want generations 1 and 4", store.contributions)
	}
	if len(store.deltas) != 2 || store.deltas[0].BaseGeneration != 1 || store.deltas[1].BaseGeneration != 2 {
		t.Fatalf("delta publications = %+v, want bases 1 and 2", store.deltas)
	}
	if len(store.deltas[0].Added.Resources) != 1 || store.deltas[0].Added.Resources[0].Claim.ImmutableKey != "b" ||
		len(store.deltas[0].Retracted.Resources) != 1 || store.deltas[0].Retracted.Resources[0].Claim.ImmutableKey != "a" {
		t.Fatalf("first delta = %+v", store.deltas[0])
	}

	store.mu.Lock()
	store.heads[contributionKey("test", "source", "inventory")] = 5
	store.mu.Unlock()
	if err := publish(6, "e"); !errors.Is(err, state.ErrContributionDeltaBaseMismatch) {
		t.Fatalf("drift publication error = %v", err)
	}
	if err := publish(7, "f"); err != nil {
		t.Fatalf("authoritative recovery publication: %v", err)
	}
	if got := store.contributions[len(store.contributions)-1].Generation; got != 7 {
		t.Fatalf("recovery checkpoint generation = %d, want 7", got)
	}

	restarted := newPublicationSession()
	if _, err := runtime.publishContribution(context.Background(), "test", "source", ContributionOutput{
		Name: "inventory", Generation: 8, Ready: true, SourceHealth: state.SourceHealthHealthy,
	}, restarted); err != nil {
		t.Fatalf("restart checkpoint: %v", err)
	}
	if got := store.contributions[len(store.contributions)-1].Generation; got != 8 {
		t.Fatalf("restart checkpoint generation = %d, want 8", got)
	}
	store.mu.Lock()
	store.deltaErr = state.ErrContributionDeltaMembershipMismatch
	store.mu.Unlock()
	if _, err := runtime.publishContribution(context.Background(), "test", "source", ContributionOutput{
		Name: "inventory", Generation: 9, Ready: true, SourceHealth: state.SourceHealthHealthy,
	}, restarted); err != nil {
		t.Fatalf("membership drift checkpoint: %v", err)
	}
	if got := store.contributions[len(store.contributions)-1].Generation; got != 9 {
		t.Fatalf("membership drift checkpoint generation = %d, want 9", got)
	}
}

func TestRuntimeKeepsPublicationStatePerContributionOwner(t *testing.T) {
	store := newFakeStore()
	runtime := &RuntimeService{
		hub: NewHub(), store: store,
		config:       RuntimeConfig{CheckpointInterval: time.Hour, CheckpointDeltas: 100},
		publications: newPublicationSession(),
	}
	for _, sourceID := range []string{"one", "two"} {
		if err := runtime.ReplaceContribution(context.Background(), "telemetry", sourceID, ContributionOutput{Name: "rollups", Generation: 1}); err != nil {
			t.Fatal(err)
		}
	}
	for _, sourceID := range []string{"one", "two"} {
		if err := runtime.ReplaceContribution(context.Background(), "telemetry", sourceID, ContributionOutput{Name: "rollups", Generation: 2}); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.contributions) != 2 || len(store.deltas) != 2 {
		t.Fatalf("publications = %d checkpoints and %d deltas, want 2 and 2", len(store.contributions), len(store.deltas))
	}
	for _, delta := range store.deltas {
		if delta.BaseGeneration != 1 || delta.Generation != 2 {
			t.Fatalf("delta generations = %d to %d, want 1 to 2", delta.BaseGeneration, delta.Generation)
		}
	}
}

func TestRuntimeStaggersInitialPeriodicCheckpointsWithinMaximum(t *testing.T) {
	store := newFakeStore()
	maximum := 8 * time.Hour
	runtime := &RuntimeService{
		hub: NewHub(), store: store,
		config: RuntimeConfig{CheckpointInterval: maximum, CheckpointDeltas: 100},
	}
	session := newPublicationSession()
	keys := []publicationKey{
		{pluginID: "test", sourceID: "one", name: "inventory"},
		{pluginID: "test", sourceID: "two", name: "inventory"},
	}
	for _, key := range keys {
		if _, err := runtime.publishContribution(context.Background(), key.pluginID, key.sourceID, ContributionOutput{
			Name: key.name, Generation: 1,
		}, session); err != nil {
			t.Fatal(err)
		}
	}
	first := session.contributions[keys[0]].checkpointAfter
	second := session.contributions[keys[1]].checkpointAfter
	minimum := maximum - maximum/checkpointStaggerDivisor
	for _, interval := range []time.Duration{first, second} {
		if interval < minimum || interval > maximum {
			t.Fatalf("checkpoint interval = %v, want [%v, %v]", interval, minimum, maximum)
		}
	}
	if first == second {
		t.Fatalf("checkpoint intervals = %v and %v, want different owner deadlines", first, second)
	}
	publication := session.contributions[keys[0]]
	publication.checkpointAt = time.Now().Add(-maximum)
	session.contributions[keys[0]] = publication
	mode, err := runtime.publishContribution(context.Background(), keys[0].pluginID, keys[0].sourceID, ContributionOutput{
		Name: keys[0].name, Generation: 2,
	}, session)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "checkpoint" || session.contributions[keys[0]].checkpointAfter != maximum {
		t.Fatalf("next publication = %s after %v, want checkpoint after %v", mode, session.contributions[keys[0]].checkpointAfter, maximum)
	}
}

func TestRuntimeSnapshotsAcceptedContributionOutput(t *testing.T) {
	store := newFakeStore()
	runtime := &RuntimeService{
		hub: NewHub(), store: store,
		config: RuntimeConfig{CheckpointInterval: time.Hour, CheckpointDeltas: 100},
	}
	session := newPublicationSession()
	first := ContributionOutput{
		Name: "inventory", Generation: 1,
		Input: graph.Input{Resources: []graph.ResourceAssertion{{
			Claim: graph.IdentityClaim{AuthorityID: "source", ImmutableKey: "a"},
			Kind:  "test/resource", Attributes: map[string]string{"version": "one"},
			PluginID: "test", SourceID: "source", RuleID: "test.resource",
		}}},
	}
	if _, err := runtime.publishContribution(context.Background(), "test", "source", first, session); err != nil {
		t.Fatal(err)
	}
	first.Input.Resources[0].Attributes["version"] = "mutated"
	second := ContributionOutput{
		Name: "inventory", Generation: 2,
		Input: graph.Input{Resources: []graph.ResourceAssertion{{
			Claim: graph.IdentityClaim{AuthorityID: "source", ImmutableKey: "a"},
			Kind:  "test/resource", Attributes: map[string]string{"version": "two"},
			PluginID: "test", SourceID: "source", RuleID: "test.resource",
		}}},
	}
	if _, err := runtime.publishContribution(context.Background(), "test", "source", second, session); err != nil {
		t.Fatal(err)
	}
	if got := store.deltas[0].Retracted.Resources[0].Attributes["version"]; got != "one" {
		t.Fatalf("retracted version = %q, want one", got)
	}
}

func TestScopedRuntimeKeepsAcceptedMetadataOnSameGenerationRetry(t *testing.T) {
	store := newFakeStore()
	runtime := &RuntimeService{
		hub: NewHub(), store: store,
		config: RuntimeConfig{CheckpointInterval: time.Hour, CheckpointDeltas: 100},
	}
	published := &publishedOutputs{byName: make(map[string]ContributionOutput)}
	scoped := scopedRuntime{
		runtime: runtime, pluginID: "test", sourceID: "source",
		published: published, publications: newPublicationSession(),
	}
	output := ContributionOutput{Name: "inventory", Generation: 1, Ready: true, SourceHealth: state.SourceHealthHealthy}
	if err := scoped.ReplaceContribution(context.Background(), "test", "source", output); err != nil {
		t.Fatal(err)
	}
	retry := output
	retry.Ready = false
	retry.SourceHealth = state.SourceHealthDegraded
	if err := scoped.ReplaceContribution(context.Background(), "test", "source", retry); err != nil {
		t.Fatal(err)
	}
	accepted := published.snapshot()
	if len(accepted) != 1 || !accepted[0].Ready || accepted[0].SourceHealth != state.SourceHealthHealthy {
		t.Fatalf("accepted output = %+v", accepted)
	}
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
