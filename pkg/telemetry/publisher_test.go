package telemetry

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

type publishedRollup struct {
	pluginID   string
	sourceID   string
	generation uint64
	input      graph.Input
}

type fakeRollupTarget struct {
	durable   map[string]uint64
	lookups   []string
	published []publishedRollup
	fail      error
}

func (target *fakeRollupTarget) ContributionGeneration(_ context.Context, pluginID, sourceID string) (uint64, error) {
	target.lookups = append(target.lookups, pluginID+"/"+sourceID)
	return target.durable[pluginID+"/"+sourceID], nil
}

func (target *fakeRollupTarget) PublishRollup(_ context.Context, pluginID, sourceID string, generation uint64, input graph.Input, _ time.Time) error {
	if target.fail != nil {
		return target.fail
	}
	target.published = append(target.published, publishedRollup{pluginID: pluginID, sourceID: sourceID, generation: generation, input: input})
	return nil
}

func (target *fakeRollupTarget) summary() []string {
	result := make([]string, 0, len(target.published))
	for _, published := range target.published {
		result = append(result, fmt.Sprintf("%s/%s@%d:%d", published.pluginID, published.sourceID, published.generation, len(published.input.Telemetry)))
	}
	target.published = nil
	return result
}

var (
	publisherSubject = graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	publisherObject  = graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "service/b"}
	publisherGraph   = graph.Snapshot{Resources: []graph.Resource{{ID: "a", Identity: publisherSubject}, {ID: "b", Identity: publisherObject}}}
)

func newTestRollupPublisher(t *testing.T, target *fakeRollupTarget, now *time.Time) *RollupPublisher {
	t.Helper()
	publisher, err := NewRollupPublisher(RollupPublisherConfig{
		Rollup:   NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 100}),
		Snapshot: func(context.Context) (graph.Snapshot, error) { return publisherGraph, nil },
		Target:   target,
		Now:      func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func publisherEvent(id, pluginID, sourceID string, observedAt time.Time) Event {
	return Event{
		EventID: id, PluginID: pluginID, SourceID: sourceID, Kind: "network-flow",
		Subject: publisherSubject, Object: publisherObject, ObservedAt: observedAt, Count: 1,
	}
}

func TestRollupPublisherAdvancesGenerationsFromDurableState(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	target := &fakeRollupTarget{durable: map[string]uint64{"cilium/hubble": 7}}
	publisher := newTestRollupPublisher(t, target, &now)

	if err := publisher.Commit(context.Background(), []Event{publisherEvent("one", "cilium", "hubble", now)}); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"cilium/hubble@8:1"}; !slices.Equal(got, want) {
		t.Fatalf("first commit = %v, want %v", got, want)
	}
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("two", "cilium", "hubble", now)}); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"cilium/hubble@9:1"}; !slices.Equal(got, want) {
		t.Fatalf("second commit = %v, want %v", got, want)
	}
	if !slices.Equal(target.lookups, []string{"cilium/hubble"}) {
		t.Fatalf("durable generation lookups = %v, want one", target.lookups)
	}

	// A quiet lifecycle tick with nothing expired publishes nothing.
	if err := publisher.Commit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := target.summary(); len(got) != 0 {
		t.Fatalf("idle tick published %v", got)
	}
}

func TestRollupPublisherRetractsExpiredOwners(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	target := &fakeRollupTarget{}
	publisher := newTestRollupPublisher(t, target, &now)
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("one", "cilium", "hubble", now)}); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"cilium/hubble@1:1"}; !slices.Equal(got, want) {
		t.Fatalf("initial commit = %v, want %v", got, want)
	}

	now = now.Add(2 * time.Hour)
	if err := publisher.Commit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	published := target.published
	if got, want := target.summary(), []string{"cilium/hubble@2:0"}; !slices.Equal(got, want) {
		t.Fatalf("expiry commit = %v, want %v", got, want)
	}
	if input := published[0].input; len(input.Resources) != 0 || len(input.Relationships) != 0 || len(input.Telemetry) != 0 {
		t.Fatalf("expired owner input = %#v, want empty", input)
	}

	// The retracted owner keeps advancing alongside new owners.
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("two", "istio", "access-log", now)}); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"istio/access-log@1:1"}; !slices.Equal(got, want) {
		t.Fatalf("commit after retraction = %v, want %v", got, want)
	}
}

func TestRollupPublisherBatchesGraphPublicationByInterval(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	target := &fakeRollupTarget{}
	publisher, err := NewRollupPublisher(RollupPublisherConfig{
		Rollup:          NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 100}),
		Snapshot:        func(context.Context) (graph.Snapshot, error) { return publisherGraph, nil },
		Target:          target,
		Now:             func() time.Time { return now },
		PublishInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("one", "cilium", "hubble", now)}); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"cilium/hubble@1:1"}; !slices.Equal(got, want) {
		t.Fatalf("first commit = %v, want %v", got, want)
	}
	now = now.Add(time.Second)
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("two", "cilium", "hubble", now)}); err != nil {
		t.Fatal(err)
	}
	if got := target.summary(); len(got) != 0 {
		t.Fatalf("commit inside interval published %v", got)
	}
	now = now.Add(29 * time.Second)
	if err := publisher.Commit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"cilium/hubble@2:1"}; !slices.Equal(got, want) {
		t.Fatalf("interval commit = %v, want %v", got, want)
	}
}

func TestRollupPublisherOrdersOwnersDeterministically(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	events := []Event{
		publisherEvent("one", "istio", "access-log", now),
		publisherEvent("two", "cilium", "z", now),
		publisherEvent("three", "cilium", "a", now),
	}
	want := []string{"cilium/a@1:1", "cilium/z@1:1", "istio/access-log@1:1"}
	for _, ordering := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 0, 2}} {
		target := &fakeRollupTarget{}
		publisher := newTestRollupPublisher(t, target, &now)
		batch := make([]Event, 0, len(ordering))
		for _, index := range ordering {
			batch = append(batch, events[index])
		}
		if err := publisher.Commit(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
		if got := target.summary(); !slices.Equal(got, want) {
			t.Fatalf("ordering %v published %v, want %v", ordering, got, want)
		}
	}
}

func TestRollupPublisherKeepsGenerationAfterFailedPublish(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	failure := errors.New("store unavailable")
	target := &fakeRollupTarget{fail: failure}
	publisher := newTestRollupPublisher(t, target, &now)
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("one", "cilium", "hubble", now)}); !errors.Is(err, failure) {
		t.Fatalf("commit error = %v, want %v", err, failure)
	}
	target.fail = nil
	if err := publisher.Commit(context.Background(), []Event{publisherEvent("two", "cilium", "hubble", now)}); err != nil {
		t.Fatal(err)
	}
	if got, want := target.summary(), []string{"cilium/hubble@1:1"}; !slices.Equal(got, want) {
		t.Fatalf("commit after failure = %v, want %v", got, want)
	}
}

func TestRetainResolvedDropsUnresolvedAssertions(t *testing.T) {
	input := graph.Input{
		Relationships: []graph.RelationshipAssertion{{RuleID: "telemetry.lease"}},
		Telemetry:     []graph.TelemetryAssertion{{EventID: "event"}},
	}
	got := retainResolved(input, graph.Snapshot{})
	if len(got.Relationships) != 0 {
		t.Fatalf("relationships = %d, want 0", len(got.Relationships))
	}
	if len(got.Telemetry) != 0 {
		t.Fatalf("telemetry = %d, want 0", len(got.Telemetry))
	}
}
