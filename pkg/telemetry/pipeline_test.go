package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

var testIdentityScheme = graph.IdentityScheme{Group: "test.agentshield.io", Version: "v1", Kind: "Resource"}

func TestPipelineRetriesAndCommitsBatch(t *testing.T) {
	sink := &retrySink{failures: 2, written: make(chan []Event, 1)}
	committed := make(chan []Event, 1)
	pipeline, err := NewPipeline(PipelineConfig{QueueCapacity: 10, MaxBatch: 2, FlushInterval: time.Hour, RetryMinimum: time.Millisecond, RetryMaximum: 2 * time.Millisecond}, sink, func(_ context.Context, events []Event) error {
		committed <- slices.Clone(events)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pipeline.Run(ctx) }()
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	observedAt := time.Unix(10, 0).UTC()
	if err := pipeline.Ingest(ctx,
		Event{EventID: "one", ObservedAt: observedAt, Kind: "request", Subject: claim, Object: claim, PluginID: "test", SourceID: "test"},
		Event{EventID: "two", ObservedAt: observedAt, Kind: "request", Subject: claim, Object: claim, PluginID: "test", SourceID: "test"},
	); err != nil {
		t.Fatal(err)
	}
	select {
	case events := <-sink.written:
		if len(events) != 2 || sink.attempts != 3 {
			t.Fatalf("write batch = %d events in %d attempts", len(events), sink.attempts)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for telemetry write")
	}
	select {
	case events := <-committed:
		if len(events) != 2 {
			t.Fatalf("committed %d events", len(events))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for telemetry commit")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPipelineCommitsLifecycleTickWithoutTelemetry(t *testing.T) {
	committed := make(chan []Event, 1)
	pipeline, err := NewPipeline(PipelineConfig{
		QueueCapacity: 1, MaxBatch: 1, FlushInterval: time.Hour, LifecycleInterval: time.Millisecond,
	}, &retrySink{written: make(chan []Event, 1)}, func(_ context.Context, events []Event) error {
		committed <- slices.Clone(events)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pipeline.Run(ctx) }()
	select {
	case events := <-committed:
		if len(events) != 0 {
			t.Fatalf("lifecycle commit contained %d telemetry events", len(events))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for telemetry lifecycle commit")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRollupBoundsSeriesAndAggregatesCounts(t *testing.T) {
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	rollup := NewRollup(RollupConfig{
		Window: time.Minute, Retention: time.Hour, MaxSeries: 1,
		Now: func() time.Time { return now },
	})
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	rollup.ObserveBatch([]Event{
		{EventID: "one", ObservedAt: now, Kind: "request", Subject: claim, Object: claim, PluginID: "test", SourceID: "test", Count: 2, Properties: map[string]string{"method": "PUT"}, RollupProperties: map[string]string{"method": "PUT"}, EvidenceIDs: []string{"raw:one"}},
		{EventID: "two", ObservedAt: now.Add(time.Second), Kind: "request", Subject: claim, Object: claim, PluginID: "test", SourceID: "test", Count: 3, Properties: map[string]string{"method": "PUT"}, RollupProperties: map[string]string{"method": "PUT"}, EvidenceIDs: []string{"raw:two"}},
	})
	input := rollup.Input()
	if len(input.Telemetry) != 1 || input.Telemetry[0].Count != 5 {
		t.Fatalf("unexpected rollup: %#v", input.Telemetry)
	}
	if got := input.Telemetry[0].Properties["method"]; got != "PUT" {
		t.Fatalf("method = %q, want PUT", got)
	}
	if input.Telemetry[0].Properties["telemetry/first-seen"] == "" || input.Telemetry[0].Properties["telemetry/last-seen"] == "" {
		t.Fatalf("missing observation bounds: %#v", input.Telemetry[0].Properties)
	}
	if len(input.Telemetry[0].EvidenceIDs) != 2 {
		t.Fatalf("evidence IDs = %v, want raw event references", input.Telemetry[0].EvidenceIDs)
	}
	other := claim
	other.ImmutableKey = "other"
	rollup.ObserveBatch([]Event{{EventID: "three", ObservedAt: now.Add(2 * time.Minute), Kind: "request", Subject: other, Object: claim, PluginID: "test", SourceID: "test", Count: 1}})
	if got := len(rollup.Input().Telemetry); got != 1 {
		t.Fatalf("series count = %d, want bounded to 1", got)
	}
}

func TestRollupEvictsOldestIncludingIncomingSeries(t *testing.T) {
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	older := Event{EventID: "older", ObservedAt: time.Unix(10, 0).UTC(), Kind: "request", Subject: claim, Object: claim, PluginID: "test", SourceID: "test"}
	newer := older
	newer.EventID = "newer"
	newer.ObservedAt = time.Unix(20, 0).UTC()
	newer.Subject.ImmutableKey = "newer"

	for _, events := range [][]Event{{older, newer}, {newer, older}} {
		rollup := NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 1})
		rollup.ObserveBatch(events)
		input := rollup.Input()
		if len(input.Telemetry) != 1 || input.Telemetry[0].Subject.ImmutableKey != "newer" {
			t.Fatalf("retained telemetry = %#v, want newer series", input.Telemetry)
		}
	}
}

func TestPipelineRejectsUnboundedProperties(t *testing.T) {
	pipeline, err := NewPipeline(PipelineConfig{QueueCapacity: 1, MaxBatch: 1}, &retrySink{written: make(chan []Event, 1)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	properties := make(map[string]string, maxPropertyCount+1)
	for index := 0; index <= maxPropertyCount; index++ {
		properties[fmt.Sprintf("property-%d", index)] = "value"
	}
	err = pipeline.Ingest(context.Background(), Event{EventID: "event", ObservedAt: time.Unix(10, 0).UTC(), Kind: "request", Subject: claim, Object: claim, PluginID: "test", SourceID: "test", Properties: properties})
	if err == nil {
		t.Fatal("expected unbounded properties to fail")
	}
}

func TestPipelineRejectsMissingObservedAt(t *testing.T) {
	pipeline, err := NewPipeline(PipelineConfig{QueueCapacity: 1, MaxBatch: 1}, &retrySink{written: make(chan []Event, 1)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	err = pipeline.Ingest(context.Background(), Event{EventID: "event", Kind: "request", Subject: claim, Object: claim, PluginID: "test", SourceID: "test"})
	if err == nil || !strings.Contains(err.Error(), "observation timestamp") {
		t.Fatalf("missing timestamp error = %v", err)
	}
}

func TestRollupEvidenceBoundIsReplayDeterministic(t *testing.T) {
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	observedAt := time.Unix(10, 0).UTC()
	events := make([]Event, 40)
	for index := range events {
		events[index] = Event{
			EventID: fmt.Sprintf("event-%02d", index), ObservedAt: observedAt, Kind: "flow", Subject: claim, Object: claim,
			PluginID: "test", SourceID: "test", EvidenceIDs: []string{fmt.Sprintf("evidence-%02d", index)},
		}
	}
	forward := NewRollup(RollupConfig{})
	forward.ObserveBatch(events)
	for left, right := 0, len(events)-1; left < right; left, right = left+1, right-1 {
		events[left], events[right] = events[right], events[left]
	}
	reversed := NewRollup(RollupConfig{})
	reversed.ObserveBatch(events)
	forwardEvidence := forward.Input().Telemetry[0].EvidenceIDs
	reversedEvidence := reversed.Input().Telemetry[0].EvidenceIDs
	if !reflect.DeepEqual(forwardEvidence, reversedEvidence) || len(forwardEvidence) != maxEvidenceIDs {
		t.Fatalf("bounded evidence changed under replay: forward=%v reversed=%v", forwardEvidence, reversedEvidence)
	}
}

func TestRollupPreservesMappedPluginOwnership(t *testing.T) {
	rollup := NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 10})
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	rollup.ObserveBatch([]Event{{
		EventID: "flow-1", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow",
		Subject: claim, Object: claim, ObservedAt: time.Now().UTC(), Count: 1,
	}})
	input := rollup.Input()
	if len(input.Telemetry) != 1 || input.Telemetry[0].PluginID != "cilium" || input.Telemetry[0].SourceID != "cluster-a/hubble" {
		t.Fatalf("unexpected rollup ownership: %#v", input.Telemetry)
	}
}

func TestRollupDropsTelemetryWithoutProviderOwnership(t *testing.T) {
	rollup := NewRollup(RollupConfig{})
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	rollup.ObserveBatch([]Event{{
		EventID: "unclaimed", Kind: "network-flow", Subject: claim, Object: claim,
		ObservedAt: time.Now().UTC(), Count: 1,
	}})
	input := rollup.Input()
	if len(input.Resources)+len(input.Relationships)+len(input.Telemetry) != 0 {
		t.Fatalf("unclaimed telemetry produced graph input: %#v", input)
	}
}

func TestRollupPartitionsInputsByMappedPluginOwnership(t *testing.T) {
	rollup := NewRollup(RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 10})
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	observedAt := time.Now().UTC()
	rollup.ObserveBatch([]Event{
		{EventID: "cilium-flow", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow", Subject: claim, Object: claim, ObservedAt: observedAt, Count: 1},
		{EventID: "istio-flow", PluginID: "istio", SourceID: "cluster-a/access-log", Kind: "network-flow", Subject: claim, Object: claim, ObservedAt: observedAt, Count: 1},
	})
	inputs := rollup.Inputs()
	if len(inputs) != 2 || inputs[0].PluginID != "cilium" || inputs[0].SourceID != "cluster-a/hubble" || inputs[1].PluginID != "istio" || inputs[1].SourceID != "cluster-a/access-log" {
		t.Fatalf("unexpected owned inputs: %#v", inputs)
	}
	for _, input := range inputs {
		if len(input.Input.Telemetry) != 1 || len(input.Input.Relationships) != 1 {
			t.Fatalf("owner %s/%s received another provider's assertions: %#v", input.PluginID, input.SourceID, input.Input)
		}
	}
}

func TestRollupCommunicationEdgeLeaseRefreshAndExpiry(t *testing.T) {
	rollup := NewRollup(RollupConfig{
		Window: time.Minute, Retention: time.Hour, EdgeRefreshBefore: 15 * time.Minute, MaxSeries: 10,
	})
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	object := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "service/b"}
	observedAt := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	event := Event{
		EventID: "flow-1", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow",
		Subject: subject, Object: object, ObservedAt: observedAt, Count: 1, EvidenceIDs: []string{"evidence-1"},
	}
	rollup.ObserveBatch([]Event{event})
	initial := rollup.Input()
	if len(initial.Relationships) != 1 {
		t.Fatalf("initial relationships = %#v", initial.Relationships)
	}

	event.EventID = "flow-2"
	event.ObservedAt = observedAt.Add(30 * time.Minute)
	event.EvidenceIDs = []string{"evidence-2"}
	rollup.ObserveBatch([]Event{event})
	ordinary := rollup.Input()
	if !reflect.DeepEqual(initial.Relationships, ordinary.Relationships) {
		t.Fatalf("ordinary activity changed edge lease: initial=%#v ordinary=%#v", initial.Relationships, ordinary.Relationships)
	}

	event.EventID = "flow-3"
	event.ObservedAt = observedAt.Add(46 * time.Minute)
	event.EvidenceIDs = []string{"evidence-3"}
	rollup.ObserveBatch([]Event{event})
	refreshed := rollup.Input()
	if reflect.DeepEqual(initial.Relationships, refreshed.Relationships) || len(refreshed.Relationships) != 1 {
		t.Fatalf("near-expiry activity did not refresh edge lease: %#v", refreshed.Relationships)
	}
	if got := refreshed.Relationships[0].Properties["telemetry/lease-expires-at"]; got != observedAt.Add(106*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("refreshed expiry = %q", got)
	}

	rollup.Advance(observedAt.Add(107 * time.Minute))
	expired := rollup.Input()
	if len(expired.Relationships) != 0 {
		t.Fatalf("expired relationships = %#v", expired.Relationships)
	}
}

func TestRollupCommunicationEdgeLeaseIsBatchPartitionIndependent(t *testing.T) {
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	object := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "service/b"}
	observedAt := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	events := []Event{
		{EventID: "flow-1", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow", Subject: subject, Object: object, ObservedAt: observedAt, Count: 1, EvidenceIDs: []string{"evidence-1"}},
		{EventID: "flow-2", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow", Subject: subject, Object: object, ObservedAt: observedAt.Add(30 * time.Minute), Count: 1, EvidenceIDs: []string{"evidence-2"}},
	}
	config := RollupConfig{Window: time.Minute, Retention: time.Hour, EdgeRefreshBefore: 15 * time.Minute, MaxSeries: 10}
	batched := NewRollup(config)
	batched.ObserveBatch(events)
	partitioned := NewRollup(config)
	partitioned.ObserveBatch(events[:1])
	partitioned.ObserveBatch(events[1:])
	if !reflect.DeepEqual(batched.Input().Relationships, partitioned.Input().Relationships) {
		t.Fatalf("edge lease changed with batch partitioning: batched=%#v partitioned=%#v", batched.Input().Relationships, partitioned.Input().Relationships)
	}
	if !batched.Advance(observedAt.Add(45*time.Minute)) || !partitioned.Advance(observedAt.Add(45*time.Minute)) {
		t.Fatal("pending edge observation did not refresh at the lease horizon")
	}
	if !reflect.DeepEqual(batched.Input().Relationships, partitioned.Input().Relationships) {
		t.Fatalf("refreshed edge lease changed with batch partitioning: batched=%#v partitioned=%#v", batched.Input().Relationships, partitioned.Input().Relationships)
	}
}

func TestRollupRestorePreservesPublishedState(t *testing.T) {
	config := RollupConfig{Window: time.Minute, Retention: time.Hour, EdgeRefreshBefore: 15 * time.Minute, MaxSeries: 10}
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	object, err := graph.NetworkPeerClassClaim("network-a", "external-destination")
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	events := []Event{
		{EventID: "flow-1", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow", Subject: subject, Object: object, ObservedAt: observedAt, Count: 1, EvidenceIDs: []string{"evidence-1"}},
		{EventID: "flow-2", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow", Subject: subject, Object: object, ObservedAt: observedAt.Add(46 * time.Minute), Count: 1, EvidenceIDs: []string{"evidence-2"}},
	}
	original := NewRollup(config)
	original.ObserveBatch(events)
	input := original.Input()
	input.Resources = append(input.Resources,
		graph.ResourceAssertion{Claim: subject, Kind: "test/workload", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory"},
	)
	registry := graph.NewRegistry()
	if err := registry.Register(graph.TrimmedIdentityScheme(testIdentityScheme)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewRollup(config)
	if err := restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	before := original.Input()
	after := restored.Input()
	if !reflect.DeepEqual(before.Resources, after.Resources) || !reflect.DeepEqual(before.Relationships, after.Relationships) || !reflect.DeepEqual(before.Telemetry, after.Telemetry) {
		t.Fatalf("restored rollup differs: before=%#v after=%#v", before, after)
	}
	events[1].EventID = "flow-3"
	events[1].ObservedAt = observedAt.Add(50 * time.Minute)
	original.ObserveBatch(events[1:])
	restored.ObserveBatch(events[1:])
	if !reflect.DeepEqual(original.Input(), restored.Input()) {
		t.Fatal("restored rollup diverged after new observation")
	}
}

func TestRollupProcessExecProjectsProcessClassAndExecutesLease(t *testing.T) {
	config := RollupConfig{Window: time.Minute, Retention: time.Hour, EdgeRefreshBefore: 15 * time.Minute, MaxSeries: 10}
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	shell, err := graph.ProcessClassClaim("cluster-a", graph.ProcessClassShell)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	original := NewRollup(config)
	original.ObserveBatch([]Event{{
		EventID: "falco-1", PluginID: "falco", SourceID: "cluster-a/falco", Kind: EventKindProcessExec, Subject: subject, Object: shell,
		Operation: "spawn-shell", Outcome: "observed", ObservedAt: observedAt, Count: 1, EvidenceIDs: []string{"falco-1"},
	}})
	input := original.Input()
	if len(input.Relationships) != 1 || input.Relationships[0].Predicate != graph.PredicateExecutes ||
		input.Relationships[0].Subject != subject || input.Relationships[0].Object != shell ||
		input.Relationships[0].RuleID != "telemetry.process-execution-lease" || input.Relationships[0].PluginID != "falco" ||
		input.Relationships[0].Properties["telemetry/lease-expires-at"] != observedAt.Add(time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("process execution lease = %#v", input.Relationships)
	}
	if len(input.Telemetry) != 1 || input.Telemetry[0].Kind != EventKindProcessExec {
		t.Fatalf("process execution rollup = %#v", input.Telemetry)
	}
	if len(input.Resources) != 1 || input.Resources[0].Claim != shell || input.Resources[0].Kind != "process/class" ||
		input.Resources[0].RuleID != "telemetry.process-class" || input.Resources[0].PluginID != "falco" ||
		!reflect.DeepEqual(input.Resources[0].EvidenceIDs, []string{"falco-1"}) {
		t.Fatalf("process class resource = %#v", input.Resources)
	}

	compiledInput := original.Input()
	compiledInput.Resources = append(compiledInput.Resources,
		graph.ResourceAssertion{Claim: subject, Kind: "test/workload", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory", EvidenceIDs: []string{"inventory"}},
	)
	registry := graph.NewRegistry()
	if err := registry.Register(graph.TrimmedIdentityScheme(testIdentityScheme)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(compiledInput)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewRollup(config)
	if err := restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original.Input(), restored.Input()) {
		t.Fatalf("restored process rollup differs: before=%#v after=%#v", original.Input(), restored.Input())
	}

	if !original.Advance(observedAt.Add(2 * time.Hour)) {
		t.Fatal("expired process series did not report a change")
	}
	if expired := original.Input(); len(expired.Resources) != 0 || len(expired.Telemetry) != 0 || len(expired.Relationships) != 0 {
		t.Fatalf("expired process rollup retained output: %#v", expired)
	}
}

func TestRollupRestorePreservesUnresolvedLeaseUntilExpiry(t *testing.T) {
	config := RollupConfig{Window: time.Minute, Retention: time.Hour, EdgeRefreshBefore: 15 * time.Minute, MaxSeries: 10}
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	object := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "service/b"}
	expiresAt := time.Date(2026, time.October, 6, 13, 0, 0, 0, time.UTC)
	registry := graph.NewRegistry()
	if err := registry.Register(graph.TrimmedIdentityScheme(testIdentityScheme)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(graph.Input{Relationships: []graph.RelationshipAssertion{{
		Subject: subject, Predicate: graph.PredicateCommunicates, Object: object, Qualifier: "telemetry-observed",
		Properties: map[string]string{
			"telemetry/lease-expires-at":   expiresAt.Format(time.RFC3339Nano),
			"telemetry/provider-plugin-id": "cilium", "telemetry/provider-source-id": "cluster-a/hubble",
		},
		PluginID: "cilium", SourceID: "cluster-a/hubble", RuleID: "telemetry.communication-edge-lease",
		EvidenceIDs: []string{"evidence-1"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	restored := NewRollup(config)
	if err := restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	if len(restored.Input().Relationships) != 1 || restored.Advance(expiresAt.Add(-time.Nanosecond)) {
		t.Fatal("unresolved edge changed before expiry")
	}
	if !restored.Advance(expiresAt.Add(time.Nanosecond)) || len(restored.Input().Relationships) != 0 {
		t.Fatal("unresolved edge did not expire")
	}
}

func TestRollupRestorePreservesMultipleProviderEdges(t *testing.T) {
	config := RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 10}
	subject := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	object := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "service/b"}
	observedAt := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	original := NewRollup(config)
	original.ObserveBatch([]Event{
		{EventID: "cilium-flow", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow", Subject: subject, Object: object, ObservedAt: observedAt, Count: 1},
		{EventID: "istio-flow", PluginID: "istio", SourceID: "cluster-a/access-log", Kind: "network-flow", Subject: subject, Object: object, ObservedAt: observedAt, Count: 1},
	})
	input := original.Input()
	input.Resources = []graph.ResourceAssertion{
		{Claim: subject, Kind: "test/workload", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory"},
		{Claim: object, Kind: "test/service", PluginID: "inventory", SourceID: "runtime", RuleID: "inventory"},
	}
	registry := graph.NewRegistry()
	if err := registry.Register(graph.TrimmedIdentityScheme(testIdentityScheme)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewRollup(config)
	if err := restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	before := original.Input()
	after := restored.Input()
	if len(after.Relationships) != 2 || !reflect.DeepEqual(before.Relationships, after.Relationships) || !reflect.DeepEqual(before.Telemetry, after.Telemetry) {
		t.Fatalf("multiple provider edges changed during restore: before=%#v after=%#v", before, after)
	}
}

type retrySink struct {
	mu       sync.Mutex
	failures int
	attempts int
	written  chan []Event
}

func (sink *retrySink) WriteBatch(_ context.Context, events []Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.attempts++
	if sink.attempts <= sink.failures {
		return errors.New("retry")
	}
	sink.written <- slices.Clone(events)
	return nil
}

func TestWriteWithRetryLogsFirstFailureAndRecoveryWithoutEventContent(t *testing.T) {
	var output strings.Builder
	sink := &retrySink{failures: 5, written: make(chan []Event, 1)}
	pipeline, err := NewPipeline(PipelineConfig{
		RetryMinimum: time.Microsecond, RetryMaximum: time.Microsecond,
		Logger: slog.New(slog.NewTextHandler(&output, nil)),
	}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "source", ImmutableKey: "resource"}
	events := []Event{{EventID: "event-private-id", PluginID: "test", SourceID: "test", Kind: "request", Subject: claim, Object: claim, Properties: map[string]string{"path": "/private-value"}}}
	if err := pipeline.writeWithRetry(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	logs := output.String()
	if strings.Count(logs, "telemetry sink write failed") != 1 || !strings.Contains(logs, "attempt=1 events=1") {
		t.Fatalf("failure logs = %q", logs)
	}
	if strings.Count(logs, "succeeded after retries") != 1 || !strings.Contains(logs, "attempts=6 events=1") {
		t.Fatalf("recovery logs = %q", logs)
	}
	if strings.Contains(logs, "private-value") || strings.Contains(logs, "event-private-id") {
		t.Fatalf("logs include event content: %q", logs)
	}
}
