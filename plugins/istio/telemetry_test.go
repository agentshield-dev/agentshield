package istio

import (
	"context"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

func TestActiveProbeOTLPMappingPreservesGraphProvenance(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster-a", SourceID: "evals/cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := telemetry.NewMappingRegistry(plugin.TelemetryMappings()...)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	events, err := registry.Map(context.Background(), ActiveProbeLogRecord(ActiveProbeObservation{
		EventID: "active-probe:05-allowed-traffic:test.tsv", ObservedAt: observedAt,
		SubjectAPIVersion: "apps/v1", SubjectKind: "Deployment", SubjectUID: "source-uid",
		ObjectAPIVersion: "v1", ObjectKind: "Service", ObjectUID: "target-uid",
		Operation: "GET /allowed", Outcome: "allowed", Coverage: "ambient-waypoint", Count: 3, HTTPStatuses: "200", Result: "pass",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	event := events[0]
	if event.PluginID != PluginID || event.SourceID != "evals/cluster-a" || event.EventID != "active-probe:05-allowed-traffic:test.tsv" {
		t.Fatalf("unexpected provenance: %#v", event)
	}
	if event.Subject.ImmutableKey != "apps/v1/deployment/source-uid" || event.Object.ImmutableKey != "v1/service/target-uid" {
		t.Fatalf("unexpected endpoints: subject=%#v object=%#v", event.Subject, event.Object)
	}
	if event.Count != 3 || event.Operation != "GET /allowed" || event.Outcome != "allowed" || event.Coverage != "ambient-waypoint" {
		t.Fatalf("unexpected event semantics: %#v", event)
	}
	if event.Properties["probe/http-statuses"] != "200" || event.Properties["probe/result"] != "pass" || len(event.EvidenceIDs) != 1 || event.EvidenceIDs[0] != event.EventID {
		t.Fatalf("unexpected event evidence: %#v", event)
	}
}

func TestActiveProbeOTLPMappingDerivesEnvoyAccessLogSemantics(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster-a", SourceID: "evals/cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := telemetry.NewMappingRegistry(plugin.TelemetryMappings()...)
	if err != nil {
		t.Fatal(err)
	}
	events, err := registry.Map(context.Background(), telemetry.LogRecord{
		Timestamp: time.Unix(10, 0).UTC(),
		Attributes: map[string]any{
			activeProbeKindAttribute: "active-probe", activeProbeEventIDAttribute: "probe-1",
			activeProbeSubjectAPIVersionAttribute: "apps/v1", activeProbeSubjectKindAttribute: "Deployment", activeProbeSubjectUIDAttribute: "source-uid",
			activeProbeObjectAPIVersionAttribute: "v1", activeProbeObjectKindAttribute: "Service", activeProbeObjectUIDAttribute: "target-uid",
			activeProbeOperationAttribute: "GET /deny", activeProbeCoverageAttribute: "ambient-waypoint",
			activeProbeStatusesAttribute: int64(403), activeProbeExpectedStatusAttribute: "403",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Count != 1 || events[0].Outcome != "denied" || events[0].Properties["probe/http-statuses"] != "403" || events[0].Properties["probe/result"] != "pass" {
		t.Fatalf("unexpected Envoy event: %#v", events)
	}
}

func TestActiveProbeOTLPMappingResolvesWaypointPeerMetadataToUIDs(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster-a", SourceID: "evals/cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	objects := testObserved(
		testObject("apps/v1", "Deployment", "client", "client", "source-uid", nil),
		testObject("v1", "Service", "echo", "echo", "target-uid", nil),
	)
	cache := make(map[string]ObservedObject, len(objects))
	for _, object := range objects {
		cache[object.Key] = object
	}
	plugin.resolver.Replace(cache)

	registry, err := telemetry.NewMappingRegistry(plugin.TelemetryMappings()...)
	if err != nil {
		t.Fatal(err)
	}
	events, err := registry.Map(context.Background(), telemetry.LogRecord{Timestamp: time.Unix(10, 0).UTC(), Attributes: map[string]any{
		activeProbeKindAttribute: "active-probe", activeProbeEventIDAttribute: "probe-1",
		activeProbeSubjectAPIVersionAttribute: "apps/v1", activeProbeSubjectKindAttribute: "Deployment", activeProbeSubjectUIDAttribute: "-",
		activeProbeSubjectNamespaceAttribute: "client", activeProbeSubjectNameAttribute: "client",
		activeProbeObjectAPIVersionAttribute: "v1", activeProbeObjectKindAttribute: "Service", activeProbeObjectUIDAttribute: "-",
		activeProbeObjectNamespaceAttribute: "echo", activeProbeObjectNameAttribute: "echo",
		activeProbeOperationAttribute: "GET /", activeProbeCoverageAttribute: "ambient-waypoint", activeProbeStatusesAttribute: int64(200),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Subject.ImmutableKey != "apps/v1/deployment/source-uid" || events[0].Object.ImmutableKey != "v1/service/target-uid" {
		t.Fatalf("unexpected resolved endpoints: %#v", events)
	}
	if events[0].Properties["probe/result"] != "observed" {
		t.Fatalf("unexpected live result: %#v", events[0].Properties)
	}
}

func TestActiveProbeOTLPMappingResolvesServiceAuthorityFallback(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster-a", SourceID: "evals/cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	objects := testObserved(
		testObject("apps/v1", "Deployment", "client", "client", "source-uid", nil),
		testObject("v1", "Service", "echo", "echo", "target-uid", nil),
	)
	cache := make(map[string]ObservedObject, len(objects))
	for _, object := range objects {
		cache[object.Key] = object
	}
	plugin.resolver.Replace(cache)
	registry, err := telemetry.NewMappingRegistry(plugin.TelemetryMappings()...)
	if err != nil {
		t.Fatal(err)
	}
	events, err := registry.Map(context.Background(), telemetry.LogRecord{Timestamp: time.Unix(10, 0).UTC(), Attributes: map[string]any{
		activeProbeKindAttribute: "active-probe", activeProbeEventIDAttribute: "probe-1",
		activeProbeSubjectAPIVersionAttribute: "apps/v1", activeProbeSubjectKindAttribute: "Deployment",
		activeProbeSubjectNamespaceAttribute: "client", activeProbeSubjectNameAttribute: "client",
		activeProbeObjectAPIVersionAttribute: "v1", activeProbeObjectKindAttribute: "Service",
		activeProbeObjectNamespaceAttribute: "-", activeProbeObjectNameAttribute: "-",
		activeProbeObjectAuthorityAttribute: "echo.echo.svc.cluster.local:8080",
		activeProbeOperationAttribute:       "GET /", activeProbeCoverageAttribute: "ambient-waypoint",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Object.ImmutableKey != "v1/service/target-uid" {
		t.Fatalf("unexpected authority-resolved endpoint: %#v", events)
	}
}
