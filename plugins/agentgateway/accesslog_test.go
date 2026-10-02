package agentgateway

import (
	"context"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

func TestNormalizeAccessLogStableIdentity(t *testing.T) {
	record := accessLogRecord{
		RequestID: "request-1", ObservedAt: time.Unix(10, 0), ClientIP: "198.51.100.42",
		BackendUID: "ABC", Method: "post", Route: "/api/models/{repo}", Operation: "repository-write",
		ResponseCode: 202, Authenticated: true,
	}
	first, err := normalizeAccessLog(accessLogConfig{ClusterID: "cluster", NetworkID: "network", SourceID: "gateway"}, record)
	if err != nil {
		t.Fatal(err)
	}
	second, err := normalizeAccessLog(accessLogConfig{ClusterID: "cluster", NetworkID: "network", SourceID: "gateway"}, record)
	if err != nil {
		t.Fatal(err)
	}
	if first.EventID != second.EventID || first.EventID != "agentgateway:gateway:request-1" {
		t.Fatalf("unstable event IDs: %q and %q", first.EventID, second.EventID)
	}
	if first.Operation != "authenticated/repository-write" || first.Outcome != "allowed" || first.Properties["authenticated"] != "true" || first.Object.ImmutableKey != "v1/pod/abc" {
		t.Fatalf("normalized event = %#v", first)
	}
}

func TestNormalizeAccessLogRejectsIncompleteRecord(t *testing.T) {
	_, err := normalizeAccessLog(accessLogConfig{ClusterID: "cluster", SourceID: "gateway"}, accessLogRecord{})
	if err == nil {
		t.Fatal("expected incomplete access log to fail")
	}
}

type discardSink struct{}

func (discardSink) WriteBatch(context.Context, []telemetry.Event) error { return nil }

func TestIngestAccessLogValidatesBeforeEnqueue(t *testing.T) {
	config := accessLogConfig{ClusterID: "cluster", SourceID: "gateway"}
	record := accessLogRecord{RequestID: "request-1", ObservedAt: time.Unix(10, 0), ClientIP: "198.51.100.42", BackendUID: "abc", Method: "get", Operation: "read", ResponseCode: 200}
	if err := ingestAccessLog(context.Background(), nil, config, record); err == nil {
		t.Fatal("ingest without a pipeline succeeded")
	}
	pipeline, err := telemetry.NewPipeline(telemetry.PipelineConfig{QueueCapacity: 1, MaxBatch: 1}, discardSink{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ingestAccessLog(context.Background(), pipeline, config, accessLogRecord{}); err == nil {
		t.Fatal("ingest of an incomplete record succeeded")
	}
	if err := ingestAccessLog(context.Background(), pipeline, config, record); err != nil {
		t.Fatal(err)
	}
}
