package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	collectorlogsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestOTLPReceiverRoutesRawLogThroughPluginMapper(t *testing.T) {
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	registry, err := NewMappingRegistry(Mapping{
		PluginID: "cilium", SourceID: "cluster-a/hubble",
		Mapper: MapperFuncs{
			MatchFunc: func(record LogRecord) bool {
				service, _ := record.ResourceAttribute("service.name")
				return service == "hubble"
			},
			MapFunc: func(_ context.Context, record LogRecord) ([]Event, error) {
				body := record.Body.(map[string]any)
				return []Event{{EventID: body["flow_id"].(string), Kind: "network-flow", Subject: claim, Object: claim}}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ingestor := &recordingEventIngestor{}
	receiver, err := NewOTLPReceiver(OTLPReceiverConfig{}, registry, ingestor)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := proto.Marshal(&collectorlogsv1.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{
		Resource: &resourcev1.Resource{Attributes: []*commonv1.KeyValue{{Key: "service.name", Value: stringValue("hubble")}}},
		ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: []*logsv1.LogRecord{{
			TimeUnixNano: 1_791_194_400_000_000_000,
			Body:         &commonv1.AnyValue{Value: &commonv1.AnyValue_KvlistValue{KvlistValue: &commonv1.KeyValueList{Values: []*commonv1.KeyValue{{Key: "flow_id", Value: stringValue("flow-1")}}}}},
		}}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-protobuf")
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	if len(ingestor.events) != 1 || ingestor.events[0].EventID != "flow-1" || ingestor.events[0].PluginID != "cilium" || ingestor.events[0].SourceID != "cluster-a/hubble" {
		t.Fatalf("unexpected ingested events: %#v", ingestor.events)
	}
}

func TestOTLPReceiverReportsUnmappedRecordAsPartialSuccess(t *testing.T) {
	registry, err := NewMappingRegistry(Mapping{PluginID: "cilium", SourceID: "cluster-a/hubble", Mapper: MapperFuncs{MatchFunc: func(LogRecord) bool { return false }}})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewOTLPReceiver(OTLPReceiverConfig{}, registry, &recordingEventIngestor{})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := proto.Marshal(&collectorlogsv1.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: []*logsv1.LogRecord{{}}}}}}})
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-protobuf")
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", response.Code, response.Body.String())
	}
	var exportResponse collectorlogsv1.ExportLogsServiceResponse
	if err := proto.Unmarshal(response.Body.Bytes(), &exportResponse); err != nil {
		t.Fatal(err)
	}
	if exportResponse.GetPartialSuccess().GetRejectedLogRecords() != 1 {
		t.Fatalf("unexpected partial success: %#v", exportResponse.PartialSuccess)
	}
}

func TestOTLPReceiverLogsBoundedRejectionSummaries(t *testing.T) {
	registry, err := NewMappingRegistry(Mapping{PluginID: "falco", SourceID: "cluster-a/falco", Mapper: MapperFuncs{
		MatchFunc: func(record LogRecord) bool {
			service, _ := record.ResourceAttribute("service.name")
			return service == "falco"
		},
		MapFunc: func(_ context.Context, record LogRecord) ([]Event, error) {
			return nil, fmt.Errorf("Falco rule %q is not mapped", record.Body)
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	receiver, err := NewOTLPReceiver(OTLPReceiverConfig{Logger: slog.New(slog.NewJSONHandler(&output, nil))}, registry, &recordingEventIngestor{})
	if err != nil {
		t.Fatal(err)
	}
	records := func(bodies ...string) []*logsv1.LogRecord {
		result := make([]*logsv1.LogRecord, 0, len(bodies))
		for _, body := range bodies {
			result = append(result, &logsv1.LogRecord{Body: stringValue(body)})
		}
		return result
	}
	falcoBodies := []string{"Drop and execute new binary in container", "Drop and execute new binary in container", strings.Repeat("x", 400)}
	for index := range maxLoggedRejectionReasons {
		falcoBodies = append(falcoBodies, fmt.Sprintf("rule-%02d", index))
	}
	payload, _ := proto.Marshal(&collectorlogsv1.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{
		{
			Resource:  &resourcev1.Resource{Attributes: []*commonv1.KeyValue{{Key: "service.name", Value: stringValue("falco")}}},
			ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: records(falcoBodies...)}},
		},
		{
			Resource:  &resourcev1.Resource{Attributes: []*commonv1.KeyValue{{Key: "service.name", Value: stringValue("unknown-producer")}}},
			ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: records("a", "b")}},
		},
	}})
	request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-protobuf")
	receiver.ServeHTTP(httptest.NewRecorder(), request)

	type line struct {
		Level       string `json:"level"`
		Message     string `json:"msg"`
		Count       int64  `json:"count"`
		Reason      string `json:"reason"`
		Plugin      string `json:"plugin"`
		Source      string `json:"source"`
		ServiceName string `json:"service_name"`
	}
	var lines []line
	var total int64
	for _, encoded := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		var decoded line
		if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
			t.Fatalf("decode log line %q: %v", encoded, err)
		}
		if decoded.Level != "WARN" || decoded.Message != "rejected OTLP log records" || len(decoded.Reason) > maxRejectionReasonBytes {
			t.Fatalf("unexpected log line: %#v", decoded)
		}
		total += decoded.Count
		lines = append(lines, decoded)
	}
	if len(lines) != maxLoggedRejectionReasons+1 || total != int64(len(falcoBodies)+2) {
		t.Fatalf("logged %d lines covering %d records, want %d lines covering %d: %s", len(lines), total, maxLoggedRejectionReasons+1, len(falcoBodies)+2, output.String())
	}
	var sawGrouped, sawUnmatched bool
	for _, logged := range lines {
		if logged.Plugin == "falco" && logged.Source == "cluster-a/falco" && logged.Count == 2 && strings.Contains(logged.Reason, "Drop and execute new binary") {
			sawGrouped = true
		}
		if logged.ServiceName == "unknown-producer" && logged.Count == 2 && logged.Reason == ErrNoTelemetryMapper.Error() && logged.Plugin == "" {
			sawUnmatched = true
		}
	}
	if !sawGrouped || !sawUnmatched || lines[len(lines)-1].Reason != "additional distinct reasons omitted" {
		t.Fatalf("missing grouped, unmatched, or omission summary: %s", output.String())
	}
}

func TestMappingErrorPreservesPluginOwnershipAndCause(t *testing.T) {
	cause := errors.New("cause")
	registry, err := NewMappingRegistry(Mapping{PluginID: "falco", SourceID: "source", Mapper: MapperFuncs{
		MatchFunc: func(LogRecord) bool { return true },
		MapFunc:   func(context.Context, LogRecord) ([]Event, error) { return nil, cause },
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Map(context.Background(), LogRecord{})
	mappingErr, ok := errors.AsType[*MappingError](err)
	if !ok || mappingErr.PluginID != "falco" || mappingErr.SourceID != "source" || !errors.Is(err, cause) ||
		err.Error() != `map telemetry for plugin "falco" source "source": cause` {
		t.Fatalf("mapping error = %#v (%v)", err, err)
	}
}

type recordingEventIngestor struct {
	events []Event
}

func (ingestor *recordingEventIngestor) Ingest(_ context.Context, events ...Event) error {
	ingestor.events = append(ingestor.events, events...)
	return nil
}

func stringValue(value string) *commonv1.AnyValue {
	return &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}}
}
