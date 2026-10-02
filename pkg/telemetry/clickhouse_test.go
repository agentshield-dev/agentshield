package telemetry

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestClickHouseSinkWritesPluginOwnership(t *testing.T) {
	var row clickHouseRow
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		reader, err := gzip.NewReader(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = reader.Close() }()
		if err := json.NewDecoder(reader).Decode(&row); err != nil {
			t.Fatal(err)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	sink, err := NewClickHouseSink(ClickHouseConfig{Endpoint: server.URL, Database: "agentshield", Table: "telemetry_events"})
	if err != nil {
		t.Fatal(err)
	}
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	if err := sink.WriteBatch(context.Background(), []Event{{
		EventID: "flow-1", PluginID: "cilium", SourceID: "cluster-a/hubble", Kind: "network-flow", Subject: claim, Object: claim,
	}}); err != nil {
		t.Fatal(err)
	}
	if row.PluginID != "cilium" || row.SourceID != "cluster-a/hubble" {
		t.Fatalf("unexpected ClickHouse ownership: %#v", row)
	}
}

func TestClickHouseStatusErrorOmitsBodyFromLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-ClickHouse-Exception-Code", "117")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`Cannot parse input: {"properties":{"path":"/private-value"}}`))
	}))
	defer server.Close()
	sink, err := NewClickHouseSink(ClickHouseConfig{Endpoint: server.URL, Database: "agentshield", Table: "telemetry_events"})
	if err != nil {
		t.Fatal(err)
	}
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	writeErr := sink.WriteBatch(context.Background(), []Event{{EventID: "flow-1", Kind: "network-flow", Subject: claim, Object: claim}})
	if writeErr == nil || !strings.Contains(writeErr.Error(), "status 400") || !strings.Contains(writeErr.Error(), "private-value") {
		t.Fatalf("WriteBatch error = %v", writeErr)
	}
	var output strings.Builder
	slog.New(slog.NewTextHandler(&output, nil)).Warn("sink failed", "error", writeErr)
	if logs := output.String(); strings.Contains(logs, "private-value") || !strings.Contains(logs, "status 400, exception code 117") {
		t.Fatalf("logged error = %q", logs)
	}
}
