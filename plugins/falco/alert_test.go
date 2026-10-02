package falco

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

const shellAlert = `{"hostname":"node-a","output":"Notice A shell was spawned in a container with an attached terminal","output_fields":{"container.id":"0123456789ab","evt.time":1760529600123456789,"k8s.ns.name":"default","k8s.pod.name":"web-7d4b9","k8s.pod.uid":"6F1C2A3B-0000-4000-8000-000000000001","proc.cmdline":"bash -c secret"},"priority":"Notice","rule":"Terminal shell in container","source":"syscall","tags":["container","shell"],"time":"2025-10-15T12:00:00.123456789Z"}`

func falcoRecord(body any) telemetry.LogRecord {
	return telemetry.LogRecord{
		Body: body, ResourceAttributes: map[string]any{"service.name": ServiceName},
		ObservedTimestamp: time.Date(2026, time.October, 15, 13, 0, 0, 0, time.UTC),
	}
}

func testRegistry(t *testing.T) *telemetry.MappingRegistry {
	t.Helper()
	plugin, err := New(Config{ClusterID: "cluster-a", SourceID: "cluster-a/falco"})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := telemetry.NewMappingRegistry(plugin.TelemetryMappings()...)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestShellAlertMapsPodToShellProcessClass(t *testing.T) {
	events, err := testRegistry(t).Map(context.Background(), falcoRecord(shellAlert))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %#v", events)
	}
	event := events[0]
	shell, err := graph.ProcessClassClaim("cluster-a", graph.ProcessClassShell)
	if err != nil {
		t.Fatal(err)
	}
	if event.PluginID != PluginID || event.SourceID != "cluster-a/falco" || event.Kind != telemetry.EventKindProcessExec ||
		event.Subject != kubernetesplugin.ClaimForUID("cluster-a", "v1", "Pod", "6f1c2a3b-0000-4000-8000-000000000001") || event.Object != shell ||
		event.Operation != OperationSpawnShell || event.Outcome != OutcomeObserved || event.Coverage != Coverage || event.Count != 1 {
		t.Fatalf("unexpected event: %#v", event)
	}
	if want := time.Date(2025, time.October, 15, 12, 0, 0, 123456789, time.UTC); !event.ObservedAt.Equal(want) {
		t.Fatalf("observedAt = %s, want original Falco time %s", event.ObservedAt, want)
	}
	if !strings.HasPrefix(event.EventID, "falco/") || len(event.EvidenceIDs) != 1 || event.EvidenceIDs[0] != event.EventID {
		t.Fatalf("event ID = %q evidence = %#v", event.EventID, event.EvidenceIDs)
	}
	wantProperties := map[string]string{"falco/rule": DefaultShellRule, "falco/priority": "Notice", "container-id": "0123456789ab"}
	if len(event.Properties) != len(wantProperties) || len(event.RollupProperties) != 0 {
		t.Fatalf("properties = %#v rollup = %#v", event.Properties, event.RollupProperties)
	}
	for key, value := range wantProperties {
		if event.Properties[key] != value {
			t.Fatalf("properties = %#v, want %#v", event.Properties, wantProperties)
		}
	}
}

func TestShellAlertEventIDIsStableAcrossRetryAndBodyEncoding(t *testing.T) {
	registry := testRegistry(t)
	first, err := registry.Map(context.Background(), falcoRecord(shellAlert))
	if err != nil {
		t.Fatal(err)
	}
	retry := falcoRecord(shellAlert)
	retry.ObservedTimestamp = retry.ObservedTimestamp.Add(time.Hour)
	retried, err := registry.Map(context.Background(), retry)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(shellAlert))
	decoder.UseNumber()
	var parsed map[string]any
	if err := decoder.Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	fromMap, err := registry.Map(context.Background(), falcoRecord(parsed))
	if err != nil {
		t.Fatal(err)
	}
	if first[0].EventID != retried[0].EventID || first[0].EventID != fromMap[0].EventID || !first[0].ObservedAt.Equal(retried[0].ObservedAt) {
		t.Fatalf("event IDs differ: string=%s retry=%s map=%s", first[0].EventID, retried[0].EventID, fromMap[0].EventID)
	}
	other := strings.Replace(shellAlert, `"evt.time":1760529600123456789`, `"evt.time":1760529600123456790`, 1)
	distinct, err := registry.Map(context.Background(), falcoRecord(other))
	if err != nil {
		t.Fatal(err)
	}
	if distinct[0].EventID == first[0].EventID {
		t.Fatal("distinct Falco alerts share an event ID")
	}
}

func TestMapperMatchesOnlyFalcoService(t *testing.T) {
	record := falcoRecord(shellAlert)
	record.ResourceAttributes["service.name"] = "falcosidekick"
	if _, err := testRegistry(t).Map(context.Background(), record); err == nil {
		t.Fatal("non-Falco service matched the Falco mapper")
	}
}

func TestMapperRejectsUnsupportedAlerts(t *testing.T) {
	for _, test := range []struct {
		name string
		body any
	}{
		{name: "empty source", body: strings.Replace(shellAlert, `"source":"syscall"`, `"source":""`, 1)},
		{name: "non-syscall shell alert", body: strings.Replace(shellAlert, `"source":"syscall"`, `"source":"k8s_audit"`, 1)},
		{name: "missing pod UID", body: strings.Replace(shellAlert, `"6F1C2A3B-0000-4000-8000-000000000001"`, `"<NA>"`, 1)},
		{name: "missing time", body: strings.Replace(shellAlert, `"time":"2025-10-15T12:00:00.123456789Z"`, `"time":""`, 1)},
		{name: "plain text output", body: "12:00:00.000000000: Notice A shell was spawned"},
		{name: "trailing data", body: shellAlert + `{}`},
		{name: "array", body: `[]`},
		{name: "unsupported body type", body: int64(1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := testRegistry(t).Map(context.Background(), falcoRecord(test.body)); err == nil {
				t.Fatal("unsupported Falco alert was accepted")
			}
		})
	}
}

func TestMapperSkipsAlertsFromOtherRulesWithoutRejection(t *testing.T) {
	for _, body := range []string{
		strings.Replace(shellAlert, DefaultShellRule, "Read sensitive file untrusted", 1),
		strings.Replace(strings.Replace(shellAlert, DefaultShellRule, "Audit rule", 1), `"source":"syscall"`, `"source":"k8s_audit"`, 1),
	} {
		events, err := testRegistry(t).Map(context.Background(), falcoRecord(body))
		if err != nil || len(events) != 0 {
			t.Fatalf("unmapped Falco rule = %d events, %v; want skipped without error", len(events), err)
		}
	}
}

func TestMapperErrorsDoNotEchoRuleOrSource(t *testing.T) {
	body := strings.Replace(shellAlert, `"source":"syscall"`, `"source":"private-source"`, 1)
	_, err := testRegistry(t).Map(context.Background(), falcoRecord(body))
	if err == nil || strings.Contains(err.Error(), "private-source") || strings.Contains(err.Error(), DefaultShellRule) {
		t.Fatalf("error = %v", err)
	}
}

func TestMapperErrorsDoNotExposeAlertPayload(t *testing.T) {
	body := strings.Replace(shellAlert, `"k8s.pod.uid":"6F1C2A3B-0000-4000-8000-000000000001"`, `"k8s.pod.uid":""`, 1)
	_, err := testRegistry(t).Map(context.Background(), falcoRecord(body))
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "web-7d4b9") {
		t.Fatalf("error = %v", err)
	}
}

func TestConfiguredShellRulesReplaceDefault(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster-a", SourceID: "cluster-a/falco", ShellRules: []string{" Custom shell ", "Custom shell", ""}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := telemetry.NewMappingRegistry(plugin.TelemetryMappings()...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Map(context.Background(), falcoRecord(strings.Replace(shellAlert, DefaultShellRule, "Custom shell", 1))); err != nil {
		t.Fatal(err)
	}
	if events, err := registry.Map(context.Background(), falcoRecord(shellAlert)); err != nil || len(events) != 0 {
		t.Fatalf("default rule after configuring shell rules = %d events, %v; want skipped", len(events), err)
	}
	if _, err := New(Config{ClusterID: "cluster-a"}); err == nil {
		t.Fatal("plugin without a source ID was accepted")
	}
}
