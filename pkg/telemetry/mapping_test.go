package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestMappingRegistryAssignsTrustedOwnership(t *testing.T) {
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	registry, err := NewMappingRegistry(Mapping{
		PluginID: "cilium", SourceID: "cluster-a/hubble",
		Mapper: MapperFuncs{
			MatchFunc: func(record LogRecord) bool {
				value, _ := record.ResourceAttribute("service.name")
				return value == "hubble"
			},
			MapFunc: func(_ context.Context, _ LogRecord) ([]Event, error) {
				return []Event{{EventID: "flow-1", PluginID: "untrusted", Kind: "network-flow", Subject: claim, Object: claim, SourceID: "untrusted"}}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	events, err := registry.Map(context.Background(), LogRecord{Timestamp: observedAt, ResourceAttributes: map[string]any{"service.name": "hubble"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].PluginID != "cilium" || events[0].SourceID != "cluster-a/hubble" {
		t.Fatalf("unexpected mapped ownership: %#v", events)
	}
	if events[0].Count != 1 || len(events[0].EvidenceIDs) != 1 || events[0].EvidenceIDs[0] != "flow-1" {
		t.Fatalf("mapped event was not normalized: %#v", events[0])
	}
	if !events[0].ObservedAt.Equal(observedAt) {
		t.Fatalf("observed time = %s, want %s", events[0].ObservedAt, observedAt)
	}
}

func TestMappingRegistryRejectsMissingAndAmbiguousRoutes(t *testing.T) {
	never := MapperFuncs{MatchFunc: func(LogRecord) bool { return false }}
	registry, err := NewMappingRegistry(Mapping{PluginID: "one", SourceID: "source", Mapper: never})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Map(context.Background(), LogRecord{}); !errors.Is(err, ErrNoTelemetryMapper) {
		t.Fatalf("missing route error = %v", err)
	}
	always := MapperFuncs{MatchFunc: func(LogRecord) bool { return true }}
	registry, err = NewMappingRegistry(
		Mapping{PluginID: "one", SourceID: "source", Mapper: always},
		Mapping{PluginID: "two", SourceID: "source", Mapper: always},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Map(context.Background(), LogRecord{}); !errors.Is(err, ErrAmbiguousTelemetryMapper) {
		t.Fatalf("ambiguous route error = %v", err)
	}
}

func TestMappingRegistryRejectsHiddenRollupDimensions(t *testing.T) {
	claim := graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "cluster-a", ImmutableKey: "pod/a"}
	registry, err := NewMappingRegistry(Mapping{PluginID: "test", SourceID: "source", Mapper: MapperFuncs{
		MatchFunc: func(LogRecord) bool { return true },
		MapFunc: func(context.Context, LogRecord) ([]Event, error) {
			return []Event{{
				EventID: "event", Kind: "request", Subject: claim, Object: claim,
				Properties: map[string]string{"method": "GET"}, RollupProperties: map[string]string{"method": "POST"},
			}}, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Map(context.Background(), LogRecord{Timestamp: time.Now()}); err == nil {
		t.Fatal("rollup dimension absent from the raw event was accepted")
	}
}
