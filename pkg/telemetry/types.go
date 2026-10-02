package telemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// Per-event bounds. They cap the size of raw rows and of rollup series keys,
// which are built from rollup properties.
const (
	maxPropertyCount = 32
	maxPropertyKey   = 128
	maxPropertyValue = 512
	maxEvidenceIDs   = 32
)

// Event is one normalized telemetry observation from Subject to Object.
//
// EventID must be stable across producer retries, and ObservedAt must be the
// original observation time rather than receipt time; the ClickHouse raw
// table deduplicates on both. Count is the number of source observations the event
// represents; zero is normalized to one. Properties are stored raw.
// RollupProperties selects the subset of Properties that become rollup series
// dimensions; leave out high-cardinality values such as ephemeral ports. It
// is not serialized to the sink.
type Event struct {
	EventID          string              `json:"eventId"`
	PluginID         string              `json:"pluginId,omitempty"`
	ObservedAt       time.Time           `json:"observedAt"`
	Kind             string              `json:"kind"`
	Subject          graph.IdentityClaim `json:"subject"`
	Object           graph.IdentityClaim `json:"object"`
	Operation        string              `json:"operation,omitempty"`
	Outcome          string              `json:"outcome,omitempty"`
	Coverage         string              `json:"coverage,omitempty"`
	Count            uint64              `json:"count,omitempty"`
	Properties       map[string]string   `json:"properties,omitempty"`
	RollupProperties map[string]string   `json:"-"`
	SourceID         string              `json:"sourceId"`
	EvidenceIDs      []string            `json:"evidenceIds,omitempty"`
}

// normalize trims and validates the event in place and applies defaults. It
// is idempotent, so mapping and Ingest can both call it.
func (event *Event) normalize() error {
	event.EventID = strings.TrimSpace(event.EventID)
	event.Kind = strings.TrimSpace(event.Kind)
	event.SourceID = strings.TrimSpace(event.SourceID)
	if event.EventID == "" || event.Kind == "" || event.SourceID == "" {
		return errors.New("telemetry event requires event ID, kind, and source ID")
	}
	if !completeIdentity(event.Subject) || !completeIdentity(event.Object) {
		return errors.New("telemetry event requires complete subject and object identities")
	}
	if event.ObservedAt.IsZero() {
		return errors.New("telemetry event requires an observation timestamp")
	}
	event.ObservedAt = event.ObservedAt.UTC()
	// A zero count represents one source observation; larger values represent pre-aggregated events.
	if event.Count == 0 {
		event.Count = 1
	}
	if len(event.Properties) > maxPropertyCount {
		return fmt.Errorf("telemetry event properties exceed limit of %d", maxPropertyCount)
	}
	for key, value := range event.Properties {
		if strings.TrimSpace(key) == "" || len(key) > maxPropertyKey || len(value) > maxPropertyValue {
			return errors.New("telemetry event property exceeds key or value bounds")
		}
	}
	if len(event.RollupProperties) > maxPropertyCount {
		return fmt.Errorf("telemetry rollup properties exceed limit of %d", maxPropertyCount)
	}
	for key, value := range event.RollupProperties {
		if strings.TrimSpace(key) == "" || len(key) > maxPropertyKey || len(value) > maxPropertyValue || event.Properties[key] != value {
			return errors.New("telemetry rollup property must match a bounded event property")
		}
	}
	// The raw event is its own evidence unless the producer names upstream
	// records.
	if len(event.EvidenceIDs) == 0 {
		event.EvidenceIDs = []string{event.EventID}
	}
	if len(event.EvidenceIDs) > maxEvidenceIDs {
		return fmt.Errorf("telemetry event evidence IDs exceed limit of %d", maxEvidenceIDs)
	}
	return nil
}

func completeIdentity(claim graph.IdentityClaim) bool {
	return claim.Scheme.Group != "" && claim.Scheme.Version != "" && claim.Scheme.Kind != "" && claim.AuthorityID != "" && claim.ImmutableKey != ""
}

// Sink durably stores raw events. WriteBatch must be all-or-nothing from the
// caller's view: on error the pipeline retries the whole batch, so a sink must
// tolerate rewriting events it partially stored. It is never called
// concurrently by Pipeline.
type Sink interface {
	WriteBatch(context.Context, []Event) error
}
