package reasoning

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// IncidentContextSchemaVersion identifies the [IncidentContext] encoding.
const IncidentContextSchemaVersion = "agentshield.ai/incident-context/v1alpha1"

// Bounds on in-memory incident history. When exceeded, the least recently
// observed baselines and the oldest timeline events are dropped first.
const (
	maxIncidentBaselines = 1024
	maxIncidentEvents    = 4096
	maxIncidentSeen      = 8192
)

// IncidentContext is the longitudinal context available to one analysis: a
// behavior baseline of previously observed communication and an ordered
// timeline of telemetry observations, each grouped under one incident ID.
// It is served only through the incident_timeline and behavior_baseline
// retrieval templates, never in the initial packet.
type IncidentContext struct {
	SchemaVersion string             `json:"schemaVersion"`
	IncidentID    string             `json:"incidentId"`
	EvaluationAt  time.Time          `json:"evaluationAt"`
	Baseline      []BehaviorBaseline `json:"baseline"`
	Timeline      []IncidentEvent    `json:"timeline"`
}

// BehaviorBaseline aggregates observations of one (subject, object, kind,
// operation, outcome, coverage) combination. WindowCount is the number of
// observed snapshots that contained it, which separates steady behavior from
// a single burst.
type BehaviorBaseline struct {
	ID               string    `json:"id"`
	SubjectID        string    `json:"subjectId"`
	ObjectID         string    `json:"objectId"`
	Kind             string    `json:"kind"`
	Operation        string    `json:"operation,omitempty"`
	Outcome          string    `json:"outcome,omitempty"`
	Coverage         string    `json:"coverage,omitempty"`
	FirstObservedAt  time.Time `json:"firstObservedAt"`
	LastObservedAt   time.Time `json:"lastObservedAt"`
	ObservationCount uint64    `json:"observationCount"`
	WindowCount      uint64    `json:"windowCount"`
}

// IncidentEvent is one telemetry observation placed on the incident timeline.
// Phase names the evaluation window that first observed it.
type IncidentEvent struct {
	ID          string            `json:"id"`
	Phase       string            `json:"phase"`
	ObservedAt  time.Time         `json:"observedAt"`
	Kind        string            `json:"kind"`
	SubjectID   string            `json:"subjectId"`
	ObjectID    string            `json:"objectId"`
	Operation   string            `json:"operation,omitempty"`
	Outcome     string            `json:"outcome,omitempty"`
	Coverage    string            `json:"coverage,omitempty"`
	Count       uint64            `json:"count"`
	Properties  map[string]string `json:"properties,omitempty"`
	EvidenceIDs []string          `json:"evidenceIds"`
}

// NewIncidentContext validates and canonicalizes incident context. Missing IDs
// are derived from content, and baselines and timeline events are sorted, so
// the same observations always produce the same context. Timeline events
// require evidence because they can ground a candidate claim.
func NewIncidentContext(incidentID string, evaluationAt time.Time, baseline []BehaviorBaseline, timeline []IncidentEvent) (IncidentContext, error) {
	incidentID = strings.TrimSpace(incidentID)
	if incidentID == "" || evaluationAt.IsZero() {
		return IncidentContext{}, errors.New("incident context requires an incident ID and evaluation time")
	}
	incident := IncidentContext{
		SchemaVersion: IncidentContextSchemaVersion,
		IncidentID:    incidentID,
		EvaluationAt:  evaluationAt.UTC(),
		Baseline:      slices.Clone(baseline),
		Timeline:      slices.Clone(timeline),
	}
	for index := range incident.Baseline {
		item := &incident.Baseline[index]
		if item.SubjectID == "" || item.ObjectID == "" || item.Kind == "" || item.FirstObservedAt.IsZero() || item.LastObservedAt.IsZero() {
			return IncidentContext{}, errors.New("behavior baseline requires endpoints, kind, and observation times")
		}
		item.FirstObservedAt = item.FirstObservedAt.UTC()
		item.LastObservedAt = item.LastObservedAt.UTC()
		if item.ID == "" {
			item.ID = incidentFactID("baseline", item.SubjectID, item.ObjectID, item.Kind, item.Operation, item.Outcome, item.Coverage)
		}
	}
	for index := range incident.Timeline {
		item := &incident.Timeline[index]
		if item.SubjectID == "" || item.ObjectID == "" || item.Kind == "" || item.ObservedAt.IsZero() || len(item.EvidenceIDs) == 0 {
			return IncidentContext{}, errors.New("incident event requires endpoints, kind, observation time, and evidence")
		}
		item.ObservedAt = item.ObservedAt.UTC()
		item.EvidenceIDs = sortedUniqueStrings(item.EvidenceIDs)
		if item.ID == "" {
			item.ID = incidentFactID("event", incidentID, item.Phase, item.SubjectID, item.ObjectID, item.Kind, item.Operation, item.Outcome, item.ObservedAt.Format(time.RFC3339Nano))
		}
	}
	slices.SortFunc(incident.Baseline, func(left, right BehaviorBaseline) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(incident.Timeline, func(left, right IncidentEvent) int {
		if order := left.ObservedAt.Compare(right.ObservedAt); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	return incident, nil
}

func incidentFactID(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "incident:sha256:" + hex.EncodeToString(digest[:])
}

// IncidentHistory accumulates incident context across evaluation windows of
// one [Service]. It is process-local: a restart starts a new history.
//
// Grouping is deliberately coarse. The service uses its consumer ID as the
// incident ID, so every window it processes belongs to one incident and the
// model correlates phases by time, endpoints, and outcome rather than by a
// host-side clustering decision. Each telemetry event ID is added to the
// timeline once, under the phase that first observed it.
type IncidentHistory struct {
	incidentID string
	baseline   map[string]BehaviorBaseline
	timeline   []IncidentEvent
	seen       map[string]struct{}
	seenOrder  []string
}

// NewIncidentHistory returns an empty history for incidentID.
func NewIncidentHistory(incidentID string) (*IncidentHistory, error) {
	incidentID = strings.TrimSpace(incidentID)
	if incidentID == "" {
		return nil, errors.New("incident history requires an incident ID")
	}
	return &IncidentHistory{
		incidentID: incidentID,
		baseline:   make(map[string]BehaviorBaseline),
		seen:       make(map[string]struct{}),
	}, nil
}

// ObserveBaseline folds the snapshot's telemetry into the behavior baseline.
// Telemetry without a first-seen time or evidence is ignored.
func (history *IncidentHistory) ObserveBaseline(snapshot graph.Snapshot) {
	windowSeen := make(map[string]struct{})
	for _, event := range snapshot.Telemetry {
		observedAt, ok := telemetryTime(event)
		if !ok || len(event.EvidenceIDs) == 0 {
			continue
		}
		key := incidentFactID("baseline", event.SubjectID, event.ObjectID, event.Kind, event.Operation, event.Outcome, event.Coverage)
		item := history.baseline[key]
		if item.ID == "" {
			item = BehaviorBaseline{
				ID: key, SubjectID: event.SubjectID, ObjectID: event.ObjectID, Kind: event.Kind,
				Operation: event.Operation, Outcome: event.Outcome, Coverage: event.Coverage,
				FirstObservedAt: observedAt, LastObservedAt: observedAt,
			}
		}
		if observedAt.Before(item.FirstObservedAt) {
			item.FirstObservedAt = observedAt
		}
		if observedAt.After(item.LastObservedAt) {
			item.LastObservedAt = observedAt
		}
		item.ObservationCount += event.Count
		if _, ok := windowSeen[key]; !ok {
			item.WindowCount++
			windowSeen[key] = struct{}{}
		}
		history.baseline[key] = item
	}
	history.trimBaselines()
}

// ObservePhase appends telemetry not yet seen to the timeline under phase.
// Telemetry without a first-seen time or evidence is ignored.
func (history *IncidentHistory) ObservePhase(phase string, snapshot graph.Snapshot) {
	for _, event := range snapshot.Telemetry {
		observedAt, ok := telemetryTime(event)
		if !ok || len(event.EvidenceIDs) == 0 {
			continue
		}
		fingerprint := incidentFactID("observed", event.ID)
		if _, ok := history.seen[fingerprint]; ok {
			continue
		}
		history.seen[fingerprint] = struct{}{}
		history.seenOrder = append(history.seenOrder, fingerprint)
		history.timeline = append(history.timeline, IncidentEvent{
			ID:    incidentFactID("event", history.incidentID, phase, event.SubjectID, event.ObjectID, event.Kind, event.Operation, event.Outcome, observedAt.Format(time.RFC3339Nano)),
			Phase: phase, ObservedAt: observedAt, Kind: event.Kind, SubjectID: event.SubjectID, ObjectID: event.ObjectID,
			Operation: event.Operation, Outcome: event.Outcome, Coverage: event.Coverage, Count: event.Count,
			Properties: telemetryProperties(event.Properties), EvidenceIDs: opaqueEvidence(event.EvidenceIDs),
		})
	}
	if len(history.timeline) > maxIncidentEvents {
		slices.SortFunc(history.timeline, func(left, right IncidentEvent) int {
			if order := left.ObservedAt.Compare(right.ObservedAt); order != 0 {
				return order
			}
			return strings.Compare(left.ID, right.ID)
		})
		history.timeline = slices.Clone(history.timeline[len(history.timeline)-maxIncidentEvents:])
	}
	if len(history.seenOrder) > maxIncidentSeen {
		removed := history.seenOrder[:len(history.seenOrder)-maxIncidentSeen]
		for _, fingerprint := range removed {
			delete(history.seen, fingerprint)
		}
		history.seenOrder = slices.Clone(history.seenOrder[len(history.seenOrder)-maxIncidentSeen:])
	}
}

func (history *IncidentHistory) trimBaselines() {
	if len(history.baseline) <= maxIncidentBaselines {
		return
	}
	items := make([]BehaviorBaseline, 0, len(history.baseline))
	for _, item := range history.baseline {
		items = append(items, item)
	}
	slices.SortFunc(items, func(left, right BehaviorBaseline) int {
		if order := right.LastObservedAt.Compare(left.LastObservedAt); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	history.baseline = make(map[string]BehaviorBaseline, maxIncidentBaselines)
	for _, item := range items[:maxIncidentBaselines] {
		history.baseline[item.ID] = item
	}
}

// Context returns the current history as a canonical [IncidentContext].
func (history *IncidentHistory) Context(evaluationAt time.Time) (IncidentContext, error) {
	baseline := make([]BehaviorBaseline, 0, len(history.baseline))
	for _, item := range history.baseline {
		baseline = append(baseline, item)
	}
	return NewIncidentContext(history.incidentID, evaluationAt, baseline, history.timeline)
}
