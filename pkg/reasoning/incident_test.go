package reasoning

import (
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestIncidentHistoryPreservesBaselineAndOrdersNewPhaseEvidence(t *testing.T) {
	first := time.Unix(10, 0).UTC()
	second := time.Unix(20, 0).UTC()
	history, err := NewIncidentHistory("campaign")
	if err != nil {
		t.Fatal(err)
	}
	baseline := graph.Snapshot{Telemetry: []graph.TelemetryEvent{{ID: "ab", Kind: "network-flow", SubjectID: "a", ObjectID: "b", Count: 3, Properties: map[string]string{"telemetry/first-seen": first.Format(time.RFC3339Nano)}, EvidenceIDs: []string{"flow-ab"}}}}
	history.ObserveBaseline(baseline)
	history.ObservePhase("baseline", baseline)
	pivot := graph.Snapshot{Telemetry: []graph.TelemetryEvent{{ID: "bc", Kind: "network-flow", SubjectID: "b", ObjectID: "c", Count: 1, Properties: map[string]string{"telemetry/first-seen": second.Format(time.RFC3339Nano)}, EvidenceIDs: []string{"flow-bc"}}}}
	history.ObservePhase("pivot", pivot)
	history.ObservePhase("pivot", pivot)
	context, err := history.Context(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(context.Baseline) != 1 || context.Baseline[0].ObservationCount != 3 || context.Baseline[0].WindowCount != 1 {
		t.Fatalf("baseline = %#v", context.Baseline)
	}
	if len(context.Timeline) != 2 || context.Timeline[0].Phase != "baseline" || context.Timeline[1].Phase != "pivot" {
		t.Fatalf("timeline = %#v", context.Timeline)
	}
}
