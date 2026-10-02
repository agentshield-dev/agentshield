package state

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
)

func TestPostgreSQLDetectionSignalsRoundTripIdempotentlyAndPrune(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	start := time.Date(2026, time.October, 16, 12, 0, 0, 0, time.UTC)
	graphSHA := strings.Repeat("a", 64)
	novelty := DetectionSignal{
		Signal: detector.InvestigationSignal{
			ID: "signal:novelty", Risk: detector.RiskMedium, Reasons: []string{"established_source", "new_communication_path"},
			AnchorIDs: []string{"checkout", "secrets"}, Window: detector.TimeWindow{Start: start, End: start.Add(10 * time.Minute)},
		},
		ThroughSequence: 7, GraphSHA256: graphSHA, Investigation: InvestigationInvestigated,
	}
	shadow := DetectionSignal{
		Signal: detector.InvestigationSignal{
			ID: "signal:shadow", Risk: detector.RiskMedium, Reasons: []string{"workload_rule_match"}, AnchorIDs: []string{"checkout"},
			Window: detector.TimeWindow{Start: start, End: start.Add(time.Minute)}, RuleID: "deployment/checkout/rule-1", RuleRevision: 1,
			RulesetDigest: strings.Repeat("b", 64), RuleMode: detector.RuleModeShadow,
		},
		ThroughSequence: 7, GraphSHA256: graphSHA, Investigation: InvestigationShadow,
	}
	for range 2 {
		if err := store.RecordDetectionSignals(ctx, []DetectionSignal{novelty, shadow}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := store.ListDetectionSignals(ctx, DetectionSignalQuery{Limit: 10})
	if err != nil || len(all) != 2 {
		t.Fatalf("signals=%#v err=%v", all, err)
	}
	ruled, err := store.ListDetectionSignals(ctx, DetectionSignalQuery{RuleID: "deployment/checkout/rule-1", Limit: 10})
	if err != nil || len(ruled) != 1 {
		t.Fatalf("rule signals=%#v err=%v", ruled, err)
	}
	got := ruled[0]
	if got.Investigation != InvestigationShadow || got.Signal.RuleMode != detector.RuleModeShadow || got.Signal.RuleRevision != 1 ||
		got.ThroughSequence != 7 || !got.Signal.Window.Start.Equal(start) || got.Signal.Reasons[0] != "workload_rule_match" {
		t.Fatalf("round trip=%#v", got)
	}
	invalid := novelty
	invalid.Signal.ID, invalid.Investigation = "signal:not-shadow", InvestigationShadow
	if err := store.RecordDetectionSignals(ctx, []DetectionSignal{invalid}); err == nil {
		t.Fatal("non-shadow signal recorded as shadow")
	}
	if _, err := store.ListDetectionSignals(ctx, DetectionSignalQuery{Investigation: "unknown", Limit: 10}); err == nil {
		t.Fatal("invalid investigation filter accepted")
	}
	if pruned, err := store.PruneDetectionSignals(ctx, time.Now().Add(time.Minute)); err != nil || pruned != 2 {
		t.Fatalf("pruned=%d err=%v", pruned, err)
	}
}
