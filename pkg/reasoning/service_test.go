package reasoning

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

type serviceStore struct {
	events     []state.ContributionChangeEvent
	checkpoint state.GraphCheckpoint
	cursor     state.ReasoningCursor
	found      bool
}

func (store *serviceStore) ReadContributionChanges(context.Context, uint64, int) ([]state.ContributionChangeEvent, error) {
	return store.events, nil
}

func (store *serviceStore) ReadGraphCheckpoint(context.Context) (state.GraphCheckpoint, error) {
	return store.checkpoint, nil
}

func (store *serviceStore) ReadReasoningCursor(context.Context, string) (state.ReasoningCursor, bool, error) {
	return store.cursor, store.found, nil
}

func (store *serviceStore) AdvanceReasoningCursor(_ context.Context, cursor state.ReasoningCursor) error {
	store.cursor, store.found = cursor, true
	return nil
}

func TestServiceEvaluateWindowSuppressesChangesWithoutSignals(t *testing.T) {
	store := &serviceStore{
		events:     []state.ContributionChangeEvent{{Sequence: 1}},
		checkpoint: state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "graph-1"}},
	}
	called := false
	service, err := NewService(store, AnalyzerFunc(func(context.Context, Packet, *ContextProvider) (AnalysisRun, error) {
		called = true
		return AnalysisRun{}, nil
	}), nil, ServiceConfig{Clock: func() time.Time { return time.Unix(1, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := service.EvaluateWindow(context.Background(), &graph.Snapshot{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("analyzer called without an investigation signal")
	}
	if evaluation.Analysis.Outcome.Promotion.Reason != "no_investigation_signal" {
		t.Fatalf("promotion = %#v", evaluation.Analysis.Outcome.Promotion)
	}
}

func TestServiceInitializeExplicitlyRebasesLaggingCursor(t *testing.T) {
	store := &serviceStore{
		checkpoint: state.GraphCheckpoint{ThroughSequence: 5, View: state.GraphView{SHA256: "graph-5"}},
		cursor:     state.ReasoningCursor{ConsumerID: "reasoning/default", ThroughSequence: 3, GraphSHA256: "graph-3"}, found: true,
	}
	var recorded Evaluation
	service, err := NewService(store, nil, ResultSinkFunc(func(_ context.Context, evaluation Evaluation) error {
		recorded = evaluation
		return nil
	}), ServiceConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, cursor, err := service.initialize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 5 || store.cursor.ThroughSequence != 5 || !recorded.Rebased || recorded.RebaseReason != "startup_without_historical_snapshot" {
		t.Fatalf("cursor=%d stored=%#v evaluation=%#v", cursor, store.cursor, recorded)
	}
}

func TestServiceInitializeToleratesTelemetryDigestDriftAtSameSequence(t *testing.T) {
	store := &serviceStore{
		checkpoint: state.GraphCheckpoint{ThroughSequence: 5, View: state.GraphView{SHA256: "graph-with-new-telemetry"}},
		cursor:     state.ReasoningCursor{ConsumerID: "reasoning/default", ThroughSequence: 5, GraphSHA256: "graph-before-telemetry"}, found: true,
	}
	service, err := NewService(store, nil, nil, ServiceConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, cursor, err := service.initialize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 5 {
		t.Fatalf("cursor = %d, want 5", cursor)
	}
}

func TestServiceBuildsLongitudinalIncidentContextForContinuousEvaluation(t *testing.T) {
	first := time.Unix(10, 0).UTC()
	second := time.Unix(20, 0).UTC()
	previous := graph.Snapshot{
		Resources: []graph.Resource{{ID: "a"}, {ID: "b"}, {ID: "c", Assertions: []graph.ResourceAssertion{{Attributes: map[string]string{"network/role": graph.NetworkRoleControlPlaneAPI}}}}},
		Telemetry: []graph.TelemetryEvent{{ID: "ab", Kind: "active-probe", SubjectID: "a", ObjectID: "b", Count: 1, Properties: map[string]string{"telemetry/first-seen": first.Format(time.RFC3339Nano)}, EvidenceIDs: []string{"ab-evidence"}}},
	}
	current := previous
	current.Telemetry = append(append([]graph.TelemetryEvent(nil), previous.Telemetry...), graph.TelemetryEvent{ID: "bc", Kind: "active-probe", SubjectID: "b", ObjectID: "c", Count: 1, Properties: map[string]string{"telemetry/first-seen": second.Format(time.RFC3339Nano)}, EvidenceIDs: []string{"bc-evidence"}})
	store := &serviceStore{events: []state.ContributionChangeEvent{{Sequence: 1}}, checkpoint: state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "graph", Snapshot: current}}}
	queried := false
	service, err := NewService(store, AnalyzerFunc(func(_ context.Context, _ Packet, provider *ContextProvider) (AnalysisRun, error) {
		result, queryErr := provider.Query(ContextQuery{Token: provider.Token(), Template: "incident_timeline", AnchorIDs: []string{"b"}})
		if queryErr != nil {
			return AnalysisRun{}, queryErr
		}
		queried = len(result.IncidentEvents) == 2
		return AnalysisRun{}, nil
	}), nil, ServiceConfig{Clock: func() time.Time { return second }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.EvaluateWindow(context.Background(), &previous, 0); err != nil {
		t.Fatal(err)
	}
	if !queried {
		t.Fatal("continuous evaluation did not expose baseline and current incident events")
	}
}

type fixedDetector struct {
	signals []detector.InvestigationSignal
}

func (fixed fixedDetector) Detect(context.Context, graph.Snapshot, graph.Snapshot, time.Time) (detector.Result, error) {
	return detector.Result{Signals: fixed.signals, WorkloadRulesDigest: "workload-digest"}, nil
}

func gateSignal(id string, risk detector.Risk, mode detector.RuleMode) detector.InvestigationSignal {
	return detector.InvestigationSignal{ID: id, Risk: risk, Reasons: []string{"test"}, AnchorIDs: []string{"a"}, RuleMode: mode}
}

func TestServiceInvestigatesOnlyEligibleNonShadowSignals(t *testing.T) {
	low := gateSignal("low", detector.RiskLow, "")
	medium := gateSignal("medium", detector.RiskMedium, "")
	shadow := gateSignal("shadow", detector.RiskCritical, detector.RuleModeShadow)
	shadow.RuleID, shadow.RuleRevision = "draft", 1
	ruleSignal := gateSignal("rule", detector.RiskCritical, "")
	ruleSignal.RuleID, ruleSignal.RuleRevision = "approved", 1
	tests := []struct {
		name          string
		signals       []detector.InvestigationSignal
		analyzer      bool
		investigation string
	}{
		{name: "low-risk signals cannot promote", signals: []detector.InvestigationSignal{low}, analyzer: true, investigation: InvestigationBelowThreshold},
		{name: "shadow rule signals are never investigated", signals: []detector.InvestigationSignal{low, shadow}, analyzer: true, investigation: InvestigationBelowThreshold},
		{name: "eligible signal runs the agent", signals: []detector.InvestigationSignal{low, medium, shadow}, analyzer: true, investigation: InvestigationInvestigated},
		{name: "eligible signal without an agent", signals: []detector.InvestigationSignal{medium}, investigation: InvestigationDisabled},
		{name: "active rule signals become findings without the agent", signals: []detector.InvestigationSignal{low, ruleSignal}, analyzer: true, investigation: InvestigationBelowThreshold},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &serviceStore{events: []state.ContributionChangeEvent{{Sequence: 1}}, checkpoint: state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "graph-1"}}}
			var packetSignals []string
			var analyzer Analyzer
			if test.analyzer {
				analyzer = AnalyzerFunc(func(_ context.Context, packet Packet, _ *ContextProvider) (AnalysisRun, error) {
					for _, signal := range packet.Signals {
						packetSignals = append(packetSignals, signal.ID)
					}
					return AnalysisRun{}, nil
				})
			}
			service, err := NewService(store, analyzer, nil, ServiceConfig{Detection: fixedDetector{signals: test.signals}, Clock: func() time.Time { return time.Unix(1, 0) }})
			if err != nil {
				t.Fatal(err)
			}
			evaluation, err := service.EvaluateWindow(context.Background(), &graph.Snapshot{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if evaluation.Investigation != test.investigation || evaluation.WorkloadRulesDigest != "workload-digest" {
				t.Fatalf("evaluation=%#v", evaluation)
			}
			if (test.investigation == InvestigationInvestigated) != (packetSignals != nil) || slices.Contains(packetSignals, "shadow") || slices.Contains(packetSignals, "rule") {
				t.Fatalf("packet signals=%v", packetSignals)
			}
			for _, signal := range evaluation.Signals {
				if signal.RuleMode == detector.RuleModeShadow {
					t.Fatalf("shadow signal in investigation signals: %#v", evaluation.Signals)
				}
			}
			hasRule := slices.ContainsFunc(test.signals, func(signal detector.InvestigationSignal) bool { return signal.ID == "rule" })
			if hasRule != (len(evaluation.RuleSignals) == 1) || slices.ContainsFunc(evaluation.Signals, func(signal detector.InvestigationSignal) bool { return signal.RuleID != "" }) {
				t.Fatalf("rule signals=%#v signals=%#v", evaluation.RuleSignals, evaluation.Signals)
			}
			hasShadow := slices.ContainsFunc(test.signals, func(signal detector.InvestigationSignal) bool { return signal.ID == "shadow" })
			if hasShadow && (len(evaluation.ShadowSignals) != 1 || evaluation.ShadowSignals[0].ID != "shadow") {
				t.Fatalf("shadow signals=%#v", evaluation.ShadowSignals)
			}
		})
	}
}

type failingDetector struct{ panics bool }

func (failing failingDetector) Detect(context.Context, graph.Snapshot, graph.Snapshot, time.Time) (detector.Result, error) {
	if failing.panics {
		panic("detector bug")
	}
	return detector.Result{}, errors.New("rule runtime error")
}

// advancingStore publishes an empty graph first and one change afterwards.
type advancingStore struct {
	serviceStore
	reads int
}

func (store *advancingStore) ReadGraphCheckpoint(context.Context) (state.GraphCheckpoint, error) {
	store.reads++
	if store.reads == 1 {
		return state.GraphCheckpoint{View: state.GraphView{SHA256: "graph-0"}}, nil
	}
	return store.checkpoint, nil
}

func TestServiceRunRecordsAWindowFailureAndContinues(t *testing.T) {
	for _, test := range []struct {
		name     string
		detector failingDetector
		want     string
	}{
		{name: "detector error", detector: failingDetector{}, want: "rule runtime error"},
		{name: "detector panic", detector: failingDetector{panics: true}, want: "detector bug"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &advancingStore{serviceStore: serviceStore{
				events:     []state.ContributionChangeEvent{{Sequence: 1}},
				checkpoint: state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "graph-1"}},
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var recorded []Evaluation
			service, err := NewService(store, nil, ResultSinkFunc(func(_ context.Context, evaluation Evaluation) error {
				recorded = append(recorded, evaluation)
				if !evaluation.Rebased {
					cancel()
				}
				return nil
			}), ServiceConfig{PollInterval: time.Millisecond, Detection: test.detector})
			if err != nil {
				t.Fatal(err)
			}
			if err := service.Run(ctx); err != nil {
				t.Fatalf("a window failure stopped detection: %v", err)
			}
			if len(recorded) != 2 || !strings.Contains(recorded[1].DetectionError, test.want) || len(recorded[1].Window.Events) != 1 {
				t.Fatalf("recorded=%#v", recorded)
			}
			if store.cursor.ThroughSequence != 1 {
				t.Fatalf("cursor=%#v, want it past the failed window", store.cursor)
			}
		})
	}
}

type signalStore struct {
	recorded []state.DetectionSignal
	prunes   []time.Time
}

func (store *signalStore) RecordDetectionSignals(_ context.Context, signals []state.DetectionSignal) error {
	store.recorded = append(store.recorded, signals...)
	return nil
}

func (store *signalStore) PruneDetectionSignals(_ context.Context, before time.Time) (int64, error) {
	store.prunes = append(store.prunes, before)
	return 0, nil
}

func TestSignalSinkRecordsInvestigationOutcomeAndPrunesHourly(t *testing.T) {
	store := &signalStore{}
	now := time.Date(2026, time.October, 16, 12, 0, 0, 0, time.UTC)
	sink, err := NewSignalSink(store, 24*time.Hour, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	evaluation := Evaluation{
		Window:        ChangeWindow{Checkpoint: state.GraphCheckpoint{ThroughSequence: 9, View: state.GraphView{SHA256: "graph-9"}}},
		Signals:       []detector.InvestigationSignal{gateSignal("medium", detector.RiskMedium, "")},
		RuleSignals:   []detector.InvestigationSignal{{ID: "rule", Risk: detector.RiskMedium, Reasons: []string{"test"}, RuleID: "approved", RuleRevision: 1}},
		ShadowSignals: []detector.InvestigationSignal{gateSignal("shadow", detector.RiskMedium, detector.RuleModeShadow)},
		Investigation: InvestigationDisabled,
	}
	for range 2 {
		if err := sink.RecordReasoningEvaluation(context.Background(), evaluation); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.recorded) != 6 || store.recorded[0].Investigation != state.InvestigationDisabled || store.recorded[1].Investigation != state.InvestigationRuleFinding || store.recorded[2].Investigation != state.InvestigationShadow ||
		store.recorded[0].ThroughSequence != 9 || store.recorded[0].GraphSHA256 != "graph-9" {
		t.Fatalf("recorded=%#v", store.recorded)
	}
	if len(store.prunes) != 1 || !store.prunes[0].Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("prunes=%v", store.prunes)
	}
	if err := sink.RecordReasoningEvaluation(context.Background(), Evaluation{Rebased: true, Signals: evaluation.Signals}); err != nil || len(store.recorded) != 6 {
		t.Fatalf("rebase recorded=%d err=%v", len(store.recorded), err)
	}
	if _, err := NewSignalSink(store, time.Minute, nil); err == nil {
		t.Fatal("sub-hour retention accepted")
	}
}
