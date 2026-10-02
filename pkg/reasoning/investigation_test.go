package reasoning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

func novelty(id string, risk detector.Risk, anchors ...string) detector.InvestigationSignal {
	return detector.InvestigationSignal{
		ID: id, Risk: risk, Reasons: []string{"new_communication_path"}, AnchorIDs: anchors,
		Window: detector.TimeWindow{Start: time.Unix(100, 0).UTC(), End: time.Unix(200, 0).UTC()},
	}
}

func testWindow(first, last uint64) ChangeWindow {
	var events []state.ContributionChangeEvent
	for sequence := first; sequence <= last; sequence++ {
		events = append(events, state.ContributionChangeEvent{Sequence: sequence})
	}
	return ChangeWindow{Events: events}
}

func testIncident(t *testing.T, events ...IncidentEvent) IncidentContext {
	t.Helper()
	incident, err := NewIncidentContext("incident", time.Unix(300, 0), nil, events)
	if err != nil {
		t.Fatal(err)
	}
	return incident
}

func TestInvestigationRequestScopesIdentifiesAndMerges(t *testing.T) {
	incident := testIncident(t,
		IncidentEvent{Phase: "observed", SubjectID: "checkout", ObjectID: "secrets", Kind: "active-probe", ObservedAt: time.Unix(150, 0), EvidenceIDs: []string{"e1"}},
		IncidentEvent{Phase: "observed", SubjectID: "ledger", ObjectID: "fraud", Kind: "active-probe", ObservedAt: time.Unix(160, 0), EvidenceIDs: []string{"e2"}},
	)
	if _, err := NewInvestigationRequest(testWindow(1, 1), "changed", []detector.InvestigationSignal{novelty("low", detector.RiskLow, "checkout")}, incident, time.Unix(300, 0)); err == nil {
		t.Fatal("request without an eligible signal accepted")
	}
	first, err := NewInvestigationRequest(testWindow(4, 6), "unchanged", []detector.InvestigationSignal{
		novelty("b", detector.RiskMedium, "checkout", "secrets"), novelty("a", detector.RiskLow, "checkout"),
	}, incident, time.Unix(300, 0))
	if err != nil {
		t.Fatal(err)
	}
	if first.FirstSequence != 4 || first.LastSequence != 6 || first.Signals[0].ID != "a" || first.Risk() != detector.RiskMedium {
		t.Fatalf("request = %#v", first)
	}
	if len(first.Incident.Timeline) != 1 || first.Incident.Timeline[0].SubjectID != "checkout" {
		t.Fatalf("incident was not scoped to anchors: %#v", first.Incident.Timeline)
	}
	recurrence, err := NewInvestigationRequest(testWindow(9, 9), "unchanged", []detector.InvestigationSignal{
		novelty("b-later", detector.RiskMedium, "secrets", "checkout"), novelty("a-later", detector.RiskLow, "checkout"),
	}, incident, time.Unix(400, 0))
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint() != recurrence.Fingerprint() || first.SampleKey() == recurrence.SampleKey() {
		t.Fatal("recurrence must share a fingerprint but not a sample key")
	}
	merged, accepted := MergeInvestigationRequests(first, recurrence)
	if !accepted || merged.FirstSequence != 4 || merged.LastSequence != 9 || len(merged.Signals) != 4 || merged.TopologyChange != "unchanged" || !merged.DetectedAt.Equal(time.Unix(300, 0)) {
		t.Fatalf("merged = %#v", merged)
	}
	if _, accepted := MergeInvestigationRequests(first, InvestigationRequest{FirstSequence: 1005, LastSequence: 1005}); accepted {
		t.Fatal("merge beyond one change batch accepted")
	}
	record, err := merged.Record()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInvestigationRequest(record.Request)
	if err != nil || decoded.SampleKey() != merged.SampleKey() || record.RiskRank != detector.RiskMedium.Rank() || !slices.Equal(record.AnchorIDs, []string{"checkout", "secrets"}) {
		t.Fatalf("record round trip = %#v err=%v", record, err)
	}
	if _, err := DecodeInvestigationRequest([]byte(`{"schemaVersion":"other"}`)); err == nil {
		t.Fatal("unknown request schema accepted")
	}
}

func TestSamplingPolicyIsDeterministicAndSparesHighRisk(t *testing.T) {
	policy := SamplingPolicy{SampleRate: 0.25}
	sampled := 0
	for index := range 2000 {
		request := InvestigationRequest{Signals: []detector.InvestigationSignal{novelty(fmt.Sprintf("signal-%d", index), detector.RiskMedium, "a")}}
		decision := policy.Sampled(request)
		if decision != policy.Sampled(request) {
			t.Fatal("sampling is not deterministic")
		}
		if decision {
			sampled++
		}
	}
	if sampled < 400 || sampled > 600 {
		t.Fatalf("sampled %d of 2000 at rate 0.25", sampled)
	}
	high := InvestigationRequest{Signals: []detector.InvestigationSignal{novelty("high", detector.RiskHigh, "a")}}
	if !(SamplingPolicy{SampleRate: 0}).Sampled(high) {
		t.Fatal("high-risk request was sampled out")
	}
	if (SamplingPolicy{SampleRate: 0}).Sampled(InvestigationRequest{Signals: []detector.InvestigationSignal{novelty("m", detector.RiskMedium, "a")}}) {
		t.Fatal("rate zero kept a medium-risk request")
	}
	if err := (SamplingPolicy{SampleRate: 1.5}).validate(); err == nil {
		t.Fatal("invalid rate accepted")
	}
}

type fakeInvestigationStore struct {
	recordingFindingStore
	checkpoint  state.GraphCheckpoint
	events      []state.ContributionChangeEvent
	jobs        []state.InvestigationJob
	admission   string
	admissions  int
	skipped     map[int64]string
	completed   map[int64]InvestigationOutcome
	retried     map[int64]bool
	renewals    int
	renewFails  bool
	invalidated [][]string
}

func newFakeInvestigationStore(checkpoint state.GraphCheckpoint, events []state.ContributionChangeEvent) *fakeInvestigationStore {
	return &fakeInvestigationStore{
		checkpoint: checkpoint, events: events, admission: state.InvestigationAdmitted,
		skipped: map[int64]string{}, completed: map[int64]InvestigationOutcome{}, retried: map[int64]bool{},
	}
}

func (store *fakeInvestigationStore) ReadGraphCheckpoint(context.Context) (state.GraphCheckpoint, error) {
	return store.checkpoint, nil
}

func (store *fakeInvestigationStore) ReadContributionChanges(_ context.Context, after uint64, limit int) ([]state.ContributionChangeEvent, error) {
	var result []state.ContributionChangeEvent
	for _, event := range store.events {
		if event.Sequence > after && len(result) < limit {
			result = append(result, event)
		}
	}
	return result, nil
}

func (store *fakeInvestigationStore) ClaimInvestigationJob(context.Context, string, time.Duration) (state.InvestigationJob, bool, error) {
	if len(store.jobs) == 0 {
		return state.InvestigationJob{}, false, nil
	}
	job := store.jobs[0]
	store.jobs = store.jobs[1:]
	return job, true, nil
}

func (store *fakeInvestigationStore) AdmitInvestigationJob(_ context.Context, _ int64, _ string, admission state.InvestigationAdmission) (string, error) {
	if admission.DeferRiskRank != detector.RiskHigh.Rank() {
		return "", errors.New("high-risk requests must be deferred, not skipped")
	}
	store.admissions++
	return store.admission, nil
}

func (store *fakeInvestigationStore) SkipInvestigationJob(_ context.Context, id int64, _, reason string) error {
	store.skipped[id] = reason
	return nil
}

func (store *fakeInvestigationStore) RenewInvestigationJob(context.Context, int64, string, time.Duration) (bool, error) {
	store.renewals++
	return !store.renewFails, nil
}

func (store *fakeInvestigationStore) CompleteInvestigationJob(_ context.Context, id int64, _ string, outcome json.RawMessage) error {
	var decoded InvestigationOutcome
	if err := json.Unmarshal(outcome, &decoded); err != nil {
		return err
	}
	store.completed[id] = decoded
	return nil
}

func (store *fakeInvestigationStore) RetryInvestigationJob(_ context.Context, id int64, _, _ string, _ time.Duration, terminal bool) error {
	store.retried[id] = terminal
	return nil
}

func (store *fakeInvestigationStore) PruneInvestigationJobs(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (store *fakeInvestigationStore) InvalidateFindings(_ context.Context, _ string, _ uint64, ids []string, _ time.Time) error {
	store.invalidated = append(store.invalidated, ids)
	return nil
}

func queuedJob(t *testing.T, id int64, request InvestigationRequest, attempts int, admitted bool) state.InvestigationJob {
	t.Helper()
	record, err := request.Record()
	if err != nil {
		t.Fatal(err)
	}
	return state.InvestigationJob{ID: id, InvestigationJobRecord: record, AttemptCount: attempts, Admitted: admitted}
}

func promotingAnalyzer(calls *int, packets *[]Packet) Analyzer {
	return AnalyzerFunc(func(_ context.Context, packet Packet, provider *ContextProvider) (AnalysisRun, error) {
		*calls++
		*packets = append(*packets, packet)
		if provider == nil {
			return AnalysisRun{}, errors.New("context provider is required")
		}
		return AnalysisRun{Attempts: 1, Outcome: AnalysisOutcome{
			InitialPacket: packet, EffectivePacket: packet, Validation: "accepted",
			Response: Response{Assessment: Assessment{
				Decision: "candidate_finding", Category: "possible_lateral_path", Severity: "high", ModelUncertainty: "low",
				Summary: "lateral path", AffectedEntityIDs: []string{"checkout"}, SignalIDs: []string{packet.Signals[0].ID},
			}},
			Promotion: Promotion{Status: "promoted", Reason: "evidence_backed_signal", FindingID: "finding:test", SignalIDs: []string{packet.Signals[0].ID}},
		}}, nil
	})
}

func TestInvestigationWorkerSamplesAdmitsInvestigatesAndReconciles(t *testing.T) {
	checkpoint := state.GraphCheckpoint{ThroughSequence: 5, View: state.GraphView{SHA256: strings.Repeat("a", 64), Snapshot: graph.Snapshot{
		Resources: []graph.Resource{{ID: "checkout", Kind: "kubernetes/deployment"}, {ID: "secrets", Kind: "kubernetes/service"}},
	}}}
	events := []state.ContributionChangeEvent{{Sequence: 3}, {Sequence: 4}, {Sequence: 5}, {Sequence: 6, Added: []state.AssertionChange{{Entity: state.EntityLocator{ID: "checkout"}}}}}
	store := newFakeInvestigationStore(checkpoint, events)
	var calls int
	var packets []Packet
	investigator, err := NewInvestigator(promotingAnalyzer(&calls, &packets), Limits{}, ContextLimits{})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewInvestigationWorker(store, investigator, InvestigationWorkerConfig{ID: "worker/test", Sampling: SamplingPolicy{SampleRate: 0, DedupWindow: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(id string, risk detector.Risk, anchors ...string) InvestigationRequest {
		return InvestigationRequest{SchemaVersion: InvestigationRequestSchemaVersion, FirstSequence: 3, LastSequence: 5, TopologyChange: "changed",
			Signals: []detector.InvestigationSignal{novelty(id, risk, anchors...)}}
	}
	ctx := context.Background()

	if err := worker.Process(ctx, queuedJob(t, 1, request("gone", detector.RiskHigh, "deleted-pod"), 0, false)); err != nil || store.skipped[1] != InvestigationSkipStale {
		t.Fatalf("stale job err=%v skipped=%v", err, store.skipped)
	}
	if err := worker.Process(ctx, queuedJob(t, 2, request("medium", detector.RiskMedium, "checkout"), 0, false)); err != nil || store.skipped[2] != InvestigationSkipSampled || store.admissions != 0 {
		t.Fatalf("sampled job err=%v skipped=%v admissions=%d", err, store.skipped, store.admissions)
	}
	store.admission = state.InvestigationDuplicate
	if err := worker.Process(ctx, queuedJob(t, 3, request("dup", detector.RiskHigh, "checkout"), 0, false)); err != nil || calls != 0 || store.admissions != 1 {
		t.Fatalf("duplicate job err=%v calls=%d admissions=%d", err, calls, store.admissions)
	}
	store.admission = state.InvestigationAdmitted
	if err := worker.Process(ctx, queuedJob(t, 4, request("high", detector.RiskHigh, "checkout", "deleted-pod"), 0, false)); err != nil {
		t.Fatal(err)
	}
	outcome, completed := store.completed[4]
	if !completed || calls != 1 || outcome.FindingID != "finding:test" || outcome.Promotion != "promoted" || outcome.HydratedAtSequence != 5 {
		t.Fatalf("completed=%t outcome=%#v calls=%d", completed, outcome, calls)
	}
	packet := packets[0]
	if packet.TriggerFirstSequence != 3 || packet.TriggerLastSequence != 5 || packet.TopologyChange != "changed" || !slices.Equal(packet.Signals[0].AnchorIDs, []string{"checkout"}) {
		t.Fatalf("packet = %#v", packet)
	}
	if store.calls != 1 || store.finding.Origin != state.FindingOriginAgenticInvestigation {
		t.Fatalf("finding = %#v calls=%d", store.finding, store.calls)
	}
	if len(store.invalidated) != 1 || !slices.Equal(store.invalidated[0], []string{"checkout"}) {
		t.Fatalf("reconcile invalidations = %#v", store.invalidated)
	}
	if err := worker.Process(ctx, queuedJob(t, 5, request("retry", detector.RiskHigh, "checkout"), 1, true)); err != nil || store.admissions != 2 || calls != 2 {
		t.Fatalf("admitted retry err=%v admissions=%d calls=%d", err, store.admissions, calls)
	}
}

func TestInvestigationWorkerRetriesModelFailures(t *testing.T) {
	checkpoint := state.GraphCheckpoint{ThroughSequence: 3, View: state.GraphView{SHA256: strings.Repeat("a", 64), Snapshot: graph.Snapshot{
		Resources: []graph.Resource{{ID: "checkout"}},
	}}}
	store := newFakeInvestigationStore(checkpoint, []state.ContributionChangeEvent{{Sequence: 3}})
	investigator, err := NewInvestigator(AnalyzerFunc(func(context.Context, Packet, *ContextProvider) (AnalysisRun, error) {
		return AnalysisRun{}, errors.New("model unavailable")
	}), Limits{}, ContextLimits{})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewInvestigationWorker(store, investigator, InvestigationWorkerConfig{ID: "worker/test", MaxAttempts: 2, Sampling: DefaultSamplingPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	request := InvestigationRequest{SchemaVersion: InvestigationRequestSchemaVersion, FirstSequence: 3, LastSequence: 3,
		Signals: []detector.InvestigationSignal{novelty("high", detector.RiskHigh, "checkout")}}
	if err := worker.Process(context.Background(), queuedJob(t, 1, request, 0, false)); err == nil || store.retried[1] {
		t.Fatalf("first failure err=%v terminal=%v", err, store.retried)
	}
	if err := worker.Process(context.Background(), queuedJob(t, 2, request, 1, true)); err == nil || !store.retried[2] {
		t.Fatalf("last failure err=%v terminal=%v", err, store.retried)
	}
	missing := request
	missing.FirstSequence, missing.LastSequence = 7, 8
	if err := worker.Process(context.Background(), queuedJob(t, 3, missing, 0, false)); err == nil || store.retried[3] {
		t.Fatalf("first unavailable-changes attempt err=%v terminal=%v", err, store.retried)
	}
	if err := worker.Process(context.Background(), queuedJob(t, 4, missing, 1, true)); err == nil || !store.retried[4] {
		t.Fatalf("last unavailable-changes attempt err=%v terminal=%v", err, store.retried)
	}
	if _, err := NewInvestigationWorker(store, investigator, InvestigationWorkerConfig{ID: "worker/test", Sampling: SamplingPolicy{SampleRate: -1}}); err == nil {
		t.Fatal("invalid sampling policy accepted")
	}
}

func TestInvestigationWorkerEndsPermanentFailuresPanicsAndSlowRuns(t *testing.T) {
	checkpoint := state.GraphCheckpoint{ThroughSequence: 3, View: state.GraphView{SHA256: strings.Repeat("a", 64), Snapshot: graph.Snapshot{
		Resources: []graph.Resource{{ID: "checkout"}},
	}}}
	request := InvestigationRequest{SchemaVersion: InvestigationRequestSchemaVersion, FirstSequence: 3, LastSequence: 3,
		Signals: []detector.InvestigationSignal{novelty("high", detector.RiskHigh, "checkout")}}
	for _, test := range []struct {
		name     string
		analyze  AnalyzerFunc
		terminal bool
		want     string
	}{
		{name: "invalid request", terminal: true, want: "400", analyze: func(context.Context, Packet, *ContextProvider) (AnalysisRun, error) {
			return AnalysisRun{}, &StatusError{StatusCode: 400, Status: "400 Bad Request"}
		}},
		{name: "rate limited", terminal: false, want: "429", analyze: func(context.Context, Packet, *ContextProvider) (AnalysisRun, error) {
			return AnalysisRun{}, &StatusError{StatusCode: 429, Status: "429 Too Many Requests"}
		}},
		{name: "panic", terminal: true, want: "panic: analyzer bug", analyze: func(context.Context, Packet, *ContextProvider) (AnalysisRun, error) {
			panic("analyzer bug")
		}},
		{name: "job timeout", terminal: false, want: "job timeout", analyze: func(ctx context.Context, _ Packet, _ *ContextProvider) (AnalysisRun, error) {
			<-ctx.Done()
			return AnalysisRun{}, ctx.Err()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeInvestigationStore(checkpoint, []state.ContributionChangeEvent{{Sequence: 3}})
			investigator, err := NewInvestigator(test.analyze, Limits{}, ContextLimits{})
			if err != nil {
				t.Fatal(err)
			}
			worker, err := NewInvestigationWorker(store, investigator, InvestigationWorkerConfig{ID: "worker/test", MaxAttempts: 5, JobTimeout: 20 * time.Millisecond, Sampling: DefaultSamplingPolicy()})
			if err != nil {
				t.Fatal(err)
			}
			err = worker.processSafely(context.Background(), queuedJob(t, 1, request, 0, true))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
			if terminal, retried := store.retried[1]; !retried || terminal != test.terminal {
				t.Fatalf("retried=%v, want terminal=%t", store.retried, test.terminal)
			}
		})
	}
}

func TestKeepLeaseToleratesABriefRenewalFailure(t *testing.T) {
	const lease = 90 * time.Millisecond
	var renewals int
	ctx, cancel := context.WithTimeout(context.Background(), 4*lease)
	defer cancel()
	// One failure in a row is tolerated: the lease is still held at the next attempt.
	err := KeepLease(ctx, lease, func(context.Context) (bool, error) {
		renewals++
		if renewals%2 == 1 {
			return false, errors.New("database unavailable")
		}
		return true, nil
	})
	if err != nil || renewals < 4 {
		t.Fatalf("err=%v renewals=%d", err, renewals)
	}
	// Failing until the lease would expire gives up.
	if err := KeepLease(context.Background(), lease, func(context.Context) (bool, error) {
		return false, errors.New("database unavailable")
	}); err == nil || !strings.Contains(err.Error(), "before it expires") {
		t.Fatalf("persistent renewal failure err=%v", err)
	}
	// A lease owned by another worker is lost at once.
	if err := KeepLease(context.Background(), lease, func(context.Context) (bool, error) { return false, nil }); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("lost lease err=%v", err)
	}
}

func TestInvestigationQueueEnqueuesAndCoalescesRequests(t *testing.T) {
	store := &recordingQueueStore{}
	queue, err := NewInvestigationQueue(store, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewInvestigationRequest(testWindow(1, 2), "changed", []detector.InvestigationSignal{novelty("a", detector.RiskMedium, "checkout")}, IncidentContext{}, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.RecordReasoningEvaluation(context.Background(), Evaluation{Investigation: InvestigationBelowThreshold, Request: &first}); err != nil || store.enqueued != 0 {
		t.Fatalf("non-queued evaluation enqueued=%d err=%v", store.enqueued, err)
	}
	if err := queue.RecordReasoningEvaluation(context.Background(), Evaluation{Investigation: InvestigationQueued, Request: &first}); err != nil || store.enqueued != 1 || store.batchWindow != 30*time.Second {
		t.Fatalf("enqueued=%d err=%v", store.enqueued, err)
	}
	second, err := NewInvestigationRequest(testWindow(3, 3), "unchanged", []detector.InvestigationSignal{novelty("b", detector.RiskHigh, "checkout")}, IncidentContext{}, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	store.existing = &store.last
	if err := queue.RecordReasoningEvaluation(context.Background(), Evaluation{Investigation: InvestigationQueued, Request: &second}); err != nil {
		t.Fatal(err)
	}
	merged, err := DecodeInvestigationRequest(store.merged.Request)
	if err != nil || merged.FirstSequence != 1 || merged.LastSequence != 3 || len(merged.Signals) != 2 || store.merged.RiskRank != detector.RiskHigh.Rank() {
		t.Fatalf("merged = %#v err=%v", merged, err)
	}
}

type recordingQueueStore struct {
	enqueued    int
	batchWindow time.Duration
	last        state.InvestigationJobRecord
	existing    *state.InvestigationJobRecord
	merged      state.InvestigationJobRecord
}

func (store *recordingQueueStore) EnqueueInvestigationJob(_ context.Context, record state.InvestigationJobRecord, batchWindow time.Duration, merge func(state.InvestigationJobRecord) (state.InvestigationJobRecord, bool, error)) (int64, bool, error) {
	store.enqueued++
	store.batchWindow = batchWindow
	if store.existing != nil {
		merged, accepted, err := merge(*store.existing)
		if err != nil || !accepted {
			return 0, false, err
		}
		store.merged = merged
		return 1, true, nil
	}
	store.last = record
	return 1, false, nil
}

func TestServiceRunQueuesInvestigationWithoutCallingModel(t *testing.T) {
	store := &serviceStore{events: []state.ContributionChangeEvent{{Sequence: 1}}, checkpoint: state.GraphCheckpoint{ThroughSequence: 1, View: state.GraphView{SHA256: "graph-1"}}}
	called := false
	service, err := NewService(store, AnalyzerFunc(func(context.Context, Packet, *ContextProvider) (AnalysisRun, error) {
		called = true
		return AnalysisRun{}, nil
	}), nil, ServiceConfig{QueueInvestigations: true, Detection: fixedDetector{signals: []detector.InvestigationSignal{gateSignal("medium", detector.RiskMedium, "")}}, Clock: func() time.Time { return time.Unix(1, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := service.evaluateWindow(context.Background(), &graph.Snapshot{}, 0, evaluateForQueue, IncidentContext{})
	if err != nil {
		t.Fatal(err)
	}
	if called || evaluation.Investigation != InvestigationQueued || evaluation.Request == nil || evaluation.Request.FirstSequence != 1 {
		t.Fatalf("called=%t evaluation=%#v", called, evaluation)
	}
	inline, err := service.EvaluateWindow(context.Background(), &graph.Snapshot{}, 0)
	if err != nil || !called || inline.Investigation != InvestigationInvestigated {
		t.Fatalf("inline evaluation called=%t investigation=%s err=%v", called, inline.Investigation, err)
	}
}
