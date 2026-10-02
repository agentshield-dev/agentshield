package reasoning

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

const InvestigationRequestSchemaVersion = "agentshield.ai/investigation-request/v1alpha1"

const (
	// maxInvestigationSpan matches the change reader's batch limit, so one read covers a request.
	maxInvestigationSpan      = state.MaxInvestigationJobSpan
	maxInvestigationSignals   = 256
	maxInvestigationAnchors   = 1024
	maxScopedIncidentEvents   = 256
	maxScopedIncidentBaseline = 256
)

// InvestigationRequest is what agentic investigation needs from detection. It is
// self-contained so a separate worker can investigate it later against a newer graph.
type InvestigationRequest struct {
	SchemaVersion  string                         `json:"schemaVersion"`
	FirstSequence  uint64                         `json:"firstSequence"`
	LastSequence   uint64                         `json:"lastSequence"`
	TopologyChange string                         `json:"topologyChange"`
	Signals        []detector.InvestigationSignal `json:"signals"`
	Incident       IncidentContext                `json:"incident"`
	DetectedAt     time.Time                      `json:"detectedAt"`
}

// NewInvestigationRequest bounds a window's novelty signals and scopes the incident
// context to their anchors. It requires at least one eligible signal.
func NewInvestigationRequest(window ChangeWindow, topology string, signals []detector.InvestigationSignal, incident IncidentContext, detectedAt time.Time) (InvestigationRequest, error) {
	if len(window.Events) == 0 {
		return InvestigationRequest{}, errors.New("investigation request requires a change window")
	}
	request := InvestigationRequest{
		SchemaVersion: InvestigationRequestSchemaVersion, FirstSequence: window.Events[0].Sequence,
		LastSequence: window.Events[len(window.Events)-1].Sequence, TopologyChange: topology,
		Signals: boundedInvestigationSignals(signals), DetectedAt: detectedAt.UTC(),
	}
	if !slices.ContainsFunc(request.Signals, InvestigationEligible) {
		return InvestigationRequest{}, errors.New("investigation request requires an eligible signal")
	}
	request.Incident = scopeIncident(incident, request.Anchors())
	return request, nil
}

func boundedInvestigationSignals(signals []detector.InvestigationSignal) []detector.InvestigationSignal {
	signals = slices.Clone(signals)
	slices.SortFunc(signals, func(left, right detector.InvestigationSignal) int { return strings.Compare(left.ID, right.ID) })
	signals = slices.CompactFunc(signals, func(left, right detector.InvestigationSignal) bool { return left.ID == right.ID })
	if len(signals) > maxInvestigationSignals {
		slices.SortStableFunc(signals, func(left, right detector.InvestigationSignal) int { return right.Risk.Rank() - left.Risk.Rank() })
		signals = signals[:maxInvestigationSignals]
		slices.SortFunc(signals, func(left, right detector.InvestigationSignal) int { return strings.Compare(left.ID, right.ID) })
	}
	return signals
}

// Anchors returns the sorted anchors of every signal in the request.
func (request InvestigationRequest) Anchors() []string {
	return signalAnchors(request.Signals)
}

// Risk returns the highest signal risk in the request.
func (request InvestigationRequest) Risk() detector.Risk {
	risk := detector.RiskLow
	for _, signal := range request.Signals {
		if signal.Risk.Rank() > risk.Rank() {
			risk = signal.Risk
		}
	}
	return risk
}

// Fingerprint identifies what the request is about, ignoring time windows and
// signal IDs, so a recurrence of the same pattern can be deduplicated.
func (request InvestigationRequest) Fingerprint() string {
	lines := make([]string, 0, len(request.Signals))
	for _, signal := range request.Signals {
		if !InvestigationEligible(signal) {
			continue
		}
		reasons := slices.Clone(signal.Reasons)
		slices.Sort(reasons)
		anchors := slices.Clone(signal.AnchorIDs)
		slices.Sort(anchors)
		lines = append(lines, strings.Join([]string{string(signal.Risk), strings.Join(reasons, ","), strings.Join(anchors, ",")}, "\x00"))
	}
	slices.Sort(lines)
	digest := sha256.Sum256([]byte(strings.Join(slices.Compact(lines), "\x01")))
	return hex.EncodeToString(digest[:])
}

// SampleKey identifies this occurrence, so sampling decisions are stable across
// retries but independent between recurrences of one pattern.
func (request InvestigationRequest) SampleKey() string {
	ids := make([]string, 0, len(request.Signals))
	for _, signal := range request.Signals {
		ids = append(ids, signal.ID)
	}
	slices.Sort(ids)
	digest := sha256.Sum256([]byte(strings.Join(ids, "\x00")))
	return hex.EncodeToString(digest[:])
}

// Record returns the request's storage form.
func (request InvestigationRequest) Record() (state.InvestigationJobRecord, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return state.InvestigationJobRecord{}, fmt.Errorf("encode investigation request: %w", err)
	}
	anchors := request.Anchors()
	if len(anchors) > maxInvestigationAnchors {
		anchors = anchors[:maxInvestigationAnchors]
	}
	return state.InvestigationJobRecord{
		RiskRank: request.Risk().Rank(), AnchorIDs: anchors, Fingerprint: request.Fingerprint(), SampleKey: request.SampleKey(),
		FirstSequence: request.FirstSequence, LastSequence: request.LastSequence, Request: encoded,
	}, nil
}

// DecodeInvestigationRequest decodes and checks a stored request.
func DecodeInvestigationRequest(encoded []byte) (InvestigationRequest, error) {
	var request InvestigationRequest
	if err := json.Unmarshal(encoded, &request); err != nil {
		return InvestigationRequest{}, fmt.Errorf("decode investigation request: %w", err)
	}
	if request.SchemaVersion != InvestigationRequestSchemaVersion {
		return InvestigationRequest{}, fmt.Errorf("unsupported investigation request schema %q", request.SchemaVersion)
	}
	if request.FirstSequence == 0 || request.LastSequence < request.FirstSequence || len(request.Signals) == 0 {
		return InvestigationRequest{}, errors.New("investigation request requires signals and an ordered sequence range")
	}
	return request, nil
}

// MergeInvestigationRequests batches next into existing. It declines when the
// combined change range exceeds one change-reader batch.
func MergeInvestigationRequests(existing, next InvestigationRequest) (InvestigationRequest, bool) {
	first, last := min(existing.FirstSequence, next.FirstSequence), max(existing.LastSequence, next.LastSequence)
	if last-first+1 > maxInvestigationSpan {
		return InvestigationRequest{}, false
	}
	merged := InvestigationRequest{
		SchemaVersion: InvestigationRequestSchemaVersion, FirstSequence: first, LastSequence: last,
		TopologyChange: mergeTopology(existing.TopologyChange, next.TopologyChange),
		Signals:        boundedInvestigationSignals(append(slices.Clone(existing.Signals), next.Signals...)),
		DetectedAt:     existing.DetectedAt,
	}
	if next.DetectedAt.Before(merged.DetectedAt) {
		merged.DetectedAt = next.DetectedAt
	}
	merged.Incident = scopeIncident(mergeIncidents(existing.Incident, next.Incident), merged.Anchors())
	return merged, true
}

func mergeTopology(left, right string) string {
	switch {
	case left == "changed" || right == "changed":
		return "changed"
	case left == right:
		return left
	case left == "unknown" || right == "unknown":
		return "unknown"
	default:
		return right
	}
}

func mergeIncidents(left, right IncidentContext) IncidentContext {
	if left.SchemaVersion == "" {
		return right
	}
	if right.SchemaVersion == "" {
		return left
	}
	merged := right
	if left.EvaluationAt.After(right.EvaluationAt) {
		merged.EvaluationAt = left.EvaluationAt
	}
	baselines := make(map[string]BehaviorBaseline)
	for _, item := range append(slices.Clone(left.Baseline), right.Baseline...) {
		if existing, found := baselines[item.ID]; !found || item.LastObservedAt.After(existing.LastObservedAt) {
			baselines[item.ID] = item
		}
	}
	merged.Baseline = merged.Baseline[:0:0]
	for _, item := range baselines {
		merged.Baseline = append(merged.Baseline, item)
	}
	events := make(map[string]IncidentEvent)
	for _, item := range append(slices.Clone(left.Timeline), right.Timeline...) {
		events[item.ID] = item
	}
	merged.Timeline = merged.Timeline[:0:0]
	for _, item := range events {
		merged.Timeline = append(merged.Timeline, item)
	}
	return merged
}

// scopeIncident keeps the incident facts that touch the anchors, bounded to the
// most recent events and baselines, in canonical order.
func scopeIncident(incident IncidentContext, anchors []string) IncidentContext {
	if incident.SchemaVersion == "" {
		return incident
	}
	anchorSet := make(map[string]struct{}, len(anchors))
	for _, anchor := range anchors {
		anchorSet[anchor] = struct{}{}
	}
	touches := func(subject, object string) bool {
		_, subjectFound := anchorSet[subject]
		_, objectFound := anchorSet[object]
		return subjectFound || objectFound
	}
	scoped := incident
	scoped.Baseline, scoped.Timeline = nil, nil
	for _, item := range incident.Baseline {
		if touches(item.SubjectID, item.ObjectID) {
			scoped.Baseline = append(scoped.Baseline, item)
		}
	}
	for _, item := range incident.Timeline {
		if touches(item.SubjectID, item.ObjectID) {
			scoped.Timeline = append(scoped.Timeline, item)
		}
	}
	if len(scoped.Baseline) > maxScopedIncidentBaseline {
		slices.SortFunc(scoped.Baseline, func(left, right BehaviorBaseline) int {
			if order := right.LastObservedAt.Compare(left.LastObservedAt); order != 0 {
				return order
			}
			return strings.Compare(left.ID, right.ID)
		})
		scoped.Baseline = scoped.Baseline[:maxScopedIncidentBaseline]
	}
	slices.SortFunc(scoped.Baseline, func(left, right BehaviorBaseline) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(scoped.Timeline, func(left, right IncidentEvent) int {
		if order := left.ObservedAt.Compare(right.ObservedAt); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	if len(scoped.Timeline) > maxScopedIncidentEvents {
		scoped.Timeline = slices.Clone(scoped.Timeline[len(scoped.Timeline)-maxScopedIncidentEvents:])
	}
	return scoped
}

// Investigator runs agentic investigation of one request against a graph checkpoint.
type Investigator struct {
	analyzer      Analyzer
	packetLimits  Limits
	contextLimits ContextLimits
}

type InvestigationRun struct {
	Packet   Packet
	Analysis AnalysisRun
}

func NewInvestigator(analyzer Analyzer, packetLimits Limits, contextLimits ContextLimits) (*Investigator, error) {
	if analyzer == nil {
		return nil, errors.New("investigation analyzer is required")
	}
	if packetLimits == (Limits{}) {
		packetLimits = DefaultLimits()
	}
	if contextLimits == (ContextLimits{}) {
		contextLimits = DefaultContextLimits()
	}
	return &Investigator{analyzer: analyzer, packetLimits: packetLimits, contextLimits: contextLimits}, nil
}

// Investigate builds the packet from the request's change events and the given
// checkpoint, which may be newer than the window that produced the request.
func (investigator *Investigator) Investigate(ctx context.Context, request InvestigationRequest, events []state.ContributionChangeEvent, checkpoint state.GraphCheckpoint, evaluationTime time.Time) (InvestigationRun, error) {
	packet, _, err := buildPacket(events, checkpoint, request.TopologyChange, false, request.Signals, evaluationTime, investigator.packetLimits)
	if err != nil {
		return InvestigationRun{}, err
	}
	snapshot := checkpoint.View.Snapshot
	telemetry := PinSnapshotTelemetry(packet, snapshot, len(snapshot.Telemetry))
	provider, err := NewContextProviderWithSnapshot(packet, snapshot, telemetry, request.Incident, investigator.contextLimits)
	if err != nil {
		return InvestigationRun{}, err
	}
	analysis, err := investigator.analyzer.Analyze(ctx, packet, provider)
	if err != nil {
		return InvestigationRun{Packet: packet, Analysis: analysis}, err
	}
	return InvestigationRun{Packet: packet, Analysis: analysis}, nil
}

// RetainPresentAnchors drops anchors that are no longer in the checkpoint's graph
// and signals left with none. A request with no remaining eligible signal is stale.
func (request InvestigationRequest) RetainPresentAnchors(checkpoint state.GraphCheckpoint) InvestigationRequest {
	request.Signals = retainPresentAnchors(request.Signals, checkpoint)
	return request
}

func retainPresentAnchors(signals []detector.InvestigationSignal, checkpoint state.GraphCheckpoint) []detector.InvestigationSignal {
	present := make(map[string]struct{}, len(checkpoint.View.Snapshot.Resources))
	for _, resource := range checkpoint.View.Snapshot.Resources {
		present[resource.ID] = struct{}{}
	}
	result := make([]detector.InvestigationSignal, 0, len(signals))
	for _, signal := range signals {
		anchors := make([]string, 0, len(signal.AnchorIDs))
		for _, anchor := range signal.AnchorIDs {
			if _, found := present[anchor]; found {
				anchors = append(anchors, anchor)
			}
		}
		if len(anchors) == 0 {
			continue
		}
		signal.AnchorIDs = anchors
		result = append(result, signal)
	}
	return result
}

// SamplingPolicy bounds agentic investigation spend. High and critical requests
// bypass rate sampling and wait, rather than drop, when the hourly budget is spent.
type SamplingPolicy struct {
	// SampleRate is the fraction of medium-risk requests investigated, from 0 to 1.
	SampleRate float64
	// MaxPerHour caps investigations started in any trailing hour; zero is unlimited.
	MaxPerHour int
	// DedupWindow skips a request whose fingerprint was investigated within the window; zero disables it.
	DedupWindow time.Duration
	// BudgetDeferral is how long an over-budget high or critical request waits before retrying.
	BudgetDeferral time.Duration
}

func DefaultSamplingPolicy() SamplingPolicy {
	return SamplingPolicy{SampleRate: 1, DedupWindow: time.Hour, BudgetDeferral: time.Minute}
}

func (policy SamplingPolicy) validate() error {
	if policy.SampleRate < 0 || policy.SampleRate > 1 {
		return errors.New("investigation sample rate must be between 0 and 1")
	}
	if policy.MaxPerHour < 0 || policy.DedupWindow < 0 || policy.BudgetDeferral < 0 {
		return errors.New("investigation budget, dedup window, and deferral must not be negative")
	}
	return nil
}

// Sampled reports whether rate sampling keeps a request. The decision is a
// deterministic function of the request's sample key.
func (policy SamplingPolicy) Sampled(request InvestigationRequest) bool {
	if request.Risk().Rank() >= detector.RiskHigh.Rank() || policy.SampleRate >= 1 {
		return true
	}
	if policy.SampleRate <= 0 {
		return false
	}
	key, err := hex.DecodeString(request.SampleKey())
	if err != nil || len(key) < 8 {
		return true
	}
	return float64(binary.BigEndian.Uint64(key[:8]))/float64(^uint64(0)) < policy.SampleRate
}

func (policy SamplingPolicy) admission() state.InvestigationAdmission {
	return state.InvestigationAdmission{
		DedupWindow: policy.DedupWindow, MaxPerHour: policy.MaxPerHour,
		DeferRiskRank: detector.RiskHigh.Rank(), DeferFor: policy.BudgetDeferral,
	}
}
