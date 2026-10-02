package reasoning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// SchemaVersion identifies the packet encoding sent to the model.
const SchemaVersion = "agentshield.ai/change-analysis/v1alpha1"

// Bounds on descriptive attributes and names copied into model context. They
// keep one resource from dominating the packet and limit what an untrusted
// attribute value can inject.
const (
	maxModelAttributes     = 32
	maxModelAttributeKey   = 128
	maxModelAttributeValue = 512
	maxModelResourceNames  = 8
	maxModelResourceName   = 256
)

// Limits bounds each collection in an initial packet. Omitted counts are
// reported in [Packet.Truncated]. A zero Changes uses the default.
type Limits struct {
	Resources     int
	Relationships int
	Facets        int
	Telemetry     int
	Changes       int
}

// DefaultLimits returns the packet bounds used by the service.
func DefaultLimits() Limits {
	return Limits{Resources: 100, Relationships: 250, Facets: 250, Telemetry: 100, Changes: 500}
}

// Packet is the canonical, model-facing description of one change window.
//
// AnalysisID is the SHA-256 of the packet's canonical encoding without the ID,
// so the same events, checkpoint, signals, and evaluation time always produce
// the same ID. Together with HydratedGraphSHA256 and TelemetryWindow it pins
// later retrieval to the analyzed state.
//
// Changes come from the trigger window; Resources come from the hydrated
// checkpoint, and Relationships and Facets are those touching the packet's
// resources, all bounded by [Limits]. Telemetry,
// IncidentEvents, and Baselines are empty in an initial packet and are filled
// only by [MergeContext] from retrieval results.
type Packet struct {
	SchemaVersion           string                         `json:"schemaVersion"`
	AnalysisID              string                         `json:"analysisId"`
	TriggerFirstSequence    uint64                         `json:"triggerFirstSequence"`
	TriggerLastSequence     uint64                         `json:"triggerLastSequence"`
	HydratedAtSequence      uint64                         `json:"hydratedAtSequence"`
	Baseline                bool                           `json:"baseline"`
	HydratedGraphSHA256     string                         `json:"hydratedGraphSha256"`
	EvaluationTime          time.Time                      `json:"evaluationTime"`
	TopologyChange          string                         `json:"topologyChange"`
	AvailableContext        []string                       `json:"availableContext,omitempty"`
	ContextReceipts         []ContextReceipt               `json:"contextReceipts,omitempty"`
	SuggestedContextAnchors []string                       `json:"suggestedContextAnchors,omitempty"`
	TelemetryWindow         *detector.TimeWindow           `json:"telemetryWindow,omitempty"`
	Signals                 []detector.InvestigationSignal `json:"signals,omitempty"`
	Changes                 []Change                       `json:"changes"`
	Resources               []Resource                     `json:"resources"`
	Relationships           []Relationship                 `json:"relationships"`
	Facets                  []Facet                        `json:"facets"`
	Telemetry               []Telemetry                    `json:"telemetry"`
	IncidentEvents          []IncidentEvent                `json:"incidentEvents,omitempty"`
	Baselines               []BehaviorBaseline             `json:"baselines,omitempty"`
	Truncated               map[string]int                 `json:"truncated,omitempty"`
}

// Change is one non-telemetry assertion added or retracted in the trigger
// window.
type Change struct {
	Sequence      uint64              `json:"sequence"`
	Operation     string              `json:"operation"`
	AssertionType string              `json:"assertionType"`
	AssertionID   string              `json:"assertionId"`
	Entity        state.EntityLocator `json:"entity"`
}

// Resource is a graph resource as shown to the model, with bounded
// descriptive attributes and names. Names and attributes are untrusted
// evidence, not authoritative classifications.
type Resource struct {
	ID         string              `json:"id"`
	Kind       string              `json:"kind"`
	Names      []string            `json:"names,omitempty"`
	Attributes map[string]string   `json:"attributes,omitempty"`
	Identity   graph.IdentityClaim `json:"identity,omitempty"`
}

// Relationship is a resolved graph relationship with its decoded security
// semantics and opaque evidence handles.
type Relationship struct {
	ID                string                    `json:"id"`
	SubjectID         string                    `json:"subjectId"`
	Predicate         graph.Predicate           `json:"predicate"`
	ObjectID          string                    `json:"objectId"`
	SecuritySemantics []graph.SecuritySemantics `json:"securitySemantics,omitempty"`
	EvidenceIDs       []string                  `json:"evidenceIds,omitempty"`
}

// Facet is a resolved graph facet with bounded attributes, decoded security
// semantics, and opaque evidence handles.
type Facet struct {
	ID                string                    `json:"id"`
	ResourceID        string                    `json:"resourceId"`
	Kind              string                    `json:"kind"`
	Key               string                    `json:"key,omitempty"`
	Attributes        map[string]string         `json:"attributes,omitempty"`
	SecuritySemantics []graph.SecuritySemantics `json:"securitySemantics,omitempty"`
	EvidenceIDs       []string                  `json:"evidenceIds,omitempty"`
}

// Telemetry is one retrieved telemetry rollup with allowlisted properties
// and opaque evidence handles.
type Telemetry struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	SubjectID   string            `json:"subjectId"`
	ObjectID    string            `json:"objectId"`
	Operation   string            `json:"operation,omitempty"`
	Outcome     string            `json:"outcome,omitempty"`
	Coverage    string            `json:"coverage,omitempty"`
	Count       uint64            `json:"count"`
	Properties  map[string]string `json:"properties,omitempty"`
	EvidenceIDs []string          `json:"evidenceIds,omitempty"`
}

// BuildPacket builds a baseline packet: the window is treated as the
// reference state, so it is suppressed rather than analyzed.
func BuildPacket(events []state.ContributionChangeEvent, checkpoint state.GraphCheckpoint, evaluationTime time.Time, limits Limits) (Packet, []byte, error) {
	return buildPacket(events, checkpoint, topologyChange(nil, checkpoint.View.Snapshot, true), true, nil, evaluationTime, limits)
}

// BuildPacketWithPrevious builds a non-baseline packet without signals, which
// is suppressed before any model request.
func BuildPacketWithPrevious(events []state.ContributionChangeEvent, checkpoint state.GraphCheckpoint, previous graph.Snapshot, evaluationTime time.Time, limits Limits) (Packet, []byte, error) {
	return buildPacket(events, checkpoint, topologyChange(&previous, checkpoint.View.Snapshot, false), false, nil, evaluationTime, limits)
}

// BuildPacketWithSignals builds the packet for a window. events must be
// non-empty and contiguous by sequence. When the checkpoint exceeds the
// resource limit, resources anchored by a signal are kept first, then
// resources touched by a change; if they alone exceed the limit, the rest are
// left out and counted as truncated "requiredResources". It is an error if a
// signal anchor is absent from the checkpoint. The returned bytes are the
// canonical encoding including AnalysisID.
func BuildPacketWithSignals(events []state.ContributionChangeEvent, checkpoint state.GraphCheckpoint, previous *graph.Snapshot, baseline bool, signals []detector.InvestigationSignal, evaluationTime time.Time, limits Limits) (Packet, []byte, error) {
	return buildPacket(events, checkpoint, topologyChange(previous, checkpoint.View.Snapshot, baseline), baseline, signals, evaluationTime, limits)
}

// buildPacket takes the topology classification precomputed against the window's
// previous graph, so an investigation can hydrate a newer checkpoint later.
func buildPacket(events []state.ContributionChangeEvent, checkpoint state.GraphCheckpoint, topology string, baseline bool, signals []detector.InvestigationSignal, evaluationTime time.Time, limits Limits) (Packet, []byte, error) {
	if len(events) == 0 {
		return Packet{}, nil, errors.New("reasoning packet requires at least one contribution change")
	}
	if limits.Changes == 0 {
		limits.Changes = DefaultLimits().Changes
	}
	if limits.Resources < 1 || limits.Relationships < 1 || limits.Facets < 1 || limits.Telemetry < 1 || limits.Changes < 1 {
		return Packet{}, nil, errors.New("reasoning packet limits must be positive")
	}
	for index, event := range events {
		if index > 0 && event.Sequence != events[index-1].Sequence+1 {
			return Packet{}, nil, fmt.Errorf("reasoning packet change sequence is not contiguous at %d", event.Sequence)
		}
	}
	packet := Packet{
		SchemaVersion: SchemaVersion, TriggerFirstSequence: events[0].Sequence,
		TriggerLastSequence: events[len(events)-1].Sequence, HydratedAtSequence: checkpoint.ThroughSequence,
		Baseline: baseline, HydratedGraphSHA256: checkpoint.View.SHA256,
		EvaluationTime: evaluationTime.UTC(), Truncated: make(map[string]int),
	}
	packet.Signals = append([]detector.InvestigationSignal(nil), signals...)
	slices.SortFunc(packet.Signals, func(left, right detector.InvestigationSignal) int { return strings.Compare(left.ID, right.ID) })
	packet.TopologyChange = topology
	packet.Changes = boundedChanges(events, limits.Changes, packet.Truncated)
	snapshot := checkpoint.View.Snapshot
	roles := resourceRoles(snapshot)
	requiredIDs := requiredResourceIDs(snapshot.Resources, packet.Changes, packet.Signals)
	resources, err := boundedResources(snapshot.Resources, requiredIDs, limits.Resources, packet.Truncated)
	if err != nil {
		return Packet{}, nil, err
	}
	required := make(map[string]struct{}, len(requiredIDs))
	for _, resourceID := range requiredIDs {
		required[resourceID] = struct{}{}
	}
	included := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		included[resource.ID] = struct{}{}
	}
	for _, resource := range resources {
		attributes := resourceAttributes(resource.Assertions)
		if role := roles[resource.ID]; role != "" {
			if attributes == nil {
				attributes = make(map[string]string)
			}
			attributes["network/role"] = role
		}
		packet.Resources = append(packet.Resources, Resource{
			ID: resource.ID, Kind: resource.Kind, Names: resourceNames(resource.Assertions), Attributes: attributes, Identity: resource.Identity,
		})
	}
	// Relationships and facets are chosen by how close they are to the change:
	// those of required resources first, then those of other included
	// resources. Facts touching no included resource are not part of the window.
	relationshipTier := func(relationship graph.Relationship) int {
		if relationship.ResolutionStatus == graph.ResolutionUnresolved {
			return -1
		}
		_, subjectRequired := required[relationship.SubjectID]
		_, objectRequired := required[relationship.ObjectID]
		_, subjectIncluded := included[relationship.SubjectID]
		_, objectIncluded := included[relationship.ObjectID]
		switch {
		case subjectRequired && objectRequired:
			return 0
		case subjectRequired || objectRequired:
			return 1
		case subjectIncluded || objectIncluded:
			return 2
		default:
			return -1
		}
	}
	for _, relationship := range boundedByTier(snapshot.Relationships, relationshipTier, limits.Relationships, packet.Truncated, "relationships") {
		semantics, err := relationshipSecuritySemantics(relationship.Assertions)
		if err != nil {
			return Packet{}, nil, fmt.Errorf("relationship %s security semantics: %w", relationship.ID, err)
		}
		packet.Relationships = append(packet.Relationships, Relationship{
			ID: relationship.ID, SubjectID: relationship.SubjectID, Predicate: relationship.Predicate,
			ObjectID: relationship.ObjectID, SecuritySemantics: semantics, EvidenceIDs: opaqueEvidence(relationshipEvidence(relationship)),
		})
	}
	facetTier := func(facet graph.Facet) int {
		if facet.ResolutionStatus == graph.ResolutionUnresolved {
			return -1
		}
		if _, ok := required[facet.ResourceID]; ok {
			return 0
		}
		if _, ok := included[facet.ResourceID]; ok {
			return 1
		}
		return -1
	}
	for _, facet := range boundedByTier(snapshot.Facets, facetTier, limits.Facets, packet.Truncated, "facets") {
		semantics, err := facetSecuritySemantics(facet.Assertions)
		if err != nil {
			return Packet{}, nil, fmt.Errorf("facet %s security semantics: %w", facet.ID, err)
		}
		packet.Facets = append(packet.Facets, Facet{
			ID: facet.ID, ResourceID: facet.ResourceID, Kind: facet.Kind, Key: facet.Key,
			Attributes:        facetAttributes(facet.Assertions),
			SecuritySemantics: semantics, EvidenceIDs: opaqueEvidence(facetEvidence(facet)),
		})
	}
	if len(packet.Signals) > 0 {
		packet.AvailableContext = slices.Clone(contextTemplates)
		packet.TelemetryWindow = signalWindow(packet.Signals)
		packet.SuggestedContextAnchors = signalAnchors(packet.Signals)
	}
	if len(packet.Truncated) == 0 {
		packet.Truncated = nil
	}
	canonical, err := canonicalPacket(packet)
	if err != nil {
		return Packet{}, nil, err
	}
	digest := sha256.Sum256(canonical)
	packet.AnalysisID = "sha256:" + hex.EncodeToString(digest[:])
	canonical, err = canonicalPacket(packet)
	if err != nil {
		return Packet{}, nil, err
	}
	return packet, canonical, nil
}

func signalAnchors(signals []detector.InvestigationSignal) []string {
	var anchors []string
	for _, signal := range signals {
		anchors = append(anchors, signal.AnchorIDs...)
	}
	slices.Sort(anchors)
	return slices.Compact(anchors)
}

// requiredResourceIDs returns the signal anchors, sorted, followed by the
// other present resources touched by a change, sorted. The order is the
// priority used when they exceed the resource limit.
func requiredResourceIDs(resources []graph.Resource, changes []Change, signals []detector.InvestigationSignal) []string {
	available := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		available[resource.ID] = struct{}{}
	}
	anchors := signalAnchors(signals)
	anchored := make(map[string]struct{}, len(anchors))
	for _, anchor := range anchors {
		anchored[anchor] = struct{}{}
	}
	var changed []string
	for _, change := range changes {
		candidates := []string{change.Entity.ResourceID, change.Entity.SubjectID, change.Entity.ObjectID}
		if change.AssertionType == "resource" {
			candidates = append(candidates, change.Entity.ID)
		}
		for _, resourceID := range candidates {
			_, present := available[resourceID]
			_, isAnchor := anchored[resourceID]
			if present && !isAnchor {
				changed = append(changed, resourceID)
			}
		}
	}
	slices.Sort(changed)
	return append(anchors, slices.Compact(changed)...)
}

// boundedChanges lists the window's non-telemetry assertion changes in
// sequence order, keeping the first limit.
func boundedChanges(events []state.ContributionChangeEvent, limit int, truncated map[string]int) []Change {
	var changes []Change
	omitted := 0
	add := func(sequence uint64, operation string, change state.AssertionChange) {
		if change.AssertionType == "telemetry" {
			return
		}
		if len(changes) == limit {
			omitted++
			return
		}
		changes = append(changes, packetChange(sequence, operation, change))
	}
	for _, event := range events {
		for _, change := range event.Added {
			add(event.Sequence, "added", change)
		}
		for _, change := range event.Retracted {
			add(event.Sequence, "retracted", change)
		}
	}
	if omitted > 0 {
		truncated["changes"] = omitted
	}
	return changes
}

func signalWindow(signals []detector.InvestigationSignal) *detector.TimeWindow {
	if len(signals) == 0 {
		return nil
	}
	window := detector.TimeWindow{Start: signals[0].Window.Start, End: signals[0].Window.End}
	for _, signal := range signals[1:] {
		if signal.Window.Start.Before(window.Start) {
			window.Start = signal.Window.Start
		}
		if signal.Window.End.After(window.End) {
			window.End = signal.Window.End
		}
	}
	return &window
}

func parseTelemetryTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	return parsed.UTC(), err == nil
}

func topologyChange(previous *graph.Snapshot, current graph.Snapshot, baseline bool) string {
	if baseline {
		return "baseline"
	}
	if previous == nil {
		return "unknown"
	}
	if topologyFingerprint(*previous) == topologyFingerprint(current) {
		return "unchanged"
	}
	return "changed"
}

func topologyFingerprint(snapshot graph.Snapshot) string {
	type topologyResource struct {
		ID         string
		Kind       string
		Attributes map[string]string
	}
	type topologyRelationship struct {
		ID                string
		SubjectID         string
		Predicate         graph.Predicate
		ObjectID          string
		SecuritySemantics []string
	}
	type topologyFacet struct {
		ID                string
		ResourceID        string
		Kind              string
		SecuritySemantics []string
	}
	resources := make([]topologyResource, 0, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		if resource.Kind == "network/destination" {
			continue
		}
		resources = append(resources, topologyResource{ID: resource.ID, Kind: resource.Kind, Attributes: resourceAttributes(resource.Assertions)})
	}
	relationships := make([]topologyRelationship, 0, len(snapshot.Relationships))
	for _, relationship := range snapshot.Relationships {
		if relationship.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		relationships = append(relationships, topologyRelationship{
			ID: relationship.ID, SubjectID: relationship.SubjectID, Predicate: relationship.Predicate, ObjectID: relationship.ObjectID,
			SecuritySemantics: relationshipSecurityPayloads(relationship.Assertions),
		})
	}
	facets := make([]topologyFacet, 0, len(snapshot.Facets))
	for _, facet := range snapshot.Facets {
		if facet.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		facets = append(facets, topologyFacet{ID: facet.ID, ResourceID: facet.ResourceID, Kind: facet.Kind, SecuritySemantics: facetSecurityPayloads(facet.Assertions)})
	}
	slices.SortFunc(resources, func(left, right topologyResource) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(relationships, func(left, right topologyRelationship) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(facets, func(left, right topologyFacet) int { return strings.Compare(left.ID, right.ID) })
	encoded, _ := json.Marshal(struct {
		Resources     []topologyResource
		Relationships []topologyRelationship
		Facets        []topologyFacet
	}{resources, relationships, facets})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func telemetryTime(event graph.TelemetryEvent) (time.Time, bool) {
	value := strings.TrimSpace(event.Properties["telemetry/first-seen"])
	if value == "" {
		return time.Time{}, false
	}
	return parseTelemetryTime(value)
}

func packetChange(sequence uint64, operation string, change state.AssertionChange) Change {
	return Change{Sequence: sequence, Operation: operation, AssertionType: change.AssertionType, AssertionID: change.AssertionID, Entity: change.Entity}
}

// boundedByTier keeps the values tier assigns a non-negative tier, lower
// tiers first, up to limit, in their original order. Kept-tier values left out
// by the limit are counted under key.
func boundedByTier[T any](values []T, tier func(T) int, limit int, truncated map[string]int, key string) []T {
	type ranked struct{ index, tier int }
	candidates := make([]ranked, 0, len(values))
	for index, value := range values {
		if rank := tier(value); rank >= 0 {
			candidates = append(candidates, ranked{index: index, tier: rank})
		}
	}
	if len(candidates) > limit {
		slices.SortStableFunc(candidates, func(left, right ranked) int { return left.tier - right.tier })
		truncated[key] = len(candidates) - limit
		candidates = candidates[:limit]
		slices.SortFunc(candidates, func(left, right ranked) int { return left.index - right.index })
	}
	result := make([]T, 0, len(candidates))
	for _, candidate := range candidates {
		result = append(result, values[candidate.index])
	}
	return result
}

func boundedResources(values []graph.Resource, requiredIDs []string, limit int, truncated map[string]int) ([]graph.Resource, error) {
	if len(values) <= limit {
		return values, nil
	}
	// A window can touch more resources than the limit, such as a large
	// rollout; keep the highest-priority ones and record the rest.
	if len(requiredIDs) > limit {
		truncated["requiredResources"] = len(requiredIDs) - limit
		requiredIDs = requiredIDs[:limit]
	}
	required := make(map[string]struct{}, len(requiredIDs))
	for _, resourceID := range requiredIDs {
		required[resourceID] = struct{}{}
	}
	result := make([]graph.Resource, 0, limit)
	found := make(map[string]struct{}, len(requiredIDs))
	for _, resource := range values {
		if _, ok := required[resource.ID]; ok {
			result = append(result, resource)
			found[resource.ID] = struct{}{}
		}
	}
	for _, resourceID := range requiredIDs {
		if _, ok := found[resourceID]; !ok {
			return nil, fmt.Errorf("reasoning packet signal anchor %q is absent from the graph snapshot", resourceID)
		}
	}
	for _, resource := range values {
		if len(result) == limit {
			break
		}
		if _, ok := required[resource.ID]; !ok {
			result = append(result, resource)
		}
	}
	truncated["resources"] = len(values) - limit
	return result, nil
}

func relationshipEvidence(relationship graph.Relationship) []string {
	var result []string
	for _, assertion := range relationship.Assertions {
		result = append(result, assertion.EvidenceIDs...)
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func facetEvidence(facet graph.Facet) []string {
	var result []string
	for _, assertion := range facet.Assertions {
		result = append(result, assertion.EvidenceIDs...)
	}
	slices.Sort(result)
	return slices.Compact(result)
}

// opaqueEvidence replaces evidence IDs with digests. Provider evidence IDs can
// embed native names or paths; the model only needs stable handles it can
// cite, and validation compares handles, not raw IDs.
func opaqueEvidence(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		digest := sha256.Sum256([]byte(value))
		result = append(result, "evidence:sha256:"+hex.EncodeToString(digest[:]))
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func resourceAttributes(assertions []graph.ResourceAssertion) map[string]string {
	payloads := make([]map[string]string, 0, len(assertions))
	for _, assertion := range assertions {
		payloads = append(payloads, assertion.Attributes)
	}
	return modelAttributes(payloads)
}

func resourceNames(assertions []graph.ResourceAssertion) []string {
	result := make([]string, 0, len(assertions))
	for _, assertion := range assertions {
		name := strings.TrimSpace(assertion.DisplayName)
		if name != "" && len(name) <= maxModelResourceName {
			result = append(result, name)
		}
	}
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) > maxModelResourceNames {
		result = result[:maxModelResourceNames]
	}
	return result
}

func facetSecuritySemantics(assertions []graph.FacetAssertion) ([]graph.SecuritySemantics, error) {
	payloads := make([]map[string]string, 0, len(assertions))
	for _, assertion := range assertions {
		payloads = append(payloads, assertion.Attributes)
	}
	return decodeSecuritySemantics(payloads)
}

func facetAttributes(assertions []graph.FacetAssertion) map[string]string {
	payloads := make([]map[string]string, 0, len(assertions))
	for _, assertion := range assertions {
		payloads = append(payloads, assertion.Attributes)
	}
	return modelAttributes(payloads)
}

// modelAttributes merges assertion attributes for model context. A key whose
// assertions disagree is dropped rather than resolved, because choosing one
// provider's value would present a contested fact as settled. Security
// semantics are carried separately in decoded form.
func modelAttributes(payloads []map[string]string) map[string]string {
	values := make(map[string]string)
	conflicts := make(map[string]struct{})
	for _, payload := range payloads {
		for key, value := range payload {
			if key == graph.SecuritySemanticsAttribute || !modelAttributeAllowed(key, value) {
				continue
			}
			if existing, ok := values[key]; ok && existing != value {
				delete(values, key)
				conflicts[key] = struct{}{}
				continue
			}
			if _, conflicted := conflicts[key]; !conflicted {
				values[key] = value
			}
		}
	}
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if len(keys) > maxModelAttributes {
		keys = keys[:maxModelAttributes]
	}
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		result[key] = values[key]
	}
	return result
}

// modelAttributeAllowed rejects empty or oversized attributes and any key
// that names credential material. Matching is by key substring, so it errs
// toward dropping descriptive attributes rather than sending a secret.
func modelAttributeAllowed(key, value string) bool {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" || len(key) > maxModelAttributeKey || len(value) > maxModelAttributeValue {
		return false
	}
	lower := strings.ToLower(key)
	for _, sensitive := range []string{"password", "credential", "private-key", "private_key", "authorization", "cookie", "api-key", "api_key", "access-key", "access_key", "token"} {
		if strings.Contains(lower, sensitive) {
			return false
		}
	}
	return true
}

func relationshipSecuritySemantics(assertions []graph.RelationshipAssertion) ([]graph.SecuritySemantics, error) {
	payloads := make([]map[string]string, 0, len(assertions))
	for _, assertion := range assertions {
		payloads = append(payloads, assertion.Properties)
	}
	return decodeSecuritySemantics(payloads)
}

func decodeSecuritySemantics(payloads []map[string]string) ([]graph.SecuritySemantics, error) {
	unique := make(map[string]graph.SecuritySemantics)
	for _, payload := range payloads {
		semantics, err := graph.DecodeSecuritySemantics(payload)
		if err != nil {
			return nil, err
		}
		if semantics == nil {
			continue
		}
		encoded, err := graph.EncodeSecuritySemantics(*semantics)
		if err != nil {
			return nil, err
		}
		unique[encoded] = *semantics
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]graph.SecuritySemantics, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result, nil
}

func facetSecurityPayloads(assertions []graph.FacetAssertion) []string {
	payloads := make([]string, 0, len(assertions))
	for _, assertion := range assertions {
		if payload := assertion.Attributes[graph.SecuritySemanticsAttribute]; payload != "" {
			payloads = append(payloads, payload)
		}
	}
	slices.Sort(payloads)
	return slices.Compact(payloads)
}

func relationshipSecurityPayloads(assertions []graph.RelationshipAssertion) []string {
	payloads := make([]string, 0, len(assertions))
	for _, assertion := range assertions {
		if payload := assertion.Properties[graph.SecuritySemanticsAttribute]; payload != "" {
			payloads = append(payloads, payload)
		}
	}
	slices.Sort(payloads)
	return slices.Compact(payloads)
}

// resourceRoles maps resource IDs to their network/role, propagating a role to
// network/destination resources whose IP or DNS identity matches an address
// of a role-bearing resource.
func resourceRoles(snapshot graph.Snapshot) map[string]string {
	roles := make(map[string]string)
	addressRoles := make(map[string]string)
	for _, resource := range snapshot.Resources {
		for _, assertion := range resource.Assertions {
			role := assertion.Attributes["network/role"]
			if role == "" {
				continue
			}
			roles[resource.ID] = role
			var addresses []string
			if json.Unmarshal([]byte(assertion.Attributes["network/addresses"]), &addresses) == nil {
				for _, address := range addresses {
					addressRoles[address] = role
					addressRoles["ip/"+address] = role
					addressRoles["dns/"+address] = role
				}
			}
		}
	}
	for _, resource := range snapshot.Resources {
		if resource.Kind != "network/destination" {
			continue
		}
		if role := addressRoles[resource.Identity.ImmutableKey]; role != "" {
			roles[resource.ID] = role
		}
	}
	return roles
}

// telemetryProperties forwards only an allowlist of low-sensitivity
// properties. Other telemetry properties can carry request content or
// credentials and stay in the telemetry sink.
func telemetryProperties(properties map[string]string) map[string]string {
	allowed := map[string]struct{}{
		"authenticated": {}, "destination-port": {}, "direction": {}, "method": {}, "protocol": {},
		"response-code": {}, "source-port": {}, "telemetry/first-seen": {}, "telemetry/last-seen": {},
	}
	result := make(map[string]string)
	for key, value := range properties {
		if _, ok := allowed[key]; ok {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func canonicalPacket(packet Packet) ([]byte, error) {
	encoded, err := json.Marshal(packet)
	if err != nil {
		return nil, fmt.Errorf("encode canonical reasoning packet: %w", err)
	}
	return encoded, nil
}
