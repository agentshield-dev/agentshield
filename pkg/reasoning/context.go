package reasoning

import (
	"errors"
	"fmt"
	"slices"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// Context templates accepted by [ContextProvider.Query]. Each MCP tool in
// pkg/reasoning/mcpserver maps to exactly one template.
const (
	TemplateSecurityNeighborhood = "security_neighborhood"
	TemplateTelemetryChain       = "telemetry_chain"
	TemplateGovernancePosture    = "governance_posture"
	TemplateGraphPath            = "graph_path"
	TemplateIncidentTimeline     = "incident_timeline"
	TemplateBehaviorBaseline     = "behavior_baseline"
)

var contextTemplates = []string{
	TemplateSecurityNeighborhood, TemplateTelemetryChain, TemplateGovernancePosture,
	TemplateGraphPath, TemplateIncidentTimeline, TemplateBehaviorBaseline,
}

// Context result closures.
const (
	// ClosureUntruncated means every match in the pinned graph view fit within
	// the query bounds. It does not establish source readiness, freshness,
	// observation coverage, or global graph completeness.
	ClosureUntruncated = "untruncated"
	// ClosureTruncated means at least one collection hit its bound. A candidate
	// that relied on a truncated result is rejected.
	ClosureTruncated = "truncated"
)

// AnalysisToken pins retrieval to one analyzed packet and graph digest.
// A query carrying any other token is rejected, so the model cannot read a
// later or different graph state than the one it is being judged against.
type AnalysisToken struct {
	AnalysisID  string `json:"analysisId"`
	GraphSHA256 string `json:"graphSha256"`
}

// ContextLimits bounds each retrieval result. PathDepth is the maximum number
// of hops a graph-path query traverses.
type ContextLimits struct {
	Resources      int
	Relationships  int
	Facets         int
	Telemetry      int
	IncidentEvents int
	Baselines      int
	PathDepth      int
}

// DefaultContextLimits returns the retrieval bounds used by the service.
func DefaultContextLimits() ContextLimits {
	return ContextLimits{Resources: 50, Relationships: 100, Facets: 100, Telemetry: 50, IncidentEvents: 100, Baselines: 50, PathDepth: 4}
}

// ContextQuery requests one bounded context template around anchor resources.
// Anchors must be resources known to the provider.
type ContextQuery struct {
	Token     AnalysisToken `json:"token"`
	Template  string        `json:"template"`
	AnchorIDs []string      `json:"anchorIds"`
	// Predicates is an explicit graph_path allowlist; an empty list uses the safe default.
	Predicates []graph.Predicate `json:"predicates,omitempty"`
}

// PinnedTelemetryContext is the telemetry available to retrieval for one
// analysis: events within the packet's telemetry window, already reduced to
// allowlisted properties and opaque evidence handles.
type PinnedTelemetryContext struct {
	Token           AnalysisToken        `json:"token"`
	TelemetryWindow *detector.TimeWindow `json:"telemetryWindow,omitempty"`
	Telemetry       []Telemetry          `json:"telemetry"`
}

// ContextResult is the bounded answer to a [ContextQuery]. Truncated counts
// omitted items per collection, and Closure summarizes whether any were.
type ContextResult struct {
	Token           AnalysisToken        `json:"token"`
	Template        string               `json:"template"`
	AnchorIDs       []string             `json:"anchorIds"`
	Predicates      []graph.Predicate    `json:"predicates,omitempty"`
	Resources       []Resource           `json:"resources"`
	Relationships   []Relationship       `json:"relationships"`
	Facets          []Facet              `json:"facets"`
	Telemetry       []Telemetry          `json:"telemetry"`
	IncidentEvents  []IncidentEvent      `json:"incidentEvents,omitempty"`
	Baselines       []BehaviorBaseline   `json:"baselines,omitempty"`
	TelemetryWindow *detector.TimeWindow `json:"telemetryWindow,omitempty"`
	Closure         string               `json:"closure"`
	Truncated       map[string]int       `json:"truncated,omitempty"`
}

// ContextReceipt records one retrieval on the effective packet so the model,
// validation, and audit can see which anchors were covered and whether the
// view was truncated.
type ContextReceipt struct {
	Template   string            `json:"template"`
	AnchorIDs  []string          `json:"anchorIds"`
	Predicates []graph.Predicate `json:"predicates,omitempty"`
	Closure    string            `json:"closure"`
	Truncated  map[string]int    `json:"truncated,omitempty"`
}

// ContextProvider answers context queries for one analysis from an immutable
// copy of the graph, pinned telemetry, and incident context. It never reads
// live state.
type ContextProvider struct {
	packet        Packet
	resources     []Resource
	relationships []Relationship
	facets        []Facet
	telemetry     []Telemetry
	incident      IncidentContext
	limits        ContextLimits
}

// defaultGraphPathPredicates is every registered predicate except runs-on,
// which stays opt-in because shared nodes fan traversal into otherwise
// unrelated workloads. It follows the registry, so a new predicate is
// traversed by default.
func defaultGraphPathPredicates() []graph.Predicate {
	var predicates []graph.Predicate
	for _, description := range graph.RegisteredPredicateDescriptions() {
		if description.Predicate != graph.PredicateRunsOn {
			predicates = append(predicates, description.Predicate)
		}
	}
	return predicates
}

// PinSnapshotTelemetry selects up to limit telemetry events from snapshot that
// fall inside the packet's telemetry window. Events without a parseable
// first-seen time are skipped because they cannot be placed in the window.
func PinSnapshotTelemetry(packet Packet, snapshot graph.Snapshot, limit int) PinnedTelemetryContext {
	pinned := PinnedTelemetryContext{
		Token:           AnalysisToken{AnalysisID: packet.AnalysisID, GraphSHA256: packet.HydratedGraphSHA256},
		TelemetryWindow: packet.TelemetryWindow,
	}
	if packet.TelemetryWindow == nil || limit < 1 {
		return pinned
	}
	for _, event := range snapshot.Telemetry {
		observedAt, ok := telemetryTime(event)
		if !ok || observedAt.Before(packet.TelemetryWindow.Start) || observedAt.After(packet.TelemetryWindow.End) {
			continue
		}
		pinned.Telemetry = append(pinned.Telemetry, Telemetry{
			ID: event.ID, Kind: event.Kind, SubjectID: event.SubjectID, ObjectID: event.ObjectID,
			Operation: event.Operation, Outcome: event.Outcome, Coverage: event.Coverage, Count: event.Count,
			Properties: telemetryProperties(event.Properties), EvidenceIDs: opaqueEvidence(event.EvidenceIDs),
		})
		if len(pinned.Telemetry) == limit {
			break
		}
	}
	return pinned
}

// NewContextProvider returns a provider limited to the packet's own resources,
// with no telemetry.
func NewContextProvider(packet Packet, limits ContextLimits) (*ContextProvider, error) {
	return NewContextProviderWithTelemetry(packet, PinnedTelemetryContext{
		Token:           AnalysisToken{AnalysisID: packet.AnalysisID, GraphSHA256: packet.HydratedGraphSHA256},
		TelemetryWindow: packet.TelemetryWindow,
	}, limits)
}

// NewContextProviderWithTelemetry returns a provider limited to the packet's
// own resources plus pinned telemetry.
func NewContextProviderWithTelemetry(packet Packet, pinned PinnedTelemetryContext, limits ContextLimits) (*ContextProvider, error) {
	return newContextProvider(packet, packet.Resources, packet.Relationships, packet.Facets, pinned, IncidentContext{}, limits)
}

// NewContextProviderWithSnapshot returns a provider over the complete
// snapshot, so retrieval can reach resources the bounded packet omitted. The
// telemetry context must carry the packet's token and window.
func NewContextProviderWithSnapshot(packet Packet, snapshot graph.Snapshot, pinned PinnedTelemetryContext, incident IncidentContext, limits ContextLimits) (*ContextProvider, error) {
	resources, relationships, facets, err := snapshotContext(snapshot)
	if err != nil {
		return nil, err
	}
	return newContextProvider(packet, resources, relationships, facets, pinned, incident, limits)
}

func newContextProvider(packet Packet, resources []Resource, relationships []Relationship, facets []Facet, pinned PinnedTelemetryContext, incident IncidentContext, limits ContextLimits) (*ContextProvider, error) {
	if packet.AnalysisID == "" || packet.HydratedGraphSHA256 == "" {
		return nil, errors.New("context provider requires an analysis ID and graph digest")
	}
	defaults := DefaultContextLimits()
	if limits.IncidentEvents == 0 {
		limits.IncidentEvents = defaults.IncidentEvents
	}
	if limits.Baselines == 0 {
		limits.Baselines = defaults.Baselines
	}
	if limits.PathDepth == 0 {
		limits.PathDepth = defaults.PathDepth
	}
	if limits.Resources < 1 || limits.Relationships < 1 || limits.Facets < 1 || limits.Telemetry < 1 || limits.IncidentEvents < 1 || limits.Baselines < 1 || limits.PathDepth < 1 {
		return nil, errors.New("context limits must be positive")
	}
	token := AnalysisToken{AnalysisID: packet.AnalysisID, GraphSHA256: packet.HydratedGraphSHA256}
	if pinned.Token != token {
		return nil, errors.New("telemetry context token does not match packet")
	}
	if !sameTimeWindow(pinned.TelemetryWindow, packet.TelemetryWindow) {
		return nil, errors.New("telemetry context window does not match packet")
	}
	if incident.SchemaVersion != "" && incident.SchemaVersion != IncidentContextSchemaVersion {
		return nil, errors.New("incident context schema is unsupported")
	}
	return &ContextProvider{
		packet: packet, resources: append([]Resource(nil), resources...), relationships: append([]Relationship(nil), relationships...),
		facets: append([]Facet(nil), facets...), telemetry: append([]Telemetry(nil), pinned.Telemetry...), incident: incident, limits: limits,
	}, nil
}

func snapshotContext(snapshot graph.Snapshot) ([]Resource, []Relationship, []Facet, error) {
	roles := resourceRoles(snapshot)
	resources := make([]Resource, 0, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		attributes := resourceAttributes(resource.Assertions)
		if role := roles[resource.ID]; role != "" {
			if attributes == nil {
				attributes = make(map[string]string)
			}
			attributes["network/role"] = role
		}
		resources = append(resources, Resource{ID: resource.ID, Kind: resource.Kind, Names: resourceNames(resource.Assertions), Attributes: attributes, Identity: resource.Identity})
	}
	relationships := make([]Relationship, 0, len(snapshot.Relationships))
	for _, relationship := range snapshot.Relationships {
		if relationship.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		semantics, err := relationshipSecuritySemantics(relationship.Assertions)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("relationship %s security semantics: %w", relationship.ID, err)
		}
		relationships = append(relationships, Relationship{ID: relationship.ID, SubjectID: relationship.SubjectID, Predicate: relationship.Predicate, ObjectID: relationship.ObjectID, SecuritySemantics: semantics, EvidenceIDs: opaqueEvidence(relationshipEvidence(relationship))})
	}
	facets := make([]Facet, 0, len(snapshot.Facets))
	for _, facet := range snapshot.Facets {
		if facet.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		semantics, err := facetSecuritySemantics(facet.Assertions)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("facet %s security semantics: %w", facet.ID, err)
		}
		facets = append(facets, Facet{ID: facet.ID, ResourceID: facet.ResourceID, Kind: facet.Kind, Key: facet.Key, Attributes: facetAttributes(facet.Assertions), SecuritySemantics: semantics, EvidenceIDs: opaqueEvidence(facetEvidence(facet))})
	}
	return resources, relationships, facets, nil
}

func sameTimeWindow(left, right *detector.TimeWindow) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Start.Equal(right.Start) && left.End.Equal(right.End)
}

// Token returns the analysis token every query to this provider must carry.
func (provider *ContextProvider) Token() AnalysisToken {
	return AnalysisToken{AnalysisID: provider.packet.AnalysisID, GraphSHA256: provider.packet.HydratedGraphSHA256}
}

// Query answers one template around the query anchors. Results are bounded
// per collection by the provider's limits. Graph-path queries use the
// supplied predicate allowlist, or every registered predicate except runs-on.
func (provider *ContextProvider) Query(query ContextQuery) (ContextResult, error) {
	query, err := provider.normalizeQuery(query)
	if err != nil {
		return ContextResult{}, err
	}
	known := make(map[string]struct{}, len(provider.resources))
	for _, resource := range provider.resources {
		known[resource.ID] = struct{}{}
	}
	selected := make(map[string]struct{})
	for _, anchorID := range query.AnchorIDs {
		if _, ok := known[anchorID]; !ok {
			return ContextResult{}, fmt.Errorf("context anchor %q was not supplied", anchorID)
		}
		selected[anchorID] = struct{}{}
	}
	anchors := mapsClone(selected)
	var selectedTelemetry map[string]struct{}
	switch query.Template {
	case TemplateSecurityNeighborhood:
		provider.selectNeighbors(selected, false)
	case TemplateGovernancePosture:
		provider.selectNeighbors(selected, true)
	case TemplateGraphPath:
		provider.selectPaths(selected, query.Predicates)
	case TemplateTelemetryChain:
		selectedTelemetry = provider.selectTelemetry(anchors, selected)
	case TemplateIncidentTimeline:
		for _, event := range provider.incident.Timeline {
			selectCounterpart(anchors, selected, event.SubjectID, event.ObjectID)
		}
	case TemplateBehaviorBaseline:
		for _, baseline := range provider.incident.Baseline {
			selectCounterpart(anchors, selected, baseline.SubjectID, baseline.ObjectID)
		}
	}
	return provider.result(query, anchors, selected, selectedTelemetry), nil
}

// normalizeQuery checks the token, template, and anchors, and resolves the
// graph-path predicate allowlist.
func (provider *ContextProvider) normalizeQuery(query ContextQuery) (ContextQuery, error) {
	if query.Token != provider.Token() {
		return ContextQuery{}, errors.New("analysis token does not match immutable context")
	}
	if !oneOf(query.Template, contextTemplates...) {
		return ContextQuery{}, fmt.Errorf("unsupported context template %q", query.Template)
	}
	if len(query.AnchorIDs) == 0 {
		return ContextQuery{}, errors.New("context query requires at least one anchor")
	}
	if query.Template != TemplateGraphPath {
		if len(query.Predicates) > 0 {
			return ContextQuery{}, errors.New("predicates are supported only for graph path queries")
		}
		return query, nil
	}
	if len(query.Predicates) == 0 {
		query.Predicates = defaultGraphPathPredicates()
	} else {
		query.Predicates = append([]graph.Predicate(nil), query.Predicates...)
	}
	for _, predicate := range query.Predicates {
		if !graph.IsRegisteredPredicate(predicate) {
			return ContextQuery{}, fmt.Errorf("graph path query has unsupported predicate %q", predicate)
		}
	}
	slices.Sort(query.Predicates)
	query.Predicates = slices.Compact(query.Predicates)
	return query, nil
}

// selectNeighbors adds the one-hop neighbors of selected, through governed-by
// relationships only when governanceOnly is set.
func (provider *ContextProvider) selectNeighbors(selected map[string]struct{}, governanceOnly bool) {
	for _, relationship := range provider.relationships {
		_, subjectSelected := selected[relationship.SubjectID]
		_, objectSelected := selected[relationship.ObjectID]
		if !subjectSelected && !objectSelected {
			continue
		}
		if governanceOnly && relationship.Predicate != "governed-by" {
			continue
		}
		selected[relationship.SubjectID] = struct{}{}
		selected[relationship.ObjectID] = struct{}{}
	}
}

// selectPaths adds every resource within PathDepth hops of selected through
// the allowed predicates.
func (provider *ContextProvider) selectPaths(selected map[string]struct{}, predicates []graph.Predicate) {
	allowed := make(map[graph.Predicate]struct{}, len(predicates))
	for _, predicate := range predicates {
		allowed[predicate] = struct{}{}
	}
	frontier := mapsClone(selected)
	for depth := 0; depth < provider.limits.PathDepth && len(frontier) > 0; depth++ {
		next := make(map[string]struct{})
		for _, relationship := range provider.relationships {
			if _, ok := allowed[relationship.Predicate]; !ok {
				continue
			}
			_, subjectSelected := frontier[relationship.SubjectID]
			_, objectSelected := frontier[relationship.ObjectID]
			if !subjectSelected && !objectSelected {
				continue
			}
			for _, resourceID := range []string{relationship.SubjectID, relationship.ObjectID} {
				if _, exists := selected[resourceID]; !exists {
					next[resourceID] = struct{}{}
				}
				selected[resourceID] = struct{}{}
			}
		}
		frontier = next
	}
}

// selectTelemetry returns the pinned telemetry touching anchors and adds its
// other endpoints to selected.
func (provider *ContextProvider) selectTelemetry(anchors, selected map[string]struct{}) map[string]struct{} {
	selectedTelemetry := make(map[string]struct{})
	for _, telemetry := range provider.telemetry {
		if _, ok := anchors[telemetry.SubjectID]; ok {
			selected[telemetry.ObjectID] = struct{}{}
			selectedTelemetry[telemetry.ID] = struct{}{}
		}
		if _, ok := anchors[telemetry.ObjectID]; ok {
			selected[telemetry.SubjectID] = struct{}{}
			selectedTelemetry[telemetry.ID] = struct{}{}
		}
	}
	return selectedTelemetry
}

// selectCounterpart adds the other endpoint of a subject-object pair that
// touches anchors.
func selectCounterpart(anchors, selected map[string]struct{}, subjectID, objectID string) {
	if _, ok := anchors[subjectID]; ok {
		selected[objectID] = struct{}{}
	}
	if _, ok := anchors[objectID]; ok {
		selected[subjectID] = struct{}{}
	}
}

func touchesAnchor(anchors map[string]struct{}, subjectID, objectID string) bool {
	_, subjectAnchored := anchors[subjectID]
	_, objectAnchored := anchors[objectID]
	return subjectAnchored || objectAnchored
}

// result collects the selected facts in provider order and bounds each collection.
func (provider *ContextProvider) result(query ContextQuery, anchors, selected, selectedTelemetry map[string]struct{}) ContextResult {
	result := ContextResult{
		Token: provider.Token(), Template: query.Template, AnchorIDs: sortedUniqueStrings(query.AnchorIDs), Predicates: query.Predicates,
		TelemetryWindow: provider.packet.TelemetryWindow, Closure: ClosureUntruncated, Truncated: make(map[string]int),
	}
	for _, resource := range provider.resources {
		if _, ok := selected[resource.ID]; ok {
			result.Resources = append(result.Resources, resource)
		}
	}
	for _, relationship := range provider.relationships {
		if query.Template == TemplateGraphPath && !slices.Contains(query.Predicates, relationship.Predicate) {
			continue
		}
		_, subjectSelected := selected[relationship.SubjectID]
		_, objectSelected := selected[relationship.ObjectID]
		if subjectSelected && objectSelected && (query.Template != TemplateGovernancePosture || relationship.Predicate == "governed-by") {
			result.Relationships = append(result.Relationships, relationship)
		}
	}
	for _, facet := range provider.facets {
		if _, ok := selected[facet.ResourceID]; ok {
			result.Facets = append(result.Facets, facet)
		}
	}
	if query.Template == TemplateIncidentTimeline {
		for _, event := range provider.incident.Timeline {
			if touchesAnchor(anchors, event.SubjectID, event.ObjectID) {
				result.IncidentEvents = append(result.IncidentEvents, event)
			}
		}
	}
	if query.Template == TemplateBehaviorBaseline {
		for _, baseline := range provider.incident.Baseline {
			if touchesAnchor(anchors, baseline.SubjectID, baseline.ObjectID) {
				result.Baselines = append(result.Baselines, baseline)
			}
		}
	}
	for _, telemetry := range provider.telemetry {
		if _, ok := selectedTelemetry[telemetry.ID]; ok {
			result.Telemetry = append(result.Telemetry, telemetry)
		}
	}
	result.Resources = boundedContext(result.Resources, provider.limits.Resources, result.Truncated, "resources")
	result.Relationships = boundedContext(result.Relationships, provider.limits.Relationships, result.Truncated, "relationships")
	result.Facets = boundedContext(result.Facets, provider.limits.Facets, result.Truncated, "facets")
	result.Telemetry = boundedContext(result.Telemetry, provider.limits.Telemetry, result.Truncated, "telemetry")
	result.IncidentEvents = boundedContext(result.IncidentEvents, provider.limits.IncidentEvents, result.Truncated, "incidentEvents")
	result.Baselines = boundedContext(result.Baselines, provider.limits.Baselines, result.Truncated, "baselines")
	if len(result.Truncated) == 0 {
		result.Truncated = nil
	} else {
		result.Closure = ClosureTruncated
	}
	return result
}

func mapsClone(values map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for key := range values {
		result[key] = struct{}{}
	}
	return result
}

// CompactPacket keeps only resources touched by the packet's changes or
// anchored by its signals, the relationships between them, and their facets.
// Everything else must be retrieved through MCP.
func CompactPacket(packet Packet) Packet {
	selected := make(map[string]struct{})
	for _, change := range packet.Changes {
		for _, resourceID := range []string{change.Entity.ID, change.Entity.ResourceID, change.Entity.SubjectID, change.Entity.ObjectID} {
			if resourceID != "" {
				selected[resourceID] = struct{}{}
			}
		}
	}
	for _, signal := range packet.Signals {
		for _, anchorID := range signal.AnchorIDs {
			selected[anchorID] = struct{}{}
		}
	}
	compact := packet
	compact.Resources = nil
	compact.Relationships = nil
	compact.Facets = nil
	compact.Telemetry = nil
	compact.IncidentEvents = nil
	compact.Baselines = nil
	for _, resource := range packet.Resources {
		if _, ok := selected[resource.ID]; ok {
			compact.Resources = append(compact.Resources, resource)
		}
	}
	for _, relationship := range packet.Relationships {
		_, subjectSelected := selected[relationship.SubjectID]
		_, objectSelected := selected[relationship.ObjectID]
		if subjectSelected && objectSelected {
			compact.Relationships = append(compact.Relationships, relationship)
		}
	}
	for _, facet := range packet.Facets {
		if _, ok := selected[facet.ResourceID]; ok {
			compact.Facets = append(compact.Facets, facet)
		}
	}
	return compact
}

// MergeContext adds a retrieval result to packet, deduplicating by ID and
// recording a [ContextReceipt]. Later results replace earlier items with the
// same ID; ordering is by ID so the merged packet is deterministic.
func MergeContext(packet Packet, retrieved ContextResult) Packet {
	packet.ContextReceipts = append(packet.ContextReceipts, ContextReceipt{
		Template: retrieved.Template, AnchorIDs: retrieved.AnchorIDs, Predicates: retrieved.Predicates, Closure: retrieved.Closure, Truncated: retrieved.Truncated,
	})
	packet.Resources = mergeByID(packet.Resources, retrieved.Resources, func(value Resource) string { return value.ID })
	packet.Relationships = mergeByID(packet.Relationships, retrieved.Relationships, func(value Relationship) string { return value.ID })
	packet.Facets = mergeByID(packet.Facets, retrieved.Facets, func(value Facet) string { return value.ID })
	packet.Telemetry = mergeByID(packet.Telemetry, retrieved.Telemetry, func(value Telemetry) string { return value.ID })
	packet.IncidentEvents = mergeByID(packet.IncidentEvents, retrieved.IncidentEvents, func(value IncidentEvent) string { return value.ID })
	packet.Baselines = mergeByID(packet.Baselines, retrieved.Baselines, func(value BehaviorBaseline) string { return value.ID })
	return packet
}

// EncodePacket returns the canonical JSON encoding of packet.
func EncodePacket(packet Packet) ([]byte, error) {
	return canonicalPacket(packet)
}

func sortedUniqueStrings(values []string) []string {
	result := append([]string(nil), values...)
	slices.Sort(result)
	return slices.Compact(result)
}

func boundedContext[T any](values []T, limit int, truncated map[string]int, key string) []T {
	if len(values) <= limit {
		return values
	}
	truncated[key] = len(values) - limit
	return values[:limit]
}

func mergeByID[T any](left, right []T, id func(T) string) []T {
	values := make(map[string]T, len(left)+len(right))
	for _, value := range append(append([]T(nil), left...), right...) {
		values[id(value)] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]T, 0, len(keys))
	for _, key := range keys {
		result = append(result, values[key])
	}
	return result
}
