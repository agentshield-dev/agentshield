package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

const maxSignalAnchors = 16

// DetectNovelChanges emits built-in investigation triggers for security-relevant
// graph changes and bounded telemetry novelty. It does not emit findings.
//
// Communication novelty is compared per workload: Pods are folded into the
// controller that instantiates them, so rollouts, restarts, and scaling do not
// look like new behavior. Ordinary topology churn (new or changed Pods, Services,
// ConfigMaps, labels, and structural edges) emits nothing; only changes with a
// security meaning do.
func DetectNovelChanges(previous, current graph.Snapshot, observedAt time.Time, config Config) []InvestigationSignal {
	config = normalizedConfig(config)
	if observedAt.IsZero() {
		observedAt = latestTelemetryTime(current)
	}
	if observedAt.IsZero() {
		observedAt = time.Unix(0, 0).UTC()
	}
	observedAt = observedAt.UTC()
	topology := newWorkloadTopology(previous, current)
	signals := detectNovelTelemetry(previous, current, topology, config)
	signals = append(signals, detectCommunicationPaths(previous, current, topology, observedAt, config)...)
	signals = append(signals, detectTopologyChanges(previous, current, observedAt, config)...)
	signals = append(signals, detectSensitiveResources(previous, current, observedAt, config)...)
	signals = append(signals, detectWorkloadIdentityChanges(previous, current, topology, observedAt, config)...)
	slices.SortFunc(signals, func(left, right InvestigationSignal) int { return strings.Compare(left.ID, right.ID) })
	return slices.CompactFunc(signals, func(left, right InvestigationSignal) bool { return left.ID == right.ID })
}

// DetectNovelTelemetry compares workload-level telemetry fingerprints and never returns telemetry IDs or evidence.
func DetectNovelTelemetry(previous, current graph.Snapshot, config Config) []InvestigationSignal {
	return detectNovelTelemetry(previous, current, newWorkloadTopology(previous, current), normalizedConfig(config))
}

func detectNovelTelemetry(previous, current graph.Snapshot, topology workloadTopology, config Config) []InvestigationSignal {
	known := make(map[string]struct{}, len(previous.Telemetry))
	knownPairs := make(map[string]struct{}, len(previous.Telemetry))
	for _, event := range previous.Telemetry {
		known[topology.telemetryFingerprint(event)] = struct{}{}
		knownPairs[topology.pathKey(event.SubjectID, event.ObjectID)] = struct{}{}
	}
	roles := graph.ResourceNetworkRoles(current)
	type novelty struct {
		observedAt time.Time
		event      graph.TelemetryEvent
		anchors    map[string]struct{}
	}
	novel := make(map[string]*novelty)
	for _, event := range current.Telemetry {
		fingerprint := topology.telemetryFingerprint(event)
		if _, ok := known[fingerprint]; ok {
			continue
		}
		observedAt, ok := telemetryTime(event)
		if !ok {
			continue
		}
		entry := novel[fingerprint]
		if entry == nil {
			entry = &novelty{observedAt: observedAt, event: event, anchors: make(map[string]struct{})}
			novel[fingerprint] = entry
		}
		if observedAt.Before(entry.observedAt) {
			entry.observedAt = observedAt
		}
		for _, anchor := range topology.anchors(event.SubjectID, event.ObjectID) {
			entry.anchors[anchor] = struct{}{}
		}
	}
	var signals []InvestigationSignal
	for _, entry := range novel {
		event := entry.event
		score := 1
		reasons := []string{"novel_telemetry"}
		if _, ok := knownPairs[topology.pathKey(event.SubjectID, event.ObjectID)]; !ok {
			score++
			if telemetry.IsCommunication(event.Kind) {
				reasons = append(reasons, "new_communication_pair")
			} else {
				reasons = append(reasons, "new_subject_object_pair")
			}
		} else {
			reasons = append(reasons, "new_operation_or_outcome")
		}
		if weight := config.SensitiveRoleWeights[roles[event.ObjectID]]; weight > 0 {
			score += weight
			reasons = append(reasons, "sensitive_destination_role")
		}
		if score < config.MinimumScore {
			continue
		}
		signals = append(signals, scoredSignal(score, reasons, boundedAnchors(setKeys(entry.anchors)), entry.observedAt, config.Window))
	}
	slices.SortFunc(signals, func(left, right InvestigationSignal) int { return strings.Compare(left.ID, right.ID) })
	return signals
}

// detectCommunicationPaths signals workload-level communication paths that first
// appear as resolved communicates-with edges. A new destination for a workload
// that already had observed traffic is the lateral-movement shape and is eligible
// for investigation; a new workload's first calls are recorded at low risk.
func detectCommunicationPaths(previous, current graph.Snapshot, topology workloadTopology, observedAt time.Time, config Config) []InvestigationSignal {
	knownEdges := make(map[string]struct{})
	knownPaths := make(map[string]struct{})
	activeSources := make(map[string]struct{})
	for _, relationship := range previous.Relationships {
		if relationship.Predicate != graph.PredicateCommunicates || relationship.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		knownEdges[relationshipKey(relationship)] = struct{}{}
		knownPaths[topology.pathKey(relationship.SubjectID, relationship.ObjectID)] = struct{}{}
		activeSources[topology.workload(relationship.SubjectID)] = struct{}{}
	}
	for _, event := range previous.Telemetry {
		knownPaths[topology.pathKey(event.SubjectID, event.ObjectID)] = struct{}{}
		activeSources[topology.workload(event.SubjectID)] = struct{}{}
	}
	resources := resourcesByID(current)
	roles := graph.ResourceNetworkRoles(current)
	type path struct {
		source, destinationRole string
		external                bool
		anchors                 map[string]struct{}
	}
	paths := make(map[string]*path)
	for _, relationship := range current.Relationships {
		if relationship.Predicate != graph.PredicateCommunicates || relationship.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		if _, known := knownEdges[relationshipKey(relationship)]; known {
			continue
		}
		key := topology.pathKey(relationship.SubjectID, relationship.ObjectID)
		if _, known := knownPaths[key]; known {
			continue
		}
		entry := paths[key]
		if entry == nil {
			entry = &path{source: topology.workload(relationship.SubjectID), anchors: make(map[string]struct{})}
			paths[key] = entry
		}
		if role := roles[relationship.ObjectID]; role != "" {
			entry.destinationRole = role
		}
		entry.external = entry.external || externalDestination(resources[relationship.ObjectID])
		for _, anchor := range topology.anchors(relationship.SubjectID, relationship.ObjectID) {
			entry.anchors[anchor] = struct{}{}
		}
	}
	var signals []InvestigationSignal
	for _, entry := range paths {
		score := 2
		reasons := []string{"new_communication_path"}
		if _, active := activeSources[entry.source]; active {
			score++
			reasons = append(reasons, "established_source")
		} else {
			reasons = append(reasons, "first_source_activity")
		}
		if weight := config.SensitiveRoleWeights[entry.destinationRole]; weight > 0 {
			score += weight
			reasons = append(reasons, "sensitive_destination_role")
		}
		if entry.external && config.ExternalDestinationWeight > 0 {
			score += config.ExternalDestinationWeight
			reasons = append(reasons, "external_destination")
		}
		signals = appendScoredSignal(signals, score, reasons, boundedAnchors(setKeys(entry.anchors)), observedAt, config)
	}
	return signals
}

func externalDestination(resource graph.Resource) bool {
	switch resource.Kind {
	case "network/peer-class":
		return resource.Identity.ImmutableKey == "external-destination"
	case "network/destination":
		key, found := strings.CutPrefix(resource.Identity.ImmutableKey, "ip/")
		if !found {
			return false
		}
		class, err := telemetry.ClassifyDestinationIP(key)
		return err == nil && class == telemetry.DestinationIPClassPublic
	}
	return false
}

func detectTopologyChanges(previous, current graph.Snapshot, observedAt time.Time, config Config) []InvestigationSignal {
	previousSemantics := securityObservations(previous)
	currentSemantics := securityObservations(current)
	currentResources := resourcesByID(current)
	var signals []InvestigationSignal
	for key, currentObservation := range currentSemantics {
		previousObservation, existed := previousSemantics[key]
		becameExternal := currentObservation.externalAddressable() && (!existed || !previousObservation.externalAddressable())
		if becameExternal {
			reasons := []string{"new_public_exposure"}
			if existed {
				reasons = append(reasons, "security_semantics_changed")
			}
			signals = appendScoredSignal(signals, 4, reasons, currentObservation.anchorIDs(), observedAt, config)
			continue
		}
		if existed && currentObservation.fingerprint() != previousObservation.fingerprint() {
			reason := "governance_semantics_changed"
			if currentObservation.class == graph.SecurityClassExposure {
				reason = "exposure_semantics_changed"
			}
			signals = appendScoredSignal(signals, 3, []string{"security_semantics_changed", reason}, currentObservation.anchorIDs(), observedAt, config)
		}
	}
	for key, previousObservation := range previousSemantics {
		if _, retained := currentSemantics[key]; retained {
			continue
		}
		anchors := retainedAnchors(previousObservation.anchorIDs(), currentResources)
		if len(anchors) > 0 {
			signals = appendScoredSignal(signals, 4, []string{"security_semantics_removed"}, anchors, observedAt, config)
		}
	}

	currentGovernance := make(map[string]struct{})
	for _, relationship := range current.Relationships {
		if relationship.Predicate == graph.PredicateGovernedBy && relationship.ResolutionStatus != graph.ResolutionUnresolved {
			currentGovernance[relationshipKey(relationship)] = struct{}{}
		}
	}
	for _, relationship := range previous.Relationships {
		if relationship.Predicate != graph.PredicateGovernedBy || relationship.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		if _, retained := currentGovernance[relationshipKey(relationship)]; retained {
			continue
		}
		var anchors []string
		if _, ok := currentResources[relationship.SubjectID]; ok {
			anchors = append(anchors, relationship.SubjectID)
		}
		if _, ok := currentResources[relationship.ObjectID]; ok {
			anchors = append(anchors, relationship.ObjectID)
		}
		if len(anchors) > 0 {
			signals = appendScoredSignal(signals, 4, []string{"lost_governance"}, anchors, observedAt, config)
		}
	}
	return signals
}

// detectSensitiveResources signals newly created resources whose kind grants
// privilege or intercepts admission. Attribute-only changes are not signaled.
func detectSensitiveResources(previous, current graph.Snapshot, observedAt time.Time, config Config) []InvestigationSignal {
	if len(config.SensitiveResourceKinds) == 0 {
		return nil
	}
	existing := resourcesByID(previous)
	added := make(map[string][]string)
	for _, resource := range current.Resources {
		reason := config.SensitiveResourceKinds[resource.Kind]
		if reason == "" {
			continue
		}
		if _, existed := existing[resource.ID]; !existed {
			added[reason] = append(added[reason], resource.ID)
		}
	}
	var signals []InvestigationSignal
	for reason, anchors := range added {
		signals = appendScoredSignal(signals, 3, []string{"sensitive_resource_added", reason}, boundedAnchors(anchors), observedAt, config)
	}
	return signals
}

// detectWorkloadIdentityChanges signals an existing workload whose instances
// start using an identity it did not use before.
func detectWorkloadIdentityChanges(previous, current graph.Snapshot, topology workloadTopology, observedAt time.Time, config Config) []InvestigationSignal {
	before := topology.workloadIdentities(previous)
	after := topology.workloadIdentities(current)
	var signals []InvestigationSignal
	for workload, identities := range after {
		known := before[workload]
		if len(known) == 0 {
			continue
		}
		for identity := range identities {
			if _, used := known[identity]; !used {
				signals = appendScoredSignal(signals, 3, []string{"workload_identity_changed"}, []string{workload, identity}, observedAt, config)
			}
		}
	}
	return signals
}

// workloadTopology folds instances such as Pods into the controllers that
// instantiate them. Hosts (runs-on objects) are not treated as controllers.
type workloadTopology struct {
	owners map[string]string
}

func newWorkloadTopology(snapshots ...graph.Snapshot) workloadTopology {
	hosts := make(map[string]struct{})
	for _, snapshot := range snapshots {
		for _, relationship := range snapshot.Relationships {
			if relationship.Predicate == graph.PredicateRunsOn {
				hosts[relationship.ObjectID] = struct{}{}
			}
		}
	}
	candidates := make(map[string][]string)
	for _, snapshot := range snapshots {
		for _, relationship := range snapshot.Relationships {
			if relationship.Predicate != graph.PredicateInstantiates || relationship.ResolutionStatus == graph.ResolutionUnresolved {
				continue
			}
			if _, host := hosts[relationship.SubjectID]; host {
				continue
			}
			candidates[relationship.ObjectID] = append(candidates[relationship.ObjectID], relationship.SubjectID)
		}
	}
	owners := make(map[string]string, len(candidates))
	for instance, controllers := range candidates {
		owners[instance] = slices.Min(controllers)
	}
	return workloadTopology{owners: owners}
}

func (topology workloadTopology) workload(id string) string {
	if owner, found := topology.owners[id]; found {
		return owner
	}
	return id
}

func (topology workloadTopology) pathKey(subjectID, objectID string) string {
	return topology.workload(subjectID) + "\x00" + topology.workload(objectID)
}

func (topology workloadTopology) telemetryFingerprint(event graph.TelemetryEvent) string {
	return strings.Join([]string{event.Kind, topology.workload(event.SubjectID), topology.workload(event.ObjectID), event.Operation, event.Outcome}, "\x00")
}

func (topology workloadTopology) anchors(ids ...string) []string {
	anchors := make([]string, 0, 2*len(ids))
	for _, id := range ids {
		anchors = append(anchors, id)
		if workload := topology.workload(id); workload != id {
			anchors = append(anchors, workload)
		}
	}
	return anchors
}

func (topology workloadTopology) workloadIdentities(snapshot graph.Snapshot) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})
	for _, relationship := range snapshot.Relationships {
		if relationship.Predicate != graph.PredicateUsesIdentity || relationship.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		workload := topology.workload(relationship.SubjectID)
		if workload == relationship.SubjectID {
			continue
		}
		if result[workload] == nil {
			result[workload] = make(map[string]struct{})
		}
		result[workload][relationship.ObjectID] = struct{}{}
	}
	return result
}

func setKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return result
}

func boundedAnchors(anchors []string) []string {
	anchors = slices.Clone(anchors)
	slices.Sort(anchors)
	anchors = slices.Compact(anchors)
	if len(anchors) > maxSignalAnchors {
		anchors = anchors[:maxSignalAnchors]
	}
	return anchors
}

type securityObservation struct {
	class     graph.SecurityClass
	semantics map[string]graph.SecuritySemantics
	anchors   map[string]struct{}
}

// securityObservations indexes typed security semantics by owner. Keys include
// the asserting plugin, source, and rule so one provider's change is not
// masked by another provider asserting the same semantics.
func securityObservations(snapshot graph.Snapshot) map[string]*securityObservation {
	result := make(map[string]*securityObservation)
	for _, facet := range snapshot.Facets {
		if facet.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		for _, assertion := range facet.Assertions {
			semantics, err := graph.DecodeSecuritySemantics(assertion.Attributes)
			if err != nil || semantics == nil {
				continue
			}
			key := eventKey("facet", facet.ResourceID, facet.Kind, facet.Key, assertion.PluginID, assertion.SourceID, assertion.RuleID, string(semantics.Class), string(semantics.Domain))
			addSecurityObservation(result, key, *semantics, facet.ResourceID)
		}
	}
	for _, relationship := range snapshot.Relationships {
		if relationship.ResolutionStatus == graph.ResolutionUnresolved {
			continue
		}
		for _, assertion := range relationship.Assertions {
			semantics, err := graph.DecodeSecuritySemantics(assertion.Properties)
			if err != nil || semantics == nil {
				continue
			}
			entityID := relationship.ID
			anchors := []string{relationship.SubjectID, relationship.ObjectID}
			if relationship.Predicate == graph.PredicateGovernedBy {
				entityID = relationship.ObjectID
				anchors = []string{relationship.ObjectID}
			}
			key := eventKey("relationship", entityID, string(relationship.Predicate), assertion.PluginID, assertion.SourceID, assertion.RuleID, string(semantics.Class), string(semantics.Domain))
			addSecurityObservation(result, key, *semantics, anchors...)
		}
	}
	return result
}

func retainedAnchors(anchors []string, resources map[string]graph.Resource) []string {
	result := make([]string, 0, len(anchors))
	for _, anchor := range anchors {
		if _, retained := resources[anchor]; retained {
			result = append(result, anchor)
		}
	}
	return result
}

func addSecurityObservation(observations map[string]*securityObservation, key string, semantics graph.SecuritySemantics, anchors ...string) {
	observation := observations[key]
	if observation == nil {
		observation = &securityObservation{class: semantics.Class, semantics: make(map[string]graph.SecuritySemantics), anchors: make(map[string]struct{})}
		observations[key] = observation
	}
	encoded, err := graph.EncodeSecuritySemantics(semantics)
	if err != nil {
		return
	}
	observation.semantics[encoded] = semantics
	for _, anchor := range anchors {
		observation.anchors[anchor] = struct{}{}
	}
}

func (observation *securityObservation) externalAddressable() bool {
	for _, semantics := range observation.semantics {
		if semantics.Class == graph.SecurityClassExposure && semantics.Effect == "external-addressable" {
			return true
		}
	}
	return false
}

func (observation *securityObservation) fingerprint() string {
	values := make([]string, 0, len(observation.semantics))
	for value := range observation.semantics {
		values = append(values, value)
	}
	slices.Sort(values)
	return strings.Join(values, "\x00")
}

func (observation *securityObservation) anchorIDs() []string {
	anchors := make([]string, 0, len(observation.anchors))
	for anchor := range observation.anchors {
		anchors = append(anchors, anchor)
	}
	return anchors
}

func appendScoredSignal(signals []InvestigationSignal, score int, reasons, anchors []string, observedAt time.Time, config Config) []InvestigationSignal {
	if score < config.MinimumScore {
		return signals
	}
	return append(signals, scoredSignal(score, reasons, anchors, observedAt, config.Window))
}

func scoredSignal(score int, reasons, anchors []string, observedAt time.Time, windowSize time.Duration) InvestigationSignal {
	anchors = slices.Clone(anchors)
	slices.Sort(anchors)
	anchors = slices.Compact(anchors)
	reasons = slices.Clone(reasons)
	slices.Sort(reasons)
	reasons = slices.Compact(reasons)
	window := TimeWindow{Start: observedAt.Add(-windowSize), End: observedAt.Add(windowSize)}
	parts := append(append([]string{}, anchors...), reasons...)
	parts = append(parts, strconv.Itoa(score), window.Start.Format(time.RFC3339Nano), window.End.Format(time.RFC3339Nano))
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return InvestigationSignal{
		ID: "signal:sha256:" + hex.EncodeToString(digest[:]), Risk: riskForScore(score),
		Reasons: reasons, AnchorIDs: anchors, Window: window,
	}
}

func riskForScore(score int) Risk {
	switch {
	case score >= 6:
		return RiskCritical
	case score >= 4:
		return RiskHigh
	case score >= 3:
		return RiskMedium
	default:
		return RiskLow
	}
}
