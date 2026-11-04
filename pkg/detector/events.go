package detector

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

// InputVersion is the [Input] contract version rules must declare. A change
// to the meaning of any input field requires a new version.
const InputVersion = "v1"

// Input holds every CEL variable; CELEnvironment declares only the subset a selector populates.
type Input struct {
	Operation             string            `json:"operation" cel_description:"Normalized operation of the observed activity; values depend on the selector."`
	Outcome               string            `json:"outcome" cel_description:"Normalized outcome of the observed activity; values depend on the selector."`
	DestinationIPClass    string            `json:"destination_ip_class" cel_description:"Class of the destination IP address. The raw address is never exposed."`
	DestinationRole       string            `json:"destination_role" cel_description:"Cluster role of the destination, from the graph's known resource addresses."`
	DestinationResourceID string            `json:"destination_resource_id" cel_description:"Stable graph resource ID of the destination."`
	ProcessClass          string            `json:"process_class" cel_description:"Class of the process the subject workload started."`
	Attributes            map[string]string `json:"attributes,omitempty" cel_description:"Bounded normalized attributes of the changed resource."`
}

// Event is one rule-evaluation input. ID is stable for the same edge owner or
// telemetry fingerprint. AnchorIDs are the subject and object; SubjectIDs are
// the subject alone. Both include any supported workload controller that
// instantiates an anchored Pod, so workload-scoped rules match Pod activity.
type Event struct {
	ID         string    `json:"id"`
	PluginID   string    `json:"pluginId"`
	SourceID   string    `json:"sourceId"`
	Type       string    `json:"type"`
	Kind       string    `json:"kind"`
	AnchorIDs  []string  `json:"anchorIds"`
	SubjectIDs []string  `json:"subjectIds,omitempty"`
	ObservedAt time.Time `json:"observedAt"`
	Input      Input     `json:"input"`
}

func (event Event) validate() error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(encoded) > 64*1024 {
		return errors.New("detection input exceeds 64 KiB")
	}
	return nil
}

// Events returns newly resolved relationship edges and newly observed telemetry combinations.
//
// A relationship yields one event per contributing (plugin, source) the first
// time it appears resolved; lease refreshes and removals yield none, so an
// existing edge never re-alerts. Telemetry novelty compares kind, endpoints,
// neutral operation, and outcome per plugin and source; count, property, and
// evidence churn alone produce nothing. Events are sorted by ID.
func Events(previous, current graph.Snapshot, observedAt time.Time) []Event {
	if observedAt.IsZero() {
		observedAt = latestTelemetryTime(current)
	}
	if observedAt.IsZero() {
		observedAt = time.Unix(0, 0)
	}
	resources := resourcesByID(current)
	roles := graph.ResourceNetworkRoles(current)
	events := newResourceEvents(previous, current, observedAt.UTC())
	events = append(events, newRelationshipEvents(previous, current, resources, roles, observedAt.UTC())...)
	events = append(events, novelTelemetryEvents(previous, current, resources, roles)...)
	attachWorkloadAnchors(events, current, resources)
	slices.SortFunc(events, func(left, right Event) int { return strings.Compare(left.ID, right.ID) })
	return events
}

func newResourceEvents(previous, current graph.Snapshot, observedAt time.Time) []Event {
	known := make(map[string]string, len(previous.Resources))
	for _, resource := range previous.Resources {
		if _, _, revision, _, ok := resourceRuleProjection(resource); ok {
			known[resource.ID] = revision
		}
	}
	var events []Event
	for _, resource := range current.Resources {
		pluginID, sourceID, revision, attributes, ok := resourceRuleProjection(resource)
		if !ok || known[resource.ID] == revision {
			continue
		}
		events = append(events, Event{
			ID: eventKey("resource", resource.ID, revision), PluginID: pluginID, SourceID: sourceID,
			Type: "resource", Kind: resource.Kind, AnchorIDs: []string{resource.ID}, SubjectIDs: []string{resource.ID},
			ObservedAt: observedAt, Input: Input{Attributes: attributes},
		})
	}
	return events
}

func resourceRuleProjection(resource graph.Resource) (string, string, string, map[string]string, bool) {
	var pluginID, sourceID, revision string
	var attributes map[string]string
	for _, assertion := range resource.Assertions {
		encoded := assertion.Attributes[graph.ResourceAuthoringContextAttribute]
		if encoded == "" {
			continue
		}
		projection, err := graph.DecodeResourceAuthoringProjection(encoded)
		if err != nil {
			continue
		}
		candidate, err := projection.RevisionSHA256()
		if err != nil {
			continue
		}
		if revision != "" && revision != candidate {
			return "", "", "", nil, false
		}
		if revision == "" {
			pluginID, sourceID, revision, attributes = assertion.PluginID, assertion.SourceID, candidate, maps.Clone(projection.Attributes)
		}
	}
	return pluginID, sourceID, revision, attributes, revision != ""
}

func newRelationshipEvents(previous, current graph.Snapshot, resources map[string]graph.Resource, roles map[string]string, observedAt time.Time) []Event {
	existing := map[string]bool{}
	for _, relationship := range previous.Relationships {
		if relationship.ResolutionStatus != graph.ResolutionUnresolved {
			existing[relationshipKey(relationship)] = true
		}
	}
	var events []Event
	for _, relationship := range current.Relationships {
		key := relationshipKey(relationship)
		if relationship.ResolutionStatus == graph.ResolutionUnresolved || existing[key] {
			continue
		}
		input := relationshipInput(relationship, resources, roles)
		owners := map[[2]string]bool{}
		for _, assertion := range relationship.Assertions {
			owner := [2]string{assertion.PluginID, assertion.SourceID}
			if owners[owner] {
				continue
			}
			owners[owner] = true
			events = append(events, Event{
				ID: eventKey("relationship", key, owner[0], owner[1]), PluginID: owner[0], SourceID: owner[1],
				Type: "relationship", Kind: string(relationship.Predicate),
				AnchorIDs: []string{relationship.SubjectID, relationship.ObjectID}, SubjectIDs: []string{relationship.SubjectID},
				ObservedAt: observedAt, Input: input,
			})
		}
	}
	return events
}

func relationshipInput(relationship graph.Relationship, resources map[string]graph.Resource, roles map[string]string) Input {
	if relationship.Predicate == graph.PredicateExecutes {
		return Input{ProcessClass: processClass(relationship.ObjectID, resources)}
	}
	if relationship.Predicate != graph.PredicateCommunicates {
		return Input{}
	}
	input := Input{DestinationIPClass: telemetry.DestinationIPClassUnknown, DestinationRole: roles[relationship.ObjectID], DestinationResourceID: relationship.ObjectID}
	object, exists := resources[relationship.ObjectID]
	if exists && object.Kind == "network/destination" && strings.HasPrefix(object.Identity.ImmutableKey, "ip/") {
		if class, err := telemetry.ClassifyDestinationIP(strings.TrimPrefix(object.Identity.ImmutableKey, "ip/")); err == nil {
			input.DestinationIPClass = class
		}
	}
	return input
}

func novelTelemetryEvents(previous, current graph.Snapshot, resources map[string]graph.Resource, roles map[string]string) []Event {
	known := map[string]bool{}
	for _, event := range previous.Telemetry {
		known[eventKey(event.PluginID, event.SourceID, telemetryFingerprint(event))] = true
	}
	var events []Event
	for _, event := range current.Telemetry {
		key := eventKey(event.PluginID, event.SourceID, telemetryFingerprint(event))
		timestamp, ok := telemetryTime(event)
		if known[key] || !ok {
			continue
		}
		events = append(events, Event{
			ID: eventKey("telemetry", key), PluginID: event.PluginID, SourceID: event.SourceID, Type: "telemetry", Kind: event.Kind,
			AnchorIDs: []string{event.SubjectID, event.ObjectID}, SubjectIDs: []string{event.SubjectID}, ObservedAt: timestamp,
			Input: Input{
				Operation: event.Operation, Outcome: event.Outcome,
				DestinationIPClass: destinationIPClass(event.Properties["destination-ip-class"]), DestinationRole: roles[event.ObjectID], DestinationResourceID: event.ObjectID,
				ProcessClass: processClass(event.ObjectID, resources),
			},
		})
	}
	return events
}

// processClass returns the object's process class, or empty when the object is not a process class.
func processClass(objectID string, resources map[string]graph.Resource) string {
	object, found := resources[objectID]
	if !found || !graph.IsProcessClassClaim(object.Identity) {
		return ""
	}
	return object.Identity.ImmutableKey
}

func destinationIPClass(value string) string {
	for _, class := range telemetry.DestinationIPClasses() {
		if class.Class == value {
			return value
		}
	}
	return telemetry.DestinationIPClassUnknown
}

func attachWorkloadAnchors(events []Event, snapshot graph.Snapshot, resources map[string]graph.Resource) {
	instances := make(map[string][]string)
	for _, relationship := range snapshot.Relationships {
		if relationship.Predicate == graph.PredicateInstantiates && relationship.ResolutionStatus != graph.ResolutionUnresolved {
			instances[relationship.SubjectID] = append(instances[relationship.SubjectID], relationship.ObjectID)
		}
	}
	for controller := range instances {
		slices.Sort(instances[controller])
		instances[controller] = slices.Compact(instances[controller])
	}
	workloadsByPod := map[string][]string{}
	for _, workload := range snapshot.Resources {
		if !resourceAuthoringKind(workload.Kind) {
			continue
		}
		visited := map[string]struct{}{workload.ID: {}}
		queue := slices.Clone(instances[workload.ID])
		for len(queue) > 0 {
			instance := queue[0]
			queue = queue[1:]
			if _, found := visited[instance]; found {
				continue
			}
			visited[instance] = struct{}{}
			if resource, found := resources[instance]; found && resource.Kind == "kubernetes/pod" {
				workloadsByPod[instance] = append(workloadsByPod[instance], workload.ID)
				continue
			}
			queue = append(queue, instances[instance]...)
		}
	}
	for index := range events {
		events[index].AnchorIDs = withWorkloads(events[index].AnchorIDs, workloadsByPod)
		events[index].SubjectIDs = withWorkloads(events[index].SubjectIDs, workloadsByPod)
	}
}

// withWorkloads adds supported controllers that instantiate any of ids, sorted and deduplicated.
func withWorkloads(ids []string, workloadsByPod map[string][]string) []string {
	for _, id := range slices.Clone(ids) {
		ids = append(ids, workloadsByPod[id]...)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func resourceAuthoringKind(kind string) bool {
	return kind == "kubernetes/deployment" || kind == "kubernetes/statefulset" || kind == "kubernetes/daemonset"
}
