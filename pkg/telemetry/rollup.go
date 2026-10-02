package telemetry

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// RollupConfig bounds a Rollup. Zero values select the defaults noted.
type RollupConfig struct {
	// Window is the series bucket width. Default 1 minute.
	Window time.Duration
	// Retention drops series whose last observation is older than this
	// relative to the newest event or lifecycle tick, and is the lease length
	// of communicates-with edges. Default 24h.
	Retention time.Duration
	// EdgeRefreshBefore is the refresh horizon: a published edge lease is
	// renewed only once it is within this long of expiring. Default and
	// fallback for out-of-range values: Retention/4.
	EdgeRefreshBefore time.Duration
	// MaxSeries caps retained series; the oldest is evicted on overflow.
	// Default 100,000.
	MaxSeries int
	// MaxClockSkew is how far past the rollup clock an event may be dated.
	// Later events stay in the raw sink but are not rolled up, so one
	// future-dated record cannot expire every series. Default 5 minutes.
	MaxClockSkew time.Duration
	// UnresolvedGrace is how long a network destination with no unique
	// exposes binding keeps its exact address in the rollup, waiting for
	// inventory, before it collapses to a peer class. Default 5 minutes.
	UnresolvedGrace time.Duration
	// Now is the rollup clock. Default time.Now.
	Now func() time.Time
}

// maxHeldFraction bounds series that hold an unresolved address: at most
// MaxSeries/maxHeldFraction of them. Beyond that, unresolved destinations
// collapse to their peer class at once, so address scans cannot fill the
// rollup.
const maxHeldFraction = 10

// Rollup is the in-memory bounded projection of sink-committed telemetry
// into graph input. It owns three kinds of state:
//
//   - series: per-window counts keyed by plugin, source, endpoints, kind,
//     operation, outcome, coverage, and rollup properties;
//   - edges: one communicates-with lease per (plugin, source, subject,
//     object), derived from series;
//   - classes: NetworkPeerClass resources referenced by live series.
//
// Graph cardinality is bounded by Retention, MaxSeries, and the per-series
// evidence cap, not by traffic volume. Counts are not deduplicated by event
// ID, so a producer retry that re-enqueues events can inflate them; the raw
// sink is authoritative. Rollup is safe for concurrent use.
type Rollup struct {
	mu      sync.Mutex
	config  RollupConfig
	series  map[seriesKey]*seriesValue
	edges   map[edgeKey]*edgeValue
	classes map[classKey][]string
}

// OwnedInput is the rollup graph input owned by one telemetry provider's
// plugin and source.
type OwnedInput struct {
	PluginID string
	SourceID string
	Input    graph.Input
}

type seriesKey struct {
	WindowStart int64
	PluginID    string
	Kind        string
	Subject     graph.IdentityClaim
	Object      graph.IdentityClaim
	Operation   string
	Outcome     string
	Coverage    string
	SourceID    string
	Properties  string
	// LeaseOnly marks a placeholder series restored from a published edge
	// lease with no backing telemetry series. It keeps the edge alive until
	// its lease would expire but is never published as telemetry.
	LeaseOnly bool `json:"-"`
	// LeasePredicate is the predicate of a LeaseOnly series restored from its relationship.
	LeasePredicate graph.Predicate `json:"-"`
}

type seriesValue struct {
	Count       uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	EvidenceIDs map[string]struct{}
	// Created is the rollup clock time the series was created. It starts
	// the UnresolvedGrace of a series holding an unresolved address.
	Created time.Time
}

type edgeKey struct {
	PluginID string
	SourceID string
	Subject  graph.IdentityClaim
	Object   graph.IdentityClaim
	// Predicate is excluded from edgeID so communicates-with lease IDs are unchanged;
	// a class object determines its kind, so one pair never carries two predicates.
	Predicate graph.Predicate `json:"-"`
}

// edgeValue is the published state of a lease. PublishedExpiresAt and
// EvidenceIDs change only on creation and refresh, so ordinary traffic does
// not change the published relationship assertion.
type edgeValue struct {
	LastSeen           time.Time
	PublishedExpiresAt time.Time
	EvidenceIDs        []string
}

type classKey struct {
	PluginID string
	SourceID string
	Claim    graph.IdentityClaim
}

// classDefinition describes a bounded core identity vocabulary that the rollup
// materializes as a resource while a retained series references it.
type classDefinition struct {
	Kind             string
	RuleID           string
	EvidencePrefix   string
	ContainsIdentity func(graph.IdentityClaim) bool
}

var classDefinitions = []classDefinition{
	{Kind: "network/peer-class", RuleID: "telemetry.network-peer-class", EvidencePrefix: "telemetry-peer-class:", ContainsIdentity: graph.IsNetworkPeerClassClaim},
	{Kind: "process/class", RuleID: "telemetry.process-class", EvidencePrefix: "telemetry-process-class:", ContainsIdentity: graph.IsProcessClassClaim},
}

func classFor(claim graph.IdentityClaim) (classDefinition, bool) {
	for _, definition := range classDefinitions {
		if definition.ContainsIdentity(claim) {
			return definition, true
		}
	}
	return classDefinition{}, false
}

// NewRollup returns an empty rollup with defaults applied.
func NewRollup(config RollupConfig) *Rollup {
	if config.Window <= 0 {
		config.Window = time.Minute
	}
	if config.Retention <= 0 {
		config.Retention = 24 * time.Hour
	}
	if config.EdgeRefreshBefore <= 0 || config.EdgeRefreshBefore >= config.Retention {
		config.EdgeRefreshBefore = config.Retention / 4
	}
	if config.MaxSeries <= 0 {
		config.MaxSeries = 100_000
	}
	if config.MaxClockSkew <= 0 {
		config.MaxClockSkew = 5 * time.Minute
	}
	if config.UnresolvedGrace <= 0 {
		config.UnresolvedGrace = 5 * time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Rollup{config: config, series: make(map[seriesKey]*seriesValue), edges: make(map[edgeKey]*edgeValue), classes: make(map[classKey][]string)}
}

// ObserveBatch folds a sink-committed batch into the rollup. Call it only
// after the sink acknowledged the batch. Endpoints should already be resolved
// with ResolveGraphEndpoints. Series whose endpoints are not yet materialized
// are kept: the host filters them out at publication and they appear once
// inventory catches up, within Retention. That retained, bounded series set
// is the retry path for unresolved endpoints.
//
// Events dated more than MaxClockSkew past the rollup clock are not rolled up
// and are counted in the result; they remain in the raw sink. Expiry runs
// from the newest event time, capped at the rollup clock.
func (rollup *Rollup) ObserveBatch(events []Event) (skipped int) {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	return rollup.observeLocked(events, rollup.config.Now().UTC())
}

// ObserveResolved resolves endpoints against snapshot and folds events into
// the rollup at now; it is what RollupPublisher uses. Unlike
// ResolveGraphEndpoints, a network destination without a unique binding
// keeps its exact address for UnresolvedGrace (within the held-series
// bound). Every call first re-resolves the held series: one whose address
// gained a binding moves to the bound resource, and one past its grace
// collapses to its peer class. It reports whether that re-resolution changed
// any series, and how many events were skipped as future-dated.
func (rollup *Rollup) ObserveResolved(events []Event, snapshot graph.Snapshot, now time.Time) (changed bool, skipped int) {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	index := newEndpointIndex(snapshot)
	changed, held := rollup.resolveHeldLocked(index, now)
	maxHeld := max(rollup.config.MaxSeries/maxHeldFraction, 1)
	resolved := make([]Event, len(events))
	copy(resolved, events)
	for position := range resolved {
		event := &resolved[position]
		subject, subjectBound := index.bind(event.Subject)
		object, objectBound := index.bind(event.Object)
		if (subjectBound && objectBound) || held < maxHeld {
			if !subjectBound || !objectBound {
				held++
			}
			event.Subject, event.Object = subject, object
			continue
		}
		event.Subject, event.Object = index.resolve(event.Subject, true), index.resolve(event.Object, false)
	}
	return changed, rollup.observeLocked(resolved, now)
}

// resolveHeldLocked re-resolves series that hold an unresolved address and
// returns whether any series moved and how many still hold one.
func (rollup *Rollup) resolveHeldLocked(index endpointIndex, now time.Time) (bool, int) {
	type move struct {
		from seriesKey
		to   seriesKey
	}
	var moves []move
	held := 0
	for key, value := range rollup.series {
		if key.LeaseOnly {
			continue
		}
		subject, subjectBound := index.bind(key.Subject)
		object, objectBound := index.bind(key.Object)
		if subjectBound && objectBound && subject == key.Subject && object == key.Object {
			continue
		}
		expired := now.Sub(value.Created) >= rollup.config.UnresolvedGrace
		if !subjectBound && expired {
			subject, subjectBound = index.resolve(key.Subject, true), true
		}
		if !objectBound && expired {
			object, objectBound = index.resolve(key.Object, false), true
		}
		if !subjectBound || !objectBound {
			held++
		}
		if subject == key.Subject && object == key.Object {
			continue
		}
		target := key
		target.Subject, target.Object = subject, object
		moves = append(moves, move{from: key, to: target})
	}
	// Apply in a fixed order so merged evidence does not depend on map order.
	slices.SortFunc(moves, func(left, right move) int { return cmp.Compare(seriesID(left.from), seriesID(right.from)) })
	for _, moved := range moves {
		value := rollup.series[moved.from]
		delete(rollup.series, moved.from)
		if existing := rollup.series[moved.to]; existing != nil {
			mergeSeries(existing, value)
		} else {
			rollup.series[moved.to] = value
		}
	}
	return len(moves) > 0, held
}

// mergeSeries folds source into target, keeping the evidence bound.
func mergeSeries(target, source *seriesValue) {
	target.Count += source.Count
	if source.FirstSeen.Before(target.FirstSeen) {
		target.FirstSeen = source.FirstSeen
	}
	if source.LastSeen.After(target.LastSeen) {
		target.LastSeen = source.LastSeen
	}
	if source.Created.Before(target.Created) {
		target.Created = source.Created
	}
	for evidenceID := range source.EvidenceIDs {
		target.EvidenceIDs[evidenceID] = struct{}{}
		if len(target.EvidenceIDs) > maxEvidenceIDs {
			delete(target.EvidenceIDs, greatestEvidenceID(target.EvidenceIDs))
		}
	}
}

func (rollup *Rollup) observeLocked(events []Event, now time.Time) (skipped int) {
	latest := now.Add(rollup.config.MaxClockSkew)
	var newest time.Time
	for _, event := range events {
		if event.PluginID == "" || event.SourceID == "" {
			continue
		}
		if event.ObservedAt.After(latest) {
			skipped++
			continue
		}
		rollup.observeClasses(event)
		if event.ObservedAt.After(newest) {
			newest = event.ObservedAt
		}
		key := seriesKey{
			WindowStart: event.ObservedAt.Truncate(rollup.config.Window).UnixNano(), PluginID: event.PluginID, Kind: event.Kind,
			Subject: event.Subject, Object: event.Object, Operation: event.Operation, Outcome: event.Outcome,
			Coverage: event.Coverage, SourceID: event.SourceID, Properties: canonicalProperties(event.RollupProperties),
		}
		value := rollup.series[key]
		added := value == nil
		if value == nil {
			value = &seriesValue{EvidenceIDs: make(map[string]struct{}), Created: now}
			rollup.series[key] = value
		}
		value.Count += event.Count
		if value.FirstSeen.IsZero() || event.ObservedAt.Before(value.FirstSeen) {
			value.FirstSeen = event.ObservedAt
		}
		if event.ObservedAt.After(value.LastSeen) {
			value.LastSeen = event.ObservedAt
		}
		// Keep the lexically smallest evidence IDs so the retained set is
		// deterministic regardless of arrival order.
		for _, evidenceID := range event.EvidenceIDs {
			value.EvidenceIDs[evidenceID] = struct{}{}
			if len(value.EvidenceIDs) > maxEvidenceIDs {
				delete(value.EvidenceIDs, greatestEvidenceID(value.EvidenceIDs))
			}
		}
		if added && len(rollup.series) > rollup.config.MaxSeries {
			rollup.evictOldest()
		}
	}
	// Expiry is driven by event time, so replayed or delayed batches age the
	// rollup consistently, but never past the rollup clock: a skewed producer
	// clock must not expire live series.
	if newest.After(now) {
		newest = now
	}
	if !newest.IsZero() {
		rollup.expireBefore(newest.Add(-rollup.config.Retention))
	}
	rollup.reconcileEdges(newest)
	rollup.reconcileClasses()
	return skipped
}

// Advance applies time-based changes at now: expiring series and leases,
// refreshing leases in their horizon, and dropping unused peer classes. It
// reports whether graph input changed, so a quiet lifecycle tick publishes
// only when something expired or was refreshed.
func (rollup *Rollup) Advance(now time.Time) bool {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	previousSeries := len(rollup.series)
	previousEdges := len(rollup.edges)
	rollup.expireBefore(now.Add(-rollup.config.Retention))
	refreshed := rollup.reconcileEdges(now)
	classesChanged := rollup.reconcileClasses()
	return refreshed || classesChanged || previousSeries != len(rollup.series) || previousEdges != len(rollup.edges)
}

// Restore rebuilds rollup state from the canonical graph after a restart,
// before new events are accepted. Restoring the published edge leases with
// their exact expiry matters: without them, the first post-restart
// publication would omit still-live edges and retract them. Leases without a
// surviving telemetry series get a LeaseOnly placeholder series.
//
// Historical rollups owned by the old telemetry/runtime host fallback are
// discarded rather than restored under a synthetic provider identity.
func (rollup *Rollup) Restore(snapshot graph.Snapshot) error {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	rollup.series = make(map[seriesKey]*seriesValue)
	rollup.edges = make(map[edgeKey]*edgeValue)
	rollup.classes = make(map[classKey][]string)
	identities := make(map[string]graph.IdentityClaim, len(snapshot.Resources))
	restoredSeriesEdges := make(map[edgeKey]struct{})
	for _, resource := range snapshot.Resources {
		identities[resource.ID] = resource.Identity
		definition, isClass := classFor(resource.Identity)
		if !isClass {
			continue
		}
		for _, assertion := range resource.Assertions {
			if assertion.RuleID == definition.RuleID {
				pluginID, pluginFound := assertion.Attributes["telemetry/provider-plugin-id"]
				sourceID, sourceFound := assertion.Attributes["telemetry/provider-source-id"]
				if !pluginFound || !sourceFound {
					pluginID, sourceID = assertion.PluginID, assertion.SourceID
				}
				if !validRollupOwner(pluginID, sourceID) {
					continue
				}
				key := classKey{PluginID: pluginID, SourceID: sourceID, Claim: resource.Identity}
				rollup.classes[key] = slices.Clone(assertion.EvidenceIDs)
			}
		}
	}
	for _, event := range snapshot.Telemetry {
		if event.RuleID != "telemetry.time-window-rollup" {
			continue
		}
		subject, subjectFound := identities[event.SubjectID]
		object, objectFound := identities[event.ObjectID]
		if !subjectFound || !objectFound {
			return fmt.Errorf("restore telemetry %q: endpoint identity is missing", event.EventID)
		}
		properties := mapsClone(event.Properties)
		windowStart, err := time.Parse(time.RFC3339Nano, properties["telemetry/window-start"])
		if err != nil {
			return fmt.Errorf("restore telemetry %q window: %w", event.EventID, err)
		}
		firstSeen, err := time.Parse(time.RFC3339Nano, properties["telemetry/first-seen"])
		if err != nil {
			return fmt.Errorf("restore telemetry %q first seen: %w", event.EventID, err)
		}
		lastSeen, err := time.Parse(time.RFC3339Nano, properties["telemetry/last-seen"])
		if err != nil {
			return fmt.Errorf("restore telemetry %q last seen: %w", event.EventID, err)
		}
		originalSourceID := properties["telemetry/source-id"]
		delete(properties, "telemetry/window-start")
		delete(properties, "telemetry/first-seen")
		delete(properties, "telemetry/last-seen")
		delete(properties, "telemetry/source-id")
		providerPluginID, ownershipRecorded := properties["telemetry/provider-plugin-id"]
		delete(properties, "telemetry/provider-plugin-id")
		pluginID, sourceID := providerPluginID, originalSourceID
		if !ownershipRecorded {
			pluginID, sourceID = event.PluginID, event.SourceID
		}
		if !validRollupOwner(pluginID, sourceID) {
			continue
		}
		key := seriesKey{
			WindowStart: windowStart.UnixNano(), PluginID: pluginID, Kind: event.Kind, Subject: subject, Object: object,
			Operation: event.Operation, Outcome: event.Outcome, Coverage: event.Coverage, SourceID: sourceID, Properties: canonicalProperties(properties),
		}
		rollup.series[key] = &seriesValue{
			Count: event.Count, FirstSeen: firstSeen, LastSeen: lastSeen, EvidenceIDs: stringSet(event.EvidenceIDs),
		}
		if edge, leased := semanticEdgeKey(key); leased {
			restoredSeriesEdges[edge] = struct{}{}
		}
	}
	for _, relationship := range snapshot.Relationships {
		for _, assertion := range relationship.Assertions {
			if leaseRuleIDs[assertion.Predicate] == "" || assertion.RuleID != leaseRuleIDs[assertion.Predicate] {
				continue
			}
			expiresAt, err := time.Parse(time.RFC3339Nano, assertion.Properties["telemetry/lease-expires-at"])
			if err != nil {
				return fmt.Errorf("restore telemetry edge %q: %w", relationship.ID, err)
			}
			pluginID, ownershipRecorded := assertion.Properties["telemetry/provider-plugin-id"]
			sourceID := assertion.Properties["telemetry/provider-source-id"]
			if !ownershipRecorded {
				pluginID, sourceID = assertion.PluginID, assertion.SourceID
			}
			if !validRollupOwner(pluginID, sourceID) {
				continue
			}
			key := edgeKey{PluginID: pluginID, SourceID: sourceID, Subject: assertion.Subject, Object: assertion.Object, Predicate: assertion.Predicate}
			lastSeen := expiresAt.Add(-rollup.config.Retention)
			rollup.edges[key] = &edgeValue{
				LastSeen: lastSeen, PublishedExpiresAt: expiresAt, EvidenceIDs: slices.Clone(assertion.EvidenceIDs),
			}
			if _, backedByTelemetry := restoredSeriesEdges[key]; backedByTelemetry {
				continue
			}
			rollup.series[seriesKey{
				WindowStart: lastSeen.Truncate(rollup.config.Window).UnixNano(), PluginID: pluginID, SourceID: sourceID,
				Subject: assertion.Subject, Object: assertion.Object, LeaseOnly: true, LeasePredicate: assertion.Predicate,
			}] = &seriesValue{
				Count: 1, FirstSeen: lastSeen, LastSeen: lastSeen, EvidenceIDs: stringSet(assertion.EvidenceIDs),
			}
		}
	}
	// A zero reference time creates missing edges but never refreshes, so
	// restored leases keep their published expiry.
	rollup.reconcileEdges(time.Time{})
	rollup.reconcileClasses()
	return nil
}

// Input returns the whole rollup as one graph input. Series without provider
// ownership are attributed to pluginID and sourceID. Output is sorted, so it
// is deterministic for a given state.
func (rollup *Rollup) Input() graph.Input {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	return rollup.inputLocked()
}

// Inputs returns the rollup split by owning provider plugin and source,
// sorted by owner, so each provider's rollups are published and retracted as
// that provider's own contribution.
func (rollup *Rollup) Inputs() []OwnedInput {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	input := rollup.inputLocked()
	type owner struct {
		pluginID string
		sourceID string
	}
	grouped := make(map[owner]graph.Input)
	for _, resource := range input.Resources {
		key := owner{pluginID: resource.PluginID, sourceID: resource.SourceID}
		owned := grouped[key]
		owned.Resources = append(owned.Resources, resource)
		grouped[key] = owned
	}
	for _, relationship := range input.Relationships {
		key := owner{pluginID: relationship.PluginID, sourceID: relationship.SourceID}
		owned := grouped[key]
		owned.Relationships = append(owned.Relationships, relationship)
		grouped[key] = owned
	}
	for _, event := range input.Telemetry {
		key := owner{pluginID: event.PluginID, sourceID: event.SourceID}
		owned := grouped[key]
		owned.Telemetry = append(owned.Telemetry, event)
		grouped[key] = owned
	}
	owners := make([]owner, 0, len(grouped))
	for key := range grouped {
		owners = append(owners, key)
	}
	slices.SortFunc(owners, func(left, right owner) int {
		if order := cmp.Compare(left.pluginID, right.pluginID); order != 0 {
			return order
		}
		return cmp.Compare(left.sourceID, right.sourceID)
	})
	result := make([]OwnedInput, 0, len(owners))
	for _, key := range owners {
		result = append(result, OwnedInput{PluginID: key.pluginID, SourceID: key.sourceID, Input: grouped[key]})
	}
	return result
}

func (rollup *Rollup) inputLocked() graph.Input {
	keys := make([]seriesKey, 0, len(rollup.series))
	for key := range rollup.series {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(left, right seriesKey) int { return cmp.Compare(seriesID(left), seriesID(right)) })
	input := graph.Input{
		Resources:     classResources(rollup.classes),
		Relationships: make([]graph.RelationshipAssertion, 0, len(rollup.edges)),
		Telemetry:     make([]graph.TelemetryAssertion, 0, len(keys)),
	}
	edgeKeys := make([]edgeKey, 0, len(rollup.edges))
	for key := range rollup.edges {
		edgeKeys = append(edgeKeys, key)
	}
	slices.SortFunc(edgeKeys, func(left, right edgeKey) int { return cmp.Compare(edgeID(left), edgeID(right)) })
	for _, key := range edgeKeys {
		edge := rollup.edges[key]
		input.Relationships = append(input.Relationships, graph.RelationshipAssertion{
			Subject: key.Subject, Predicate: key.Predicate, Object: key.Object, Qualifier: "telemetry-observed",
			Properties: map[string]string{
				"telemetry/lease-expires-at":   edge.PublishedExpiresAt.UTC().Format(time.RFC3339Nano),
				"telemetry/provider-plugin-id": key.PluginID,
				"telemetry/provider-source-id": key.SourceID,
			},
			PluginID: key.PluginID, SourceID: key.SourceID, RuleID: leaseRuleIDs[key.Predicate],
			EvidenceIDs: slices.Clone(edge.EvidenceIDs),
		})
	}
	for _, key := range keys {
		if key.LeaseOnly {
			continue
		}
		id := seriesID(key)
		value := rollup.series[key]
		properties := decodeProperties(key.Properties)
		properties["telemetry/window-start"] = time.Unix(0, key.WindowStart).UTC().Format(time.RFC3339Nano)
		properties["telemetry/first-seen"] = value.FirstSeen.UTC().Format(time.RFC3339Nano)
		properties["telemetry/last-seen"] = value.LastSeen.UTC().Format(time.RFC3339Nano)
		properties["telemetry/source-id"] = key.SourceID
		properties["telemetry/provider-plugin-id"] = key.PluginID
		input.Telemetry = append(input.Telemetry, graph.TelemetryAssertion{
			EventID: id, Kind: key.Kind, Subject: key.Subject, Object: key.Object,
			Operation: key.Operation, Outcome: key.Outcome, Coverage: key.Coverage, Count: value.Count,
			Properties: properties,
			PluginID:   key.PluginID, SourceID: key.SourceID, RuleID: "telemetry.time-window-rollup",
			EvidenceIDs: sortedEvidence(value.EvidenceIDs, "telemetry-rollup:"+id),
		})
	}
	return input
}

func classResources(classes map[classKey][]string) []graph.ResourceAssertion {
	resourceKeys := make([]classKey, 0, len(classes))
	for key := range classes {
		resourceKeys = append(resourceKeys, key)
	}
	slices.SortFunc(resourceKeys, func(left, right classKey) int {
		leftID := left.PluginID + "\x00" + left.SourceID + "\x00" + left.Claim.AuthorityID + "\x00" + left.Claim.ImmutableKey
		rightID := right.PluginID + "\x00" + right.SourceID + "\x00" + right.Claim.AuthorityID + "\x00" + right.Claim.ImmutableKey
		return cmp.Compare(leftID, rightID)
	})
	result := make([]graph.ResourceAssertion, 0, len(resourceKeys))
	for _, key := range resourceKeys {
		definition, _ := classFor(key.Claim)
		result = append(result, graph.ResourceAssertion{
			Claim: key.Claim, Kind: definition.Kind, DisplayName: key.Claim.ImmutableKey,
			Attributes: map[string]string{
				definition.Kind:                key.Claim.ImmutableKey,
				"telemetry/provider-plugin-id": key.PluginID,
				"telemetry/provider-source-id": key.SourceID,
			},
			PluginID: key.PluginID, SourceID: key.SourceID, RuleID: definition.RuleID,
			EvidenceIDs: slices.Clone(classes[key]),
		})
	}
	return result
}

func (rollup *Rollup) observeClasses(event Event) {
	for _, claim := range []graph.IdentityClaim{event.Subject, event.Object} {
		definition, isClass := classFor(claim)
		if !isClass {
			continue
		}
		key := classKey{PluginID: event.PluginID, SourceID: event.SourceID, Claim: claim}
		if _, found := rollup.classes[key]; !found {
			rollup.classes[key] = sortedEvidence(stringSet(event.EvidenceIDs), definition.EvidencePrefix+claim.ImmutableKey)
		}
	}
}

func (rollup *Rollup) reconcileClasses() bool {
	active := make(map[classKey]map[string]struct{})
	for key, value := range rollup.series {
		for _, claim := range []graph.IdentityClaim{key.Subject, key.Object} {
			if _, isClass := classFor(claim); !isClass {
				continue
			}
			class := classKey{PluginID: key.PluginID, Claim: claim}
			if key.PluginID != "" {
				class.SourceID = key.SourceID
			}
			if active[class] == nil {
				active[class] = make(map[string]struct{})
			}
			for evidenceID := range value.EvidenceIDs {
				active[class][evidenceID] = struct{}{}
			}
		}
	}
	changed := false
	for key, evidence := range active {
		if _, found := rollup.classes[key]; !found {
			definition, _ := classFor(key.Claim)
			rollup.classes[key] = sortedEvidence(evidence, definition.EvidencePrefix+key.Claim.ImmutableKey)
			changed = true
		}
	}
	for key := range rollup.classes {
		if _, found := active[key]; !found {
			delete(rollup.classes, key)
			changed = true
		}
	}
	return changed
}

func (rollup *Rollup) expireBefore(cutoff time.Time) {
	for key, value := range rollup.series {
		if value.LastSeen.Before(cutoff) {
			delete(rollup.series, key)
		}
	}
}

// reconcileEdges derives communicates-with leases from the retained series.
//
// An edge is a lease rather than a per-batch fact. The reasoning outbox emits
// an event for every relationship assertion change, so the published edge
// must change on lifecycle transitions, not on traffic volume:
//
//   - First sighting: the edge is created with an expiry of first-seen plus
//     Retention and an evidence snapshot from the earliest series. This is
//     one outbox addition.
//   - Steady traffic: LastSeen advances but the published expiry and
//     evidence do not, so the relationship assertion is byte-identical and
//     publication emits no event for it.
//   - Refresh: once referenceTime enters the refresh horizon
//     (PublishedExpiresAt - EdgeRefreshBefore) and traffic has been seen since
//     the lease was set, the expiry moves to LastSeen plus Retention and the
//     evidence is re-snapshotted. This replaces the assertion once per lease
//     period at most.
//   - Expiry: when every series behind an edge has aged out, the edge is
//     deleted and its omission retracts the relationship. Advance runs this
//     on a timer so expiry happens even without traffic.
//
// Leases are keyed by provider and endpoint pair only, so edge cardinality is
// bounded by distinct endpoint pairs within Retention. A zero referenceTime
// creates and expires edges but never refreshes them. It reports whether any
// edge was created, refreshed, or deleted.
func (rollup *Rollup) reconcileEdges(referenceTime time.Time) bool {
	type aggregate struct {
		firstSeen            time.Time
		lastSeen             time.Time
		evidenceIDs          map[string]struct{}
		firstSeenEvidenceIDs map[string]struct{}
	}
	aggregates := make(map[edgeKey]*aggregate)
	for key, value := range rollup.series {
		edge, leased := semanticEdgeKey(key)
		if !leased {
			continue
		}
		current := aggregates[edge]
		if current == nil {
			current = &aggregate{evidenceIDs: make(map[string]struct{}), firstSeenEvidenceIDs: make(map[string]struct{})}
			aggregates[edge] = current
		}
		if current.firstSeen.IsZero() || value.FirstSeen.Before(current.firstSeen) {
			current.firstSeen = value.FirstSeen
			clear(current.firstSeenEvidenceIDs)
		}
		if value.LastSeen.After(current.lastSeen) {
			current.lastSeen = value.LastSeen
		}
		for evidenceID := range value.EvidenceIDs {
			current.evidenceIDs[evidenceID] = struct{}{}
			if len(current.evidenceIDs) > maxEvidenceIDs {
				delete(current.evidenceIDs, greatestEvidenceID(current.evidenceIDs))
			}
			if value.FirstSeen.Equal(current.firstSeen) {
				current.firstSeenEvidenceIDs[evidenceID] = struct{}{}
				if len(current.firstSeenEvidenceIDs) > maxEvidenceIDs {
					delete(current.firstSeenEvidenceIDs, greatestEvidenceID(current.firstSeenEvidenceIDs))
				}
			}
		}
	}
	changed := false
	for key := range rollup.edges {
		if aggregates[key] == nil {
			delete(rollup.edges, key)
			changed = true
		}
	}
	for key, aggregate := range aggregates {
		current := rollup.edges[key]
		if current == nil {
			current = &edgeValue{
				LastSeen: aggregate.lastSeen, PublishedExpiresAt: aggregate.firstSeen.Add(rollup.config.Retention),
				EvidenceIDs: sortedEvidence(aggregate.firstSeenEvidenceIDs, "telemetry-edge:"+edgeID(key)),
			}
			rollup.edges[key] = current
			changed = true
		}
		if aggregate.lastSeen.After(current.LastSeen) {
			current.LastSeen = aggregate.lastSeen
		}
		refreshAt := current.PublishedExpiresAt.Add(-rollup.config.EdgeRefreshBefore)
		if !referenceTime.IsZero() && !referenceTime.Before(refreshAt) && current.LastSeen.Add(rollup.config.Retention).After(current.PublishedExpiresAt) {
			current.PublishedExpiresAt = current.LastSeen.Add(rollup.config.Retention)
			current.EvidenceIDs = sortedEvidence(aggregate.evidenceIDs, "telemetry-edge:"+edgeID(key))
			changed = true
		}
	}
	return changed
}

// semanticEdgeKey returns the lease a series supports, if its kind projects one.
func semanticEdgeKey(key seriesKey) (edgeKey, bool) {
	predicate := LeasePredicate(key.Kind)
	if key.LeaseOnly {
		predicate = key.LeasePredicate
	}
	if predicate == "" {
		return edgeKey{}, false
	}
	edge := edgeKey{PluginID: key.PluginID, Subject: key.Subject, Object: key.Object, Predicate: predicate}
	if key.PluginID != "" {
		edge.SourceID = key.SourceID
	}
	return edge, true
}

func validRollupOwner(pluginID, sourceID string) bool {
	return pluginID != "" && sourceID != "" && !(pluginID == "telemetry" && sourceID == "runtime")
}

func mapsClone(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func edgeID(key edgeKey) string {
	encoded, _ := json.Marshal(key)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// evictOldest removes the series with the oldest LastSeen, breaking ties by
// series ID so eviction is deterministic. It is O(series) per overflow.
func (rollup *Rollup) evictOldest() {
	var oldestKey seriesKey
	var oldest time.Time
	first := true
	for key, value := range rollup.series {
		if first || value.LastSeen.Before(oldest) || value.LastSeen.Equal(oldest) && seriesID(key) < seriesID(oldestKey) {
			oldestKey = key
			oldest = value.LastSeen
			first = false
		}
	}
	if !first {
		delete(rollup.series, oldestKey)
	}
}

func greatestEvidenceID(values map[string]struct{}) string {
	var greatest string
	for value := range values {
		if value > greatest {
			greatest = value
		}
	}
	return greatest
}

// canonicalProperties encodes properties as a comparable series key component.
// encoding/json sorts map keys, so equal maps produce equal strings.
func canonicalProperties(properties map[string]string) string {
	if properties == nil {
		return "{}"
	}
	encoded, _ := json.Marshal(properties)
	return string(encoded)
}

func decodeProperties(encoded string) map[string]string {
	properties := make(map[string]string)
	_ = json.Unmarshal([]byte(encoded), &properties)
	return properties
}

func sortedEvidence(values map[string]struct{}, fallback string) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	if len(result) == 0 {
		result = append(result, fallback)
	}
	sort.Strings(result)
	return result
}

func seriesID(key seriesKey) string {
	encoded, _ := json.Marshal(key)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
