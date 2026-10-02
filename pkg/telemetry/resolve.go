package telemetry

import (
	"net/netip"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// ResolveGraphEndpoints rewrites NetworkDestination endpoints of
// sink-committed events before rollup. A destination exposed by exactly one
// current resource (through an exposes relationship) resolves to that
// resource; a destination that is itself a materialized resource is kept;
// anything else collapses to a direction-aware NetworkPeerClass in the same
// realm. Ambiguous bindings are not guessed. Non-destination endpoints are
// returned unchanged. The exact address stays only in the raw sink, which
// keeps rollup identity bounded.
//
// Resolution uses the current graph, so it reflects bindings at processing
// time, not at the event's observation time. It collapses unresolved
// destinations at once; RollupPublisher instead uses Rollup.ObserveResolved,
// which holds them for a grace period while inventory catches up.
func ResolveGraphEndpoints(events []Event, snapshot graph.Snapshot) []Event {
	index := newEndpointIndex(snapshot)
	resolved := make([]Event, len(events))
	copy(resolved, events)
	for position := range resolved {
		resolved[position].Subject = index.resolve(resolved[position].Subject, true)
		resolved[position].Object = index.resolve(resolved[position].Object, false)
	}
	return resolved
}

// endpointIndex holds the current resources and exposes bindings of
// network destinations.
type endpointIndex struct {
	resources map[graph.IdentityClaim]struct{}
	bindings  map[graph.IdentityClaim]map[graph.IdentityClaim]struct{}
}

func newEndpointIndex(snapshot graph.Snapshot) endpointIndex {
	index := endpointIndex{
		resources: make(map[graph.IdentityClaim]struct{}, len(snapshot.Resources)),
		bindings:  make(map[graph.IdentityClaim]map[graph.IdentityClaim]struct{}),
	}
	for _, resource := range snapshot.Resources {
		index.resources[resource.Identity] = struct{}{}
	}
	for _, relationship := range snapshot.Relationships {
		if relationship.Predicate != graph.PredicateExposes {
			continue
		}
		for _, assertion := range relationship.Assertions {
			if assertion.Predicate != graph.PredicateExposes || !graph.IsNetworkDestinationClaim(assertion.Object) {
				continue
			}
			if index.bindings[assertion.Object] == nil {
				index.bindings[assertion.Object] = make(map[graph.IdentityClaim]struct{})
			}
			index.bindings[assertion.Object][assertion.Subject] = struct{}{}
		}
	}
	return index
}

// bind returns the resource an endpoint resolves to and true, or the claim
// unchanged and false for a network destination with no unique binding to a
// current resource that is not itself a resource. Non-destination claims,
// including peer classes, are always bound to themselves.
func (index endpointIndex) bind(claim graph.IdentityClaim) (graph.IdentityClaim, bool) {
	if !graph.IsNetworkDestinationClaim(claim) {
		return claim, true
	}
	if candidates := index.bindings[claim]; len(candidates) == 1 {
		for candidate := range candidates {
			if _, found := index.resources[candidate]; found {
				return candidate, true
			}
		}
	}
	if _, found := index.resources[claim]; found {
		return claim, true
	}
	return claim, false
}

// resolve binds an endpoint or collapses it to its direction-aware peer class.
func (index endpointIndex) resolve(claim graph.IdentityClaim, source bool) graph.IdentityClaim {
	if bound, found := index.bind(claim); found {
		return bound
	}
	class := networkPeerClass(claim.ImmutableKey, source)
	peer, err := graph.NetworkPeerClassClaim(claim.AuthorityID, class)
	if err != nil {
		return claim
	}
	return peer
}

func networkPeerClass(key string, source bool) string {
	direction := "destination"
	if source {
		direction = "source"
	}
	prefix, value, found := strings.Cut(strings.ToLower(strings.TrimSpace(key)), "/")
	if !found || prefix != "ip" {
		if prefix == "dns" {
			return "dns-" + direction
		}
		return "external-" + direction
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "external-" + direction
	}
	address = address.Unmap().WithZone("")
	switch {
	case address.IsLoopback():
		return "loopback-ip"
	case address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast():
		return "link-local-ip"
	}
	switch classifyAddress(address) {
	case DestinationIPClassPrivate:
		return "private-ip"
	case DestinationIPClassSpecial:
		return "special-use-ip"
	default:
		return "external-" + direction
	}
}
