package istio

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	istioapi "github.com/agentshield-dev/agentshield/plugins/istio/api"
)

// routeReference is one destination named by a VirtualService route, kept
// only to digest and count the routes behind an edge.
type routeReference struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Subset   string `json:"subset,omitempty"`
	Port     uint32 `json:"port,omitempty"`
	Mirror   bool   `json:"mirror,omitempty"`
}

// resolvedRoute aggregates every reference of one protocol that resolves to
// the same destination, so the projector emits one edge per pair instead of
// one per route.
type resolvedRoute struct {
	claim      graph.IdentityClaim
	evidence   string
	count      int
	mirror     bool
	subsets    []string
	ports      []uint32
	references []routeReference
}

// projectVirtualServices emits a resource per VirtualService and an exposes
// edge to each destination its routes forward to. The edge describes
// configured forwarding, not reachability or a security effect, so it carries
// no security semantics.
//
// Destinations resolve against Services in the VirtualService's namespace
// (short names are relative to it) and against ServiceEntry hosts exported to
// that namespace. ServiceEntries are projected first so their hosts are
// indexed. Wildcard, unknown, and ambiguous destinations get no edge but still
// count toward istio/destination-count.
func (projector *projection) projectVirtualServices() error {
	for _, observed := range projector.index.byKind["VirtualService"] {
		item := observed.Object
		if item.GetAPIVersion() != "networking.istio.io/v1" {
			continue
		}
		decoded, err := istioapi.VirtualServiceObject(item)
		if err != nil {
			return err
		}
		virtualService := decoded.Value
		hosts := virtualService.Spec.Hosts
		// Hosts that do not canonicalize, such as a bare "*", are left out
		// of the attribute.
		canonicalHosts := make([]string, 0, len(hosts))
		for _, host := range hosts {
			if canonical, _, err := canonicalHost(host); err == nil {
				canonicalHosts = append(canonicalHosts, canonical)
			}
		}
		canonicalHosts = sortedUnique(canonicalHosts)
		gateways := slices.Clone(virtualService.Spec.Gateways)
		exportTo := slices.Clone(virtualService.Spec.ExportTo)
		httpRoutes := virtualService.Spec.HTTP
		tlsRoutes := virtualService.Spec.TLS
		tcpRoutes := virtualService.Spec.TCP
		slices.Sort(gateways)
		slices.Sort(exportTo)
		references := append(extractHTTPRouteReferences(httpRoutes), extractL4RouteReferences("tls", tlsRoutes)...)
		references = append(references, extractL4RouteReferences("tcp", tcpRoutes)...)
		attributes := map[string]string{
			"kubernetes/api-version":  item.GetAPIVersion(),
			"kubernetes/name":         item.GetName(),
			"kubernetes/namespace":    item.GetNamespace(),
			"istio/hosts":             projectkit.MustCanonicalJSON(canonicalHosts),
			"istio/gateway-count":     strconv.Itoa(len(gateways)),
			"istio/export-to":         projectkit.MustCanonicalJSON(exportTo),
			"istio/http-route-count":  strconv.Itoa(len(httpRoutes)),
			"istio/tls-route-count":   strconv.Itoa(len(tlsRoutes)),
			"istio/tcp-route-count":   strconv.Itoa(len(tcpRoutes)),
			"istio/destination-count": strconv.Itoa(len(references)),
			"istio/spec-sha256":       projectkit.Digest(decoded.SpecJSON),
		}
		projector.input.Resources = append(projector.input.Resources, resourceAssertion(projector.context.SourceID, observed, "istio/virtualservice", "istio.virtualservice", attributes))

		resolved := make(map[string]*resolvedRoute)
		for _, reference := range references {
			result := projector.index.resolveDestination(item.GetNamespace(), reference.Host)
			if result.Status != resolutionResolved {
				continue
			}
			// Keyed by protocol too, so HTTP and TCP forwarding to one
			// destination stay separate edges.
			key := reference.Protocol + "/" + claimKey(result.Claim)
			route := resolved[key]
			if route == nil {
				route = &resolvedRoute{claim: result.Claim, evidence: result.Evidence}
				resolved[key] = route
			}
			route.count++
			route.mirror = route.mirror || reference.Mirror
			route.references = append(route.references, reference)
			if reference.Subset != "" {
				route.subsets = append(route.subsets, reference.Subset)
			}
			if reference.Port != 0 {
				route.ports = append(route.ports, reference.Port)
			}
		}
		keys := make([]string, 0, len(resolved))
		for key := range resolved {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			route := resolved[key]
			route.subsets = sortedUnique(route.subsets)
			route.ports = sortedUniqueUint32(route.ports)
			slices.SortFunc(route.references, func(left, right routeReference) int {
				return cmp.Compare(projectkit.MustCanonicalJSON(left), projectkit.MustCanonicalJSON(right))
			})
			protocol := strings.SplitN(key, "/", 2)[0]
			properties := map[string]string{
				"semantic":     "istio-configured-forwarding",
				"route-count":  strconv.Itoa(route.count),
				"mirror":       strconv.FormatBool(route.mirror),
				"subsets":      projectkit.MustCanonicalJSON(route.subsets),
				"ports":        projectkit.MustCanonicalJSON(route.ports),
				"route-sha256": projectkit.Digest(route.references),
			}
			projector.input.Relationships = append(projector.input.Relationships, relationship(
				projector.context.SourceID, "istio.virtualservice-destination", observed.Claim, graph.PredicateExposes, route.claim,
				"istio-route-"+protocol, properties, observed.EventID, route.evidence,
			))
		}
	}
	return nil
}

// extractHTTPRouteReferences collects weighted destinations and mirrors.
// Mirrors receive a copy of the traffic, so they count as forwarding but are
// flagged.
func extractHTTPRouteReferences(routes []istioapi.HTTPRoute) []routeReference {
	var result []routeReference
	for _, route := range routes {
		for _, weighted := range route.Route {
			// An explicit weight of 0 sends no traffic; an omitted weight
			// does not mean 0.
			if weighted.Weight != nil && *weighted.Weight == 0 {
				continue
			}
			if reference, ok := routeReferenceFrom("http", weighted.Destination, false); ok {
				result = append(result, reference)
			}
		}
		if reference, ok := routeReferenceFrom("http", route.Mirror, true); ok {
			result = append(result, reference)
		}
		for _, mirror := range route.Mirrors {
			if reference, ok := routeReferenceFrom("http", mirror.Destination, true); ok {
				result = append(result, reference)
			}
		}
	}
	return result
}

// extractL4RouteReferences collects weighted destinations from TLS or TCP
// routes, which have no mirrors.
func extractL4RouteReferences(protocol string, routes []istioapi.L4Route) []routeReference {
	var result []routeReference
	for _, route := range routes {
		for _, weighted := range route.Route {
			if weighted.Weight != nil && *weighted.Weight == 0 {
				continue
			}
			if reference, ok := routeReferenceFrom(protocol, weighted.Destination, false); ok {
				result = append(result, reference)
			}
		}
	}
	return result
}

func routeReferenceFrom(protocol string, destination *istioapi.Destination, mirror bool) (routeReference, bool) {
	if destination == nil || strings.TrimSpace(destination.Host) == "" {
		return routeReference{}, false
	}
	reference := routeReference{Protocol: protocol, Host: destination.Host, Subset: destination.Subset, Mirror: mirror}
	if destination.Port != nil {
		reference.Port = destination.Port.Number
	}
	return reference, true
}

func sortedUniqueUint32(values []uint32) []uint32 {
	slices.Sort(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
