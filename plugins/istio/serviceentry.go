package istio

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	istioapi "github.com/agentshield-dev/agentshield/plugins/istio/api"
)

// projectServiceEntries emits a resource and a serviceentry-binding facet per
// ServiceEntry, plus a network/destination resource and an exposes edge for
// each valid host. Destination identity is the network ID and canonical host,
// so every ServiceEntry declaring a host in that network shares one node.
// Each host is also indexed, honoring exportTo, so VirtualService routes can
// resolve to it.
//
// A ServiceEntry only adds a name to Istio's service registry; it does not
// prove the endpoints are reachable, so these outputs carry no security
// semantics. Endpoint addresses are reduced to address classes and never
// stored.
func (projector *projection) projectServiceEntries() error {
	for _, observed := range projector.index.byKind["ServiceEntry"] {
		item := observed.Object
		if item.GetAPIVersion() != "networking.istio.io/v1" {
			continue
		}
		decoded, err := istioapi.ServiceEntryObject(item)
		if err != nil {
			return err
		}
		serviceEntry := decoded.Value
		hosts := serviceEntry.Spec.Hosts
		exportTo := slices.Clone(serviceEntry.Spec.ExportTo)
		ports := serviceEntry.Spec.Ports
		location := normalizeServiceEntryLocation(serviceEntry.Spec.Location)
		resolution := serviceEntry.Spec.Resolution
		protocols := serviceEntryProtocols(ports)
		addressClasses, bindingPosture := serviceEntryBindingPosture(location, serviceEntry.Spec.Endpoints)
		validHosts := make([]string, 0, len(hosts))
		invalidCount := 0
		for _, declaredHost := range hosts {
			canonical, _, err := canonicalHost(declaredHost)
			// Invalid hosts are diagnosed and counted; the rest of the
			// entry still projects.
			if err != nil {
				invalidCount++
				projector.diagnostics = append(projector.diagnostics, Diagnostic{Code: "invalid-serviceentry-host", Resource: projectkit.DisplayName(item)})
				continue
			}
			validHosts = append(validHosts, canonical)
		}
		validHosts = sortedUnique(validHosts)
		slices.Sort(exportTo)
		attributes := map[string]string{
			"kubernetes/api-version":         item.GetAPIVersion(),
			"kubernetes/name":                item.GetName(),
			"kubernetes/namespace":           item.GetNamespace(),
			"istio/hosts":                    projectkit.MustCanonicalJSON(validHosts),
			"istio/host-count":               strconv.Itoa(len(hosts)),
			"istio/invalid-host-count":       strconv.Itoa(invalidCount),
			"istio/location":                 location,
			"istio/resolution":               strings.ToUpper(resolution),
			"istio/port-count":               strconv.Itoa(len(ports)),
			"istio/protocols":                projectkit.MustCanonicalJSON(protocols),
			"istio/export-to":                projectkit.MustCanonicalJSON(exportTo),
			"istio/endpoint-count":           strconv.Itoa(len(serviceEntry.Spec.Endpoints)),
			"istio/endpoint-address-classes": projectkit.MustCanonicalJSON(addressClasses),
			"istio/binding-posture":          bindingPosture,
		}
		projector.input.Resources = append(projector.input.Resources, projectedResourceAssertion(projector.context.SourceID, observed, "istio/serviceentry", "istio.serviceentry", attributes))
		projector.input.Facets = append(projector.input.Facets, graph.FacetAssertion{
			Resource: observed.Claim, Kind: "serviceentry-binding", Key: "registry-endpoints", Attributes: map[string]string{
				"istio/location":                 location,
				"istio/endpoint-count":           strconv.Itoa(len(serviceEntry.Spec.Endpoints)),
				"istio/endpoint-address-classes": projectkit.MustCanonicalJSON(addressClasses),
				"istio/binding-posture":          bindingPosture,
			},
			PluginID: PluginID, SourceID: projector.context.SourceID, RuleID: "istio.serviceentry-binding",
			EvidenceIDs: []string{observed.EventID},
		})
		for _, host := range validHosts {
			claim, err := networkDestinationClaim(projector.context.NetworkID, host)
			if err != nil {
				continue
			}
			_, wildcard, _ := canonicalHost(host)
			destinationAttributes := map[string]string{
				"istio/declared-host": host,
				"istio/wildcard":      strconv.FormatBool(wildcard),
				"istio/location":      location,
				"istio/resolution":    strings.ToUpper(resolution),
				"istio/port-count":    strconv.Itoa(len(ports)),
				"istio/protocols":     projectkit.MustCanonicalJSON(protocols),
				"istio/export-to":     projectkit.MustCanonicalJSON(exportTo),
			}
			pluginID, sourceID, evidence := provenance(projector.context.SourceID, observed.EventID)
			projector.input.Resources = append(projector.input.Resources, graph.ResourceAssertion{
				Claim: claim, Kind: "network/destination", DisplayName: host, Attributes: destinationAttributes,
				PluginID: pluginID, SourceID: sourceID, RuleID: "istio.serviceentry-host", EvidenceIDs: evidence,
			})
			properties := map[string]string{"semantic": "istio-service-registry-declaration", "declared-host": host}
			projector.input.Relationships = append(projector.input.Relationships, relationship(
				projector.context.SourceID, "istio.serviceentry-exposes-host", observed.Claim, graph.PredicateExposes, claim,
				"istio-serviceentry-host", properties, observed.EventID,
			))
			projector.index.addServiceEntryHost(host, serviceEntryDestination{
				Claim: claim, Namespace: item.GetNamespace(), ExportTo: exportTo, Evidence: observed.EventID,
			})
		}
	}
	return nil
}

// normalizeServiceEntryLocation applies Istio's default location,
// MESH_EXTERNAL, when the field is unset.
func normalizeServiceEntryLocation(location string) string {
	location = strings.ToUpper(strings.TrimSpace(location))
	if location == "" {
		return "MESH_EXTERNAL"
	}
	return location
}

// serviceEntryBindingPosture summarizes where explicit endpoints point
// relative to the declared location, so a reviewer can spot, for example, a
// MESH_EXTERNAL host bound to private or loopback addresses without seeing
// the addresses. Entries without endpoints send traffic to the hosts
// themselves and report "no-explicit-endpoints".
func serviceEntryBindingPosture(location string, endpoints []istioapi.ServiceEntryEndpoint) ([]string, string) {
	classes := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		classes = append(classes, serviceEntryAddressClass(endpoint.Address))
	}
	classes = sortedUnique(classes)
	if len(classes) == 0 {
		return classes, "no-explicit-endpoints"
	}
	if len(classes) > 1 {
		return classes, "mixed-address-classes"
	}
	scope := classes[0]
	switch location {
	case "MESH_EXTERNAL":
		return classes, "external-declaration-to-" + scope
	case "MESH_INTERNAL":
		return classes, "internal-declaration-to-" + scope
	default:
		return classes, "unspecified-location-to-" + scope
	}
}

// serviceEntryAddressClass classifies an endpoint address, which Istio
// accepts as an IP, a DNS name, or a unix:// socket path. Go's IsPrivate
// covers only RFC 1918 and IPv6 unique-local ranges, so ranges such as CGNAT
// fall into public-or-special-use-ip.
func serviceEntryAddressClass(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unspecified"
	}
	if strings.HasPrefix(strings.ToLower(value), "unix://") {
		return "unix-socket"
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "dns-or-provider-name"
	}
	switch {
	case address.IsLoopback():
		return "loopback-ip"
	case address.IsPrivate():
		return "private-ip"
	case address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast():
		return "link-local-ip"
	case address.IsUnspecified():
		return "unspecified-ip"
	default:
		return "public-or-special-use-ip"
	}
}

func serviceEntryProtocols(ports []istioapi.ServicePort) []string {
	protocols := make([]string, 0, len(ports))
	for _, port := range ports {
		if port.Protocol != "" {
			protocols = append(protocols, strings.ToUpper(port.Protocol))
		}
	}
	return sortedUnique(protocols)
}

// resourceAssertion asserts the observed Istio object itself, citing its own
// observation as evidence.
func resourceAssertion(sourceID string, observed indexedObject, kind, ruleID string, attributes map[string]string) graph.ResourceAssertion {
	pluginID, source, evidence := provenance(sourceID, observed.EventID)
	return graph.ResourceAssertion{
		Claim: observed.Claim, Kind: kind, DisplayName: projectkit.DisplayName(observed.Object), Attributes: attributes,
		PluginID: pluginID, SourceID: source, RuleID: ruleID, EvidenceIDs: evidence,
	}
}
