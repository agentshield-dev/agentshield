package kubernetes

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type serviceClusterAddress struct {
	Address string `json:"address"`
	Family  string `json:"family,omitempty"`
}

func projectionAttributes(item *unstructured.Unstructured, index objectIndex) (map[string]string, error) {
	result := attributes(item)
	switch {
	case item.GetAPIVersion() == "apps/v1" && item.GetKind() == "Deployment":
		if err := addDeploymentAttributes(result, item); err != nil {
			return nil, err
		}
	case item.GetAPIVersion() == "v1" && item.GetKind() == "Service":
		decoded, err := kubernetesapi.Service(item)
		if err != nil {
			return nil, err
		}
		addServiceAttributes(result, &decoded.Value)
	case item.GetAPIVersion() == "networking.k8s.io/v1" && item.GetKind() == "Ingress":
		return ingressAttributes(item, index)
	case item.GetAPIVersion() == "networking.k8s.io/v1" && item.GetKind() == "NetworkPolicy":
		return networkPolicyAttributes(item)
	case item.GetAPIVersion() == "gateway.networking.k8s.io/v1" && item.GetKind() == "Gateway":
		return gatewayAttributes(item)
	case item.GetAPIVersion() == "gateway.networking.k8s.io/v1" && item.GetKind() == "HTTPRoute":
		return httpRouteAttributes(item, index)
	}
	return result, nil
}

func addServiceAttributes(result map[string]string, service *corev1.Service) {
	setStringAttribute(result, "kubernetes/service-type", string(service.Spec.Type))
	setStringAttribute(result, "kubernetes/external-name", service.Spec.ExternalName)
	setStringPointerAttribute(result, "kubernetes/load-balancer-class", service.Spec.LoadBalancerClass)
	setStringAttribute(result, "kubernetes/external-traffic-policy", string(service.Spec.ExternalTrafficPolicy))
	if service.Spec.InternalTrafficPolicy != nil {
		setStringAttribute(result, "kubernetes/internal-traffic-policy", string(*service.Spec.InternalTrafficPolicy))
	}
	setStringPointerAttribute(result, "kubernetes/traffic-distribution", service.Spec.TrafficDistribution)
	if service.Spec.IPFamilyPolicy != nil {
		setStringAttribute(result, "kubernetes/ip-family-policy", string(*service.Spec.IPFamilyPolicy))
	}

	clusterIPs := service.Spec.ClusterIPs
	if len(clusterIPs) == 0 && service.Spec.ClusterIP != "" {
		clusterIPs = []string{service.Spec.ClusterIP}
	}
	clusterAddresses := make([]serviceClusterAddress, 0, len(clusterIPs))
	for index, address := range clusterIPs {
		clusterAddress := serviceClusterAddress{Address: address}
		if index < len(service.Spec.IPFamilies) {
			clusterAddress.Family = string(service.Spec.IPFamilies[index])
		}
		clusterAddresses = append(clusterAddresses, clusterAddress)
	}
	if len(clusterAddresses) > 0 {
		result["kubernetes/cluster-addresses"] = projectkit.MustCanonicalJSON(clusterAddresses)
	}
	setJSONAttribute(result, "kubernetes/external-ips", service.Spec.ExternalIPs)
	setJSONAttribute(result, "kubernetes/load-balancer-source-ranges", service.Spec.LoadBalancerSourceRanges)
	if len(service.Spec.Ports) > 0 {
		result["kubernetes/ports"] = canonicalTypedList(service.Spec.Ports)
	}
	if len(service.Status.LoadBalancer.Ingress) > 0 {
		result["kubernetes/load-balancer-ingress"] = canonicalTypedList(service.Status.LoadBalancer.Ingress)
	}
	addresses := append([]string(nil), clusterIPs...)
	addresses = append(addresses, service.Spec.ExternalIPs...)
	addresses = append(addresses, service.Spec.ExternalName)
	for _, ingress := range service.Status.LoadBalancer.Ingress {
		addresses = append(addresses, ingress.IP, ingress.Hostname)
	}
	role := graph.NetworkRoleService
	if service.Namespace == "default" && service.Name == "kubernetes" {
		role = graph.NetworkRoleControlPlaneAPI
	}
	setNetworkMetadata(result, role, addresses)
}

func setNetworkMetadata(result map[string]string, role string, values []string) {
	addresses := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(value, "none") {
			continue
		}
		if address, err := netip.ParseAddr(value); err == nil {
			addresses = append(addresses, "ip/"+address.String())
		} else {
			addresses = append(addresses, "dns/"+strings.ToLower(strings.TrimSuffix(value, ".")))
		}
	}
	addresses = uniqueSorted(addresses)
	if len(addresses) == 0 {
		return
	}
	result["network/role"] = role
	result["network/addresses"] = projectkit.MustCanonicalJSON(addresses)
}

func projectServices(clusterID, sourceID string, index objectIndex, input *graph.Input) error {
	serviceKeys := make([]string, 0, len(index.servicesByName))
	for key := range index.servicesByName {
		serviceKeys = append(serviceKeys, key)
	}
	slices.Sort(serviceKeys)
	for _, key := range serviceKeys {
		service := index.servicesByName[key]
		decoded, err := kubernetesapi.Service(service)
		if err != nil {
			return err
		}
		exposure, err := serviceExposureFacet(clusterID, sourceID, service, &decoded.Value)
		if err != nil {
			return err
		}
		input.Facets = append(input.Facets, exposure)
		selector := decoded.Value.Spec.Selector
		for _, pod := range index.podsForLabels(service.GetNamespace(), selector) {
			if len(selector) > 0 && labelsMatch(selector, pod.GetLabels()) {
				input.Relationships = append(input.Relationships, relationshipAssertion(
					sourceID, "kubernetes.service.selector",
					claimFor(clusterID, service), graph.PredicateExposes, claimFor(clusterID, pod), "",
					map[string]string{"basis": "selector"}, service, pod,
				))
			}
		}
	}
	return nil
}

func serviceExposureFacet(clusterID, sourceID string, object *unstructured.Unstructured, service *corev1.Service) (graph.FacetAssertion, error) {
	effect := "internal"
	scope := "cluster"
	if service.Spec.Type == corev1.ServiceTypeLoadBalancer || service.Spec.Type == corev1.ServiceTypeNodePort || len(service.Spec.ExternalIPs) > 0 || len(service.Status.LoadBalancer.Ingress) > 0 {
		effect = "external-addressable"
		scope = "external"
	}
	protocols := make([]string, 0, len(service.Spec.Ports))
	ports := make([]graph.SecurityPort, 0, len(service.Spec.Ports))
	for _, port := range service.Spec.Ports {
		protocol := string(port.Protocol)
		if protocol == "" {
			protocol = string(corev1.ProtocolTCP)
		}
		protocols = append(protocols, protocol)
		if port.Port > 0 && port.Port <= 65535 {
			ports = append(ports, graph.SecurityPort{Protocol: protocol, Port: uint16(port.Port)})
		}
	}
	protocols, ports, truncated := boundedSecurityDetails(protocols, ports)
	coverage := "complete"
	if truncated {
		coverage = "partial"
	}
	semantics := graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
		State: graph.SecurityStateDeclared, Effect: effect, Scope: scope, Direction: "ingress", Coverage: coverage,
		Protocols: protocols, Ports: ports, ConfigurationDigest: projectkit.SecurityDigest(map[string]any{
			"type": service.Spec.Type, "ports": canonicalUnorderedJSON(service.Spec.Ports),
			"externalIPs":              canonicalUnorderedJSON(service.Spec.ExternalIPs),
			"loadBalancerSourceRanges": canonicalUnorderedJSON(service.Spec.LoadBalancerSourceRanges),
		}),
	}
	attributes, err := graph.WithSecuritySemantics(nil, semantics)
	if err != nil {
		return graph.FacetAssertion{}, fmt.Errorf("service %s exposure semantics: %w", projectkit.DisplayName(object), err)
	}
	return graph.FacetAssertion{
		Resource: claimFor(clusterID, object), Kind: "network-exposure", Key: "service", Attributes: attributes,
		PluginID: PluginID, SourceID: sourceID, RuleID: "kubernetes.service.exposure",
		EvidenceIDs: evidenceIDs(object),
	}, nil
}

func setStringAttribute(result map[string]string, attribute, value string) {
	if value != "" {
		result[attribute] = value
	}
}

func setStringPointerAttribute(result map[string]string, attribute string, value *string) {
	if value != nil {
		setStringAttribute(result, attribute, *value)
	}
}

func setJSONAttribute(result map[string]string, key string, values []string) {
	values = uniqueSorted(values)
	if len(values) > 0 {
		result[key] = projectkit.MustCanonicalJSON(values)
	}
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func boundedStrings(values []string, limit int) []string {
	values = uniqueSorted(values)
	if len(values) > limit {
		return values[:limit]
	}
	return values
}

func canonicalObjectList(values []any) string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		normalized = append(normalized, projectkit.MustCanonicalJSON(value))
	}
	slices.Sort(normalized)
	result := make([]jsonRaw, 0, len(normalized))
	for _, value := range normalized {
		result = append(result, jsonRaw(value))
	}
	return projectkit.MustCanonicalJSON(result)
}

func canonicalTypedList[T any](values []T) string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		var canonical any
		// Decoding cannot fail because the input was just encoded.
		_ = json.Unmarshal([]byte(projectkit.MustCanonicalJSON(value)), &canonical)
		normalized = append(normalized, projectkit.MustCanonicalJSON(canonical))
	}
	slices.Sort(normalized)
	result := make([]jsonRaw, 0, len(normalized))
	for _, value := range normalized {
		result = append(result, jsonRaw(value))
	}
	return projectkit.MustCanonicalJSON(result)
}

type jsonRaw string

func (raw jsonRaw) MarshalJSON() ([]byte, error) { return []byte(raw), nil }
