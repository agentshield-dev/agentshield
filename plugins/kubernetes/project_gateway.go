package kubernetes

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func gatewayAttributes(item *unstructured.Unstructured) (map[string]string, error) {
	decoded, err := kubernetesapi.GatewayObject(item)
	if err != nil {
		return nil, err
	}
	gateway := decoded.Value
	result := attributes(item)
	if len(gateway.Spec.Listeners) > 0 {
		result["kubernetes/listeners"] = canonicalTypedList(limitTyped(gateway.Spec.Listeners, maxDiagnosticReferences))
	}
	if len(gateway.Spec.Addresses) > 0 {
		result["kubernetes/addresses"] = canonicalTypedList(limitTyped(gateway.Spec.Addresses, maxDiagnosticReferences))
	}
	if len(gateway.Status.Addresses) > 0 {
		result["kubernetes/status-addresses"] = canonicalTypedList(limitTyped(gateway.Status.Addresses, maxDiagnosticReferences))
	}
	if len(gateway.Status.Listeners) > 0 {
		result["kubernetes/listener-status"] = canonicalTypedList(limitTyped(gateway.Status.Listeners, maxDiagnosticReferences))
	}
	setStringAttribute(result, "kubernetes/gateway-class", gateway.Spec.GatewayClassName)
	return result, nil
}

func httpRouteAttributes(route *unstructured.Unstructured, index objectIndex) (map[string]string, error) {
	decoded, err := kubernetesapi.HTTPRouteObject(route)
	if err != nil {
		return nil, err
	}
	httpRoute := &decoded.Value
	result := attributes(route)
	setJSONAttribute(result, "kubernetes/hostnames", httpRoute.Spec.Hostnames)
	if len(httpRoute.Spec.ParentRefs) > 0 {
		result["kubernetes/parent-refs"] = canonicalTypedList(limitTyped(httpRoute.Spec.ParentRefs, maxDiagnosticReferences))
	}
	if len(httpRoute.Spec.Rules) > 0 {
		result["kubernetes/rules"] = canonicalTypedList(limitTyped(httpRoute.Spec.Rules, maxDiagnosticReferences))
	}
	if len(httpRoute.Status.Parents) > 0 {
		result["kubernetes/parent-status"] = canonicalTypedList(limitTyped(httpRoute.Status.Parents, maxDiagnosticReferences))
	}
	unresolved := routeUnresolvedReferences(httpRoute, index)
	setJSONAttribute(result, "kubernetes/unresolved-references", boundedStrings(unresolved, maxDiagnosticReferences))
	return result, nil
}

func projectGatewayAPI(clusterID, sourceID string, index objectIndex, input *graph.Input) error {
	gatewayKeys := make([]string, 0, len(index.gatewaysByName))
	for key := range index.gatewaysByName {
		gatewayKeys = append(gatewayKeys, key)
	}
	slices.Sort(gatewayKeys)
	for _, key := range gatewayKeys {
		item := index.gatewaysByName[key]
		decoded, err := kubernetesapi.GatewayObject(item)
		if err != nil {
			return err
		}
		protocols := make([]string, 0, len(decoded.Value.Spec.Listeners))
		ports := make([]graph.SecurityPort, 0, len(decoded.Value.Spec.Listeners))
		for _, listener := range decoded.Value.Spec.Listeners {
			if listener.Protocol != "" {
				protocols = append(protocols, listener.Protocol)
				if listener.Port > 0 && listener.Port <= 65535 {
					ports = append(ports, graph.SecurityPort{Protocol: listener.Protocol, Port: uint16(listener.Port)})
				}
			}
		}
		protocols, ports, truncated := boundedSecurityDetails(protocols, ports)
		coverage := "complete"
		if truncated {
			coverage = "partial"
		}
		state := graph.SecurityStateDeclared
		if len(decoded.Value.Status.Addresses) > 0 || len(decoded.Value.Status.Listeners) > 0 || len(decoded.Value.Status.Conditions) > 0 {
			state = graph.SecurityStateObserved
		}
		semanticAttributes, err := graph.WithSecuritySemantics(nil, graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
			State: state, Effect: "unknown", Scope: "gateway", Direction: "ingress", Coverage: coverage,
			Protocols: protocols, Ports: ports, ConfigurationDigest: projectkit.SecurityDigest(map[string]any{
				"gatewayClassName": decoded.Value.Spec.GatewayClassName,
				"addresses":        canonicalUnorderedJSON(decoded.Value.Spec.Addresses),
				"listeners":        canonicalUnorderedJSON(decoded.Value.Spec.Listeners),
			}),
		})
		if err != nil {
			return fmt.Errorf("Gateway %s exposure semantics: %w", projectkit.DisplayName(item), err)
		}
		input.Facets = append(input.Facets, graph.FacetAssertion{
			Resource: claimFor(clusterID, item), Kind: "network-exposure", Key: "gateway", Attributes: semanticAttributes,
			PluginID: PluginID, SourceID: sourceID, RuleID: "kubernetes.gateway.exposure",
			EvidenceIDs: evidenceIDs(item),
		})
		transport, err := gatewayTransportFacet(clusterID, sourceID, item, &decoded.Value)
		if err != nil {
			return err
		}
		input.Facets = append(input.Facets, transport)
	}
	for _, route := range index.httpRoutes {
		decoded, err := kubernetesapi.HTTPRouteObject(route)
		if err != nil {
			return err
		}
		httpRoute := &decoded.Value
		transport, err := httpRouteTransportFacet(clusterID, sourceID, route, httpRoute, index)
		if err != nil {
			return err
		}
		input.Facets = append(input.Facets, transport, httpRouteBackendFacet(clusterID, sourceID, route, httpRoute, index))
		parents := httpRoute.Spec.ParentRefs
		for _, parent := range parents {
			group := defaultValue(parent.Group, "gateway.networking.k8s.io")
			kind := defaultValue(parent.Kind, "Gateway")
			name := parent.Name
			namespace := defaultValue(parent.Namespace, route.GetNamespace())
			if group != "gateway.networking.k8s.io" || kind != "Gateway" || namespace != route.GetNamespace() || name == "" {
				continue
			}
			gateway := index.gatewaysByName[namespacedName(namespace, name)]
			if gateway == nil {
				continue
			}
			properties := map[string]string{"sectionName": parent.SectionName}
			input.Relationships = append(input.Relationships, relationshipAssertion(
				sourceID, "kubernetes.gateway.parent",
				claimFor(clusterID, route), graph.PredicateMemberOf, claimFor(clusterID, gateway), projectkit.Qualifier(parent), properties,
				route, gateway,
			))
		}

		for _, rule := range httpRoute.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				group := backend.Group
				kind := defaultValue(backend.Kind, "Service")
				name := backend.Name
				namespace := defaultValue(backend.Namespace, route.GetNamespace())
				if group != "" || kind != "Service" || namespace != route.GetNamespace() || name == "" {
					continue
				}
				service := index.servicesByName[namespacedName(namespace, name)]
				if service == nil {
					continue
				}
				properties := map[string]string{
					"port":    scalarInt32Pointer(backend.Port),
					"weight":  scalarInt32Pointer(backend.Weight),
					"matches": canonicalOptionalTypedList(rule.Matches),
					"filters": canonicalOptionalTypedList(rule.Filters),
				}
				qualifier := projectkit.Qualifier(map[string]any{"backend": backend, "matches": rule.Matches})
				input.Relationships = append(input.Relationships, relationshipAssertion(
					sourceID, "kubernetes.httproute.backend",
					claimFor(clusterID, route), graph.PredicateExposes, claimFor(clusterID, service), qualifier, properties,
					route, service,
				))
			}
		}
	}
	return nil
}

type gatewayTransportSummary struct {
	Posture  string
	Effect   string
	Coverage string
	Modes    []string
}

func gatewayTransportFacet(clusterID, sourceID string, item *unstructured.Unstructured, gateway *kubernetesapi.Gateway) (graph.FacetAssertion, error) {
	summary := summarizeGatewayListeners(gateway.Spec.Listeners)
	attributes, err := graph.WithSecuritySemantics(map[string]string{
		"kubernetes/posture":        summary.Posture,
		"kubernetes/listener-modes": projectkit.MustCanonicalJSON(summary.Modes),
		"kubernetes/listener-count": strconv.Itoa(len(gateway.Spec.Listeners)),
	}, graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainTransportAuthentication,
		State: graph.SecurityStateDeclared, Effect: summary.Effect, Scope: "gateway", Direction: "ingress", Coverage: summary.Coverage,
		ConfigurationDigest: projectkit.SecurityDigest(map[string]any{"listeners": canonicalUnorderedJSON(gateway.Spec.Listeners)}),
	})
	if err != nil {
		return graph.FacetAssertion{}, fmt.Errorf("Gateway %s transport semantics: %w", projectkit.DisplayName(item), err)
	}
	return graph.FacetAssertion{
		Resource: claimFor(clusterID, item), Kind: "transport-posture", Key: "gateway", Attributes: attributes,
		PluginID: PluginID, SourceID: sourceID, RuleID: "kubernetes.gateway.transport",
		EvidenceIDs: evidenceIDs(item),
	}, nil
}

func httpRouteTransportFacet(clusterID, sourceID string, item *unstructured.Unstructured, route *kubernetesapi.HTTPRoute, index objectIndex) (graph.FacetAssertion, error) {
	var listeners []kubernetesapi.GatewayListener
	evidence := []*unstructured.Unstructured{item}
	unresolved := 0
	for _, parent := range route.Spec.ParentRefs {
		group := defaultValue(parent.Group, "gateway.networking.k8s.io")
		kind := defaultValue(parent.Kind, "Gateway")
		namespace := defaultValue(parent.Namespace, route.Namespace)
		gatewayObject := index.gatewaysByName[namespacedName(namespace, parent.Name)]
		if group != "gateway.networking.k8s.io" || kind != "Gateway" || namespace != route.Namespace || gatewayObject == nil {
			unresolved++
			continue
		}
		decoded, err := kubernetesapi.GatewayObject(gatewayObject)
		if err != nil {
			return graph.FacetAssertion{}, err
		}
		evidence = append(evidence, gatewayObject)
		matched := 0
		for _, listener := range decoded.Value.Spec.Listeners {
			if parent.SectionName == "" || listener.Name == parent.SectionName {
				listeners = append(listeners, listener)
				matched++
			}
		}
		if matched == 0 {
			unresolved++
		}
	}
	summary := summarizeGatewayListeners(listeners)
	if len(listeners) == 0 {
		summary = gatewayTransportSummary{Posture: "unknown", Effect: "unknown", Coverage: "unknown", Modes: []string{}}
	} else if unresolved > 0 {
		summary.Coverage = "partial"
	}
	attributes, err := graph.WithSecuritySemantics(map[string]string{
		"kubernetes/posture":                 summary.Posture,
		"kubernetes/parent-listener-modes":   projectkit.MustCanonicalJSON(summary.Modes),
		"kubernetes/resolved-listener-count": strconv.Itoa(len(listeners)),
		"kubernetes/unresolved-parent-count": strconv.Itoa(unresolved),
	}, graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainTransportAuthentication,
		State: graph.SecurityStateDeclared, Effect: summary.Effect, Scope: "gateway", Direction: "ingress", Coverage: summary.Coverage,
		ConfigurationDigest: projectkit.SecurityDigest(map[string]any{"parents": canonicalUnorderedJSON(route.Spec.ParentRefs), "listeners": canonicalUnorderedJSON(listeners)}),
	})
	if err != nil {
		return graph.FacetAssertion{}, fmt.Errorf("HTTPRoute %s transport semantics: %w", projectkit.DisplayName(item), err)
	}
	return graph.FacetAssertion{
		Resource: claimFor(clusterID, item), Kind: "transport-posture", Key: "parent-listeners", Attributes: attributes,
		PluginID: PluginID, SourceID: sourceID, RuleID: "kubernetes.httproute.transport",
		EvidenceIDs: evidenceIDs(evidence...),
	}, nil
}

func httpRouteBackendFacet(clusterID, sourceID string, item *unstructured.Unstructured, route *kubernetesapi.HTTPRoute, index objectIndex) graph.FacetAssertion {
	declared := 0
	active := 0
	weighted := 0
	zeroWeight := 0
	resolved := 0
	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			declared++
			if backend.Weight != nil {
				weighted++
				if *backend.Weight == 0 {
					zeroWeight++
					continue
				}
			}
			active++
			group := backend.Group
			kind := defaultValue(backend.Kind, "Service")
			namespace := defaultValue(backend.Namespace, route.Namespace)
			if group == "" && kind == "Service" && namespace == route.Namespace && index.servicesByName[namespacedName(namespace, backend.Name)] != nil {
				resolved++
			}
		}
	}
	attributes := map[string]string{
		"kubernetes/declared-backend-count":          strconv.Itoa(declared),
		"kubernetes/active-backend-count":            strconv.Itoa(active),
		"kubernetes/weighted-backend-count":          strconv.Itoa(weighted),
		"kubernetes/zero-weight-backend-count":       strconv.Itoa(zeroWeight),
		"kubernetes/resolved-active-backend-count":   strconv.Itoa(resolved),
		"kubernetes/unresolved-active-backend-count": strconv.Itoa(active - resolved),
		"kubernetes/protection-evaluation":           "graph-traversal-required",
	}
	return graph.FacetAssertion{
		Resource: claimFor(clusterID, item), Kind: "route-backends", Key: "httproute", Attributes: attributes,
		PluginID: PluginID, SourceID: sourceID, RuleID: "kubernetes.httproute.backends",
		EvidenceIDs: evidenceIDs(item),
	}
}

func summarizeGatewayListeners(listeners []kubernetesapi.GatewayListener) gatewayTransportSummary {
	modes := make([]string, 0, len(listeners))
	secure, plaintext, opaque, invalid := 0, 0, 0, 0
	for _, listener := range listeners {
		protocol := strings.ToUpper(strings.TrimSpace(listener.Protocol))
		var mode string
		switch protocol {
		case "HTTP":
			mode = "plaintext"
			plaintext++
		case "HTTPS":
			if len(listener.TLS) == 0 {
				mode = "tls-config-missing"
				invalid++
			} else {
				mode = "tls-terminate"
				secure++
			}
		case "TLS":
			var configuration struct {
				Mode string `json:"mode"`
			}
			if len(listener.TLS) == 0 || json.Unmarshal(listener.TLS, &configuration) != nil {
				mode = "tls-config-unknown"
				invalid++
			} else {
				switch strings.ToUpper(configuration.Mode) {
				case "PASSTHROUGH":
					mode = "tls-passthrough"
					secure++
				case "TERMINATE":
					mode = "tls-terminate"
					secure++
				default:
					mode = "tls-config-unknown"
					invalid++
				}
			}
		default:
			mode = "opaque-" + strings.ToLower(protocol)
			opaque++
		}
		modes = append(modes, listener.Name+":"+mode)
	}
	modes = uniqueSorted(modes)
	summary := gatewayTransportSummary{Posture: "unknown", Effect: "unknown", Coverage: "complete", Modes: modes}
	switch {
	case len(listeners) == 0:
		summary.Coverage = "unknown"
	case invalid > 0 || opaque > 0:
		summary.Coverage = "partial"
	case secure > 0 && plaintext == 0:
		summary.Posture = "tls-only"
		summary.Effect = "require"
	case secure > 0 && plaintext > 0:
		summary.Posture = "mixed"
		summary.Effect = "permit"
	case plaintext > 0:
		summary.Posture = "plaintext-only"
		summary.Effect = "disable"
	}
	return summary
}

func routeUnresolvedReferences(route *kubernetesapi.HTTPRoute, index objectIndex) []string {
	var result []string
	for _, parent := range route.Spec.ParentRefs {
		group := defaultValue(parent.Group, "gateway.networking.k8s.io")
		kind := defaultValue(parent.Kind, "Gateway")
		name := parent.Name
		namespace := defaultValue(parent.Namespace, route.Namespace)
		if group != "gateway.networking.k8s.io" || kind != "Gateway" || namespace != route.Namespace || name == "" || index.gatewaysByName[namespacedName(namespace, name)] == nil {
			result = append(result, "parent:"+group+"/"+kind+":"+namespace+"/"+name)
		}
	}
	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			group := backend.Group
			kind := defaultValue(backend.Kind, "Service")
			name := backend.Name
			namespace := defaultValue(backend.Namespace, route.Namespace)
			if group != "" || kind != "Service" || namespace != route.Namespace || name == "" || index.servicesByName[namespacedName(namespace, name)] == nil {
				if group == "" {
					group = "core"
				}
				result = append(result, "backend:"+group+"/"+kind+":"+namespace+"/"+name)
			}
		}
	}
	slices.Sort(result)
	return result
}

func defaultValue(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func scalarInt32Pointer(value *int32) string {
	if value == nil {
		return ""
	}
	return scalarString(*value)
}

func canonicalOptionalTypedList[T any](values []T) string {
	if values == nil {
		return "null"
	}
	return canonicalTypedList(values)
}
