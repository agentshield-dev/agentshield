package agentgateway

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	// PluginID is the plugin and contribution owner ID.
	PluginID = "agentgateway"
	// DefaultControllerName is the GatewayClass controller agentgateway
	// registers.
	DefaultControllerName = "agentgateway.dev/gatewayclass-controller"
	// DefaultGatewayClass is the fallback class name used only when the
	// GatewayClass object is not observed.
	DefaultGatewayClass = "agentgateway"
)

type projection struct {
	context     ProjectionContext
	input       graph.Input
	diagnostics []Diagnostic
	objects     []ObservedObject
	classes     map[string]ObservedObject
	gateways    map[string]ObservedObject
	routes      []ObservedObject
	services    map[string]ObservedObject
}

// Project projects bare objects, deriving evidence IDs from their identity
// and resource version. It exists for tests and offline evaluation; the plugin
// uses [ProjectObserved] with collection event IDs.
func Project(clusterID, sourceID string, objects []*unstructured.Unstructured) (graph.Input, error) {
	observations := make([]ObservedObject, 0, len(objects))
	for _, object := range objects {
		if object == nil {
			continue
		}
		observations = append(observations, ObservedObject{Key: projectkit.ObjectKey(object), Object: object, EventID: evidenceID(object), Revision: object.GetResourceVersion()})
	}
	result, err := ProjectObserved(ProjectionContext{ClusterID: clusterID, SourceID: sourceID}, observations)
	return result.Input, err
}

// ProjectObserved deterministically projects one coherent snapshot. The
// result is independent of observation order.
func ProjectObserved(scope ProjectionContext, observations []ObservedObject) (ProjectionResult, error) {
	scope.ClusterID = strings.TrimSpace(scope.ClusterID)
	scope.SourceID = strings.TrimSpace(scope.SourceID)
	if scope.ClusterID == "" || scope.SourceID == "" {
		return ProjectionResult{}, errors.New("cluster and source IDs are required")
	}
	scope.ControllerNames = normalizedSet(scope.ControllerNames, DefaultControllerName)
	scope.GatewayClasses = normalizedSet(scope.GatewayClasses, DefaultGatewayClass)
	projector := &projection{context: scope}
	if err := projector.buildIndex(observations); err != nil {
		return ProjectionResult{}, err
	}
	if err := projector.project(); err != nil {
		return ProjectionResult{}, err
	}
	projector.sortOutput()
	return ProjectionResult{Input: projector.input, Diagnostics: projector.diagnostics}, nil
}

func (p *projection) buildIndex(observations []ObservedObject) error {
	p.classes = make(map[string]ObservedObject)
	p.gateways = make(map[string]ObservedObject)
	p.services = make(map[string]ObservedObject)
	for _, observation := range observations {
		if observation.Object == nil {
			continue
		}
		copy := observation
		if copy.Key == "" {
			copy.Key = projectkit.ObjectKey(copy.Object)
		}
		if copy.EventID == "" {
			copy.EventID = evidenceID(copy.Object)
		}
		p.objects = append(p.objects, copy)
	}
	sort.Slice(p.objects, func(i, j int) bool { return p.objects[i].Key < p.objects[j].Key })
	for _, observation := range p.objects {
		item := observation.Object
		if item.GetUID() == "" {
			if isGatewayAPI(item) {
				return fmt.Errorf("project %s %s/%s: metadata.uid is required", item.GetKind(), item.GetNamespace(), item.GetName())
			}
			continue
		}
		switch {
		case isKind(item, "gateway.networking.k8s.io/v1", "GatewayClass"):
			p.classes[item.GetName()] = observation
		case isKind(item, "gateway.networking.k8s.io/v1", "Gateway"):
			p.gateways[namespacedName(item.GetNamespace(), item.GetName())] = observation
		case isKind(item, "gateway.networking.k8s.io/v1", "HTTPRoute"):
			p.routes = append(p.routes, observation)
		case isKind(item, "v1", "Service"):
			p.services[namespacedName(item.GetNamespace(), item.GetName())] = observation
		}
	}
	return nil
}

func (p *projection) project() error {
	selectedClasses := make(map[string]ObservedObject)
	for name, observation := range p.classes {
		decoded, err := kubernetesapi.Decode[gatewayClass](observation.Object)
		if err != nil {
			return fmt.Errorf("decode GatewayClass %q: %w", name, err)
		}
		if contains(p.context.ControllerNames, decoded.Value.Spec.ControllerName) {
			selectedClasses[name] = observation
			p.addResource(observation, "kubernetes/gatewayclass", "agentgateway.gatewayclass.resource", map[string]string{
				"agentgateway/controller-name": decoded.Value.Spec.ControllerName,
				"agentgateway/accepted":        conditionValue(decoded.Value.Status.Conditions, "Accepted"),
			})
		}
	}

	selectedGateways := make(map[string]ObservedObject)
	for key, observation := range p.gateways {
		decoded, err := kubernetesapi.Decode[gateway](observation.Object)
		if err != nil {
			return fmt.Errorf("decode Gateway %q: %w", key, err)
		}
		className := decoded.Value.Spec.GatewayClassName
		class, observedClass := selectedClasses[className]
		_, anyClassObserved := p.classes[className]
		if anyClassObserved && !observedClass || !anyClassObserved && !contains(p.context.GatewayClasses, className) {
			continue
		}
		selectedGateways[key] = observation
		attrs := map[string]string{
			"agentgateway/gateway-class": className,
			"agentgateway/accepted":      conditionValue(decoded.Value.Status.Conditions, "Accepted"),
			"agentgateway/programmed":    conditionValue(decoded.Value.Status.Conditions, "Programmed"),
			"agentgateway/listeners":     projectkit.MustCanonicalJSON(sortedListeners(decoded.Value.Spec.Listeners)),
			"agentgateway/addresses":     projectkit.MustCanonicalJSON(decoded.Value.Status.Addresses),
			"agentgateway/class-source":  map[bool]string{true: "observed", false: "configured"}[observedClass],
		}
		p.addResource(observation, "kubernetes/gateway", "agentgateway.gateway.resource", attrs)
		facetAttributes, err := gatewayExposureAttributes(attrs, decoded.Value)
		if err != nil {
			return fmt.Errorf("Gateway %s exposure semantics: %w", projectkit.DisplayName(observation.Object), err)
		}
		p.addFacet(observation, "agentgateway-ingress", "gateway/"+projectkit.DisplayName(observation.Object), facetAttributes, "agentgateway.gateway.facet")
		if observedClass {
			p.input.Relationships = append(p.input.Relationships, p.relationship(observation, class, graph.PredicateGovernedBy, "", nil, "agentgateway.gateway.class"))
		}
	}

	backendRoutes := make(map[string]map[string]ObservedObject)
	for _, routeObservation := range p.routes {
		decoded, err := kubernetesapi.Decode[httpRoute](routeObservation.Object)
		if err != nil {
			return fmt.Errorf("decode HTTPRoute %q: %w", routeObservation.Key, err)
		}
		parents := matchingParents(routeObservation.Object.GetNamespace(), decoded.Value.Spec.ParentRefs, selectedGateways)
		if len(parents) == 0 {
			continue
		}
		attrs := map[string]string{
			"agentgateway/hostnames":     projectkit.MustCanonicalJSON(sortedStrings(decoded.Value.Spec.Hostnames)),
			"agentgateway/accepted":      routeCondition(decoded.Value.Status.Parents, p.context.ControllerNames, "Accepted"),
			"agentgateway/resolved-refs": routeCondition(decoded.Value.Status.Parents, p.context.ControllerNames, "ResolvedRefs"),
		}
		p.addResource(routeObservation, "kubernetes/httproute", "agentgateway.httproute.resource", attrs)
		p.addFacet(routeObservation, "agentgateway-route", "httproute/"+projectkit.DisplayName(routeObservation.Object), attrs, "agentgateway.httproute.facet")
		for _, parent := range parents {
			properties := map[string]string{"sectionName": parent.reference.SectionName}
			p.input.Relationships = append(p.input.Relationships, p.relationship(routeObservation, parent.gateway, graph.PredicateMemberOf, projectkit.Qualifier(parent.reference), properties, "agentgateway.httproute.gateway"))
		}
		for _, rule := range decoded.Value.Spec.Rules {
			for _, backend := range rule.BackendRefs {
				if defaultString(backend.Group, "") != "" || defaultString(backend.Kind, "Service") != "Service" {
					continue
				}
				namespace := defaultString(backend.Namespace, routeObservation.Object.GetNamespace())
				if namespace != routeObservation.Object.GetNamespace() {
					p.diagnostics = append(p.diagnostics, Diagnostic{Resource: projectkit.DisplayName(routeObservation.Object), Code: "reference-grant-unknown", Message: "cross-namespace backend omitted because ReferenceGrant coverage is unavailable"})
					continue
				}
				service, found := p.services[namespacedName(namespace, backend.Name)]
				if !found {
					p.diagnostics = append(p.diagnostics, Diagnostic{Resource: projectkit.DisplayName(routeObservation.Object), Code: "backend-unresolved", Message: "Service " + namespace + "/" + backend.Name + " was not observed"})
					continue
				}
				properties := map[string]string{"port": int32Value(backend.Port), "weight": int32Value(backend.Weight)}
				p.input.Relationships = append(p.input.Relationships, p.relationship(routeObservation, service, graph.PredicateExposes, projectkit.Qualifier(backend), properties, "agentgateway.httproute.backend"))
				serviceKey := namespacedName(namespace, backend.Name)
				if backendRoutes[serviceKey] == nil {
					backendRoutes[serviceKey] = make(map[string]ObservedObject)
				}
				backendRoutes[serviceKey][routeObservation.Key] = routeObservation
			}
		}
	}

	for serviceKey, routesByKey := range backendRoutes {
		service := p.services[serviceKey]
		routes := make([]ObservedObject, 0, len(routesByKey))
		for _, route := range routesByKey {
			routes = append(routes, route)
		}
		attrs := map[string]string{"agentgateway/route-count": strconv.Itoa(len(routesByKey))}
		p.addResource(service, "kubernetes/service", "agentgateway.backend.resource", attrs)
		p.addFacet(service, "agentgateway-backend", "service/"+projectkit.DisplayName(service.Object), attrs, "agentgateway.backend.facet", routes...)
	}
	return nil
}

func gatewayExposureAttributes(attributes map[string]string, gateway gateway) (map[string]string, error) {
	protocols := make([]string, 0, len(gateway.Spec.Listeners))
	ports := make([]graph.SecurityPort, 0, len(gateway.Spec.Listeners))
	for _, listener := range gateway.Spec.Listeners {
		protocol := strings.ToUpper(strings.TrimSpace(listener.Protocol))
		if protocol != "" {
			protocols = append(protocols, protocol)
		}
		if protocol != "" && listener.Port > 0 && listener.Port <= 65535 {
			ports = append(ports, graph.SecurityPort{Protocol: protocol, Port: uint16(listener.Port)})
		}
	}
	protocols = compactStrings(sortedStrings(protocols))
	sort.Slice(ports, func(left, right int) bool {
		if ports[left].Protocol != ports[right].Protocol {
			return ports[left].Protocol < ports[right].Protocol
		}
		return ports[left].Port < ports[right].Port
	})
	ports = compactPorts(ports)
	if len(protocols) > 16 {
		protocols = protocols[:16]
	}
	if len(ports) > 64 {
		ports = ports[:64]
	}
	state := graph.SecurityStateDeclared
	if conditionValue(gateway.Status.Conditions, "Accepted") != "unknown" || conditionValue(gateway.Status.Conditions, "Programmed") != "unknown" || len(gateway.Status.Addresses) > 0 {
		state = graph.SecurityStateObserved
	}
	return graph.WithSecuritySemantics(attributes, graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
		State: state, Effect: "unknown", Scope: "gateway", Direction: "ingress", Coverage: "partial",
		Protocols: protocols, Ports: ports, ConfigurationDigest: projectkit.SecurityDigest(map[string]any{
			"gatewayClassName": gateway.Spec.GatewayClassName,
			"listeners":        sortedListeners(gateway.Spec.Listeners),
		}),
	})
}

func compactStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result
}

func compactPorts(values []graph.SecurityPort) []graph.SecurityPort {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

type matchedParent struct {
	reference parentReference
	gateway   ObservedObject
}

func matchingParents(namespace string, references []parentReference, gateways map[string]ObservedObject) []matchedParent {
	var result []matchedParent
	for _, reference := range references {
		if defaultString(reference.Group, "gateway.networking.k8s.io") != "gateway.networking.k8s.io" || defaultString(reference.Kind, "Gateway") != "Gateway" {
			continue
		}
		parentNamespace := defaultString(reference.Namespace, namespace)
		if parentNamespace != namespace {
			continue
		}
		if gateway, found := gateways[namespacedName(parentNamespace, reference.Name)]; found {
			result = append(result, matchedParent{reference: reference, gateway: gateway})
		}
	}
	return result
}

func (p *projection) addResource(observation ObservedObject, kind, ruleID string, attributes map[string]string) {
	p.input.Resources = append(p.input.Resources, graph.ResourceAssertion{
		Claim: kubernetesplugin.ClaimFor(p.context.ClusterID, observation.Object), Kind: kind, DisplayName: projectkit.DisplayName(observation.Object), Attributes: attributes,
		PluginID: PluginID, SourceID: p.context.SourceID, RuleID: ruleID, EvidenceIDs: evidenceIDs(observation),
	})
}

func (p *projection) addFacet(observation ObservedObject, kind, key string, attributes map[string]string, ruleID string, additional ...ObservedObject) {
	evidence := append([]ObservedObject{observation}, additional...)
	p.input.Facets = append(p.input.Facets, graph.FacetAssertion{
		Resource: kubernetesplugin.ClaimFor(p.context.ClusterID, observation.Object), Kind: kind, Key: key, Attributes: attributes,
		PluginID: PluginID, SourceID: p.context.SourceID, RuleID: ruleID, EvidenceIDs: evidenceIDs(evidence...),
	})
}

func (p *projection) relationship(subject ObservedObject, object ObservedObject, predicate graph.Predicate, relationshipQualifier string, properties map[string]string, ruleID string) graph.RelationshipAssertion {
	return graph.RelationshipAssertion{
		Subject: kubernetesplugin.ClaimFor(p.context.ClusterID, subject.Object), Predicate: predicate, Object: kubernetesplugin.ClaimFor(p.context.ClusterID, object.Object), Qualifier: relationshipQualifier, Properties: properties,
		PluginID: PluginID, SourceID: p.context.SourceID, RuleID: ruleID, EvidenceIDs: evidenceIDs(subject, object),
	}
}

func (p *projection) sortOutput() {
	sort.Slice(p.input.Resources, func(i, j int) bool {
		return assertionKey(p.input.Resources[i].Claim, p.input.Resources[i].RuleID) < assertionKey(p.input.Resources[j].Claim, p.input.Resources[j].RuleID)
	})
	sort.Slice(p.input.Facets, func(i, j int) bool {
		return assertionKey(p.input.Facets[i].Resource, p.input.Facets[i].Kind+p.input.Facets[i].Key) < assertionKey(p.input.Facets[j].Resource, p.input.Facets[j].Kind+p.input.Facets[j].Key)
	})
	sort.Slice(p.input.Relationships, func(i, j int) bool {
		left, right := p.input.Relationships[i], p.input.Relationships[j]
		return assertionKey(left.Subject, string(left.Predicate)+left.Qualifier+left.Object.ImmutableKey) < assertionKey(right.Subject, string(right.Predicate)+right.Qualifier+right.Object.ImmutableKey)
	})
	sort.Slice(p.diagnostics, func(i, j int) bool {
		return p.diagnostics[i].Resource+p.diagnostics[i].Code+p.diagnostics[i].Message < p.diagnostics[j].Resource+p.diagnostics[j].Code+p.diagnostics[j].Message
	})
}

func conditionValue(conditions []metav1.Condition, conditionType string) string {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return strings.ToLower(string(condition.Status))
		}
	}
	return "unknown"
}

func routeCondition(parents []routeParentStatus, controllers []string, conditionType string) string {
	values := make(map[string]struct{})
	for _, parent := range parents {
		if contains(controllers, parent.ControllerName) {
			values[conditionValue(parent.Conditions, conditionType)] = struct{}{}
		}
	}
	if len(values) == 0 {
		return "unknown"
	}
	ordered := make([]string, 0, len(values))
	for value := range values {
		ordered = append(ordered, value)
	}
	sort.Strings(ordered)
	return strings.Join(ordered, ",")
}

func evidenceIDs(observations ...ObservedObject) []string {
	set := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		if observation.EventID != "" {
			set[observation.EventID] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// evidenceID names a bare object for [Project]. It falls back to "observed"
// rather than dropping the version component, so it intentionally differs
// from the Kubernetes event ID format used in live projection.
func evidenceID(item *unstructured.Unstructured) string {
	return "kubernetes:" + projectkit.ObjectKey(item) + ":" + defaultString(item.GetResourceVersion(), "observed")
}

func assertionKey(claim graph.IdentityClaim, suffix string) string {
	return strings.Join([]string{claim.Scheme.Group, claim.Scheme.Version, claim.Scheme.Kind, claim.AuthorityID, claim.ImmutableKey, suffix}, "/")
}

func normalizedSet(values []string, fallback string) []string {
	if len(values) == 0 {
		values = []string{fallback}
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, strings.TrimSpace(target))
	return index < len(values) && values[index] == strings.TrimSpace(target)
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
func sortedListeners(values []gatewayListener) []gatewayListener {
	result := append([]gatewayListener(nil), values...)
	sort.Slice(result, func(left, right int) bool {
		return projectkit.MustCanonicalJSON(result[left]) < projectkit.MustCanonicalJSON(result[right])
	})
	return result
}
func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
func namespacedName(namespace, name string) string { return namespace + "/" + name }
func isKind(item *unstructured.Unstructured, apiVersion, kind string) bool {
	return item.GetAPIVersion() == apiVersion && item.GetKind() == kind
}
func isGatewayAPI(item *unstructured.Unstructured) bool {
	return strings.HasPrefix(item.GetAPIVersion(), "gateway.networking.k8s.io/")
}
func int32Value(value *int32) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(int64(*value), 10)
}
