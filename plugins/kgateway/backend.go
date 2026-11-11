package kgateway

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
)

// projectBackends emits each Backend with an egress facet, a network
// destination and exposes edge per static host, and HTTPRoute exposes Backend
// edges. A dynamicForwardProxy Backend forwards to any requested host, so it
// is flagged as open egress.
func (p *projection) projectBackends() error {
	for _, observation := range p.byKind[kindBackend] {
		decoded, err := kubernetesapi.Decode[backend](observation.Object)
		if err != nil {
			return fmt.Errorf("decode Backend %q: %w", observation.Key, err)
		}
		spec := decoded.Value.Spec
		backendType := backendType(decoded.Value)
		attributes := map[string]string{
			"kgateway/backend-type": backendType,
			"kgateway/open-egress":  strconv.FormatBool(spec.DynamicForwardProxy != nil),
		}
		semantics := graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
			State: graph.SecurityStateDeclared, Effect: "unknown", Scope: "gateway", Direction: "egress", Coverage: "partial",
		}
		var hosts []string
		switch {
		case spec.DynamicForwardProxy != nil:
			semantics.Effect = "external-addressable"
			semantics.Scope = "external"
			semantics.Coverage = "complete"
		case spec.Static != nil:
			for _, host := range spec.Static.Hosts {
				canonical, err := canonicalHost(host.Host)
				if err != nil {
					p.diagnose(observation, "invalid-backend-host", err.Error())
					continue
				}
				hosts = append(hosts, canonical)
				if host.Port > 0 && host.Port <= 65535 && len(semantics.Ports) < 64 {
					semantics.Ports = append(semantics.Ports, graph.SecurityPort{Protocol: "TCP", Port: uint16(host.Port)})
				}
				if err := p.addBackendHost(observation, canonical, host.Port); err != nil {
					return err
				}
			}
		case spec.AWS != nil:
			attributes["kgateway/aws-region"] = spec.AWS.Region
			attributes["kgateway/aws-account-id"] = spec.AWS.AccountID
		case spec.GCP != nil:
			attributes["kgateway/gcp-host"] = spec.GCP.Host
		}
		attributes["kgateway/static-hosts"] = projectkit.MustCanonicalJSON(sortedUnique(hosts))
		semantics.ConfigurationDigest = projectkit.SecurityDigest(map[string]any{"type": backendType, "hosts": sortedUnique(hosts), "dynamicForwardProxy": spec.DynamicForwardProxy != nil})
		p.addResource(observation, "kgateway.backend.resource", attributes)
		facet, err := graph.WithSecuritySemantics(map[string]string{
			"kgateway/backend-type": backendType,
			"kgateway/open-egress":  attributes["kgateway/open-egress"],
			"kgateway/static-hosts": attributes["kgateway/static-hosts"],
		}, semantics)
		if err != nil {
			return fmt.Errorf("Backend %s egress semantics: %w", projectkit.DisplayName(observation.Object), err)
		}
		p.addFacet(observation, "kgateway-egress", "backend", facet, "kgateway.backend.egress")
	}
	return p.projectRouteBackends()
}

func backendType(value backend) string {
	spec := value.Spec
	switch {
	case spec.Type != "":
		return spec.Type
	case spec.DynamicForwardProxy != nil:
		return "DynamicForwardProxy"
	case spec.Static != nil:
		return "Static"
	case spec.AWS != nil:
		return "AWS"
	case spec.GCP != nil:
		return "GCP"
	case len(spec.PriorityGroups) > 0:
		return "PriorityGroups"
	}
	return "unknown"
}

func (p *projection) addBackendHost(observation ObservedObject, host string, port int32) error {
	keyType := "dns"
	if _, err := netip.ParseAddr(host); err == nil {
		keyType = "ip"
	}
	claim, err := graph.NetworkDestinationClaim(p.context.NetworkID, keyType+"/"+host)
	if err != nil {
		p.diagnose(observation, "invalid-backend-host", err.Error())
		return nil
	}
	p.input.Resources = append(p.input.Resources, graph.ResourceAssertion{
		Claim: claim, Kind: "network/destination", DisplayName: host, Attributes: map[string]string{"kgateway/declared-host": host},
		PluginID: PluginID, SourceID: p.context.SourceID, RuleID: "kgateway.backend.host", EvidenceIDs: evidenceIDs(observation),
	})
	properties := map[string]string{"semantic": "kgateway-static-backend-host", "declared-host": host, "port": strconv.Itoa(int(port))}
	p.addRelationship(observation, graph.PredicateExposes, claim, "kgateway-static-host-"+projectkit.Qualifier(map[string]any{"host": host, "port": port}), properties, "kgateway.backend.exposes-host")
	return nil
}

// projectRouteBackends emits HTTPRoute exposes Backend for same-namespace
// backendRefs. The Kubernetes plugin only projects core Service backends.
func (p *projection) projectRouteBackends() error {
	for _, route := range p.byKind["HTTPRoute"] {
		decoded, err := kubernetesapi.Decode[httpRoute](route.Object)
		if err != nil {
			return fmt.Errorf("decode HTTPRoute %q: %w", route.Key, err)
		}
		for _, rule := range decoded.Value.Spec.Rules {
			for _, reference := range rule.BackendRefs {
				if reference.Group != kgatewayGroup || reference.Kind != kindBackend {
					continue
				}
				namespace := defaultString(reference.Namespace, route.Object.GetNamespace())
				if namespace != route.Object.GetNamespace() {
					p.diagnose(route, "reference-grant-unknown", "cross-namespace Backend omitted because ReferenceGrant coverage is unavailable")
					continue
				}
				target, found := p.lookup(kindBackend, namespace, reference.Name)
				if !found {
					p.diagnose(route, "backend-unresolved", "Backend "+namespace+"/"+reference.Name+" was not observed")
					continue
				}
				properties := map[string]string{"port": int32String(reference.Port), "weight": int32String(reference.Weight), "rule": stringValue(rule.Name)}
				p.addRelationship(route, graph.PredicateExposes, p.claim(target), "kgateway-backend-"+projectkit.Qualifier(map[string]any{"ref": reference, "rule": stringValue(rule.Name)}), properties, "kgateway.httproute.backend", target)
			}
		}
	}
	return nil
}

// projectDirectResponses emits each DirectResponse and a facet on every
// HTTPRoute whose rules answer from the gateway through an ExtensionRef
// filter, so those rules are not mistaken for unresolved backends.
func (p *projection) projectDirectResponses() error {
	for _, observation := range p.byKind[kindDirectResponse] {
		decoded, err := kubernetesapi.Decode[directResponse](observation.Object)
		if err != nil {
			return fmt.Errorf("decode DirectResponse %q: %w", observation.Key, err)
		}
		p.addResource(observation, "kgateway.directresponse.resource", map[string]string{
			"kgateway/status-code": strconv.Itoa(int(decoded.Value.Spec.StatusCode)),
			"kgateway/has-body":    strconv.FormatBool(decoded.Value.Spec.Body != nil),
		})
	}
	for _, route := range p.byKind["HTTPRoute"] {
		decoded, err := kubernetesapi.Decode[httpRoute](route.Object)
		if err != nil {
			return fmt.Errorf("decode HTTPRoute %q: %w", route.Key, err)
		}
		var statuses, names []string
		var evidence []ObservedObject
		rules := 0
		for _, rule := range decoded.Value.Spec.Rules {
			matched := false
			for _, filter := range rule.Filters {
				reference := filter.ExtensionRef
				if filter.Type != "ExtensionRef" || reference == nil || reference.Group != kgatewayGroup || reference.Kind != kindDirectResponse {
					continue
				}
				response, found := p.lookup(kindDirectResponse, route.Object.GetNamespace(), reference.Name)
				if !found {
					p.diagnose(route, "direct-response-unresolved", "DirectResponse "+route.Object.GetNamespace()+"/"+reference.Name+" was not observed")
					continue
				}
				responseValue, err := kubernetesapi.Decode[directResponse](response.Object)
				if err != nil {
					return fmt.Errorf("decode DirectResponse %q: %w", response.Key, err)
				}
				matched = true
				statuses = append(statuses, strconv.Itoa(int(responseValue.Value.Spec.StatusCode)))
				names = append(names, reference.Name)
				evidence = append(evidence, response)
			}
			if matched {
				rules++
			}
		}
		if rules == 0 {
			continue
		}
		p.addFacet(route, "kgateway-direct-response", "httproute", map[string]string{
			"kgateway/direct-response-rules":    strconv.Itoa(rules),
			"kgateway/direct-response-statuses": projectkit.MustCanonicalJSON(sortedUnique(statuses)),
			"kgateway/direct-responses":         projectkit.MustCanonicalJSON(sortedUnique(names)),
			"kgateway/rule-count":               strconv.Itoa(len(decoded.Value.Spec.Rules)),
		}, "kgateway.httproute.direct-response", evidence...)
	}
	return nil
}

// projectGatewayExtensions emits each GatewayExtension with its type, which
// names the external service an auth policy depends on.
func (p *projection) projectGatewayExtensions() error {
	for _, observation := range p.byKind[kindGatewayExtension] {
		decoded, err := kubernetesapi.Decode[gatewayExtension](observation.Object)
		if err != nil {
			return fmt.Errorf("decode GatewayExtension %q: %w", observation.Key, err)
		}
		spec := decoded.Value.Spec
		extensionType := spec.Type
		switch {
		case extensionType != "":
		case spec.ExtAuth != nil:
			extensionType = "ExtAuth"
		case spec.ExtProc != nil:
			extensionType = "ExtProc"
		case spec.RateLimit != nil:
			extensionType = "RateLimit"
		case spec.JWT != nil:
			extensionType = "JWT"
		case spec.OAuth2 != nil:
			extensionType = "OAuth2"
		}
		p.addResource(observation, "kgateway.gatewayextension.resource", map[string]string{"kgateway/extension-type": defaultString(extensionType, "unknown")})
	}
	return nil
}

// projectGatewayParameters emits each GatewayParameters and, for a Gateway
// that resolves one, the declared proxy Service type as an exposure facet.
// The Gateway reference wins over the GatewayClass reference; field-level
// merging of the two is not modeled.
func (p *projection) projectGatewayParameters() error {
	serviceTypes := make(map[string]string)
	for _, observation := range p.byKind[kindGatewayParams] {
		decoded, err := kubernetesapi.Decode[gatewayParameters](observation.Object)
		if err != nil {
			return fmt.Errorf("decode GatewayParameters %q: %w", observation.Key, err)
		}
		serviceType := "unset"
		if kube := decoded.Value.Spec.Kube; kube != nil && kube.Service != nil && kube.Service.Type != nil {
			serviceType = *kube.Service.Type
		}
		serviceTypes[observation.Key] = serviceType
		p.addResource(observation, "kgateway.gatewayparameters.resource", map[string]string{
			"kgateway/service-type": serviceType,
			"kgateway/self-managed": strconv.FormatBool(decoded.Value.Spec.SelfManaged != nil),
		})
	}
	for _, observation := range p.byKind["Gateway"] {
		decoded, err := kubernetesapi.Decode[gateway](observation.Object)
		if err != nil {
			return fmt.Errorf("decode Gateway %q: %w", observation.Key, err)
		}
		parameters, source, found, evidence := p.gatewayParametersFor(observation, decoded.Value)
		if !found {
			continue
		}
		serviceType := serviceTypes[parameters.Key]
		effect := "unknown"
		switch serviceType {
		case "LoadBalancer":
			effect = "external-addressable"
		case "ClusterIP":
			effect = "internal"
		}
		facet, err := graph.WithSecuritySemantics(map[string]string{
			"kgateway/service-type":        serviceType,
			"kgateway/parameters-source":   source,
			"kgateway/gateway-parameters":  projectkit.DisplayName(parameters.Object),
			"kgateway/exposure-limitation": "proxy-service-only",
		}, graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
			State: graph.SecurityStateDeclared, Effect: effect, Scope: "gateway", Direction: "ingress", Coverage: "partial",
			ConfigurationDigest: projectkit.SecurityDigest(map[string]string{"serviceType": serviceType, "source": source}),
		})
		if err != nil {
			return fmt.Errorf("Gateway %s service semantics: %w", projectkit.DisplayName(observation.Object), err)
		}
		p.addFacet(observation, "kgateway-gateway-service", "service-type", facet, "kgateway.gateway.service", append(evidence, parameters)...)
	}
	return nil
}

func (p *projection) gatewayParametersFor(observation ObservedObject, value gateway) (ObservedObject, string, bool, []ObservedObject) {
	if infrastructure := value.Spec.Infrastructure; infrastructure != nil && infrastructure.ParametersRef != nil {
		reference := infrastructure.ParametersRef
		if reference.Group == kgatewayGroup && reference.Kind == kindGatewayParams {
			parameters, found := p.lookup(kindGatewayParams, observation.Object.GetNamespace(), reference.Name)
			if found {
				return parameters, "gateway", true, nil
			}
			p.diagnose(observation, "gateway-parameters-unresolved", "GatewayParameters "+observation.Object.GetNamespace()+"/"+reference.Name+" was not observed")
		}
	}
	class, found := p.lookup("GatewayClass", "", value.Spec.GatewayClassName)
	if !found {
		return ObservedObject{}, "", false, nil
	}
	decoded, err := kubernetesapi.Decode[gatewayClass](class.Object)
	if err != nil || decoded.Value.Spec.ParametersRef == nil {
		return ObservedObject{}, "", false, nil
	}
	reference := decoded.Value.Spec.ParametersRef
	if reference.Group != kgatewayGroup || reference.Kind != kindGatewayParams {
		return ObservedObject{}, "", false, nil
	}
	parameters, found := p.lookup(kindGatewayParams, reference.Namespace, reference.Name)
	if !found {
		p.diagnose(observation, "gateway-parameters-unresolved", "GatewayParameters "+reference.Namespace+"/"+reference.Name+" was not observed")
		return ObservedObject{}, "", false, nil
	}
	return parameters, "gatewayclass", true, []ObservedObject{class}
}

// canonicalHost lowercases a static Backend host and rejects anything that
// is not a bare IP address or DNS name.
func canonicalHost(value string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if host == "" {
		return "", errors.New("backend host is empty")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String(), nil
	}
	if len(host) > 253 {
		return "", errors.New("backend host exceeds 253 characters")
	}
	for _, label := range strings.Split(host, ".") {
		if !validDNSLabel(label) {
			return "", errors.New("backend host is not an IP address or DNS name")
		}
	}
	return host, nil
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func int32String(value *int32) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(int(*value))
}
