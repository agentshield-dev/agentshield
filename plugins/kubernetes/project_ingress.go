package kubernetes

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// maxDiagnosticReferences caps the unresolved backends listed on an Ingress.
const maxDiagnosticReferences = 100

// ingressBackend is one Service backend reached through an Ingress. Host and
// path are empty for the default backend.
type ingressBackend struct {
	host     string
	path     string
	pathType string
	service  string
	port     string
}

// ingressAttributes describes an Ingress's class, routes, TLS, and published
// addresses. A backend is unresolved when no observed Service in the
// Ingress's namespace has its name; Ingress cannot reference other
// namespaces.
func ingressAttributes(rawIngress *unstructured.Unstructured, index objectIndex) (map[string]string, error) {
	decoded, err := kubernetesapi.Ingress(rawIngress)
	if err != nil {
		return nil, err
	}
	ingress := &decoded.Value
	result := attributes(rawIngress)
	setStringPointerAttribute(result, "kubernetes/ingress-class", ingress.Spec.IngressClassName)
	backends := ingressBackends(ingress)
	hosts := make([]string, 0)
	summaries := make([]any, 0, len(backends))
	unresolved := make([]string, 0)
	for _, backend := range backends {
		hosts = append(hosts, backend.host)
		resolved := index.servicesByName[namespacedName(ingress.Namespace, backend.service)] != nil
		summaries = append(summaries, map[string]any{"host": backend.host, "path": backend.path, "pathType": backend.pathType, "service": backend.service, "port": backend.port, "resolved": resolved})
		if !resolved {
			unresolved = append(unresolved, backend.service+":"+backend.port)
		}
	}
	setJSONAttribute(result, "kubernetes/hosts", hosts)
	result["kubernetes/backends"] = canonicalObjectList(summaries)
	setJSONAttribute(result, "kubernetes/unresolved-backends", boundedStrings(unresolved, maxDiagnosticReferences))

	if len(ingress.Spec.TLS) > 0 {
		result["kubernetes/tls"] = canonicalTypedList(ingress.Spec.TLS)
	}
	if len(ingress.Status.LoadBalancer.Ingress) > 0 {
		result["kubernetes/load-balancer-ingress"] = canonicalTypedList(ingress.Status.LoadBalancer.Ingress)
	}
	return result, nil
}

// projectIngresses emits an exposes edge from each Ingress to every observed
// Service it routes to, one edge per host, path, and port, and a
// network-exposure facet on the Ingress.
//
// The facet's effect is unknown and coverage partial: the Ingress API says
// what is routed, not who can reach it, and controller-specific behavior
// (class, annotations, HTTP-to-HTTPS redirects) is not modeled. The state is
// observed once the controller has published an address in status, declared
// before that.
func projectIngresses(clusterID, sourceID string, index objectIndex, input *graph.Input) error {
	for _, ingress := range index.ingresses {
		decoded, err := kubernetesapi.Ingress(ingress)
		if err != nil {
			return err
		}
		backends := ingressBackends(&decoded.Value)
		for _, backend := range backends {
			service := index.servicesByName[namespacedName(ingress.GetNamespace(), backend.service)]
			// Unresolved backends appear only in the Ingress attributes; an
			// edge would need the Service's identity.
			if service == nil {
				continue
			}
			route := map[string]string{"host": backend.host, "path": backend.path, "pathType": backend.pathType, "service": backend.service, "port": backend.port}
			input.Relationships = append(input.Relationships, relationshipAssertion(
				sourceID, "kubernetes.ingress.backend",
				claimFor(clusterID, ingress), graph.PredicateExposes, claimFor(clusterID, service), projectkit.Qualifier(route), route,
				ingress, service,
			))
		}
		protocols := []string{"HTTP"}
		if len(decoded.Value.Spec.TLS) > 0 {
			protocols = append(protocols, "HTTPS")
		}
		state := graph.SecurityStateDeclared
		if len(decoded.Value.Status.LoadBalancer.Ingress) > 0 {
			state = graph.SecurityStateObserved
		}
		semanticAttributes, err := graph.WithSecuritySemantics(nil, graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
			State: state, Effect: "unknown", Scope: "gateway", Direction: "ingress", Coverage: "partial",
			Protocols: protocols, ConfigurationDigest: projectkit.SecurityDigest(decoded.Value.Spec),
		})
		if err != nil {
			return fmt.Errorf("Ingress %s exposure semantics: %w", projectkit.DisplayName(ingress), err)
		}
		input.Facets = append(input.Facets, graph.FacetAssertion{
			Resource: claimFor(clusterID, ingress), Kind: "network-exposure", Key: "ingress", Attributes: semanticAttributes,
			PluginID: PluginID, SourceID: sourceID, RuleID: "kubernetes.ingress.exposure",
			EvidenceIDs: evidenceIDs(ingress),
		})
	}
	return nil
}

// ingressBackends lists the default backend and every HTTP path backend,
// sorted for stable output.
func ingressBackends(ingress *networkingv1.Ingress) []ingressBackend {
	var result []ingressBackend
	if ingress.Spec.DefaultBackend != nil {
		if normalized, ok := normalizeIngressBackend("", "", "", *ingress.Spec.DefaultBackend); ok {
			result = append(result, normalized)
		}
	}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			pathType := ""
			if path.PathType != nil {
				pathType = string(*path.PathType)
			}
			if normalized, ok := normalizeIngressBackend(rule.Host, path.Path, pathType, path.Backend); ok {
				result = append(result, normalized)
			}
		}
	}
	slices.SortFunc(result, func(left, right ingressBackend) int {
		return cmp.Compare(projectkit.MustCanonicalJSON(left), projectkit.MustCanonicalJSON(right))
	})
	return result
}

// normalizeIngressBackend keeps Service backends only; resource backends
// (for example a storage bucket CRD) are not modeled. The port is the
// Service port name if set, else its number.
func normalizeIngressBackend(host, path, pathType string, backend networkingv1.IngressBackend) (ingressBackend, bool) {
	if backend.Service == nil {
		return ingressBackend{}, false
	}
	name := backend.Service.Name
	port := backend.Service.Port.Name
	if port == "" {
		port = scalarString(backend.Service.Port.Number)
	}
	if name == "" || port == "" {
		return ingressBackend{}, false
	}
	return ingressBackend{host: host, path: path, pathType: pathType, service: name, port: port}, true
}

func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case int64:
		return fmt.Sprintf("%d", typed)
	case int32:
		return fmt.Sprintf("%d", typed)
	case int:
		return fmt.Sprintf("%d", typed)
	case float64:
		return fmt.Sprintf("%g", typed)
	default:
		return ""
	}
}
