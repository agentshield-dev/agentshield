package kubernetes

import (
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestProjectIngressBackends(t *testing.T) {
	service := testObject("v1", "Service", "demo", "api", "service", nil)
	ingress := testObject("networking.k8s.io/v1", "Ingress", "demo", "public", "ingress", map[string]any{
		"spec": map[string]any{
			"defaultBackend": map[string]any{"service": map[string]any{"name": "api", "port": map[string]any{"number": int64(80)}}},
			"rules": []any{map[string]any{"host": "api.example.com", "http": map[string]any{"paths": []any{map[string]any{
				"path": "/v1", "pathType": "Prefix", "backend": map[string]any{"service": map[string]any{"name": "api", "port": map[string]any{"name": "http"}}},
			}}}}},
			"tls": []any{map[string]any{"hosts": []any{"api.example.com"}, "secretName": "api-cert"}},
		},
		"status": map[string]any{"loadBalancer": map[string]any{"ingress": []any{map[string]any{"hostname": "lb.example.net"}}}},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{ingress, service})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	qualifiers := map[string]bool{}
	for _, relationship := range input.Relationships {
		if relationship.Subject == ClaimFor("cluster", ingress) && relationship.Object == ClaimFor("cluster", service) {
			count++
			qualifiers[relationship.Qualifier] = true
		}
	}
	if count != 2 || len(qualifiers) != 2 {
		t.Fatalf("Ingress edges = %d with %d qualifiers, want 2 distinct", count, len(qualifiers))
	}
	resource := resourceOfKind(t, input, "kubernetes/ingress")
	if resource.Attributes["kubernetes/load-balancer-ingress"] == "" || resource.Attributes["kubernetes/tls"] == "" {
		t.Fatalf("missing bounded ingress attributes: %#v", resource.Attributes)
	}
	var exposure *graph.SecuritySemantics
	for _, facet := range input.Facets {
		if facet.Resource == ClaimFor("cluster", ingress) && facet.Kind == "network-exposure" {
			exposure, err = graph.DecodeSecuritySemantics(facet.Attributes)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if exposure == nil || exposure.Effect != "unknown" || exposure.State != graph.SecurityStateObserved || exposure.Scope != "gateway" || exposure.Coverage != "partial" || exposure.ConfigurationDigest == "" {
		t.Fatalf("Ingress exposure semantics = %#v", exposure)
	}
	compileInput(t, input)
}
