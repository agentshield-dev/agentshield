package istio

import (
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

func TestVirtualServiceResolvesOnlyUnambiguousDestinations(t *testing.T) {
	service := testObject("v1", "Service", "demo", "web", "svc-web", nil)
	ambiguousService := testObject("v1", "Service", "demo", "ambiguous", "svc-ambiguous", nil)
	serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "demo", "registry", "se", map[string]any{
		"hosts": []any{"external.example.com", "ambiguous.demo.svc.cluster.local"}, "exportTo": []any{"."},
	})
	virtualService := testObject("networking.istio.io/v1", "VirtualService", "demo", "routes", "vs", map[string]any{
		"hosts": []any{"routes.example.com"},
		"http": []any{map[string]any{
			"route": []any{
				map[string]any{"destination": map[string]any{"host": "web", "subset": "v1", "port": map[string]any{"number": int64(8080)}}},
				map[string]any{"destination": map[string]any{"host": "external.example.com", "port": map[string]any{"number": int64(443)}}},
				map[string]any{"destination": map[string]any{"host": "ambiguous.demo.svc.cluster.local"}},
				map[string]any{"destination": map[string]any{"host": "missing.example.com"}},
				map[string]any{"destination": map[string]any{"host": "web"}, "weight": int64(0)},
			},
			"mirror": map[string]any{"host": "web", "port": map[string]any{"number": int64(8443)}},
		}},
	})
	objects := testObserved(service, ambiguousService, serviceEntry, virtualService)
	result, err := ProjectObserved(testContext(), objects)
	if err != nil {
		t.Fatal(err)
	}
	var routes []graph.RelationshipAssertion
	for _, relation := range result.Input.Relationships {
		if relation.Qualifier == "istio-route-http" {
			routes = append(routes, relation)
		}
	}
	if len(routes) != 2 {
		t.Fatalf("resolved HTTP routes = %d, want Service and exact ServiceEntry only", len(routes))
	}
	for _, route := range routes {
		if route.Predicate != graph.PredicateExposes || route.Properties["semantic"] != "istio-configured-forwarding" {
			t.Fatalf("unexpected route relationship: %#v", route)
		}
		if len(route.EvidenceIDs) != 2 {
			t.Fatalf("route evidence = %#v, want VirtualService and destination events", route.EvidenceIDs)
		}
		wantPorts := `[443]`
		if route.Object == kubernetesplugin.ClaimFor(testContext().ClusterID, service) {
			wantPorts = `[8080,8443]`
		}
		if route.Properties["ports"] != wantPorts {
			t.Fatalf("route ports = %s, want %s", route.Properties["ports"], wantPorts)
		}
	}
	compileProjection(t, result, service, ambiguousService)
}
