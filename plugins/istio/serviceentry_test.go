package istio

import (
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
)

func TestServiceEntryProjectsSafeRegistryDeclarations(t *testing.T) {
	serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "demo", "external", "se-uid", map[string]any{
		"hosts":    []any{"API.Example.COM.", "*.Example.net", "https://secret@example.org/path"},
		"location": "MESH_EXTERNAL", "resolution": "DNS",
		"ports":     []any{map[string]any{"number": int64(443), "protocol": "TLS"}},
		"endpoints": []any{}, "exportTo": []any{"."},
	})
	result, err := ProjectObserved(testContext(), testObserved(serviceEntry))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Input.Resources) != 3 {
		t.Fatalf("resources = %d, want ServiceEntry plus two valid destinations", len(result.Input.Resources))
	}
	if len(result.Input.Relationships) != 2 {
		t.Fatalf("relationships = %d, want 2", len(result.Input.Relationships))
	}
	for _, relation := range result.Input.Relationships {
		if relation.Predicate != graph.PredicateExposes || relation.Qualifier != "istio-serviceentry-host" || relation.Properties["semantic"] != "istio-service-registry-declaration" {
			t.Fatalf("unsafe ServiceEntry relationship: %#v", relation)
		}
		encoded := strings.ToLower(projectkit.MustCanonicalJSON(relation))
		if strings.Contains(encoded, "internet") || strings.Contains(encoded, "public") || strings.Contains(encoded, "reachable") || strings.Contains(encoded, "communicates-with") {
			t.Fatalf("relationship overstates configuration: %s", encoded)
		}
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "invalid-serviceentry-host" {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}
	if strings.Contains(projectkit.MustCanonicalJSON(result), "secret") {
		t.Fatal("malformed host diagnostic leaked credential-like input")
	}
	compileProjection(t, result)
}

func TestServiceEntryEndpointUpdateRefreshesEvidenceWithoutProjectingEndpoints(t *testing.T) {
	project := func(address, revision string) ProjectionResult {
		serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "demo", "external", "se-uid", map[string]any{
			"hosts":     []any{"api.example.com"},
			"ports":     []any{map[string]any{"number": int64(443), "protocol": "TLS"}},
			"endpoints": []any{map[string]any{"address": address}},
		})
		serviceEntry.SetResourceVersion(revision)
		observed := testObserved(serviceEntry)
		observed[0].EventID = "event:se-uid:" + revision
		result, err := ProjectObserved(testContext(), observed)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	first := project("192.0.2.10", "1")
	second := project("192.0.2.11", "2")
	if projectkit.MustCanonicalJSON(first.Input.Resources[0].Attributes) != projectkit.MustCanonicalJSON(second.Input.Resources[0].Attributes) {
		t.Fatal("endpoint-only update changed projected semantic attributes")
	}
	if projectkit.MustCanonicalJSON(first.Input) == projectkit.MustCanonicalJSON(second.Input) {
		t.Fatal("endpoint-only update did not refresh assertion evidence")
	}
	for _, result := range []ProjectionResult{first, second} {
		encoded := projectkit.MustCanonicalJSON(result.Input)
		if strings.Contains(encoded, "192.0.2.") {
			t.Fatalf("ServiceEntry endpoint leaked into graph output: %s", encoded)
		}
		for _, resource := range result.Input.Resources {
			if resource.Kind == "istio/serviceentry" && resource.Attributes["istio/location"] != "MESH_EXTERNAL" {
				t.Fatalf("default ServiceEntry location = %q", resource.Attributes["istio/location"])
			}
		}
	}
}

func TestServiceEntryBindingFacetClassifiesRedirectionWithoutEndpointValues(t *testing.T) {
	serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "demo", "external", "se-uid", map[string]any{
		"hosts": []any{"api.example.com"}, "location": "MESH_EXTERNAL",
		"endpoints": []any{map[string]any{"address": "10.20.0.15"}},
	})
	result, err := ProjectObserved(testContext(), testObserved(serviceEntry))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, facet := range result.Input.Facets {
		if facet.Kind != "serviceentry-binding" {
			continue
		}
		found = true
		if facet.Attributes["istio/binding-posture"] != "external-declaration-to-private-ip" || facet.Attributes["istio/endpoint-address-classes"] != `["private-ip"]` {
			t.Fatalf("binding facet = %#v", facet.Attributes)
		}
		if strings.Contains(projectkit.MustCanonicalJSON(facet), "10.20.0.15") {
			t.Fatal("binding facet exposed endpoint value")
		}
	}
	if !found {
		t.Fatal("serviceentry-binding facet not found")
	}
	compileProjection(t, result)
}
