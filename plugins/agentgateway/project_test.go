package agentgateway

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestProjectAgentgatewaySemanticsCompileAndRemainDeterministic(t *testing.T) {
	class := testObject("gateway.networking.k8s.io/v1", "GatewayClass", "", "agentgateway", "class", map[string]any{
		"spec": map[string]any{"controllerName": DefaultControllerName},
	})
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
		"spec": map[string]any{"gatewayClassName": "agentgateway", "listeners": []any{map[string]any{"name": "http", "port": int64(80), "protocol": "HTTP"}}},
	})
	route := testObject("gateway.networking.k8s.io/v1", "HTTPRoute", "demo", "api", "route", map[string]any{
		"spec": map[string]any{
			"hostnames":  []any{"api.example.com"},
			"parentRefs": []any{map[string]any{"name": "edge"}},
			"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "api", "port": int64(8080)}}}},
		},
	})
	service := testObject("v1", "Service", "demo", "api", "service", map[string]any{"spec": map[string]any{"ports": []any{map[string]any{"port": int64(8080)}}}})
	other := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "other", "other", map[string]any{"spec": map[string]any{"gatewayClassName": "not-agentgateway"}})
	objects := []*unstructured.Unstructured{class, gateway, route, service, other}

	registry := graph.NewRegistry()
	if err := discovery.RegisterIdentitySchemes(registry, kubernetesplugin.Descriptor()); err != nil {
		t.Fatal(err)
	}
	compiler := graph.NewCompiler(registry)
	var expectedHash string
	for seed := int64(0); seed < 10; seed++ {
		shuffled := append([]*unstructured.Unstructured(nil), objects...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		input, err := Project("cluster", "source", shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if len(input.Resources) != 4 || len(input.Facets) != 3 || len(input.Relationships) != 3 {
			t.Fatalf("projected resources=%d facets=%d relationships=%d", len(input.Resources), len(input.Facets), len(input.Relationships))
		}
		predicates := map[graph.Predicate]int{}
		for _, relationship := range input.Relationships {
			predicates[relationship.Predicate]++
		}
		if predicates[graph.PredicateGovernedBy] != 1 || predicates[graph.PredicateMemberOf] != 1 || predicates[graph.PredicateExposes] != 1 {
			t.Fatalf("projected predicates = %#v", predicates)
		}
		var exposure *graph.SecuritySemantics
		for _, facet := range input.Facets {
			if facet.Kind == "agentgateway-ingress" {
				exposure, err = graph.DecodeSecuritySemantics(facet.Attributes)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		if exposure == nil || exposure.Class != graph.SecurityClassExposure || exposure.Effect != "unknown" || exposure.State != graph.SecurityStateDeclared || exposure.Scope != "gateway" || exposure.Coverage != "partial" || exposure.ConfigurationDigest == "" {
			t.Fatalf("agentgateway exposure semantics = %#v", exposure)
		}
		if len(exposure.Ports) != 1 || exposure.Ports[0] != (graph.SecurityPort{Protocol: "HTTP", Port: 80}) {
			t.Fatalf("agentgateway exposure ports = %#v", exposure.Ports)
		}
		if len(input.Telemetry) != 0 {
			t.Fatal("projection fabricated telemetry")
		}
		snapshot, err := compiler.Compile(input)
		if err != nil {
			t.Fatalf("compile projected input: %v", err)
		}
		hash, err := snapshot.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if seed == 0 {
			expectedHash = hash
		} else if hash != expectedHash {
			t.Fatalf("seed %d hash = %s, want %s", seed, hash, expectedHash)
		}
	}
}

func TestProjectBoundsAgentgatewaySecurityDetails(t *testing.T) {
	listeners := make([]any, 0, 70)
	for port := 1; port <= 70; port++ {
		listeners = append(listeners, map[string]any{"name": fmt.Sprintf("listener-%02d", port), "port": int64(port), "protocol": "TCP"})
	}
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
		"spec": map[string]any{"gatewayClassName": DefaultGatewayClass, "listeners": listeners},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{gateway})
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Facets) != 1 {
		t.Fatalf("facets = %d, want 1", len(input.Facets))
	}
	semantics, err := graph.DecodeSecuritySemantics(input.Facets[0].Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if semantics == nil || len(semantics.Ports) != 64 || semantics.Coverage != "partial" {
		t.Fatalf("bounded agentgateway semantics = %#v", semantics)
	}
}

func TestProjectSortsGatewayListeners(t *testing.T) {
	listeners := []any{
		map[string]any{"name": "https", "port": int64(443), "protocol": "HTTPS"},
		map[string]any{"name": "http", "port": int64(80), "protocol": "HTTP"},
	}
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
		"spec": map[string]any{"gatewayClassName": DefaultGatewayClass, "listeners": listeners},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{gateway})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"name":"http","port":80,"protocol":"HTTP"},{"name":"https","port":443,"protocol":"HTTPS"}]`
	if got := input.Resources[0].Attributes["agentgateway/listeners"]; got != want {
		t.Fatalf("listeners = %s, want %s", got, want)
	}
	slices.Reverse(listeners)
	reordered := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
		"spec": map[string]any{"gatewayClassName": DefaultGatewayClass, "listeners": listeners},
	})
	reorderedInput, err := Project("cluster", "source", []*unstructured.Unstructured{reordered})
	if err != nil {
		t.Fatal(err)
	}
	originalSemantics, err := graph.DecodeSecuritySemantics(input.Facets[0].Attributes)
	if err != nil {
		t.Fatal(err)
	}
	reorderedSemantics, err := graph.DecodeSecuritySemantics(reorderedInput.Facets[0].Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if originalSemantics.ConfigurationDigest != reorderedSemantics.ConfigurationDigest {
		t.Fatalf("listener reorder changed digest from %s to %s", originalSemantics.ConfigurationDigest, reorderedSemantics.ConfigurationDigest)
	}
}

func TestProjectIdentitySurvivesRename(t *testing.T) {
	before := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "old-name", "gateway", map[string]any{"spec": map[string]any{"gatewayClassName": DefaultGatewayClass}})
	after := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "new-name", "gateway", map[string]any{"spec": map[string]any{"gatewayClassName": DefaultGatewayClass}})
	beforeInput, err := Project("cluster", "source", []*unstructured.Unstructured{before})
	if err != nil {
		t.Fatal(err)
	}
	afterInput, err := Project("cluster", "source", []*unstructured.Unstructured{after})
	if err != nil {
		t.Fatal(err)
	}
	if beforeInput.Resources[0].Claim != afterInput.Resources[0].Claim {
		t.Fatalf("rename changed identity from %#v to %#v", beforeInput.Resources[0].Claim, afterInput.Resources[0].Claim)
	}
	if beforeInput.Resources[0].DisplayName == afterInput.Resources[0].DisplayName {
		t.Fatal("rename did not update mutable display name")
	}
}

func TestProjectObservedClassOwnershipStatusAndUnknownCoverage(t *testing.T) {
	nonMatchingClass := testObject("gateway.networking.k8s.io/v1", "GatewayClass", "", DefaultGatewayClass, "class", map[string]any{
		"spec": map[string]any{"controllerName": "example.net/other-controller"},
	})
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
		"spec": map[string]any{"gatewayClassName": DefaultGatewayClass},
	})
	result, err := ProjectObserved(ProjectionContext{ClusterID: "cluster", SourceID: "source"}, []ObservedObject{
		observed(nonMatchingClass, "event:class"), observed(gateway, "event:gateway"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Input.Resources) != 0 || len(result.Input.Facets) != 0 {
		t.Fatal("configured class fallback overrode an observed non-agentgateway class")
	}

	matchingClass := testObject("gateway.networking.k8s.io/v1", "GatewayClass", "", DefaultGatewayClass, "class", map[string]any{
		"spec":   map[string]any{"controllerName": DefaultControllerName},
		"status": map[string]any{"conditions": []any{map[string]any{"type": "Accepted", "status": "True", "reason": "Accepted", "lastTransitionTime": "2026-10-04T00:00:00Z"}}},
	})
	result, err = ProjectObserved(ProjectionContext{ClusterID: "cluster", SourceID: "source"}, []ObservedObject{
		observed(matchingClass, "event:class"), observed(gateway, "event:gateway"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Input.Resources) != 2 || result.Input.Resources[0].EvidenceIDs[0] == "" {
		t.Fatalf("matching class projection = %#v", result.Input.Resources)
	}
	var gatewayFacet graph.FacetAssertion
	for _, facet := range result.Input.Facets {
		if facet.Kind == "agentgateway-ingress" {
			gatewayFacet = facet
		}
	}
	if gatewayFacet.Attributes["agentgateway/accepted"] != "unknown" || gatewayFacet.Attributes["agentgateway/class-source"] != "observed" {
		t.Fatalf("gateway status facet = %#v", gatewayFacet.Attributes)
	}
}

func TestProjectMalformedGatewayAPIObjectAndCrossNamespaceBackend(t *testing.T) {
	malformed := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "", map[string]any{"spec": map[string]any{"gatewayClassName": DefaultGatewayClass}})
	if _, err := Project("cluster", "source", []*unstructured.Unstructured{malformed}); err == nil {
		t.Fatal("missing Gateway UID did not fail projection")
	}

	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{"spec": map[string]any{"gatewayClassName": DefaultGatewayClass}})
	route := testObject("gateway.networking.k8s.io/v1", "HTTPRoute", "demo", "api", "route", map[string]any{"spec": map[string]any{
		"parentRefs": []any{map[string]any{"name": "edge"}},
		"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"namespace": "other", "name": "api"}}}},
	}})
	service := testObject("v1", "Service", "other", "api", "service", nil)
	result, err := ProjectObserved(ProjectionContext{ClusterID: "cluster", SourceID: "source"}, []ObservedObject{
		observed(gateway, "event:gateway"), observed(route, "event:route"), observed(service, "event:service"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Input.Relationships) != 1 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "reference-grant-unknown" {
		t.Fatalf("cross-namespace result relationships=%#v diagnostics=%#v", result.Input.Relationships, result.Diagnostics)
	}
}

func testObject(apiVersion, kind, namespace, name, uid string, fields map[string]any) *unstructured.Unstructured {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": namespace, "uid": uid, "resourceVersion": "1"},
	}}
	for key, value := range fields {
		object.Object[key] = value
	}
	object.SetUID(types.UID(uid))
	return object
}

func observed(item *unstructured.Unstructured, eventID string) ObservedObject {
	return ObservedObject{Key: projectkit.ObjectKey(item), Object: item, EventID: eventID, Revision: item.GetResourceVersion()}
}
