package kubernetes

import (
	"fmt"
	"slices"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestProjectGatewayHTTPRoute(t *testing.T) {
	service := testObject("v1", "Service", "demo", "api", "service", nil)
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
		"spec": map[string]any{"gatewayClassName": "prod", "listeners": []any{map[string]any{"name": "https", "port": int64(443), "protocol": "HTTPS"}}},
	})
	route := testObject("gateway.networking.k8s.io/v1", "HTTPRoute", "demo", "api", "route", map[string]any{
		"spec": map[string]any{
			"hostnames": []any{"api.example.com"},
			"parentRefs": []any{
				map[string]any{"name": "edge", "sectionName": "https"},
				map[string]any{"group": "apps", "kind": "Deployment", "name": "edge"},
			},
			"rules": []any{map[string]any{
				"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/v1"}}},
				"backendRefs": []any{
					map[string]any{"name": "api", "port": int64(8080), "weight": int64(10)},
					map[string]any{"group": "example.io", "kind": "Thing", "name": "api"},
				},
			}},
		},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{route, service, gateway})
	if err != nil {
		t.Fatal(err)
	}
	want := map[graph.Predicate]bool{graph.PredicateMemberOf: false, graph.PredicateExposes: false}
	for _, relationship := range input.Relationships {
		if relationship.Subject == ClaimFor("cluster", route) {
			want[relationship.Predicate] = true
		}
	}
	for predicate, found := range want {
		if !found {
			t.Fatalf("HTTPRoute %s relationship not found", predicate)
		}
	}
	routeResource := resourceOfKind(t, input, "kubernetes/httproute")
	if got := routeResource.Attributes["kubernetes/unresolved-references"]; got != `["backend:example.io/Thing:demo/api","parent:apps/Deployment:demo/edge"]` {
		t.Fatalf("unresolved references = %s", got)
	}
	var exposure *graph.SecuritySemantics
	for _, facet := range input.Facets {
		if facet.Resource == ClaimFor("cluster", gateway) && facet.Kind == "network-exposure" {
			exposure, err = graph.DecodeSecuritySemantics(facet.Attributes)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if exposure == nil || exposure.Effect != "unknown" || exposure.State != graph.SecurityStateDeclared || exposure.Scope != "gateway" || exposure.Coverage != "complete" || exposure.ConfigurationDigest == "" {
		t.Fatalf("Gateway exposure semantics = %#v", exposure)
	}
	if len(exposure.Ports) != 1 || exposure.Ports[0] != (graph.SecurityPort{Protocol: "HTTPS", Port: 443}) {
		t.Fatalf("Gateway exposure ports = %#v", exposure.Ports)
	}
	compileInput(t, input)

	withoutRoute, err := Project("cluster", "source", []*unstructured.Unstructured{gateway, service})
	if err != nil {
		t.Fatal(err)
	}
	foundGateway := false
	for _, resource := range withoutRoute.Resources {
		if resource.Kind == "kubernetes/gateway" {
			foundGateway = true
		}
	}
	if !foundGateway {
		t.Fatal("Gateway omitted from covered replay snapshot with no HTTPRoute objects")
	}
}

func TestGatewayExposureDigestIgnoresListenerAndAddressOrder(t *testing.T) {
	listeners := []any{
		map[string]any{"name": "https", "port": int64(443), "protocol": "HTTPS"},
		map[string]any{"name": "http", "port": int64(80), "protocol": "HTTP"},
	}
	addresses := []any{map[string]any{"type": "IPAddress", "value": "192.0.2.2"}, map[string]any{"type": "IPAddress", "value": "192.0.2.1"}}
	digest := func() string {
		gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
			"spec": map[string]any{"gatewayClassName": "prod", "listeners": listeners, "addresses": addresses},
		})
		input, err := Project("cluster", "source", []*unstructured.Unstructured{gateway})
		if err != nil {
			t.Fatal(err)
		}
		semantics, err := graph.DecodeSecuritySemantics(input.Facets[0].Attributes)
		if err != nil {
			t.Fatal(err)
		}
		return semantics.ConfigurationDigest
	}
	before := digest()
	slices.Reverse(listeners)
	slices.Reverse(addresses)
	if after := digest(); before != after {
		t.Fatalf("Gateway reorder changed digest from %s to %s", before, after)
	}
}

func TestProjectGatewayBoundsSecurityDetails(t *testing.T) {
	listeners := make([]any, 0, 70)
	for port := 1; port <= 70; port++ {
		listeners = append(listeners, map[string]any{"name": fmt.Sprintf("listener-%02d", port), "port": int64(port), "protocol": "TCP"})
	}
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
		"spec": map[string]any{"gatewayClassName": "prod", "listeners": listeners},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{gateway})
	if err != nil {
		t.Fatal(err)
	}
	for _, facet := range input.Facets {
		if facet.Resource != ClaimFor("cluster", gateway) || facet.Kind != "network-exposure" {
			continue
		}
		semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		if semantics == nil || semantics.Coverage != "partial" || len(semantics.Ports) != 64 {
			t.Fatalf("bounded Gateway semantics = %#v", semantics)
		}
		compileInput(t, input)
		return
	}
	t.Fatal("Gateway exposure facet not found")
}

func TestGatewayAndHTTPRouteTransportAndBackendPosture(t *testing.T) {
	service := testObject("v1", "Service", "demo", "api", "service", nil)
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{
		"spec": map[string]any{
			"gatewayClassName": "prod",
			"listeners": []any{
				map[string]any{"name": "https", "port": int64(443), "protocol": "HTTPS", "tls": map[string]any{"mode": "Terminate", "certificateRefs": []any{map[string]any{"name": "cert"}}}},
				map[string]any{"name": "http", "port": int64(80), "protocol": "HTTP"},
			},
		},
	})
	route := testObject("gateway.networking.k8s.io/v1", "HTTPRoute", "demo", "api", "route", map[string]any{
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "edge", "sectionName": "https"}},
			"rules": []any{map[string]any{"backendRefs": []any{
				map[string]any{"name": "api", "weight": int64(90)},
				map[string]any{"name": "shadow", "weight": int64(10)},
				map[string]any{"name": "disabled", "weight": int64(0)},
			}}},
		},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{route, gateway, service})
	if err != nil {
		t.Fatal(err)
	}
	foundGateway := false
	foundRoute := false
	foundBackends := false
	for _, facet := range input.Facets {
		switch {
		case facet.Resource == ClaimFor("cluster", gateway) && facet.Kind == "transport-posture":
			foundGateway = true
			semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
			if err != nil || semantics == nil || semantics.Effect != "permit" || facet.Attributes["kubernetes/posture"] != "mixed" {
				t.Fatalf("Gateway transport = %#v, semantics = %#v, err = %v", facet.Attributes, semantics, err)
			}
		case facet.Resource == ClaimFor("cluster", route) && facet.Kind == "transport-posture":
			foundRoute = true
			semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
			if err != nil || semantics == nil || semantics.Effect != "require" || facet.Attributes["kubernetes/posture"] != "tls-only" {
				t.Fatalf("HTTPRoute transport = %#v, semantics = %#v, err = %v", facet.Attributes, semantics, err)
			}
		case facet.Resource == ClaimFor("cluster", route) && facet.Kind == "route-backends":
			foundBackends = true
			if facet.Attributes["kubernetes/active-backend-count"] != "2" || facet.Attributes["kubernetes/resolved-active-backend-count"] != "1" || facet.Attributes["kubernetes/zero-weight-backend-count"] != "1" || facet.Attributes["kubernetes/protection-evaluation"] != "graph-traversal-required" {
				t.Fatalf("HTTPRoute backend posture = %#v", facet.Attributes)
			}
		}
	}
	if !foundGateway || !foundRoute || !foundBackends {
		t.Fatalf("Gateway transport = %t, route transport = %t, backends = %t", foundGateway, foundRoute, foundBackends)
	}
	compileInput(t, input)
}

func TestProjectHTTPRouteCrossNamespaceParent(t *testing.T) {
	namespace := func(name string, labels map[string]any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "Namespace",
			"metadata": map[string]any{"name": name, "uid": "ns-" + name, "labels": labels},
		}}
	}
	gatewayWith := func(namespaces map[string]any) *unstructured.Unstructured {
		listener := map[string]any{"name": "http", "port": int64(80), "protocol": "HTTP"}
		if namespaces != nil {
			listener["allowedRoutes"] = map[string]any{"namespaces": namespaces}
		}
		return testObject("gateway.networking.k8s.io/v1", "Gateway", "gateway-system", "edge", "gateway", map[string]any{
			"spec": map[string]any{"gatewayClassName": "prod", "listeners": []any{listener}},
		})
	}
	route := testObject("gateway.networking.k8s.io/v1", "HTTPRoute", "apps", "hook", "route", map[string]any{
		"spec": map[string]any{"parentRefs": []any{map[string]any{"name": "edge", "namespace": "gateway-system"}}},
	})
	for _, test := range []struct {
		name       string
		namespaces map[string]any
		labels     map[string]any
		attached   bool
	}{
		{name: "from all", namespaces: map[string]any{"from": "All"}, attached: true},
		{name: "default same", namespaces: nil, attached: false},
		{name: "explicit same", namespaces: map[string]any{"from": "Same"}, attached: false},
		{name: "selector match", namespaces: map[string]any{"from": "Selector", "selector": map[string]any{"matchLabels": map[string]any{"edge": "true"}}}, labels: map[string]any{"edge": "true"}, attached: true},
		{name: "selector miss", namespaces: map[string]any{"from": "Selector", "selector": map[string]any{"matchLabels": map[string]any{"edge": "true"}}}, labels: map[string]any{"edge": "false"}, attached: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway := gatewayWith(test.namespaces)
			objects := []*unstructured.Unstructured{namespace("apps", test.labels), namespace("gateway-system", nil), gateway, route}
			input, err := Project("cluster", "source", objects)
			if err != nil {
				t.Fatal(err)
			}
			attached := false
			for _, relationship := range input.Relationships {
				if relationship.Subject == ClaimFor("cluster", route) && relationship.Predicate == graph.PredicateMemberOf && relationship.Object == ClaimFor("cluster", gateway) {
					attached = true
				}
			}
			if attached != test.attached {
				t.Fatalf("member-of attached = %t, want %t", attached, test.attached)
			}
			unresolved := resourceOfKind(t, input, "kubernetes/httproute").Attributes["kubernetes/unresolved-references"]
			if test.attached && unresolved != "" && unresolved != "[]" {
				t.Fatalf("unresolved references = %s", unresolved)
			}
			if !test.attached && unresolved != `["parent:gateway.networking.k8s.io/Gateway:gateway-system/edge"]` {
				t.Fatalf("unresolved references = %s", unresolved)
			}
			compileInput(t, input)
		})
	}
}
