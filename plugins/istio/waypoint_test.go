package istio

import (
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestWaypointIntentRequiresResolvedReadyGateway(t *testing.T) {
	demo := testObject("v1", "Namespace", "", "demo", "ns-demo", nil)
	demo.SetLabels(map[string]string{"istio.io/dataplane-mode": "ambient", "istio.io/use-waypoint": "namespace-waypoint"})
	inheritedService := testObject("v1", "Service", "demo", "inherited", "svc-inherited", nil)
	directService := testObject("v1", "Service", "demo", "direct", "svc-direct", nil)
	directService.SetLabels(map[string]string{"istio.io/use-waypoint": "direct-waypoint"})
	pod := testObject("v1", "Pod", "demo", "app", "pod", nil)
	pod.SetLabels(map[string]string{"istio.io/use-waypoint": "missing-waypoint"})
	namespaceGateway := readyWaypoint("demo", "namespace-waypoint", "gateway-namespace")
	directGateway := readyWaypoint("demo", "direct-waypoint", "gateway-direct")
	result, err := ProjectObserved(testContext(), testObserved(demo, inheritedService, directService, pod, namespaceGateway, directGateway))
	if err != nil {
		t.Fatal(err)
	}
	resolvedEdges := 0
	missingPod := false
	for _, relation := range result.Input.Relationships {
		if relation.Qualifier == "istio-waypoint" {
			resolvedEdges++
			semantics, err := graph.DecodeSecuritySemantics(relation.Properties)
			if err != nil {
				t.Fatal(err)
			}
			if semantics == nil || semantics.Class != graph.SecurityClassGovernance || semantics.Domain != graph.SecurityDomainNetworkAccess || semantics.State != graph.SecurityStateObserved || semantics.Effect != "unknown" || semantics.Direction != "ingress" || semantics.Coverage != "partial" || semantics.ConfigurationDigest == "" {
				t.Fatalf("waypoint governance semantics = %#v", semantics)
			}
		}
	}
	for _, facet := range result.Input.Facets {
		if facet.Kind != "istio-data-plane" || facet.Key != "ambient" {
			continue
		}
		if _, exists := facet.Attributes["enforcement"]; exists {
			t.Fatalf("waypoint intent claimed enforcement: %#v", facet.Attributes)
		}
		if facet.Resource.ImmutableKey == claimKeyForObject(pod) && facet.Attributes["waypoint-binding"] == "missing" {
			missingPod = true
		}
	}
	if resolvedEdges != 3 {
		t.Fatalf("resolved waypoint edges = %d, want Namespace plus two Services", resolvedEdges)
	}
	if !missingPod {
		t.Fatal("missing waypoint was not represented as unresolved intent")
	}
	compileProjection(t, result, demo, inheritedService, directService, pod, namespaceGateway, directGateway)
}

func TestManagedWaypointPodDoesNotReceiveAmbientTargetFacet(t *testing.T) {
	demo := testObject("v1", "Namespace", "", "demo", "ns-demo", nil)
	demo.SetLabels(map[string]string{"istio.io/dataplane-mode": "ambient"})
	waypointPod := testObject("v1", "Pod", "demo", "waypoint-abc", "waypoint-pod", nil)
	waypointPod.SetLabels(map[string]string{"gateway.networking.k8s.io/gateway-name": "waypoint"})

	result, err := ProjectObserved(testContext(), testObserved(demo, waypointPod))
	if err != nil {
		t.Fatal(err)
	}
	for _, facet := range result.Input.Facets {
		if facet.Kind == "istio-data-plane" && facet.Resource.ImmutableKey == claimKeyForObject(waypointPod) {
			t.Fatalf("managed waypoint Pod received an application ambient facet: %#v", facet)
		}
	}
}

func TestWaypointAcceptedButNotProgrammedIsNotResolved(t *testing.T) {
	demo := testObject("v1", "Namespace", "", "demo", "ns-demo", nil)
	demo.SetLabels(map[string]string{"istio.io/dataplane-mode": "ambient", "istio.io/use-waypoint": "waypoint"})
	service := testObject("v1", "Service", "demo", "api", "svc-api", nil)
	gateway := readyWaypoint("demo", "waypoint", "gateway")
	gateway.Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Accepted", "status": "True"}}}

	result, err := ProjectObserved(testContext(), testObserved(demo, service, gateway))
	if err != nil {
		t.Fatal(err)
	}
	for _, relationship := range result.Input.Relationships {
		if relationship.Qualifier == "istio-waypoint" {
			t.Fatalf("accepted-only waypoint emitted governance edge: %#v", relationship)
		}
	}
	for _, facet := range result.Input.Facets {
		if facet.Resource.ImmutableKey == claimKeyForObject(service) && facet.Attributes["waypoint-binding"] != "not-ready" {
			t.Fatalf("accepted-only waypoint binding = %q, want not-ready", facet.Attributes["waypoint-binding"])
		}
	}
}

func TestWaypointDigestStableAcrossPodRecreation(t *testing.T) {
	demo := testObject("v1", "Namespace", "", "demo", "ns-demo", nil)
	demo.SetLabels(map[string]string{"istio.io/dataplane-mode": "ambient"})
	gateway := readyWaypoint("demo", "waypoint", "gateway")
	gateway.SetLabels(map[string]string{"istio.io/waypoint-for": "all"})
	digestForPod := func(uid string) string {
		pod := testObject("v1", "Pod", "demo", "app", uid, nil)
		pod.SetLabels(map[string]string{"istio.io/use-waypoint": "waypoint"})
		result, err := ProjectObserved(testContext(), testObserved(demo, pod, gateway))
		if err != nil {
			t.Fatal(err)
		}
		for _, relationship := range result.Input.Relationships {
			if relationship.Qualifier != "istio-waypoint" {
				continue
			}
			semantics, err := graph.DecodeSecuritySemantics(relationship.Properties)
			if err != nil {
				t.Fatal(err)
			}
			return semantics.ConfigurationDigest
		}
		t.Fatal("waypoint relationship not found")
		return ""
	}
	before := digestForPod("pod-before")
	after := digestForPod("pod-after")
	if before != after {
		t.Fatalf("Pod recreation changed waypoint digest from %s to %s", before, after)
	}
}

func readyWaypoint(namespace, name, uid string) *unstructured.Unstructured {
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", namespace, name, uid, map[string]any{
		"gatewayClassName": "istio-waypoint",
		"listeners":        []any{map[string]any{"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "Same"}}}},
	})
	gateway.SetLabels(map[string]string{"istio.io/waypoint-for": "service"})
	gateway.Object["status"] = map[string]any{"conditions": []any{map[string]any{"type": "Programmed", "status": "True"}}}
	return gateway
}

func claimKeyForObject(object *unstructured.Unstructured) string {
	return strings.ToLower(object.GetAPIVersion() + "/" + object.GetKind() + "/" + string(object.GetUID()))
}

func TestWaypointBindingWithoutObservedNamespace(t *testing.T) {
	gateway := readyWaypoint("demo", "waypoint", "gateway")
	selectorGateway := readyWaypoint("demo", "selector-waypoint", "gateway-selector")
	selectorGateway.Object["spec"].(map[string]any)["listeners"] = []any{map[string]any{"allowedRoutes": map[string]any{"namespaces": map[string]any{
		"from": "Selector", "selector": map[string]any{"matchLabels": map[string]any{"team": "a"}},
	}}}}
	sameNamespace := testObject("v1", "Service", "demo", "api", "svc-api", nil)
	sameNamespace.SetLabels(map[string]string{"istio.io/use-waypoint": "waypoint"})
	selected := testObject("v1", "Service", "demo", "other", "svc-other", nil)
	selected.SetLabels(map[string]string{"istio.io/use-waypoint": "selector-waypoint"})

	result, err := ProjectObserved(testContext(), testObserved(sameNamespace, selected, gateway, selectorGateway))
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]string{}
	for _, facet := range result.Input.Facets {
		if facet.Kind == "istio-data-plane" && facet.Key == "ambient" {
			bindings[facet.Resource.ImmutableKey] = facet.Attributes["waypoint-binding"]
		}
	}
	// "Same" only needs the namespace name, which the target carries.
	if got := bindings[claimKeyForObject(sameNamespace)]; got != "resolved" {
		t.Fatalf("same-namespace binding = %q, want resolved", got)
	}
	// A selector needs Namespace labels; without the object the answer is unknown.
	if got := bindings[claimKeyForObject(selected)]; got != "coverage-unknown" {
		t.Fatalf("selector binding = %q, want coverage-unknown", got)
	}
}
