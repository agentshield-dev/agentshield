package kgateway

import (
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

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

func kgw(kind, namespace, name string, spec map[string]any) *unstructured.Unstructured {
	return testObject(kgatewayAPIVersion, kind, namespace, name, "uid-"+kind+"-"+namespace+"-"+name, map[string]any{"spec": spec})
}

func gatewayClassObject(name, controller string, parametersRef map[string]any) *unstructured.Unstructured {
	spec := map[string]any{"controllerName": controller}
	if parametersRef != nil {
		spec["parametersRef"] = parametersRef
	}
	return testObject(gatewayAPIVersion, "GatewayClass", "", name, "uid-class-"+name, map[string]any{"spec": spec})
}

func gatewayObject(namespace, name, class string) *unstructured.Unstructured {
	return testObject(gatewayAPIVersion, "Gateway", namespace, name, "uid-gateway-"+namespace+"-"+name, map[string]any{
		"spec": map[string]any{"gatewayClassName": class, "listeners": []any{map[string]any{"name": "http", "port": int64(80), "protocol": "HTTP"}}},
	})
}

func routeObject(namespace, name string, labels map[string]any, rules ...any) *unstructured.Unstructured {
	route := testObject(gatewayAPIVersion, "HTTPRoute", namespace, name, "uid-route-"+namespace+"-"+name, map[string]any{
		"spec": map[string]any{"parentRefs": []any{map[string]any{"name": "edge", "namespace": "kgateway-system"}}, "rules": rules},
	})
	if labels != nil {
		route.Object["metadata"].(map[string]any)["labels"] = labels
	}
	return route
}

func serviceObject(namespace, name string) *unstructured.Unstructured {
	return testObject("v1", "Service", namespace, name, "uid-service-"+namespace+"-"+name, map[string]any{"spec": map[string]any{"ports": []any{map[string]any{"port": int64(80)}}}})
}

func serviceRule(service string) map[string]any {
	return map[string]any{"backendRefs": []any{map[string]any{"name": service, "port": int64(80)}}}
}

func targetRef(kind, name string) map[string]any {
	group := gatewayAPIGroup
	if kind == "Service" {
		group = ""
	}
	if kind == kindBackend {
		group = kgatewayGroup
	}
	return map[string]any{"group": group, "kind": kind, "name": name}
}

func observed(item *unstructured.Unstructured, eventID string) ObservedObject {
	return ObservedObject{Key: projectkit.ObjectKey(item), Object: item, EventID: eventID, Revision: item.GetResourceVersion()}
}

func allCovered() map[string]CoverageState {
	result := map[string]CoverageState{}
	for _, requirement := range resourceRequirements {
		result[requirement.Capability] = CoverageStateCovered
	}
	return result
}

func mustProject(t *testing.T, objects ...*unstructured.Unstructured) ProjectionResult {
	t.Helper()
	observations := make([]ObservedObject, 0, len(objects))
	for _, object := range objects {
		observations = append(observations, observed(object, projectkit.KubernetesEvidenceID(object)))
	}
	result, err := ProjectObserved(ProjectionContext{ClusterID: "cluster", SourceID: "source", Coverage: allCovered()}, observations)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func claimOf(item *unstructured.Unstructured) graph.IdentityClaim {
	return kubernetesplugin.ClaimFor("cluster", item)
}

func relationshipsBetween(input graph.Input, subject *unstructured.Unstructured, predicate graph.Predicate, object graph.IdentityClaim) []graph.RelationshipAssertion {
	var result []graph.RelationshipAssertion
	for _, relationship := range input.Relationships {
		if relationship.Subject == claimOf(subject) && relationship.Predicate == predicate && relationship.Object == object {
			result = append(result, relationship)
		}
	}
	return result
}

func facetOf(input graph.Input, item *unstructured.Unstructured, kind string) (graph.FacetAssertion, bool) {
	for _, facet := range input.Facets {
		if facet.Resource == claimOf(item) && facet.Kind == kind {
			return facet, true
		}
	}
	return graph.FacetAssertion{}, false
}

func mustSemantics(t *testing.T, attributes map[string]string) *graph.SecuritySemantics {
	t.Helper()
	semantics, err := graph.DecodeSecuritySemantics(attributes)
	if err != nil {
		t.Fatal(err)
	}
	if semantics == nil {
		t.Fatalf("no security semantics in %#v", attributes)
	}
	return semantics
}

func hasDiagnostic(result ProjectionResult, code string) bool {
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}
