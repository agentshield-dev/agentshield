package istio

import (
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func testObject(apiVersion, kind, namespace, name, uid string, spec map[string]any) *unstructured.Unstructured {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion, "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": namespace, "uid": uid, "resourceVersion": "1"},
	}}
	if spec != nil {
		object.Object["spec"] = spec
	}
	return object
}

func testObserved(objects ...*unstructured.Unstructured) []ObservedObject {
	result := make([]ObservedObject, 0, len(objects))
	for _, object := range objects {
		result = append(result, ObservedObject{
			Key: projectkit.ObjectKey(object), Object: object, EventID: "event:" + string(object.GetUID()), Revision: object.GetResourceVersion(),
		})
	}
	return result
}

func testContext() ProjectionContext {
	return ProjectionContext{ClusterID: "cluster", NetworkID: "network", SourceID: "source", RootNamespace: "istio-system", GatewayCoverageKnown: true}
}

func compileProjection(t *testing.T, result ProjectionResult, kubernetesObjects ...*unstructured.Unstructured) graph.Snapshot {
	t.Helper()
	input, err := kubernetesplugin.Project("cluster", "source", kubernetesObjects)
	if err != nil {
		t.Fatal(err)
	}
	input.Resources = append(input.Resources, result.Input.Resources...)
	input.Facets = append(input.Facets, result.Input.Facets...)
	input.Relationships = append(input.Relationships, result.Input.Relationships...)
	registry := graph.NewRegistry()
	if err := registry.Register(kubernetesplugin.IdentitySchemeDefinition()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
