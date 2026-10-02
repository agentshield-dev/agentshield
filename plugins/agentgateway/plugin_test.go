package agentgateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type fakeRuntime struct {
	objects    map[string]chan discovery.Change
	coverage   chan discovery.Change
	outputs    chan discovery.ContributionOutput
	generation uint64
}

func newFakeRuntime() *fakeRuntime {
	runtime := &fakeRuntime{
		objects: make(map[string]chan discovery.Change), coverage: make(chan discovery.Change, 32),
		outputs: make(chan discovery.ContributionOutput, 32), generation: 11,
	}
	for _, requirement := range resourceRequirements {
		runtime.objects[requirement.Collection()] = make(chan discovery.Change, 32)
	}
	return runtime
}

func (runtime *fakeRuntime) Publish(context.Context, discovery.Change) error { return nil }
func (runtime *fakeRuntime) MarkReady(context.Context, string, string, string, uint64) error {
	return nil
}
func (runtime *fakeRuntime) Subscribe(_ context.Context, collection string) (<-chan discovery.Change, error) {
	if changes := runtime.objects[collection]; changes != nil {
		return changes, nil
	}
	if collection == kubernetesplugin.CollectionResourceCoverage {
		return runtime.coverage, nil
	}
	return nil, errors.New("unexpected collection")
}
func (runtime *fakeRuntime) ReplaceContribution(_ context.Context, _, _ string, output discovery.ContributionOutput) error {
	runtime.outputs <- output
	return nil
}
func (runtime *fakeRuntime) ContributionGeneration(context.Context, string, string) (uint64, error) {
	return runtime.generation, nil
}

func TestPluginReplayReadinessGenerationAndDeleteRetraction(t *testing.T) {
	runtime := newFakeRuntime()
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- plugin.Run(ctx, runtime) }()

	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{"spec": map[string]any{"gatewayClassName": DefaultGatewayClass}})
	route := testObject("gateway.networking.k8s.io/v1", "HTTPRoute", "demo", "api", "route", map[string]any{"spec": map[string]any{"parentRefs": []any{map[string]any{"name": "edge"}}}})
	runtime.sendObject(t, gateway, discovery.OperationUpsert, time.Unix(10, 0))
	runtime.sendObject(t, route, discovery.OperationUpsert, time.Unix(11, 0))
	runtime.syncResources(1, time.Unix(12, 0))
	assertNoOutput(t, runtime.outputs)

	coverage := kubernetesplugin.ResourceCoverage{Capability: "gateway-api-v1", GVR: "gateway.networking.k8s.io/v1, Resource=gateways", Advertised: true, Status: kubernetesplugin.CoverageCovered}
	payload, _ := json.Marshal(coverage)
	runtime.coverage <- discovery.Change{Key: "gateway", Operation: discovery.OperationUpsert, Payload: payload, ObservedAt: time.Unix(13, 0)}
	runtime.coverage <- discovery.Change{Generation: 1, Operation: discovery.OperationSync, ObservedAt: time.Unix(14, 0)}
	first := receiveOutput(t, runtime.outputs)
	if first.Generation != 12 || first.Name != "semantics" || first.SourceHealth != "healthy" || !first.Ready {
		t.Fatalf("first output metadata = %#v", first)
	}
	if len(first.Input.Resources) != 2 || len(first.Input.Facets) != 2 || len(first.Input.Relationships) != 1 {
		t.Fatalf("first output resources=%d facets=%d relationships=%d", len(first.Input.Resources), len(first.Input.Facets), len(first.Input.Relationships))
	}

	runtime.sendObject(t, route, discovery.OperationDelete, time.Unix(15, 0))
	runtime.syncResources(2, time.Unix(16, 0))
	runtime.coverage <- discovery.Change{Generation: 2, Operation: discovery.OperationSync, ObservedAt: time.Unix(16, 0)}
	second := receiveOutput(t, runtime.outputs)
	if second.Generation != 13 {
		t.Fatalf("delete generation = %d, want 13", second.Generation)
	}
	for _, resource := range second.Input.Resources {
		if resource.Kind == "kubernetes/httproute" {
			t.Fatal("deleted HTTPRoute remained in replacement contribution")
		}
	}

	close(runtime.objects[collectionFor(resourceRequirements, "gateway.networking.k8s.io", "v1", "httproutes")])
	degraded := receiveOutput(t, runtime.outputs)
	if degraded.Generation != 14 || degraded.SourceHealth != "degraded" {
		t.Fatalf("closure output = generation %d health %q", degraded.Generation, degraded.SourceHealth)
	}
	select {
	case runErr := <-errorsChannel:
		if runErr == nil || !strings.Contains(runErr.Error(), "closed unexpectedly") {
			t.Fatalf("run error = %v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("plugin did not return after subscription closure")
	}
}

func TestGatewayCoverageHealth(t *testing.T) {
	tests := []struct {
		name    string
		records map[string]kubernetesplugin.ResourceCoverage
		want    string
	}{
		{name: "missing", records: nil, want: "degraded"},
		{name: "covered", records: map[string]kubernetesplugin.ResourceCoverage{"gateway": {Capability: "gateway-api-v1", Status: kubernetesplugin.CoverageCovered}}, want: "healthy"},
		{name: "unsupported optional API", records: map[string]kubernetesplugin.ResourceCoverage{"gateway": {Capability: "gateway-api-v1", Status: kubernetesplugin.CoverageUnsupported}}, want: "healthy"},
		{name: "degraded", records: map[string]kubernetesplugin.ResourceCoverage{"gateway": {Capability: "gateway-api-v1", Status: kubernetesplugin.CoverageDegraded}}, want: "degraded"},
		{name: "failed required core API", records: map[string]kubernetesplugin.ResourceCoverage{
			"service": {Capability: "agentgateway-core-v1", Required: true, Status: kubernetesplugin.CoverageFailed},
			"gateway": {Capability: "gateway-api-v1", Status: kubernetesplugin.CoverageCovered},
		}, want: "degraded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := gatewayCoverageHealth(test.records); got != test.want {
				t.Fatalf("gatewayCoverageHealth() = %q, want %q", got, test.want)
			}
		})
	}
}

func objectChange(t *testing.T, item *unstructured.Unstructured, operation discovery.Operation, observedAt time.Time) discovery.Change {
	t.Helper()
	payload, err := json.Marshal(item.UnstructuredContent())
	if err != nil {
		t.Fatal(err)
	}
	return discovery.Change{EventID: "event:" + string(item.GetUID()), Key: projectkit.ObjectKey(item), Operation: operation, ObservedAt: observedAt, Payload: payload}
}

func (runtime *fakeRuntime) sendObject(t *testing.T, item *unstructured.Unstructured, operation discovery.Operation, observedAt time.Time) {
	t.Helper()
	change := objectChange(t, item, operation, observedAt)
	change.Collection = collectionForKind(resourceRequirements, item.GetAPIVersion(), item.GetKind())
	runtime.objects[change.Collection] <- change
}

func (runtime *fakeRuntime) syncResources(generation uint64, observedAt time.Time) {
	for collection, changes := range runtime.objects {
		changes <- discovery.Change{Collection: collection, Generation: generation, Operation: discovery.OperationSync, ObservedAt: observedAt}
	}
}

func collectionFor(requirements []kubernetesplugin.ResourceRequirement, group, version, resource string) string {
	for _, requirement := range requirements {
		if requirement.GVR.Group == group && requirement.GVR.Version == version && requirement.GVR.Resource == resource {
			return requirement.Collection()
		}
	}
	return ""
}

func collectionForKind(requirements []kubernetesplugin.ResourceRequirement, apiVersion, kind string) string {
	resources := map[string]string{
		"Service": "services", "GatewayClass": "gatewayclasses", "Gateway": "gateways", "HTTPRoute": "httproutes",
	}
	group, version := "", apiVersion
	if parts := strings.SplitN(apiVersion, "/", 2); len(parts) == 2 {
		group, version = parts[0], parts[1]
	}
	return collectionFor(requirements, group, version, resources[kind])
}

func receiveOutput(t *testing.T, outputs <-chan discovery.ContributionOutput) discovery.ContributionOutput {
	t.Helper()
	select {
	case output := <-outputs:
		return output
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for contribution output")
		return discovery.ContributionOutput{Input: graph.Input{}}
	}
}

func assertNoOutput(t *testing.T, outputs <-chan discovery.ContributionOutput) {
	t.Helper()
	select {
	case output := <-outputs:
		t.Fatalf("unexpected output before readiness: %#v", output)
	case <-time.After(20 * time.Millisecond):
	}
}
