package cilium

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

func TestPluginReplayReadinessRetractionAndCoverageHealth(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster-a", SourceID: "cilium-a"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := newFakeRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- plugin.Run(ctx, runtime) }()

	pod := object("v1", "Pod", "shop", "frontend", "pod-1", nil)
	endpoint := object("cilium.io/v2", "CiliumEndpoint", "shop", "frontend", "endpoint-1", map[string]any{"status": map[string]any{"state": "ready"}})
	runtime.sendObject(t, "pod", "pod-event", pod)
	runtime.sendObject(t, "endpoint", "endpoint-event", endpoint)
	runtime.syncResources(1)
	select {
	case output := <-runtime.outputs:
		t.Fatalf("published before coverage readiness: %#v", output)
	case <-time.After(20 * time.Millisecond):
	}

	coverage := kubernetesplugin.ResourceCoverage{Capability: "cilium-endpoint-v2", GVR: "cilium.io/v2, Resource=ciliumendpoints", Advertised: true, Status: kubernetesplugin.CoverageCovered}
	runtime.coverage <- coverageChange(t, "endpoint-coverage", coverage)
	runtime.coverage <- discovery.Change{Collection: kubernetesplugin.CollectionResourceCoverage, Generation: 1, Operation: discovery.OperationSync, ObservedAt: time.Now().UTC()}
	initial := receiveContribution(t, runtime.outputs)
	if initial.Generation != 10 || initial.SourceHealth != "healthy" || len(initial.Input.Facets) != 1 {
		t.Fatalf("initial contribution = %#v", initial)
	}

	coverage.Status = kubernetesplugin.CoverageDegraded
	runtime.coverage <- coverageChange(t, "endpoint-coverage", coverage)
	endpointCollection := collectionFor(ciliumResourceRequirements, "cilium.io", "v2", "ciliumendpoints")
	runtime.objects[endpointCollection] <- discovery.Change{Collection: endpointCollection, Key: "endpoint", Operation: discovery.OperationDelete}
	runtime.syncResources(2)
	runtime.coverage <- discovery.Change{Collection: kubernetesplugin.CollectionResourceCoverage, Generation: 2, Operation: discovery.OperationSync, ObservedAt: time.Now().UTC()}
	replacement := receiveContribution(t, runtime.outputs)
	if replacement.Generation != 11 || replacement.SourceHealth != "degraded" || len(replacement.Input.Facets) != 0 {
		t.Fatalf("replacement contribution = %#v", replacement)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if descriptor := plugin.Descriptor(); descriptor.ID != PluginID || len(descriptor.Consumes) != len(ciliumResourceRequirements)+1 || descriptor.Publishes[0] != CollectionProjection {
		t.Fatalf("descriptor = %#v", descriptor)
	}
}

func TestCiliumCoverageHealthDistinguishesUnsupportedAndDegraded(t *testing.T) {
	coverage := map[string]kubernetesplugin.ResourceCoverage{
		"endpoint": {Capability: "cilium-endpoint-v2", Status: kubernetesplugin.CoverageUnsupported},
	}
	if health := ciliumCoverageHealth(coverage); health != "healthy" {
		t.Fatalf("unsupported coverage health = %q", health)
	}
	coverage["endpoint"] = kubernetesplugin.ResourceCoverage{Capability: "cilium-endpoint-v2", Advertised: true, Status: kubernetesplugin.CoverageDegraded}
	if health := ciliumCoverageHealth(coverage); health != "degraded" {
		t.Fatalf("degraded coverage health = %q", health)
	}
	coverage = map[string]kubernetesplugin.ResourceCoverage{
		"pod": {Capability: "core", Required: true, Status: kubernetesplugin.CoverageFailed},
	}
	if health := ciliumCoverageHealth(coverage); health != "degraded" {
		t.Fatalf("failed required coverage health = %q", health)
	}
}

type fakeRuntime struct {
	objects  map[string]chan discovery.Change
	coverage chan discovery.Change
	outputs  chan discovery.ContributionOutput
	ready    chan uint64
}

func newFakeRuntime() *fakeRuntime {
	runtime := &fakeRuntime{
		objects: make(map[string]chan discovery.Change), coverage: make(chan discovery.Change, 16),
		outputs: make(chan discovery.ContributionOutput, 16), ready: make(chan uint64, 16),
	}
	for _, requirement := range ciliumResourceRequirements {
		runtime.objects[requirement.Collection()] = make(chan discovery.Change, 16)
	}
	return runtime
}

func (*fakeRuntime) Publish(context.Context, discovery.Change) error { return nil }

func (runtime *fakeRuntime) MarkReady(_ context.Context, _, _, _ string, generation uint64) error {
	runtime.ready <- generation
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

func (*fakeRuntime) ContributionGeneration(context.Context, string, string) (uint64, error) {
	return 9, nil
}

func (runtime *fakeRuntime) sendObject(t *testing.T, key, eventID string, item interface {
	UnstructuredContent() map[string]any
	GetAPIVersion() string
	GetKind() string
}) {
	t.Helper()
	payload, err := json.Marshal(item.UnstructuredContent())
	if err != nil {
		t.Fatal(err)
	}
	collection := collectionForKind(ciliumResourceRequirements, item.GetAPIVersion(), item.GetKind())
	runtime.objects[collection] <- discovery.Change{EventID: eventID, Collection: collection, Key: key, Operation: discovery.OperationUpsert, Payload: payload, ObservedAt: time.Now().UTC()}
}

func (runtime *fakeRuntime) syncResources(generation uint64) {
	for collection, changes := range runtime.objects {
		changes <- discovery.Change{Collection: collection, Generation: generation, Operation: discovery.OperationSync, ObservedAt: time.Now().UTC()}
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
		"Pod": "pods", "Node": "nodes", "CiliumNetworkPolicy": "ciliumnetworkpolicies",
		"CiliumClusterwideNetworkPolicy": "ciliumclusterwidenetworkpolicies", "CiliumEndpoint": "ciliumendpoints", "CiliumNode": "ciliumnodes",
	}
	group, version := "", apiVersion
	if parts := strings.SplitN(apiVersion, "/", 2); len(parts) == 2 {
		group, version = parts[0], parts[1]
	}
	return collectionFor(requirements, group, version, resources[kind])
}

func coverageChange(t *testing.T, key string, coverage kubernetesplugin.ResourceCoverage) discovery.Change {
	t.Helper()
	payload, err := json.Marshal(coverage)
	if err != nil {
		t.Fatal(err)
	}
	return discovery.Change{EventID: "coverage:" + key, Collection: kubernetesplugin.CollectionResourceCoverage, Key: key, Operation: discovery.OperationUpsert, Payload: payload, ObservedAt: time.Now().UTC()}
}

func receiveContribution(t *testing.T, outputs <-chan discovery.ContributionOutput) discovery.ContributionOutput {
	t.Helper()
	select {
	case output := <-outputs:
		return output
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Cilium contribution")
		return discovery.ContributionOutput{Input: graph.Input{}}
	}
}
