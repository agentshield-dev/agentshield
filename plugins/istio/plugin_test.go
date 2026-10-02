package istio

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type fakeRuntime struct {
	resources  map[string]chan discovery.Change
	coverage   chan discovery.Change
	outputs    chan discovery.ContributionOutput
	ready      chan uint64
	generation uint64
	mu         sync.Mutex
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		resources: make(map[string]chan discovery.Change), coverage: make(chan discovery.Change, 32),
		outputs: make(chan discovery.ContributionOutput, 32), ready: make(chan uint64, 32), generation: 7,
	}
}

func (runtime *fakeRuntime) Publish(context.Context, discovery.Change) error { return nil }
func (runtime *fakeRuntime) Subscribe(_ context.Context, collection string) (<-chan discovery.Change, error) {
	if collection == collectionResourceCoverage {
		return runtime.coverage, nil
	}
	return runtime.resource(collection), nil
}
func (runtime *fakeRuntime) ReplaceContribution(_ context.Context, _, _ string, output discovery.ContributionOutput) error {
	runtime.outputs <- output
	return nil
}
func (runtime *fakeRuntime) MarkReady(_ context.Context, _, _, _ string, generation uint64) error {
	runtime.ready <- generation
	return nil
}
func (runtime *fakeRuntime) ContributionGeneration(context.Context, string, string) (uint64, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.generation, nil
}

func (runtime *fakeRuntime) resource(collection string) chan discovery.Change {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	changes := runtime.resources[collection]
	if changes == nil {
		changes = make(chan discovery.Change, 32)
		runtime.resources[collection] = changes
	}
	return changes
}

func TestPluginWaitsForObjectsAndCoverageAndPublishesHealth(t *testing.T) {
	runtime := newFakeRuntime()
	plugin, err := New(Config{ClusterID: "cluster", NetworkID: "network", SourceID: "source"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- plugin.Run(ctx, runtime) }()

	serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "demo", "external", "se", map[string]any{"hosts": []any{"external.example.com"}})
	payload, err := json.Marshal(serviceEntry.Object)
	if err != nil {
		t.Fatal(err)
	}
	objectsAt := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	coverageAt := objectsAt.Add(time.Minute)
	serviceEntries := kubernetesplugin.ResourceRequirement{
		GVR: schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "serviceentries"},
	}.Collection()
	runtime.resource(serviceEntries) <- discovery.Change{
		EventID: "native:serviceentry", Collection: serviceEntries, Key: "se", Generation: 1, Operation: discovery.OperationUpsert,
		ObservedAt: objectsAt, Payload: payload,
	}
	syncIstioResources(runtime, plugin, 1, objectsAt)
	select {
	case output := <-runtime.outputs:
		t.Fatalf("published before coverage sync: %#v", output)
	case <-time.After(20 * time.Millisecond):
	}

	records := coverageEnvelope{Resources: []coverageRecord{
		{GVR: "security.istio.io/v1, Resource=authorizationpolicies", Capability: "istio-security-v1", Advertised: true, Status: kubernetesplugin.CoverageCovered},
		{GVR: "security.istio.io/v1, Resource=peerauthentications", Capability: "istio-security-v1", Advertised: true, Status: kubernetesplugin.CoverageCovered},
		{GVR: "networking.istio.io/v1, Resource=serviceentries", Capability: "istio-networking-v1", Advertised: true, Status: kubernetesplugin.CoverageCovered},
		{GVR: "networking.istio.io/v1, Resource=virtualservices", Capability: "istio-networking-v1", Advertised: true, Status: kubernetesplugin.CoverageCovered},
		{GVR: "gateway.networking.k8s.io/v1, Resource=gateways", Capability: "istio-gateway-v1", Status: kubernetesplugin.CoverageUnsupported},
	}}
	coveragePayload, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	runtime.coverage <- discovery.Change{EventID: "coverage:initial", Collection: collectionResourceCoverage, Key: "coverage", Operation: discovery.OperationUpsert, Payload: coveragePayload, ObservedAt: coverageAt}
	runtime.coverage <- discovery.Change{Collection: collectionResourceCoverage, Key: "sync", Generation: 1, Operation: discovery.OperationSync, ObservedAt: coverageAt}
	first := receiveOutput(t, runtime.outputs)
	if first.Generation != 8 || first.SourceHealth != "healthy" || !first.SourceObservedAt.Equal(coverageAt) {
		t.Fatalf("first output metadata = generation %d health %q observed %s", first.Generation, first.SourceHealth, first.SourceObservedAt)
	}
	foundNativeEvidence := false
	for _, resource := range first.Input.Resources {
		for _, evidence := range resource.EvidenceIDs {
			foundNativeEvidence = foundNativeEvidence || evidence == "native:serviceentry"
		}
	}
	if !foundNativeEvidence {
		t.Fatal("native event ID was not preserved in projected evidence")
	}

	runtime.resource(serviceEntries) <- discovery.Change{EventID: "native:serviceentry:delete", Collection: serviceEntries, Key: "se", Generation: 2, Operation: discovery.OperationDelete, ObservedAt: coverageAt.Add(time.Minute)}
	runtime.resource(serviceEntries) <- discovery.Change{Collection: serviceEntries, Key: "sync", Generation: 2, Operation: discovery.OperationSync, ObservedAt: coverageAt.Add(time.Minute)}
	runtime.resource(serviceEntries) <- discovery.Change{
		EventID: "native:serviceentry:future", Collection: serviceEntries, Key: "se", Generation: 2, Operation: discovery.OperationUpsert,
		ObservedAt: coverageAt.Add(2 * time.Minute), Payload: payload,
	}
	for _, client := range plugin.resources {
		if client.Collection() != serviceEntries {
			runtime.resource(client.Collection()) <- discovery.Change{
				Collection: client.Collection(), Key: "sync", Generation: 2, Operation: discovery.OperationSync, ObservedAt: coverageAt.Add(time.Minute),
			}
		}
	}
	assertNoOutput(t, runtime.outputs, "published generation 2 before coverage sync")
	runtime.coverage <- discovery.Change{Collection: collectionResourceCoverage, Key: "sync", Generation: 2, Operation: discovery.OperationSync, ObservedAt: coverageAt.Add(time.Minute)}
	second := receiveOutput(t, runtime.outputs)
	if second.Generation != 9 {
		t.Fatalf("delete generation = %d, want 9", second.Generation)
	}
	for _, resource := range second.Input.Resources {
		if resource.Kind == "istio/serviceentry" || resource.Kind == "network/destination" {
			t.Fatalf("deleted ServiceEntry remained in replacement: %#v", resource)
		}
	}
	syncIstioResources(runtime, plugin, 3, coverageAt.Add(2*time.Minute))
	runtime.coverage <- discovery.Change{Collection: collectionResourceCoverage, Key: "sync", Generation: 3, Operation: discovery.OperationSync, ObservedAt: coverageAt.Add(2 * time.Minute)}
	third := receiveOutput(t, runtime.outputs)
	foundServiceEntry := false
	for _, resource := range third.Input.Resources {
		foundServiceEntry = foundServiceEntry || resource.Kind == "istio/serviceentry"
	}
	if !foundServiceEntry {
		t.Fatal("post-sync ServiceEntry update was not published at the next coherent generation")
	}

	records.Resources[4].Status = kubernetesplugin.CoverageDegraded
	coveragePayload, _ = json.Marshal(records)
	runtime.coverage <- discovery.Change{EventID: "coverage:forbidden", Collection: collectionResourceCoverage, Key: "coverage", Operation: discovery.OperationUpsert, Payload: coveragePayload, ObservedAt: coverageAt.Add(2 * time.Minute)}
	runtime.coverage <- discovery.Change{Collection: collectionResourceCoverage, Key: "sync", Generation: 4, Operation: discovery.OperationSync, ObservedAt: coverageAt.Add(3 * time.Minute)}
	assertNoOutput(t, runtime.outputs, "published generation 4 before object sync")
	syncIstioResources(runtime, plugin, 4, coverageAt.Add(3*time.Minute))
	fourth := receiveOutput(t, runtime.outputs)
	if fourth.Generation != 11 || fourth.SourceHealth != "degraded" {
		t.Fatalf("degraded output = generation %d health %q", fourth.Generation, fourth.SourceHealth)
	}

	close(runtime.coverage)
	closure := receiveOutput(t, runtime.outputs)
	if closure.Generation != 12 || closure.SourceHealth != "degraded" {
		t.Fatalf("closure output = generation %d health %q", closure.Generation, closure.SourceHealth)
	}
	select {
	case runErr := <-errorsChannel:
		if runErr == nil || !strings.Contains(runErr.Error(), "closed unexpectedly") {
			t.Fatalf("closure error = %v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("plugin did not return after subscription closure")
	}
}

// coverageEnvelope is the multi-record coverage payload form the shared
// consumer cache also accepts.
type coverageEnvelope struct {
	Resources []coverageRecord `json:"resources"`
}

func assertNoOutput(t *testing.T, outputs <-chan discovery.ContributionOutput, message string) {
	t.Helper()
	select {
	case output := <-outputs:
		t.Fatalf("%s: %#v", message, output)
	case <-time.After(20 * time.Millisecond):
	}
}

func syncIstioResources(runtime *fakeRuntime, plugin *Plugin, generation uint64, observedAt time.Time) {
	for _, client := range plugin.resources {
		runtime.resource(client.Collection()) <- discovery.Change{
			Collection: client.Collection(), Key: "sync", Generation: generation, Operation: discovery.OperationSync, ObservedAt: observedAt,
		}
	}
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
