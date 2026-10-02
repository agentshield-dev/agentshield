package coherentcache

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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type fakeRuntime struct {
	mu          sync.Mutex
	collections map[string]chan discovery.Change
	outputs     chan discovery.ContributionOutput
	ready       chan uint64
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{collections: make(map[string]chan discovery.Change), outputs: make(chan discovery.ContributionOutput, 8), ready: make(chan uint64, 8)}
}

func (r *fakeRuntime) channel(collection string) chan discovery.Change {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.collections[collection] == nil {
		r.collections[collection] = make(chan discovery.Change, 16)
	}
	return r.collections[collection]
}

func (r *fakeRuntime) Publish(context.Context, discovery.Change) error { return nil }
func (r *fakeRuntime) MarkReady(_ context.Context, _, _, _ string, generation uint64) error {
	r.ready <- generation
	return nil
}
func (r *fakeRuntime) Subscribe(_ context.Context, collection string) (<-chan discovery.Change, error) {
	return r.channel(collection), nil
}
func (r *fakeRuntime) ReplaceContribution(_ context.Context, _, _ string, output discovery.ContributionOutput) error {
	r.outputs <- output
	return nil
}
func (r *fakeRuntime) ContributionGeneration(context.Context, string, string) (uint64, error) {
	return 4, nil
}

func TestRunPublishesOnlyCoherentSnapshots(t *testing.T) {
	var clients []*kubernetesplugin.ResourceClient[*unstructured.Unstructured]
	for _, resource := range []string{"pods", "services"} {
		client, err := kubernetesplugin.NewUnstructuredResourceClient(kubernetesplugin.ResourceRequirement{
			GVR: schema.GroupVersionResource{Version: "v1", Resource: resource}, Capability: "core", Required: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
	}
	pods, services, coverage := clients[0].Collection(), clients[1].Collection(), kubernetesplugin.CollectionResourceCoverage
	runtime := newFakeRuntime()
	var coherentSizes []int
	var mu sync.Mutex
	config := Config{
		PluginID: "test", SourceID: "source", Contribution: "semantics", Resources: clients, ReadyCollection: "test/projection",
		OnObjects: func(objects map[string]Object) {
			mu.Lock()
			defer mu.Unlock()
			coherentSizes = append(coherentSizes, len(objects))
		},
		Project: func(snapshot Snapshot) (graph.Input, string, error) {
			health := "healthy"
			for _, record := range snapshot.Coverage {
				if record.Status != kubernetesplugin.CoverageCovered {
					health = "degraded"
				}
			}
			var input graph.Input
			for _, object := range snapshot.Objects {
				input.Resources = append(input.Resources, graph.ResourceAssertion{Kind: object.Object.GetKind(), EvidenceIDs: []string{object.EventID}})
			}
			return input, health, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, runtime, config) }()

	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	pod, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "a", "uid": "a"}})
	record, _ := json.Marshal(kubernetesplugin.ResourceCoverage{Capability: "core", GVR: "pods", Required: true, Status: kubernetesplugin.CoverageCovered})
	syncAt := func(collection string, generation uint64, observedAt time.Time) {
		runtime.channel(collection) <- discovery.Change{Collection: collection, Key: "sync", Generation: generation, Operation: discovery.OperationSync, ObservedAt: observedAt}
	}
	runtime.channel(pods) <- discovery.Change{EventID: "pod-a", Collection: pods, Key: "a", Generation: 1, Operation: discovery.OperationUpsert, Payload: pod, ObservedAt: at}
	runtime.channel(coverage) <- discovery.Change{EventID: "coverage", Collection: coverage, Key: "core/pods", Operation: discovery.OperationUpsert, Payload: record, ObservedAt: at}
	syncAt(pods, 1, at)
	syncAt(coverage, 1, at)
	// Services has not synced at generation 1, so nothing is coherent yet.
	expectNoOutput(t, runtime.outputs)
	syncAt(services, 1, at.Add(time.Second))
	first := expectOutput(t, runtime.outputs)
	if first.Generation != 5 || first.SourceHealth != "healthy" || len(first.Input.Resources) != 1 || !first.SourceObservedAt.Equal(at.Add(time.Second)) {
		t.Fatalf("first output = %#v", first)
	}
	if ready := <-runtime.ready; ready != 5 {
		t.Fatalf("ready generation = %d", ready)
	}

	// A coverage upsert after its sync belongs to the next generation: it
	// changes neither the published health nor the observation time.
	degraded, _ := json.Marshal(kubernetesplugin.ResourceCoverage{Capability: "core", GVR: "pods", Required: true, Status: kubernetesplugin.CoverageDegraded})
	runtime.channel(pods) <- discovery.Change{EventID: "pod-a-delete", Collection: pods, Key: "a", Generation: 2, Operation: discovery.OperationDelete, ObservedAt: at.Add(time.Minute)}
	syncAt(pods, 2, at.Add(time.Minute))
	syncAt(services, 2, at.Add(time.Minute))
	syncAt(coverage, 2, at.Add(time.Minute))
	runtime.channel(coverage) <- discovery.Change{EventID: "coverage-2", Collection: coverage, Key: "core/pods", Operation: discovery.OperationUpsert, Payload: degraded, ObservedAt: at.Add(time.Hour)}
	second := expectOutput(t, runtime.outputs)
	if second.Generation != 6 || second.SourceHealth != "healthy" || len(second.Input.Resources) != 0 || !second.SourceObservedAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("second output = %#v", second)
	}
	<-runtime.ready

	// Unexpected closure republishes the last snapshot as degraded.
	close(runtime.channel(coverage))
	closure := expectOutput(t, runtime.outputs)
	if closure.Generation != 7 || closure.SourceHealth != "degraded" {
		t.Fatalf("closure output = %#v", closure)
	}
	if err := <-result; err == nil || !strings.Contains(err.Error(), "closed unexpectedly") {
		t.Fatalf("Run error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(coherentSizes) != 2 || coherentSizes[0] != 1 || coherentSizes[1] != 0 {
		t.Fatalf("coherent object set sizes = %v", coherentSizes)
	}
}

func TestDecodeCoverageAcceptsRecordAndEnvelope(t *testing.T) {
	records, err := decodeCoverage([]byte(`{"capability":"core","gvr":"pods","status":"covered"}`))
	if err != nil || len(records) != 1 || coverageKey(records[0]) != "core/pods" {
		t.Fatalf("single record = %#v, err = %v", records, err)
	}
	records, err = decodeCoverage([]byte(`{"resources":[{"capability":"a","gvr":"x"}],"coverage":[{"capability":"b","gvr":"y"}]}`))
	if err != nil || len(records) != 2 {
		t.Fatalf("envelope = %#v, err = %v", records, err)
	}
}

func TestPublishSkipsUnchangedProjection(t *testing.T) {
	runtime := newFakeRuntime()
	cache := cache{
		config: Config{
			PluginID: "test", SourceID: "source", Contribution: "semantics",
			Project: func(Snapshot) (graph.Input, string, error) {
				return graph.Input{Resources: []graph.ResourceAssertion{{Kind: "test/resource"}}}, "healthy", nil
			},
		},
		runtime: runtime, objectGeneration: 1, coverageGeneration: 1,
	}
	if err := cache.publish(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := cache.publish(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	first := expectOutput(t, runtime.outputs)
	if first.Generation != 1 {
		t.Fatalf("generation = %d, want 1", first.Generation)
	}
	expectNoOutput(t, runtime.outputs)
}

func expectOutput(t *testing.T, outputs <-chan discovery.ContributionOutput) discovery.ContributionOutput {
	t.Helper()
	select {
	case output := <-outputs:
		return output
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for output")
		return discovery.ContributionOutput{}
	}
}

func expectNoOutput(t *testing.T, outputs <-chan discovery.ContributionOutput) {
	t.Helper()
	select {
	case output := <-outputs:
		t.Fatalf("unexpected output %#v", output)
	case <-time.After(20 * time.Millisecond):
	}
}
