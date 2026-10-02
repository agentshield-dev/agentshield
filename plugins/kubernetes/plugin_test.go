package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestPublishCoverageIsDeterministicAndExhaustive(t *testing.T) {
	plan, err := resolveInventory(context.Background(), discoveryWithResources(optionalResourceNames()))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &recordingRuntime{}
	plugin := &Plugin{config: Config{SourceID: "source"}}
	if err := plugin.publishCoverage(context.Background(), runtime, plan.coverage, 7); err != nil {
		t.Fatal(err)
	}
	if len(runtime.changes) != len(plan.coverage) {
		t.Fatalf("coverage changes = %d, want %d", len(runtime.changes), len(plan.coverage))
	}
	seen := make(map[string]bool)
	for _, change := range runtime.changes {
		if change.Collection != CollectionResourceCoverage || change.Generation != 7 || change.Operation != discovery.OperationUpsert {
			t.Fatalf("unexpected coverage change: %#v", change)
		}
		if seen[change.Key] {
			t.Fatalf("duplicate coverage key %q", change.Key)
		}
		seen[change.Key] = true
	}
	if runtime.changes[0].Key > runtime.changes[len(runtime.changes)-1].Key {
		t.Fatal("coverage changes are not in deterministic key order")
	}
	if descriptor := plugin.Descriptor(); len(descriptor.Publishes) != len(requiredResourceSpecs)+3 || descriptor.Publishes[0] != CollectionResourceCoverage {
		t.Fatalf("descriptor publications = %v", descriptor.Publishes)
	}
}

func TestDescriptorPublishesRequestedResourceCollection(t *testing.T) {
	requirement := ResourceRequirement{
		GVR:        schema.GroupVersionResource{Group: "foo.example.io", Version: "v1", Resource: "foos"},
		Capability: "foo-v1",
	}
	plugin := &Plugin{config: Config{Resources: []ResourceRequirement{requirement}}}
	found := false
	for _, collection := range plugin.Descriptor().Publishes {
		found = found || collection == requirement.Collection()
	}
	if !found {
		t.Fatalf("descriptor does not publish %q: %v", requirement.Collection(), plugin.Descriptor().Publishes)
	}
}

func TestPublishSanitizesSecretObservationPayload(t *testing.T) {
	item := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": map[string]any{
			"namespace": "default", "name": "credentials", "uid": "secret-uid", "resourceVersion": "7",
			"annotations": map[string]any{"credential": "annotation-secret"}, "labels": map[string]any{"app": "worker"},
		},
		"data": map[string]any{"token": "c2VjcmV0"}, "stringData": map[string]any{"password": "secret"},
	}}
	item.SetUID(types.UID("secret-uid"))
	runtimeRecorder := &recordingRuntime{}
	plugin := &Plugin{config: Config{SourceID: "source"}}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	if err := plugin.publish(context.Background(), runtimeRecorder, gvr, item, discovery.OperationUpsert, 1); err != nil {
		t.Fatal(err)
	}
	if len(runtimeRecorder.changes) != 1 {
		t.Fatalf("published changes = %d, want 1", len(runtimeRecorder.changes))
	}
	// Projectors cite this exact ID, so evidence resolves to the event receipt.
	if got, want := runtimeRecorder.changes[0].EventID, projectkit.KubernetesEvidenceID(item); got != want {
		t.Fatalf("event ID = %s, evidence ID = %s", got, want)
	}
	var payload map[string]any
	if err := json.Unmarshal(runtimeRecorder.changes[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if _, found := payload["data"]; found {
		t.Fatal("Secret data was persisted")
	}
	if _, found := payload["stringData"]; found {
		t.Fatal("Secret stringData was persisted")
	}
	if _, found := payload["type"]; found {
		t.Fatal("Secret body fields were persisted")
	}
	keys, found, err := unstructured.NestedStringSlice(payload, "keys")
	if err != nil {
		t.Fatal(err)
	}
	if !found || !slices.Equal(keys, []string{"password", "token"}) {
		t.Fatalf("Secret keys = %v, want sorted keys-only representation", keys)
	}
	metadata, _, err := unstructured.NestedMap(payload, "metadata")
	if err != nil {
		t.Fatal(err)
	}
	if _, found := metadata["annotations"]; found {
		t.Fatal("Secret annotations were persisted")
	}
	if name, _, _ := unstructured.NestedString(payload, "metadata", "name"); name != "credentials" {
		t.Fatalf("Secret metadata name = %q", name)
	}
	if label, _, _ := unstructured.NestedString(payload, "metadata", "labels", "app"); label != "worker" {
		t.Fatalf("Secret metadata label = %q", label)
	}
}

func TestInformerTransformRemovesManagedFields(t *testing.T) {
	item := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":          "checkout",
			"managedFields": []any{map[string]any{"manager": "kubectl"}},
		},
	}}
	transformed, err := stripManagedFields(item)
	if err != nil {
		t.Fatal(err)
	}
	got := transformed.(*unstructured.Unstructured)
	if len(got.GetManagedFields()) != 0 {
		t.Fatalf("managed fields = %#v", got.GetManagedFields())
	}
	if got.GetName() != "checkout" {
		t.Fatalf("name = %q", got.GetName())
	}
}

func TestRunMarksCollectionsReadyOnlyAfterHandlersPublishInitialList(t *testing.T) {
	const pods = 50
	listKinds := make(map[schema.GroupVersionResource]string)
	for _, spec := range requiredResourceSpecs {
		listKinds[spec.gvr] = spec.gvr.Resource + "List"
	}
	var objects []runtime.Object
	for index := range pods {
		pod := testObject("v1", "Pod", "default", fmt.Sprintf("pod-%02d", index), fmt.Sprintf("pod-uid-%02d", index), map[string]any{"spec": map[string]any{}})
		objects = append(objects, pod)
	}
	plugin, err := New(Config{
		ClusterID: "cluster", SourceID: "source",
		Dynamic:   dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...),
		Discovery: discoveryWithResources(optionalResourceNames()),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	recorder := &readinessRuntime{collection: ResourceRequirement{GVR: schema.GroupVersionResource{Version: "v1", Resource: "pods"}}.Collection(), cancel: cancel}
	if err := plugin.Run(ctx, recorder); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if recorder.upsertsAtReady != pods {
		t.Fatalf("pods published before the collection was marked ready = %d, want %d", recorder.upsertsAtReady, pods)
	}
}

// readinessRuntime slows each publication of collection, so handlers lag the
// informer store, and records how many upserts preceded its first sync.
type readinessRuntime struct {
	recordingRuntime
	collection     string
	cancel         context.CancelFunc
	mu             sync.Mutex
	upserts        int
	upsertsAtReady int
	ready          bool
}

func (runtime *readinessRuntime) Publish(_ context.Context, change discovery.Change) error {
	if change.Collection != runtime.collection {
		return nil
	}
	time.Sleep(5 * time.Millisecond)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.upserts++
	return nil
}

func (runtime *readinessRuntime) MarkReady(_ context.Context, _, _, collection string, _ uint64) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if collection == runtime.collection && !runtime.ready {
		runtime.ready = true
		runtime.upsertsAtReady = runtime.upserts
		runtime.cancel()
	}
	return nil
}

type recordingRuntime struct {
	changes []discovery.Change
}

func (runtime *recordingRuntime) Publish(_ context.Context, change discovery.Change) error {
	runtime.changes = append(runtime.changes, change)
	return nil
}

func (*recordingRuntime) MarkReady(context.Context, string, string, string, uint64) error {
	return nil
}

func (*recordingRuntime) Subscribe(context.Context, string) (<-chan discovery.Change, error) {
	return nil, nil
}

func (*recordingRuntime) ReplaceContribution(context.Context, string, string, discovery.ContributionOutput) error {
	return nil
}

func (*recordingRuntime) ContributionGeneration(context.Context, string, string) (uint64, error) {
	return 0, nil
}
