package kubernetes

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestResourceClientUsesScopedCollectionAndDecodesTypedChanges(t *testing.T) {
	type policy struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	requirement := ResourceRequirement{
		GVR:        schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"},
		Capability: "istio-security-v1",
	}
	client, err := NewResourceClient(requirement, func(payload []byte) (*policy, error) {
		result := &policy{}
		return result, json.Unmarshal(payload, result)
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.Collection() != "kubernetes/resources/security.istio.io/v1/authorizationpolicies" {
		t.Fatalf("collection = %q", client.Collection())
	}
	runtime := &resourceClientRuntime{changes: make(chan discovery.Change, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	events, errorsChannel, err := client.Subscribe(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	runtime.changes <- discovery.Change{Collection: client.Collection(), Operation: discovery.OperationUpsert, Payload: json.RawMessage(`{"metadata":{"name":"allow"}}`)}
	event := <-events
	if event.Object == nil || event.Object.Metadata.Name != "allow" {
		t.Fatalf("decoded event = %#v", event)
	}
	cancel()
	close(runtime.changes)
	if err := <-errorsChannel; err != nil {
		t.Fatal(err)
	}
}

type resourceClientRuntime struct {
	changes chan discovery.Change
}

func (*resourceClientRuntime) Publish(context.Context, discovery.Change) error { return nil }
func (runtime *resourceClientRuntime) Subscribe(_ context.Context, collection string) (<-chan discovery.Change, error) {
	return runtime.changes, nil
}
func (*resourceClientRuntime) ReplaceContribution(context.Context, string, string, discovery.ContributionOutput) error {
	return nil
}
func (*resourceClientRuntime) MarkReady(context.Context, string, string, string, uint64) error {
	return nil
}
func (*resourceClientRuntime) ContributionGeneration(context.Context, string, string) (uint64, error) {
	return 0, nil
}
