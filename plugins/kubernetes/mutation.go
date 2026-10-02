package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// ResourceReader is the read subset of a dynamic resource client.
type ResourceReader interface {
	Get(context.Context, string, metav1.GetOptions, ...string) (*unstructured.Unstructured, error)
	List(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

// ResourceWriter adds the create and update calls remediation uses.
// Remediation never patches or deletes provider objects.
type ResourceWriter interface {
	ResourceReader
	Create(context.Context, *unstructured.Unstructured, metav1.CreateOptions, ...string) (*unstructured.Unstructured, error)
	Update(context.Context, *unstructured.Unstructured, metav1.UpdateOptions, ...string) (*unstructured.Unstructured, error)
}

// ReadTransport opens readers for a GVR in a namespace, or cluster-scoped
// when namespace is empty.
type ReadTransport interface {
	ReadResource(schema.GroupVersionResource, string) ResourceReader
}

// WriteTransport is shared by the Kubernetes, Istio, and Cilium remediation
// actions so all writes go through one client and can be faked in tests.
type WriteTransport interface {
	ReadTransport
	WriteResource(schema.GroupVersionResource, string) ResourceWriter
}

// DynamicTransport implements [WriteTransport] with a dynamic client.
type DynamicTransport struct {
	client dynamic.Interface
}

// NewDynamicTransport wraps client.
func NewDynamicTransport(client dynamic.Interface) (*DynamicTransport, error) {
	if client == nil {
		return nil, errors.New("Kubernetes action transport requires a dynamic client")
	}
	return &DynamicTransport{client: client}, nil
}

// ReadResource implements [ReadTransport].
func (transport *DynamicTransport) ReadResource(resource schema.GroupVersionResource, namespace string) ResourceReader {
	return namespacedResource(transport.client, resource, namespace)
}

// WriteResource implements [WriteTransport].
func (transport *DynamicTransport) WriteResource(resource schema.GroupVersionResource, namespace string) ResourceWriter {
	return namespacedResource(transport.client, resource, namespace)
}

func namespacedResource(client dynamic.Interface, resource schema.GroupVersionResource, namespace string) dynamic.ResourceInterface {
	if namespace == "" {
		return client.Resource(resource)
	}
	return client.Resource(resource).Namespace(namespace)
}

// ActionObservation records the provider state a remediation step observed
// for one object. ControlledSHA256 digests only the fields the action
// controls, so unrelated changes do not invalidate a plan.
type ActionObservation struct {
	Resource         string `json:"resource"`
	Namespace        string `json:"namespace,omitempty"`
	Name             string `json:"name"`
	Exists           bool   `json:"exists"`
	UID              string `json:"uid,omitempty"`
	ResourceVersion  string `json:"resourceVersion,omitempty"`
	ControlledSHA256 string `json:"controlledSha256,omitempty"`
}

// ProviderState encodes the current and prepared observations of one object
// in canonical JSON for a remediation preparation or result.
func ProviderState(key string, current, prepared ActionObservation) (remediation.ProviderState, error) {
	currentJSON, err := canonicalObservationJSON(current)
	if err != nil {
		return remediation.ProviderState{}, fmt.Errorf("encode current Kubernetes action observation: %w", err)
	}
	preparedJSON, err := canonicalObservationJSON(prepared)
	if err != nil {
		return remediation.ProviderState{}, fmt.Errorf("encode prepared Kubernetes action observation: %w", err)
	}
	return remediation.ProviderState{Key: key, Current: currentJSON, Prepared: preparedJSON}, nil
}

func canonicalObservationJSON(observation ActionObservation) ([]byte, error) {
	encoded, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	var canonical any
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

// DecodeProviderState reverses [ProviderState].
func DecodeProviderState(state remediation.ProviderState) (ActionObservation, ActionObservation, error) {
	var current, prepared ActionObservation
	if err := json.Unmarshal(state.Current, &current); err != nil {
		return current, prepared, fmt.Errorf("decode current Kubernetes action observation %q: %w", state.Key, err)
	}
	if err := json.Unmarshal(state.Prepared, &prepared); err != nil {
		return current, prepared, fmt.Errorf("decode prepared Kubernetes action observation %q: %w", state.Key, err)
	}
	return current, prepared, nil
}

// ControlledDigest digests the fields of an object that an action controls.
type ControlledDigest func(*unstructured.Unstructured) (string, error)

// UpdatePodLabel updates desired, optionally as a server-side dry run, and
// fails if admission changed any controlled field or the UID. operation
// prefixes the update error.
func UpdatePodLabel(ctx context.Context, transport WriteTransport, resource schema.GroupVersionResource, desired *unstructured.Unstructured, nativeDryRun bool, digest ControlledDigest, operation string) (*unstructured.Unstructured, error) {
	options := metav1.UpdateOptions{}
	if nativeDryRun {
		options.DryRun = []string{metav1.DryRunAll}
	}
	updated, err := transport.WriteResource(resource, desired.GetNamespace()).Update(ctx, desired.DeepCopy(), options)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	want, err := digest(desired)
	if err != nil {
		return nil, err
	}
	got, err := digest(updated)
	if err != nil {
		return nil, err
	}
	if want != got || updated.GetUID() != desired.GetUID() {
		return nil, errors.New("Kubernetes admission mutated controlled remediation Pod fields")
	}
	return updated, nil
}

// RollbackPodLabel restores original's controlled fields over updated using
// updated's resource version, so a concurrent change fails the rollback
// instead of being overwritten.
func RollbackPodLabel(ctx context.Context, transport WriteTransport, resource schema.GroupVersionResource, original, updated *unstructured.Unstructured, digest ControlledDigest, operation string) error {
	rollback := original.DeepCopy()
	rollback.SetResourceVersion(updated.GetResourceVersion())
	_, err := UpdatePodLabel(ctx, transport, resource, rollback, false, digest, operation)
	return err
}
