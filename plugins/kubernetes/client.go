package kubernetes

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const resourceCollectionPrefix = "kubernetes/resources/"

// ResourceRequirement asks the Kubernetes plugin to watch one GVR. Capability
// groups GVRs into one coverage boundary; a Required capability that is not
// available fails source startup.
type ResourceRequirement struct {
	GVR        schema.GroupVersionResource
	Capability string
	Required   bool
}

// Collection returns kubernetes/resources/<group>/<version>/<resource>, with
// "core" for the empty group. It names delivery, not identity.
func (requirement ResourceRequirement) Collection() string {
	group := strings.TrimSpace(requirement.GVR.Group)
	if group == "" {
		group = "core"
	}
	return resourceCollectionPrefix + strings.ToLower(strings.Join([]string{group, requirement.GVR.Version, requirement.GVR.Resource}, "/"))
}

// ResourceRequirementsProvider is implemented by semantic plugins that consume
// Kubernetes collections. The host collects requirements before constructing
// the Kubernetes plugin.
type ResourceRequirementsProvider interface {
	KubernetesResources() []ResourceRequirement
}

// ResourceChange is a collection change with its payload decoded. Object is
// the zero value for delete and sync changes.
type ResourceChange[T any] struct {
	discovery.Change
	Object T
}

// ResourceClient is a typed subscription to one shared Kubernetes resource
// collection. It never opens a Kubernetes connection.
type ResourceClient[T any] struct {
	requirement ResourceRequirement
	decode      func([]byte) (T, error)
}

// NewResourceClient returns a client that decodes upsert payloads with decode.
func NewResourceClient[T any](requirement ResourceRequirement, decode func([]byte) (T, error)) (*ResourceClient[T], error) {
	if err := validateResourceRequirement(requirement); err != nil {
		return nil, err
	}
	if decode == nil {
		return nil, errors.New("Kubernetes resource client requires a decoder")
	}
	return &ResourceClient[T]{requirement: requirement, decode: decode}, nil
}

func validateResourceRequirement(requirement ResourceRequirement) error {
	if strings.TrimSpace(requirement.GVR.Version) == "" || strings.TrimSpace(requirement.GVR.Resource) == "" {
		return errors.New("Kubernetes resource requirement requires GVR version and resource")
	}
	if strings.TrimSpace(requirement.Capability) == "" {
		return errors.New("Kubernetes resource requirement requires a capability")
	}
	return nil
}

// NewUnstructuredResourceClient returns a client that decodes payloads into
// unstructured objects.
func NewUnstructuredResourceClient(requirement ResourceRequirement) (*ResourceClient[*unstructured.Unstructured], error) {
	return NewResourceClient(requirement, func(payload []byte) (*unstructured.Unstructured, error) {
		item := &unstructured.Unstructured{}
		if err := json.Unmarshal(payload, &item.Object); err != nil {
			return nil, err
		}
		return item, nil
	})
}

// Requirement returns the requirement this client was built for.
func (client *ResourceClient[T]) Requirement() ResourceRequirement {
	return client.requirement
}

// Collection returns the collection this client subscribes to.
func (client *ResourceClient[T]) Collection() string {
	return client.requirement.Collection()
}

// Subscribe replays and then follows the collection. The error channel
// receives at most one error: a decode failure or unexpected collection
// closure. Both channels close when delivery stops.
func (client *ResourceClient[T]) Subscribe(ctx context.Context, runtime discovery.Runtime) (<-chan ResourceChange[T], <-chan error, error) {
	if runtime == nil {
		return nil, nil, errors.New("discovery runtime is required")
	}
	changes, err := runtime.Subscribe(ctx, client.Collection())
	if err != nil {
		return nil, nil, err
	}
	events := make(chan ResourceChange[T])
	errorsChannel := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errorsChannel)
		for change := range changes {
			var object T
			if change.Operation == discovery.OperationUpsert {
				object, err = client.decode(change.Payload)
				if err != nil {
					errorsChannel <- fmt.Errorf("decode %s change %q: %w", client.requirement.GVR, change.Key, err)
					return
				}
			}
			select {
			case events <- ResourceChange[T]{Change: change, Object: object}:
			case <-ctx.Done():
				return
			}
		}
		if ctx.Err() == nil {
			errorsChannel <- fmt.Errorf("Kubernetes resource collection %q closed unexpectedly", client.Collection())
		}
	}()
	return events, errorsChannel, nil
}

// ResourceRequirements merges the requirements of every plugin that
// implements [ResourceRequirementsProvider], deduplicating by capability and
// GVR. A GVR is required if any plugin requires it. The result is sorted.
func ResourceRequirements(plugins ...discovery.Plugin) []ResourceRequirement {
	byKey := make(map[string]ResourceRequirement)
	for _, plugin := range plugins {
		provider, ok := plugin.(ResourceRequirementsProvider)
		if !ok {
			continue
		}
		for _, requirement := range provider.KubernetesResources() {
			key := requirement.Capability + "\x00" + requirement.GVR.String()
			current := byKey[key]
			current.GVR = requirement.GVR
			current.Capability = requirement.Capability
			current.Required = current.Required || requirement.Required
			byKey[key] = current
		}
	}
	result := make([]ResourceRequirement, 0, len(byKey))
	for _, requirement := range byKey {
		result = append(result, requirement)
	}
	sortResourceRequirements(result)
	return result
}

func sortResourceRequirements(requirements []ResourceRequirement) {
	slices.SortFunc(requirements, func(left, right ResourceRequirement) int {
		if left.Collection() != right.Collection() {
			return cmp.Compare(left.Collection(), right.Collection())
		}
		return cmp.Compare(left.Capability, right.Capability)
	})
}
