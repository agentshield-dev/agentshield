package kubernetes

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

// discoveryTimeout bounds one API discovery request at startup.
var discoveryTimeout = 30 * time.Second

// CollectionResourceCoverage reports which resource types this plugin can reliably observe.
const CollectionResourceCoverage = "kubernetes/resource-coverage"

// CoverageStatus is the observation state of one capability's API.
type CoverageStatus string

const (
	// CoverageCovered means the API is advertised and its informer synced.
	CoverageCovered CoverageStatus = "covered"
	// CoverageUnsupported means an optional API is not advertised.
	CoverageUnsupported CoverageStatus = "unsupported"
	// CoverageDegraded means an optional API is advertised but could not be
	// discovered or synced.
	CoverageDegraded CoverageStatus = "degraded"
	// CoverageFailed means a required API is unavailable or its informer is
	// not synced. During discovery it fails source startup.
	CoverageFailed CoverageStatus = "failed"
)

// ResourceCoverage states whether one API resource falls inside this source's
// observation boundary; unsupported or degraded coverage does not prove nonexistence.
type ResourceCoverage struct {
	Capability string         `json:"capability"`
	GVR        string         `json:"gvr"`
	Required   bool           `json:"required"`
	Advertised bool           `json:"advertised"`
	Status     CoverageStatus `json:"status"`
	Message    string         `json:"message,omitempty"`
}

type resourceSpec struct {
	gvr        schema.GroupVersionResource
	capability string
	required   bool
}

type inventoryPlan struct {
	resources []schema.GroupVersionResource
	coverage  []ResourceCoverage
	degraded  bool
}

var requiredResourceSpecs = []resourceSpec{
	requiredSpec("core", "", "v1", "namespaces"),
	requiredSpec("core", "", "v1", "nodes"),
	requiredSpec("core", "", "v1", "serviceaccounts"),
	requiredSpec("core", "", "v1", "pods"),
	requiredSpec("core", "", "v1", "services"),
	requiredSpec("configuration", "", "v1", "configmaps"),
	requiredSpec("configuration", "", "v1", "secrets"),
	requiredSpec("storage", "", "v1", "persistentvolumeclaims"),
	requiredSpec("workloads", "apps", "v1", "deployments"),
	requiredSpec("workloads", "apps", "v1", "statefulsets"),
	requiredSpec("workloads", "apps", "v1", "daemonsets"),
	requiredSpec("workloads", "apps", "v1", "replicasets"),
	requiredSpec("batch", "batch", "v1", "jobs"),
	requiredSpec("batch", "batch", "v1", "cronjobs"),
	requiredSpec("ingress", "networking.k8s.io", "v1", "ingresses"),
	requiredSpec("network-policy", "networking.k8s.io", "v1", "networkpolicies"),
	requiredSpec("rbac", "rbac.authorization.k8s.io", "v1", "roles"),
	requiredSpec("rbac", "rbac.authorization.k8s.io", "v1", "rolebindings"),
	requiredSpec("rbac", "rbac.authorization.k8s.io", "v1", "clusterroles"),
	requiredSpec("rbac", "rbac.authorization.k8s.io", "v1", "clusterrolebindings"),
	requiredSpec("admission", "admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations"),
	requiredSpec("admission", "admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations"),
	requiredSpec("admission", "admissionregistration.k8s.io", "v1", "validatingadmissionpolicies"),
	requiredSpec("admission", "admissionregistration.k8s.io", "v1", "validatingadmissionpolicybindings"),
}

var optionalResourceCapabilities = [][]resourceSpec{
	{
		optionalSpec("gateway-api-v1", "gateway.networking.k8s.io", "v1", "gateways"),
		optionalSpec("gateway-api-v1", "gateway.networking.k8s.io", "v1", "httproutes"),
	},
}

func requiredSpec(capability, group, version, resource string) resourceSpec {
	return resourceSpec{gvr: schema.GroupVersionResource{Group: group, Version: version, Resource: resource}, capability: capability, required: true}
}

func optionalSpec(capability, group, version, resource string) resourceSpec {
	return resourceSpec{gvr: schema.GroupVersionResource{Group: group, Version: version, Resource: resource}, capability: capability}
}

// serverResources lists one group version's resources within
// discoveryTimeout. The discovery client takes no context, so a stalled
// request is abandoned rather than cancelled; its goroutine ends when the REST
// client's own timeout or connection does.
func serverResources(ctx context.Context, client discovery.DiscoveryInterface, groupVersion string) (*metav1.APIResourceList, error) {
	type result struct {
		list *metav1.APIResourceList
		err  error
	}
	done := make(chan result, 1)
	go func() {
		list, err := client.ServerResourcesForGroupVersion(groupVersion)
		done <- result{list: list, err: err}
	}()
	timer := time.NewTimer(discoveryTimeout)
	defer timer.Stop()
	select {
	case value := <-done:
		return value.list, value.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("discover %s: no response within %s", groupVersion, discoveryTimeout)
	}
}

func resolveInventory(ctx context.Context, client discovery.DiscoveryInterface, requirements ...ResourceRequirement) (inventoryPlan, error) {
	byVersion := make(map[string]map[string]struct{})
	discoveryErrors := make(map[string]error)
	discover := func(gvr schema.GroupVersionResource) (bool, error) {
		groupVersion := schema.GroupVersion{Group: gvr.Group, Version: gvr.Version}.String()
		if err, ok := discoveryErrors[groupVersion]; ok {
			return false, err
		}
		resources, ok := byVersion[groupVersion]
		if !ok {
			list, err := serverResources(ctx, client, groupVersion)
			if err != nil {
				discoveryErrors[groupVersion] = err
				return false, err
			}
			resources = make(map[string]struct{}, len(list.APIResources))
			for _, resource := range list.APIResources {
				resources[resource.Name] = struct{}{}
			}
			byVersion[groupVersion] = resources
		}
		_, found := resources[gvr.Resource]
		return found, nil
	}

	var plan inventoryPlan
	selected := make(map[schema.GroupVersionResource]struct{})
	selectResource := func(gvr schema.GroupVersionResource) {
		if _, found := selected[gvr]; found {
			return
		}
		selected[gvr] = struct{}{}
		plan.resources = append(plan.resources, gvr)
	}
	for _, spec := range requiredResourceSpecs {
		advertised, err := discover(spec.gvr)
		coverage := coverageFor(spec, advertised, CoverageCovered, "")
		if err != nil {
			coverage.Status = CoverageFailed
			coverage.Message = "discovery failed"
			plan.coverage = append(plan.coverage, coverage)
			return inventoryPlan{}, fmt.Errorf("discover required Kubernetes API %s: %w", spec.gvr, err)
		}
		if !advertised {
			coverage.Status = CoverageFailed
			coverage.Message = "resource is not advertised"
			plan.coverage = append(plan.coverage, coverage)
			return inventoryPlan{}, fmt.Errorf("required Kubernetes API %s is not advertised", spec.gvr)
		}
		selectResource(spec.gvr)
		plan.coverage = append(plan.coverage, coverage)
	}

	capabilities := slices.Clone(optionalResourceCapabilities)
	byCapability := make(map[string][]resourceSpec)
	for _, requirement := range requirements {
		byCapability[requirement.Capability] = append(byCapability[requirement.Capability], resourceSpec{
			gvr: requirement.GVR, capability: requirement.Capability, required: requirement.Required,
		})
	}
	capabilityNames := make([]string, 0, len(byCapability))
	for capability := range byCapability {
		capabilityNames = append(capabilityNames, capability)
	}
	slices.Sort(capabilityNames)
	for _, capability := range capabilityNames {
		capabilities = append(capabilities, byCapability[capability])
	}
	for _, capability := range capabilities {
		advertised := make([]bool, len(capability))
		var capabilityErr error
		allAdvertised := true
		required := false
		for index, spec := range capability {
			required = required || spec.required
			advertised[index], capabilityErr = discover(spec.gvr)
			if capabilityErr != nil {
				break
			}
			allAdvertised = allAdvertised && advertised[index]
		}
		status := CoverageCovered
		message := ""
		if required && capabilityErr != nil {
			return inventoryPlan{}, fmt.Errorf("discover required Kubernetes capability %s: %w", capability[0].capability, capabilityErr)
		}
		if required && !allAdvertised {
			return inventoryPlan{}, fmt.Errorf("required Kubernetes capability %s is not fully advertised", capability[0].capability)
		}
		if capabilityErr != nil && !isUnsupportedDiscoveryError(capabilityErr) {
			status = CoverageDegraded
			message = "discovery failed"
			plan.degraded = true
		} else if capabilityErr != nil || !allAdvertised {
			status = CoverageUnsupported
			message = "coherent capability is not fully advertised"
		}
		for index, spec := range capability {
			plan.coverage = append(plan.coverage, coverageFor(spec, advertised[index], status, message))
			if status == CoverageCovered {
				selectResource(spec.gvr)
			}
		}
	}

	slices.SortFunc(plan.resources, func(left, right schema.GroupVersionResource) int { return cmp.Compare(left.String(), right.String()) })
	slices.SortFunc(plan.coverage, func(left, right ResourceCoverage) int {
		if left.Capability != right.Capability {
			return cmp.Compare(left.Capability, right.Capability)
		}
		return cmp.Compare(left.GVR, right.GVR)
	})
	return plan, nil
}

func isUnsupportedDiscoveryError(err error) bool {
	message := strings.ToLower(err.Error())
	return apierrors.IsNotFound(err) || strings.Contains(message, "could not find") || strings.Contains(message, "not found")
}

func coverageFor(spec resourceSpec, advertised bool, status CoverageStatus, message string) ResourceCoverage {
	return ResourceCoverage{
		Capability: spec.capability,
		GVR:        spec.gvr.String(),
		Required:   spec.required,
		Advertised: advertised,
		Status:     status,
		Message:    message,
	}
}

func (coverage ResourceCoverage) key() string {
	return strings.ToLower(coverage.Capability + "/" + coverage.GVR)
}

func (coverage ResourceCoverage) payload() ([]byte, error) {
	return json.Marshal(coverage)
}

func capabilityCovered(coverage []ResourceCoverage, capability string) bool {
	found := false
	for _, item := range coverage {
		if item.Capability != capability {
			continue
		}
		found = true
		if item.Status != CoverageCovered {
			return false
		}
	}
	return found
}
