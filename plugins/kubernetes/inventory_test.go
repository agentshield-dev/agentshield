package kubernetes

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestResolveInventory(t *testing.T) {
	allOptional := 0
	for _, capability := range optionalResourceCapabilities {
		allOptional += len(capability)
	}
	tests := []struct {
		name          string
		omit          map[string]bool
		wantErr       bool
		wantGateway   bool
		wantStatus    CoverageStatus
		wantResources int
		requirements  []ResourceRequirement
	}{
		{name: "required plus all optional", wantGateway: true, wantStatus: CoverageCovered, wantResources: len(requiredResourceSpecs) + allOptional},
		{name: "optional APIs absent", omit: optionalResourceNames(), wantStatus: CoverageUnsupported, wantResources: len(requiredResourceSpecs)},
		{name: "partial gateway is unsupported", omit: map[string]bool{"gateway.networking.k8s.io/v1/httproutes": true}, wantStatus: CoverageUnsupported, wantResources: len(requiredResourceSpecs)},
		{name: "plugin requirements extend inventory", wantGateway: true, wantStatus: CoverageCovered, wantResources: len(requiredResourceSpecs) + allOptional + 2, requirements: []ResourceRequirement{
			{GVR: schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"}, Capability: "istio-security-v1"},
			{GVR: schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"}, Capability: "istio-security-v1"},
		}},
		{name: "missing required fails", omit: map[string]bool{"networking.k8s.io/v1/networkpolicies": true}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := discoveryWithResources(test.omit, test.requirements...)
			plan, err := resolveInventory(context.Background(), client, test.requirements...)
			if test.wantErr {
				if err == nil {
					t.Fatal("resolveInventory() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.resources) != test.wantResources {
				t.Fatalf("resources = %d, want %d", len(plan.resources), test.wantResources)
			}
			gatewayStatus := capabilityStatus(t, plan, "gateway-api-v1")
			if gatewayStatus != test.wantStatus {
				t.Fatalf("gateway status = %q, want %q", gatewayStatus, test.wantStatus)
			}
			if containsResource(plan, "gateway.networking.k8s.io/v1, Resource=gateways") != test.wantGateway {
				t.Fatalf("gateway selected = %t, want %t", !test.wantGateway, test.wantGateway)
			}
		})
	}
}

func TestResolveInventoryDeduplicatesWatchesAndPreservesCapabilityCoverage(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "example.io", Version: "v1", Resource: "foos"}
	requirements := []ResourceRequirement{
		{GVR: gvr, Capability: "foo-a"},
		{GVR: gvr, Capability: "foo-b"},
	}
	plan, err := resolveInventory(context.Background(), discoveryWithResources(nil, requirements...), requirements...)
	if err != nil {
		t.Fatal(err)
	}
	selected := 0
	for _, resource := range plan.resources {
		if resource == gvr {
			selected++
		}
	}
	if selected != 1 {
		t.Fatalf("selected foo watches = %d, want 1", selected)
	}
	if capabilityStatus(t, plan, "foo-a") != CoverageCovered || capabilityStatus(t, plan, "foo-b") != CoverageCovered {
		t.Fatalf("coverage = %#v", plan.coverage)
	}
}

// stalledDiscovery never answers discovery for one group version.
type stalledDiscovery struct {
	*fake.FakeDiscovery
	stalled string
	release chan struct{}
}

func (client stalledDiscovery) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	if groupVersion == client.stalled {
		<-client.release
	}
	return client.FakeDiscovery.ServerResourcesForGroupVersion(groupVersion)
}

func TestResolveInventoryBoundsStalledDiscovery(t *testing.T) {
	previous := discoveryTimeout
	discoveryTimeout = 10 * time.Millisecond
	t.Cleanup(func() { discoveryTimeout = previous })
	release := make(chan struct{})
	defer close(release)

	// A stalled optional API degrades its coverage instead of blocking.
	optional := stalledDiscovery{FakeDiscovery: discoveryWithResources(nil), stalled: "gateway.networking.k8s.io/v1", release: release}
	plan, err := resolveInventory(context.Background(), optional)
	if err != nil {
		t.Fatal(err)
	}
	for _, coverage := range plan.coverage {
		if coverage.Capability == "gateway-api-v1" && coverage.Status != CoverageDegraded {
			t.Fatalf("stalled optional coverage = %#v", coverage)
		}
	}

	// A stalled required API fails startup with a timeout.
	required := stalledDiscovery{FakeDiscovery: discoveryWithResources(nil), stalled: "networking.k8s.io/v1", release: release}
	if _, err := resolveInventory(context.Background(), required); err == nil || !strings.Contains(err.Error(), "no response within") {
		t.Fatalf("resolveInventory error = %v", err)
	}
}

func discoveryWithResources(omit map[string]bool, requirements ...ResourceRequirement) *fake.FakeDiscovery {
	client := &fake.FakeDiscovery{Fake: &clienttesting.Fake{}}
	byVersion := make(map[string][]metav1.APIResource)
	allSpecs := slices.Clone(requiredResourceSpecs)
	for _, capability := range optionalResourceCapabilities {
		allSpecs = append(allSpecs, capability...)
	}
	for _, requirement := range requirements {
		allSpecs = append(allSpecs, resourceSpec{gvr: requirement.GVR, capability: requirement.Capability, required: requirement.Required})
	}
	for _, spec := range allSpecs {
		key := spec.gvr.GroupVersion().String() + "/" + spec.gvr.Resource
		if omit[key] {
			continue
		}
		groupVersion := spec.gvr.GroupVersion().String()
		byVersion[groupVersion] = append(byVersion[groupVersion], metav1.APIResource{Name: spec.gvr.Resource})
	}
	for groupVersion, resources := range byVersion {
		client.Resources = append(client.Resources, &metav1.APIResourceList{GroupVersion: groupVersion, APIResources: resources})
	}
	return client
}

func optionalResourceNames() map[string]bool {
	result := make(map[string]bool)
	for _, capability := range optionalResourceCapabilities {
		for _, spec := range capability {
			result[spec.gvr.GroupVersion().String()+"/"+spec.gvr.Resource] = true
		}
	}
	return result
}

func capabilityStatus(t *testing.T, plan inventoryPlan, capability string) CoverageStatus {
	t.Helper()
	for _, coverage := range plan.coverage {
		if coverage.Capability == capability {
			return coverage.Status
		}
	}
	t.Fatalf("capability %q not found", capability)
	return ""
}

func containsResource(plan inventoryPlan, target string) bool {
	for _, resource := range plan.resources {
		if resource.String() == target {
			return true
		}
	}
	return false
}
