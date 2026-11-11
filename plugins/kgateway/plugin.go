package kgateway

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/coherentcache"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Config identifies the cluster and source shared with the Kubernetes plugin.
// ControllerNames select the Gateways that get coverage facets.
type Config struct {
	ClusterID       string
	NetworkID       string
	SourceID        string
	ControllerNames []string
}

// Plugin is the kgateway semantic projection plugin.
type Plugin struct {
	config    Config
	resources []*kubernetesplugin.ResourceClient[*unstructured.Unstructured]
}

// SourceID returns the Kubernetes source ID this plugin projects for.
func (p *Plugin) SourceID() string { return p.config.SourceID }

func kgatewayRequirement(resource string) kubernetesplugin.ResourceRequirement {
	return kubernetesplugin.ResourceRequirement{
		GVR:        schema.GroupVersionResource{Group: kgatewayGroup, Version: "v1alpha1", Resource: resource},
		Capability: "kgateway-" + resource + "-v1alpha1",
	}
}

// Each kgateway CRD is its own capability so one missing CRD does not hide
// the others.
var resourceRequirements = []kubernetesplugin.ResourceRequirement{
	{GVR: schema.GroupVersionResource{Version: "v1", Resource: "services"}, Capability: "kgateway-core-v1", Required: true},
	{GVR: schema.GroupVersionResource{Group: gatewayAPIGroup, Version: "v1", Resource: "gatewayclasses"}, Capability: "gateway-api-v1"},
	{GVR: schema.GroupVersionResource{Group: gatewayAPIGroup, Version: "v1", Resource: "gateways"}, Capability: "gateway-api-v1"},
	{GVR: schema.GroupVersionResource{Group: gatewayAPIGroup, Version: "v1", Resource: "httproutes"}, Capability: "gateway-api-v1"},
	kgatewayRequirement("backendconfigpolicies"),
	kgatewayRequirement("backends"),
	kgatewayRequirement("directresponses"),
	kgatewayRequirement("gatewayextensions"),
	kgatewayRequirement("gatewayparameters"),
	kgatewayRequirement("listenerpolicies"),
	kgatewayRequirement("trafficpolicies"),
}

// New validates config and prepares typed clients for the shared Kubernetes
// collections.
func New(config Config) (*Plugin, error) {
	config.ClusterID = strings.TrimSpace(config.ClusterID)
	config.SourceID = strings.TrimSpace(config.SourceID)
	config.NetworkID = strings.TrimSpace(config.NetworkID)
	if config.ClusterID == "" || config.SourceID == "" {
		return nil, errors.New("kgateway plugin requires cluster and source IDs")
	}
	if config.NetworkID == "" {
		config.NetworkID = config.ClusterID
	}
	config.ControllerNames = normalizedSet(config.ControllerNames, DefaultControllerName)
	resources := make([]*kubernetesplugin.ResourceClient[*unstructured.Unstructured], 0, len(resourceRequirements))
	for _, requirement := range resourceRequirements {
		client, err := kubernetesplugin.NewUnstructuredResourceClient(requirement)
		if err != nil {
			return nil, fmt.Errorf("create kgateway Kubernetes resource client: %w", err)
		}
		resources = append(resources, client)
	}
	return &Plugin{config: config, resources: resources}, nil
}

// SplitList splits a comma-separated flag value.
func SplitList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

// Descriptor implements discovery.Plugin; it returns the same value as the
// package-level [Descriptor], which main also uses before construction.
func (p *Plugin) Descriptor() discovery.Descriptor {
	return Descriptor()
}

// Descriptor declares the consumed Kubernetes collections. The plugin
// publishes no collection and introduces no identity scheme of its own.
func Descriptor() discovery.Descriptor {
	consumes := []string{kubernetesplugin.CollectionResourceCoverage}
	for _, requirement := range resourceRequirements {
		consumes = append(consumes, requirement.Collection())
	}
	slices.Sort(consumes[1:])
	return discovery.Descriptor{
		ID: PluginID, Version: "0.1.0", Description: "kgateway policy, backend, and gateway semantics",
		Consumes: consumes,
	}
}

// KubernetesResources lists the GVRs the Kubernetes plugin must watch for
// this plugin.
func (p *Plugin) KubernetesResources() []kubernetesplugin.ResourceRequirement {
	return slices.Clone(resourceRequirements)
}

// Run consumes the Kubernetes collections and replaces the semantics
// contribution whenever both object and coverage collections reach a new
// coherent generation.
func (p *Plugin) Run(ctx context.Context, runtime discovery.Runtime) error {
	return coherentcache.Run(ctx, runtime, coherentcache.Config{
		PluginID: PluginID, SourceID: p.config.SourceID, Contribution: "semantics", Resources: p.resources, Project: p.project,
	})
}

func (p *Plugin) project(snapshot coherentcache.Snapshot) (graph.Input, string, error) {
	result, err := ProjectObserved(ProjectionContext{
		ClusterID: p.config.ClusterID, NetworkID: p.config.NetworkID, SourceID: p.config.SourceID,
		ControllerNames: p.config.ControllerNames, Coverage: capabilityCoverage(snapshot.Coverage),
	}, snapshot.Objects)
	if err != nil {
		return graph.Input{}, "", fmt.Errorf("project kgateway semantics: %w", err)
	}
	return result.Input, coverageHealth(snapshot.Coverage), nil
}

// capabilityCoverage folds per-GVR coverage records into one state per
// capability; the worst record wins.
func capabilityCoverage(records map[string]kubernetesplugin.ResourceCoverage) map[string]CoverageState {
	rank := map[CoverageState]int{CoverageStateCovered: 0, CoverageStateNotInstalled: 1, CoverageStateUnknown: 2, CoverageStateDegraded: 3}
	result := make(map[string]CoverageState)
	for _, record := range records {
		state := CoverageStateUnknown
		switch record.Status {
		case kubernetesplugin.CoverageCovered:
			state = CoverageStateCovered
		case kubernetesplugin.CoverageUnsupported:
			state = CoverageStateNotInstalled
		case kubernetesplugin.CoverageDegraded, kubernetesplugin.CoverageFailed:
			state = CoverageStateDegraded
		}
		if current, found := result[record.Capability]; !found || rank[state] > rank[current] {
			result[record.Capability] = state
		}
	}
	return result
}

// coverageHealth is degraded when a required API is not covered, the Gateway
// API record is missing, or any consumed API failed to sync. CRDs that are
// simply not installed keep the source healthy; the coverage facet says so.
func coverageHealth(records map[string]kubernetesplugin.ResourceCoverage) string {
	owned := make(map[string]bool, len(resourceRequirements))
	for _, requirement := range resourceRequirements {
		owned[requirement.Capability] = true
	}
	gatewayAPI := false
	for _, record := range records {
		if !owned[record.Capability] {
			continue
		}
		if record.Required && record.Status != kubernetesplugin.CoverageCovered {
			return "degraded"
		}
		if record.Status == kubernetesplugin.CoverageDegraded || record.Status == kubernetesplugin.CoverageFailed {
			return "degraded"
		}
		gatewayAPI = gatewayAPI || record.Capability == "gateway-api-v1"
	}
	if !gatewayAPI {
		return "degraded"
	}
	return "healthy"
}
