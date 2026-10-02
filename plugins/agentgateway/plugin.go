package agentgateway

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
// ControllerNames and GatewayClasses select agentgateway-managed Gateways.
type Config struct {
	ClusterID       string
	SourceID        string
	ControllerNames []string
	GatewayClasses  []string
}

// Plugin is the agentgateway semantic projection plugin.
type Plugin struct {
	config    Config
	resources []*kubernetesplugin.ResourceClient[*unstructured.Unstructured]
}

// SourceID returns the Kubernetes source ID this plugin projects for.
func (p *Plugin) SourceID() string { return p.config.SourceID }

var resourceRequirements = []kubernetesplugin.ResourceRequirement{
	{GVR: schema.GroupVersionResource{Version: "v1", Resource: "services"}, Capability: "agentgateway-core-v1", Required: true},
	{GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}, Capability: "gateway-api-v1"},
	{GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}, Capability: "gateway-api-v1"},
	{GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}, Capability: "gateway-api-v1"},
}

// New validates config and prepares typed clients for the shared Kubernetes
// collections.
func New(config Config) (*Plugin, error) {
	config.ClusterID = strings.TrimSpace(config.ClusterID)
	config.SourceID = strings.TrimSpace(config.SourceID)
	if config.ClusterID == "" || config.SourceID == "" {
		return nil, errors.New("agentgateway plugin requires cluster and source IDs")
	}
	config.ControllerNames = normalizedSet(config.ControllerNames, DefaultControllerName)
	config.GatewayClasses = normalizedSet(config.GatewayClasses, DefaultGatewayClass)
	resources := make([]*kubernetesplugin.ResourceClient[*unstructured.Unstructured], 0, len(resourceRequirements))
	for _, requirement := range resourceRequirements {
		client, err := kubernetesplugin.NewUnstructuredResourceClient(requirement)
		if err != nil {
			return nil, fmt.Errorf("create agentgateway Kubernetes resource client: %w", err)
		}
		resources = append(resources, client)
	}
	return &Plugin{config: config, resources: resources}, nil
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
		ID: PluginID, Version: "0.1.0", Description: "agentgateway Gateway API ingress semantics",
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
// coherent generation. No other plugin consumes agentgateway output, so it
// marks no collection ready.
func (p *Plugin) Run(ctx context.Context, runtime discovery.Runtime) error {
	return coherentcache.Run(ctx, runtime, coherentcache.Config{
		PluginID: PluginID, SourceID: p.config.SourceID, Contribution: "semantics", Resources: p.resources, Project: p.project,
	})
}

func (p *Plugin) project(snapshot coherentcache.Snapshot) (graph.Input, string, error) {
	result, err := ProjectObserved(ProjectionContext{
		ClusterID: p.config.ClusterID, SourceID: p.config.SourceID,
		ControllerNames: p.config.ControllerNames, GatewayClasses: p.config.GatewayClasses,
	}, snapshot.Objects)
	if err != nil {
		return graph.Input{}, "", fmt.Errorf("project agentgateway semantics: %w", err)
	}
	return result.Input, gatewayCoverageHealth(snapshot.Coverage), nil
}

func gatewayCoverageHealth(records map[string]kubernetesplugin.ResourceCoverage) string {
	found := false
	for _, record := range records {
		if record.Required && record.Status != kubernetesplugin.CoverageCovered {
			return "degraded"
		}
		if record.Capability != "gateway-api-v1" {
			continue
		}
		found = true
		if record.Status == kubernetesplugin.CoverageDegraded || record.Status == kubernetesplugin.CoverageFailed {
			return "degraded"
		}
	}
	if !found {
		return "degraded"
	}
	return "healthy"
}
