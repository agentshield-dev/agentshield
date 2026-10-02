package cilium

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

// CollectionProjection signals readiness of the Cilium semantic contribution;
// its graph assertions are published separately through ReplaceContribution.
const CollectionProjection = "cilium/projection"

// Config identifies the cluster and source shared with the Kubernetes plugin.
// Actions enables the remediation action; nil leaves it unadvertised.
type Config struct {
	ClusterID string
	SourceID  string
	Actions   kubernetesplugin.WriteTransport
}

// Plugin is the Cilium semantic projection and remediation plugin.
type Plugin struct {
	config    Config
	resources []*kubernetesplugin.ResourceClient[*unstructured.Unstructured]
}

// SourceID returns the Kubernetes source ID this plugin projects for.
func (plugin *Plugin) SourceID() string { return plugin.config.SourceID }

var ciliumResourceRequirements = []kubernetesplugin.ResourceRequirement{
	{GVR: schema.GroupVersionResource{Version: "v1", Resource: "pods"}, Capability: "cilium-core-v1", Required: true},
	{GVR: schema.GroupVersionResource{Version: "v1", Resource: "nodes"}, Capability: "cilium-core-v1", Required: true},
	{GVR: schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}, Capability: "cilium-policy-v2"},
	{GVR: schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}, Capability: "cilium-policy-v2"},
	{GVR: schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumendpoints"}, Capability: "cilium-endpoint-v2"},
	{GVR: schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnodes"}, Capability: "cilium-node-v2"},
}

// New validates config and prepares typed clients for the shared Kubernetes
// collections.
func New(config Config) (*Plugin, error) {
	if strings.TrimSpace(config.ClusterID) == "" || strings.TrimSpace(config.SourceID) == "" {
		return nil, errors.New("Cilium plugin requires cluster and source IDs")
	}
	resources := make([]*kubernetesplugin.ResourceClient[*unstructured.Unstructured], 0, len(ciliumResourceRequirements))
	for _, requirement := range ciliumResourceRequirements {
		client, err := kubernetesplugin.NewUnstructuredResourceClient(requirement)
		if err != nil {
			return nil, fmt.Errorf("create Cilium Kubernetes resource client: %w", err)
		}
		resources = append(resources, client)
	}
	return &Plugin{config: config, resources: resources}, nil
}

// Descriptor implements discovery.Plugin; it returns the same value as the
// package-level [Descriptor], which main also uses before construction.
func (plugin *Plugin) Descriptor() discovery.Descriptor {
	return Descriptor()
}

// Descriptor declares the consumed Kubernetes collections and the projection
// readiness collection. Cilium introduces no identity scheme of its own.
func Descriptor() discovery.Descriptor {
	consumes := []string{kubernetesplugin.CollectionResourceCoverage}
	for _, requirement := range ciliumResourceRequirements {
		consumes = append(consumes, requirement.Collection())
	}
	slices.Sort(consumes[1:])
	return discovery.Descriptor{
		ID: PluginID, Version: "0.1.0", Description: "Cilium CNI state and Hubble flow semantics",
		Consumes:  consumes,
		Publishes: []string{CollectionProjection},
	}
}

// KubernetesResources lists the GVRs the Kubernetes plugin must watch for
// this plugin.
func (plugin *Plugin) KubernetesResources() []kubernetesplugin.ResourceRequirement {
	return slices.Clone(ciliumResourceRequirements)
}

// Run consumes the Kubernetes collections and replaces the cni-semantics
// contribution whenever both object and coverage collections reach a new
// coherent generation.
func (plugin *Plugin) Run(ctx context.Context, runtime discovery.Runtime) error {
	return coherentcache.Run(ctx, runtime, coherentcache.Config{
		PluginID: PluginID, SourceID: plugin.config.SourceID, Contribution: "cni-semantics", Resources: plugin.resources,
		ReadyCollection: CollectionProjection, Project: plugin.project,
	})
}

func (plugin *Plugin) project(snapshot coherentcache.Snapshot) (graph.Input, string, error) {
	result, err := ProjectObserved(ProjectionContext{ClusterID: plugin.config.ClusterID, SourceID: plugin.config.SourceID}, snapshot.Objects)
	if err != nil {
		return graph.Input{}, "", fmt.Errorf("project Cilium CNI semantics: %w", err)
	}
	return result.Input, ciliumCoverageHealth(snapshot.Coverage), nil
}

func ciliumCoverageHealth(coverage map[string]kubernetesplugin.ResourceCoverage) string {
	for _, record := range coverage {
		if record.Required && record.Status != kubernetesplugin.CoverageCovered {
			return "degraded"
		}
		if !strings.HasPrefix(record.Capability, "cilium-") {
			continue
		}
		if record.Status == kubernetesplugin.CoverageDegraded || record.Status == kubernetesplugin.CoverageFailed {
			return "degraded"
		}
	}
	return "healthy"
}
