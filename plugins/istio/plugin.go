package istio

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
	"github.com/agentshield-dev/agentshield/plugins/internal/coherentcache"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CollectionProjection signals readiness of the Istio semantic contribution;
// its graph assertions are published separately through ReplaceContribution.
const CollectionProjection = "istio/projection"

// Config identifies the cluster and source shared with the Kubernetes plugin.
// NetworkID defaults to ClusterID and RootNamespace to istio-system. Actions
// enables the remediation action; nil leaves it unadvertised.
type Config struct {
	ClusterID     string
	NetworkID     string
	SourceID      string
	RootNamespace string
	Actions       kubernetesplugin.WriteTransport
}

// Plugin is the Istio semantic projection, telemetry mapping, and
// remediation plugin.
type Plugin struct {
	config    Config
	resolver  *telemetryObjectResolver
	resources []*kubernetesplugin.ResourceClient[*unstructured.Unstructured]
}

// SourceID returns the Kubernetes source ID this plugin projects for.
func (p *Plugin) SourceID() string { return p.config.SourceID }

// New validates config, applies defaults, and prepares typed clients for the
// shared Kubernetes collections.
func New(config Config) (*Plugin, error) {
	if strings.TrimSpace(config.ClusterID) == "" || strings.TrimSpace(config.SourceID) == "" {
		return nil, errors.New("Istio plugin requires cluster and source IDs")
	}
	if strings.TrimSpace(config.NetworkID) == "" {
		config.NetworkID = config.ClusterID
	}
	if strings.TrimSpace(config.RootNamespace) == "" {
		config.RootNamespace = "istio-system"
	}
	resourceClients := make([]*kubernetesplugin.ResourceClient[*unstructured.Unstructured], 0, len(istioResourceRequirements))
	for _, requirement := range istioResourceRequirements {
		client, err := kubernetesplugin.NewUnstructuredResourceClient(requirement)
		if err != nil {
			return nil, fmt.Errorf("create Istio Kubernetes resource client: %w", err)
		}
		resourceClients = append(resourceClients, client)
	}
	return &Plugin{config: config, resolver: newTelemetryObjectResolver(config.ClusterID), resources: resourceClients}, nil
}

// Descriptor implements discovery.Plugin; it returns the same value as the
// package-level [Descriptor], which main also uses before construction.
func (p *Plugin) Descriptor() discovery.Descriptor {
	return Descriptor()
}

// TelemetryMappings registers the active-probe OTLP mapper. Its resolver sees
// the same coherent snapshot as the last projection.
func (p *Plugin) TelemetryMappings() []telemetry.Mapping {
	return []telemetry.Mapping{{PluginID: PluginID, SourceID: p.config.SourceID, Mapper: activeProbeMapper{clusterID: p.config.ClusterID, resolver: p.resolver}}}
}

var istioResourceRequirements = []kubernetesplugin.ResourceRequirement{
	{GVR: schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, Capability: "istio-core-v1", Required: true},
	{GVR: schema.GroupVersionResource{Version: "v1", Resource: "pods"}, Capability: "istio-core-v1", Required: true},
	{GVR: schema.GroupVersionResource{Version: "v1", Resource: "services"}, Capability: "istio-core-v1", Required: true},
	{GVR: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, Capability: "istio-workloads-v1", Required: true},
	{GVR: schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}, Capability: "istio-gateway-v1"},
	{GVR: schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "authorizationpolicies"}, Capability: "istio-security-v1"},
	{GVR: schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"}, Capability: "istio-security-v1"},
	{GVR: schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "serviceentries"}, Capability: "istio-networking-v1"},
	{GVR: schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1", Resource: "virtualservices"}, Capability: "istio-networking-v1"},
}

// KubernetesResources lists the GVRs the Kubernetes plugin must watch for
// this plugin.
func (p *Plugin) KubernetesResources() []kubernetesplugin.ResourceRequirement {
	return slices.Clone(istioResourceRequirements)
}

// Descriptor declares Istio as a semantic consumer of Kubernetes observations,
// avoiding a second watch against the same cluster APIs.
func Descriptor() discovery.Descriptor {
	consumes := []string{collectionResourceCoverage}
	for _, requirement := range istioResourceRequirements {
		consumes = append(consumes, requirement.Collection())
	}
	slices.Sort(consumes[1:])
	return discovery.Descriptor{
		ID: PluginID, Version: "0.1.0", Description: "Istio registry, routing, policy, mTLS, ambient, and waypoint semantics",
		Consumes:  consumes,
		Publishes: []string{CollectionProjection},
	}
}

// Run consumes the Kubernetes collections and replaces the semantics
// contribution whenever both object and coverage collections reach a new
// coherent generation. Each coherent object set also refreshes the telemetry
// resolver, so the mapper sees the same snapshot as the projection.
func (p *Plugin) Run(ctx context.Context, runtime discovery.Runtime) error {
	return coherentcache.Run(ctx, runtime, coherentcache.Config{
		PluginID: PluginID, SourceID: p.config.SourceID, Contribution: "semantics", Resources: p.resources,
		ReadyCollection: CollectionProjection, OnObjects: p.resolver.Replace, Project: p.project,
	})
}

func (p *Plugin) project(snapshot coherentcache.Snapshot) (graph.Input, string, error) {
	health, gatewayCoverageKnown := coverageHealth(snapshot.Coverage)
	result, err := ProjectObserved(ProjectionContext{
		ClusterID: p.config.ClusterID, NetworkID: p.config.NetworkID, SourceID: p.config.SourceID,
		RootNamespace: p.config.RootNamespace, GatewayCoverageKnown: gatewayCoverageKnown,
	}, snapshot.Objects)
	if err != nil {
		return graph.Input{}, "", fmt.Errorf("project Istio semantics: %w", err)
	}
	return result.Input, health, nil
}
