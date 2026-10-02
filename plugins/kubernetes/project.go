package kubernetes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	// PluginID is the plugin and contribution owner ID, and the prefix of
	// Kubernetes observation event IDs.
	PluginID = "kubernetes"
)

func identityScheme() graph.IdentityScheme {
	return graph.IdentityScheme{Group: "kubernetes.io", Version: "v1", Kind: "Object"}
}

// IdentitySchemeDefinition makes Kubernetes object UIDs cluster-qualified so
// other plugins can assert against the same canonical resources.
func IdentitySchemeDefinition() graph.SchemeDefinition {
	scheme := identityScheme()
	return graph.SchemeDefinition{
		Scheme: scheme,
		Normalize: func(claim graph.IdentityClaim) (graph.IdentityClaim, error) {
			claim.AuthorityID = strings.TrimSpace(claim.AuthorityID)
			claim.ImmutableKey = strings.ToLower(strings.TrimSpace(claim.ImmutableKey))
			if claim.Scheme != scheme || claim.AuthorityID == "" || claim.ImmutableKey == "" {
				return graph.IdentityClaim{}, errors.New("invalid kubernetes.io/v1 Object identity claim")
			}
			return claim, nil
		},
	}
}

// Project projects bare objects with the cluster ID as network ID. It exists
// for tests and offline evaluation.
func Project(clusterID, sourceID string, objects []*unstructured.Unstructured) (graph.Input, error) {
	return ProjectWithNetworkID(clusterID, clusterID, sourceID, objects)
}

// ProjectWithNetworkID is [Project] with an explicit network ID.
func ProjectWithNetworkID(clusterID, networkID, sourceID string, objects []*unstructured.Unstructured) (graph.Input, error) {
	return projectWithIdentityResolvers(clusterID, networkID, sourceID, objects, nil)
}

func projectWithIdentityResolvers(clusterID, networkID, sourceID string, objects []*unstructured.Unstructured, resolvers []discovery.IdentityReferenceResolver) (graph.Input, error) {
	if strings.TrimSpace(clusterID) == "" || strings.TrimSpace(networkID) == "" || strings.TrimSpace(sourceID) == "" {
		return graph.Input{}, errors.New("cluster, network, and source IDs are required")
	}
	index := buildObjectIndex(objects)
	// Partial API discovery never enters the object collection, so either kind proves
	// that replay came from the coherently selected Gateway API capability.
	return projectSnapshot(clusterID, networkID, sourceID, index, index.observedGateway || index.observedHTTPRoute, resolvers)
}

func projectSnapshot(clusterID, networkID, sourceID string, index objectIndex, gatewayCovered bool, resolvers []discovery.IdentityReferenceResolver) (graph.Input, error) {
	var input graph.Input
	for _, item := range index.items {
		if !includeGraphResource(item) || isGatewayResource(item) && !gatewayCovered {
			continue
		}
		itemAttributes, err := projectionAttributes(item, index)
		if err != nil {
			return graph.Input{}, err
		}
		ruleID := "kubernetes.resource.base"
		if item.GetAPIVersion() == "apps/v1" && item.GetKind() == "Deployment" {
			ruleID = "kubernetes.deployment.authoring-context"
		} else if item.GetAPIVersion() == "v1" && item.GetKind() == "Service" {
			ruleID = "kubernetes.service.resource"
		} else if item.GetAPIVersion() == "networking.k8s.io/v1" && item.GetKind() == "Ingress" {
			ruleID = "kubernetes.ingress.resource"
		} else if item.GetAPIVersion() == "networking.k8s.io/v1" && item.GetKind() == "NetworkPolicy" {
			ruleID = "kubernetes.networkpolicy.resource"
		} else if item.GetAPIVersion() == "gateway.networking.k8s.io/v1" && item.GetKind() == "Gateway" {
			ruleID = "kubernetes.gateway.resource"
		} else if item.GetAPIVersion() == "gateway.networking.k8s.io/v1" && item.GetKind() == "HTTPRoute" {
			ruleID = "kubernetes.httproute.resource"
		}
		input.Resources = append(input.Resources, resourceAssertion(clusterID, sourceID, ruleID, item, itemAttributes))
		if err := projectNetworkAddresses(clusterID, networkID, sourceID, item, itemAttributes, &input); err != nil {
			return graph.Input{}, err
		}
	}
	for _, item := range index.items {
		if !includeGraphResource(item) || isGatewayResource(item) && !gatewayCovered {
			continue
		}
		itemClaim := claimFor(clusterID, item)
		for _, owner := range item.GetOwnerReferences() {
			ownerObject, ok := graphOwner(index.byUID, string(owner.UID))
			if ok {
				input.Relationships = append(input.Relationships, relationshipAssertion(sourceID, "kubernetes.owner.instantiates", claimFor(clusterID, ownerObject), graph.PredicateInstantiates, itemClaim, "", nil, ownerObject, item))
			}
		}
		if namespace := index.namespacesByName[item.GetNamespace()]; namespace != nil {
			input.Relationships = append(input.Relationships, relationshipAssertion(sourceID, "kubernetes.namespace.contains", claimFor(clusterID, namespace), graph.PredicateContains, itemClaim, "", nil, namespace, item))
		}
		if len(resolvers) > 0 && item.GetAPIVersion() == "v1" && item.GetKind() == "Node" {
			decoded, err := kubernetesapi.Node(item)
			if err != nil {
				return graph.Input{}, err
			}
			backend, matched, err := discovery.ResolveIdentityReference(decoded.Value.Spec.ProviderID, resolvers...)
			if err != nil {
				return graph.Input{}, fmt.Errorf("resolve Node %s provider ID: %w", item.GetName(), err)
			}
			if matched {
				input.Relationships = append(input.Relationships, relationshipAssertion(sourceID, "kubernetes.node.backed-by-provider", itemClaim, graph.PredicateBackedBy, backend, "provider-id", nil, item))
			}
		}
	}
	for _, pod := range index.items {
		if pod.GetAPIVersion() != "v1" || pod.GetKind() != "Pod" {
			continue
		}
		decoded, err := kubernetesapi.Pod(pod)
		if err != nil {
			return graph.Input{}, err
		}
		accountName := decoded.Value.Spec.ServiceAccountName
		if account := index.serviceAccountsByName[namespacedName(pod.GetNamespace(), accountName)]; account != nil {
			input.Relationships = append(input.Relationships, relationshipAssertion(sourceID, "kubernetes.pod.service-account", claimFor(clusterID, pod), graph.PredicateUsesIdentity, claimFor(clusterID, account), "", nil, pod, account))
		}
		if node := index.nodesByName[decoded.Value.Spec.NodeName]; node != nil {
			input.Relationships = append(input.Relationships, relationshipAssertion(sourceID, "kubernetes.pod.runs-on-node", claimFor(clusterID, pod), graph.PredicateRunsOn, claimFor(clusterID, node), "", nil, pod, node))
		}
	}
	if err := projectServices(clusterID, sourceID, index, &input); err != nil {
		return graph.Input{}, err
	}
	if err := projectIngresses(clusterID, sourceID, index, &input); err != nil {
		return graph.Input{}, err
	}
	if err := projectNetworkPolicies(clusterID, sourceID, index, &input); err != nil {
		return graph.Input{}, err
	}
	if gatewayCovered {
		if err := projectGatewayAPI(clusterID, sourceID, index, &input); err != nil {
			return graph.Input{}, err
		}
	}
	return input, nil
}

// ClaimFor returns the cluster-qualified identity of item.
func ClaimFor(clusterID string, item *unstructured.Unstructured) graph.IdentityClaim {
	return claimFor(clusterID, item)
}

// ClaimForUID returns the cluster-qualified identity of an object known only
// by apiVersion, kind, and UID, for example from telemetry.
func ClaimForUID(clusterID, apiVersion, kind, uid string) graph.IdentityClaim {
	return graph.IdentityClaim{
		Scheme: identityScheme(), AuthorityID: strings.TrimSpace(clusterID),
		ImmutableKey: strings.ToLower(strings.TrimSpace(apiVersion) + "/" + strings.TrimSpace(kind) + "/" + strings.TrimSpace(uid)),
	}
}

func includeGraphResource(item *unstructured.Unstructured) bool {
	if item == nil || string(item.GetUID()) == "" || item.GetKind() == "ReplicaSet" || item.GetKind() == "EndpointSlice" || item.GetKind() == "Event" {
		return false
	}
	return !isIstioOwned(item)
}

func isGatewayResource(item *unstructured.Unstructured) bool {
	return item.GetAPIVersion() == "gateway.networking.k8s.io/v1" && (item.GetKind() == "Gateway" || item.GetKind() == "HTTPRoute")
}

func graphOwner(byUID map[string]*unstructured.Unstructured, uid string) (*unstructured.Unstructured, bool) {
	owner := byUID[uid]
	visited := map[string]bool{uid: true}
	for owner != nil && owner.GetKind() == "ReplicaSet" {
		references := owner.GetOwnerReferences()
		if len(references) == 0 {
			return nil, false
		}
		uid = string(references[0].UID)
		if visited[uid] {
			return nil, false
		}
		visited[uid] = true
		owner = byUID[uid]
	}
	return owner, includeGraphResource(owner)
}

func claimFor(clusterID string, item *unstructured.Unstructured) graph.IdentityClaim {
	return ClaimForUID(clusterID, item.GetAPIVersion(), item.GetKind(), string(item.GetUID()))
}

func attributes(item *unstructured.Unstructured) map[string]string {
	result := map[string]string{"kubernetes/api-version": item.GetAPIVersion(), "kubernetes/name": item.GetName()}
	if item.GetNamespace() != "" {
		result["kubernetes/namespace"] = item.GetNamespace()
	}
	for key, value := range item.GetLabels() {
		result["kubernetes/label/"+key] = value
	}
	if spec, found := item.Object["spec"]; found {
		result["kubernetes/spec-sha256"] = projectkit.Digest(spec)
	}
	if item.GetAPIVersion() == "v1" && item.GetKind() == "Pod" {
		if decoded, err := kubernetesapi.Pod(item); err == nil {
			if decoded.Value.Status.PodIP != "" {
				result["kubernetes/pod-ip"] = decoded.Value.Status.PodIP
			}
			addresses := make([]string, 0, len(decoded.Value.Status.PodIPs)+1)
			addresses = append(addresses, decoded.Value.Status.PodIP)
			for _, podIP := range decoded.Value.Status.PodIPs {
				addresses = append(addresses, podIP.IP)
			}
			setNetworkMetadata(result, graph.NetworkRoleWorkload, addresses)
		}
	}
	if item.GetAPIVersion() == "v1" && item.GetKind() == "Node" {
		if decoded, err := kubernetesapi.Node(item); err == nil && strings.TrimSpace(decoded.Value.Spec.ProviderID) != "" {
			result["kubernetes/provider-id"] = strings.TrimSpace(decoded.Value.Spec.ProviderID)
		}
	}
	return result
}

func namespacedName(namespace, name string) string { return namespace + "/" + name }
func labelsMatch(selector, labels map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}
