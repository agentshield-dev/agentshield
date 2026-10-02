package istio

import (
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// PluginID is the plugin and contribution owner ID.
const PluginID = "istio"

// Project projects bare objects with the cluster ID as network ID and the
// default istio-system root namespace. It exists for tests and offline
// evaluation; the plugin uses [ProjectObserved] with collection event IDs.
func Project(clusterID, sourceID string, objects []*unstructured.Unstructured) (graph.Input, error) {
	return ProjectForNetwork(clusterID, clusterID, "istio-system", sourceID, objects)
}

// ProjectForNetwork is [Project] with an explicit network ID and root
// namespace.
func ProjectForNetwork(clusterID, networkID, rootNamespace, sourceID string, objects []*unstructured.Unstructured) (graph.Input, error) {
	observations := make([]ObservedObject, 0, len(objects))
	for _, object := range objects {
		if object != nil {
			observations = append(observations, ObservedObject{Key: projectkit.ObjectKey(object), Object: object, EventID: evidenceID(object), Revision: object.GetResourceVersion()})
		}
	}
	result, err := ProjectObserved(ProjectionContext{ClusterID: clusterID, NetworkID: networkID, SourceID: sourceID, RootNamespace: rootNamespace}, observations)
	return result.Input, err
}

func effectiveLabel(resource, namespace map[string]string, key string) string {
	if value, ok := resource[key]; ok {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return strings.ToLower(strings.TrimSpace(namespace[key]))
}

func labelsMatch(selector, labels map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

// evidenceID names a bare object for [Project] by UID only. Live projection
// uses the Kubernetes plugin's event IDs instead, so this format is not shared
// with [projectkit.KubernetesEvidenceID].
func evidenceID(item *unstructured.Unstructured) string { return "kubernetes:" + string(item.GetUID()) }
