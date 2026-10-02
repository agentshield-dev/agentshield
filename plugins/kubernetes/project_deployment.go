package kubernetes

import (
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func addDeploymentAttributes(result map[string]string, item *unstructured.Unstructured) error {
	decoded, err := kubernetesapi.Deployment(item)
	if err != nil {
		return err
	}
	if account := decoded.Value.Spec.Template.Spec.ServiceAccountName; account != "" {
		result["kubernetes/service-account-name"] = account
	}
	// The Pod template digest identifies a workload revision. Annotations are
	// excluded so that `kubectl rollout restart`, which only stamps one, is not
	// a new revision.
	podSpec, _, _ := unstructured.NestedFieldNoCopy(item.Object, "spec", "template", "spec")
	labels, _, _ := unstructured.NestedFieldNoCopy(item.Object, "spec", "template", "metadata", "labels")
	result["kubernetes/pod-template-sha256"] = projectkit.Digest(map[string]any{"labels": labels, "spec": podSpec})
	return nil
}
