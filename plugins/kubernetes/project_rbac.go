package kubernetes

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	maxRBACSubjects             = 32
	maxRBACSubjectsEncodedBytes = 512
)

type rbacSubject struct {
	APIGroup  string `json:"apiGroup,omitempty"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func rbacBindingAttributes(binding *unstructured.Unstructured) (map[string]string, error) {
	result := attributes(binding)
	var roleRef rbacv1.RoleRef
	var subjects []rbacv1.Subject
	switch binding.GetKind() {
	case "RoleBinding":
		decoded, err := kubernetesapi.Decode[rbacv1.RoleBinding](binding)
		if err != nil {
			return nil, err
		}
		roleRef, subjects = decoded.Value.RoleRef, decoded.Value.Subjects
	case "ClusterRoleBinding":
		decoded, err := kubernetesapi.Decode[rbacv1.ClusterRoleBinding](binding)
		if err != nil {
			return nil, err
		}
		roleRef, subjects = decoded.Value.RoleRef, decoded.Value.Subjects
	}
	setStringAttribute(result, "kubernetes/rbac-role-ref-api-group", strings.TrimSpace(roleRef.APIGroup))
	setStringAttribute(result, "kubernetes/rbac-role-ref-kind", strings.TrimSpace(roleRef.Kind))
	setStringAttribute(result, "kubernetes/rbac-role-ref-name", strings.TrimSpace(roleRef.Name))

	normalized := make([]rbacSubject, 0, len(subjects))
	for _, subject := range subjects {
		normalized = append(normalized, rbacSubject{
			APIGroup: strings.TrimSpace(subject.APIGroup), Kind: strings.TrimSpace(subject.Kind),
			Namespace: strings.TrimSpace(subject.Namespace), Name: strings.TrimSpace(subject.Name),
		})
	}
	slices.SortFunc(normalized, func(left, right rbacSubject) int {
		return cmp.Compare(projectkit.MustCanonicalJSON(left), projectkit.MustCanonicalJSON(right))
	})
	normalized = slices.Compact(normalized)
	result["kubernetes/rbac-subjects-sha256"] = projectkit.Digest(normalized)

	kept := make([]rbacSubject, 0, min(len(normalized), maxRBACSubjects))
	for _, subject := range normalized[:min(len(normalized), maxRBACSubjects)] {
		candidate := append(slices.Clone(kept), subject)
		if len(projectkit.MustCanonicalJSON(candidate)) > maxRBACSubjectsEncodedBytes {
			break
		}
		kept = candidate
	}
	if len(kept) > 0 {
		result["kubernetes/rbac-subjects"] = projectkit.MustCanonicalJSON(kept)
	}
	if omitted := len(normalized) - len(kept); omitted > 0 {
		result["kubernetes/rbac-subjects-omitted"] = strconv.Itoa(omitted)
	}
	return result, nil
}
