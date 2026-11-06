package kubernetes

import (
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestProjectRBACBindingContextIsBoundedSortedAndDeterministic(t *testing.T) {
	subjects := make([]any, 40)
	for index := range subjects {
		subjects[index] = map[string]any{
			"apiGroup": "rbac.authorization.k8s.io", "kind": "User",
			"name": "attendee-" + strconv.Itoa(100-index),
		}
	}
	roleBinding := testObject("rbac.authorization.k8s.io/v1", "RoleBinding", "demo", "readers", "role-binding", map[string]any{
		"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
		"subjects": []any{map[string]any{"kind": "ServiceAccount", "namespace": "demo", "name": "api"}},
	})
	clusterRoleBinding := testObject("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "platform-admin", "cluster-role-binding", map[string]any{
		"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
		"subjects": subjects,
	})
	clusterRoleBinding.SetResourceVersion("10")

	input, err := Project("cluster", "source", []*unstructured.Unstructured{clusterRoleBinding, roleBinding})
	if err != nil {
		t.Fatal(err)
	}
	role := resourceOfKind(t, input, "kubernetes/rolebinding")
	if role.RuleID != "kubernetes.rbac-binding.resource" || role.Attributes["kubernetes/rbac-role-ref-kind"] != "Role" || role.Attributes["kubernetes/rbac-role-ref-name"] != "reader" {
		t.Fatalf("RoleBinding context = %#v", role)
	}
	binding := resourceOfKind(t, input, "kubernetes/clusterrolebinding")
	attributes := binding.Attributes
	if attributes["kubernetes/rbac-role-ref-api-group"] != "rbac.authorization.k8s.io" || attributes["kubernetes/rbac-role-ref-kind"] != "ClusterRole" || attributes["kubernetes/rbac-role-ref-name"] != "cluster-admin" {
		t.Fatalf("role reference = %#v", attributes)
	}
	if attributes["kubernetes/rbac-subjects-sha256"] == "" {
		t.Fatal("subject digest is missing")
	}
	if len(attributes["kubernetes/rbac-subjects"]) > maxRBACSubjectsEncodedBytes {
		t.Fatalf("subjects bytes = %d", len(attributes["kubernetes/rbac-subjects"]))
	}
	var projected []rbacSubject
	if err := json.Unmarshal([]byte(attributes["kubernetes/rbac-subjects"]), &projected); err != nil {
		t.Fatal(err)
	}
	omitted, err := strconv.Atoi(attributes["kubernetes/rbac-subjects-omitted"])
	if err != nil || len(projected) == 0 || len(projected) > maxRBACSubjects || omitted != len(subjects)-len(projected) {
		t.Fatalf("subjects=%d omitted=%q err=%v", len(projected), attributes["kubernetes/rbac-subjects-omitted"], err)
	}
	if !slices.IsSortedFunc(projected, func(left, right rbacSubject) int {
		if left.APIGroup != right.APIGroup {
			return cmp.Compare(left.APIGroup, right.APIGroup)
		}
		if left.Kind != right.Kind {
			return cmp.Compare(left.Kind, right.Kind)
		}
		if left.Namespace != right.Namespace {
			return cmp.Compare(left.Namespace, right.Namespace)
		}
		return cmp.Compare(left.Name, right.Name)
	}) {
		t.Fatalf("subjects are not sorted: %#v", projected)
	}

	slices.Reverse(subjects)
	reversed := testObject("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "platform-admin", "cluster-role-binding", map[string]any{
		"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
		"subjects": subjects,
	})
	reversed.SetResourceVersion("10")
	reversedInput, err := Project("cluster", "source", []*unstructured.Unstructured{reversed})
	if err != nil {
		t.Fatal(err)
	}
	if got := resourceOfKind(t, reversedInput, "kubernetes/clusterrolebinding").Attributes; !maps.Equal(got, attributes) {
		t.Fatalf("reordered subjects changed projection: got=%#v want=%#v", got, attributes)
	}
	replaced := slices.Clone(subjects)
	for index, subject := range replaced {
		if subject.(map[string]any)["name"] == "attendee-99" {
			replaced[index] = map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "zzzz-replaced-omitted-subject"}
			break
		}
	}
	replacedBinding := testObject("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "platform-admin", "cluster-role-binding", map[string]any{
		"roleRef": map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"}, "subjects": replaced,
	})
	replacedBinding.SetResourceVersion("11")
	replacedInput, err := Project("cluster", "source", []*unstructured.Unstructured{replacedBinding})
	if err != nil {
		t.Fatal(err)
	}
	replacedAttributes := resourceOfKind(t, replacedInput, "kubernetes/clusterrolebinding").Attributes
	if replacedAttributes["kubernetes/rbac-subjects"] != attributes["kubernetes/rbac-subjects"] || replacedAttributes["kubernetes/rbac-subjects-omitted"] != attributes["kubernetes/rbac-subjects-omitted"] || replacedAttributes["kubernetes/rbac-subjects-sha256"] == attributes["kubernetes/rbac-subjects-sha256"] {
		t.Fatalf("omitted subject replacement was not revision-sensitive: got=%#v want retained subjects unchanged", replacedAttributes)
	}
	if replacedAttributes[graph.ResourceAuthoringContextAttribute] == attributes[graph.ResourceAuthoringContextAttribute] {
		t.Fatal("an omitted subject replacement did not change the source revision")
	}
	before := state.ResourceAuthoringContextFor(graph.Resource{ID: "binding", Kind: binding.Kind, Assertions: []graph.ResourceAssertion{binding}})
	afterAssertion := resourceOfKind(t, replacedInput, "kubernetes/clusterrolebinding")
	after := state.ResourceAuthoringContextFor(graph.Resource{ID: "binding", Kind: afterAssertion.Kind, Assertions: []graph.ResourceAssertion{afterAssertion}})
	if before.ContextSHA256 == after.ContextSHA256 || string(before.Context) != string(after.Context) || !maps.Equal(before.Attributes, after.Attributes) {
		t.Fatalf("source revision changed model context: before=%#v after=%#v", before, after)
	}
}
