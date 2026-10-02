package cilium

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const remediationTestGraphSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestCiliumRemediationLifecycleDeclaresIsolation(t *testing.T) {
	pod := ciliumTestPod("target-uid", map[string]string{"app": "target"})
	base := ciliumFake(pod)
	transport := &ciliumDryRunTransport{Interface: base}
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, transport)})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	proposal := ciliumProposal(t, "target-uid")
	executor, err := remediation.NewExecutor(registry, ciliumGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, ciliumRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !transport.observedDryRun || len(preparation.ProviderState) != 2 {
		t.Fatalf("preparation = %#v", preparation)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
	verification, err := executor.Verify(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Satisfied {
		t.Fatalf("declaration verification = %#v", verification)
	}
	policy, err := base.Resource(ciliumNetworkPoliciesGVR).Namespace("demo").Get(context.Background(), ciliumPolicyName("target-uid"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ingress, found, err := unstructured.NestedSlice(policy.Object, "spec", "ingress")
	if err != nil || !found || len(ingress) != 0 {
		t.Fatalf("declared ingress = %#v found=%t err=%v", ingress, found, err)
	}
}

func TestCiliumProjectorOnlyConstructionAdvertisesNoRemediationAction(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source"})
	if err != nil {
		t.Fatal(err)
	}
	if actions := plugin.RemediationDescriptor().Actions; len(actions) != 0 {
		t.Fatalf("actions = %#v, want none without mutation transport", actions)
	}
}

func TestCiliumRemediationRejectsUIDReplacementAndOverlaps(t *testing.T) {
	pod := ciliumTestPod("replacement-uid", map[string]string{"app": "target"})
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, ciliumFake(pod))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), ciliumProposal(t, "target-uid"), ciliumRemediationActionID); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("UID replacement error = %v", err)
	}

	pod = ciliumTestPod("target-uid", map[string]string{"app": "target"})
	overlap := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
		"metadata": map[string]any{"name": "existing", "namespace": "demo", "uid": "policy-uid", "resourceVersion": "1"},
		"spec":     map[string]any{"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "target"}}, "ingress": []any{}},
	}}
	plugin, err = New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, ciliumFake(pod, overlap))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), ciliumProposal(t, "target-uid"), ciliumRemediationActionID); err == nil || !strings.Contains(err.Error(), "already selects") {
		t.Fatalf("overlap error = %v", err)
	}
}

func TestCiliumRemediationRejectsSpoofedManagedPolicyDrift(t *testing.T) {
	pod := ciliumTestPod("target-uid", map[string]string{"app": "target"})
	policy := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name": ciliumPolicyName("target-uid"), "namespace": "demo",
			"labels": map[string]any{ciliumManagedByLabel: "agentshield"}, "annotations": map[string]any{ciliumTargetUIDAnnotation: "target-uid"},
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{ciliumTargetLabel: kubernetesplugin.RemediationTargetValue("target-uid")}},
			"ingress":          []any{map[string]any{}},
		},
	}}
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, ciliumFake(pod, policy))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), ciliumProposal(t, "target-uid"), ciliumRemediationActionID); err == nil || !strings.Contains(err.Error(), "drifted controlled content") {
		t.Fatalf("spoofed managed policy error = %v", err)
	}
}

func TestCiliumRemediationReusesIdenticalExistingManagedPolicy(t *testing.T) {
	uid := "target-uid"
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, ciliumFake(ciliumTestPod(uid, map[string]string{"app": "target"}), ciliumManagedPolicy(uid)))})
	if err != nil {
		t.Fatal(err)
	}
	proposal := ciliumProposal(t, uid)
	plan, err := plugin.Plan(context.Background(), proposal, ciliumRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Prepare(context.Background(), proposal, plan); err != nil {
		t.Fatal(err)
	}
}

func TestCiliumRemediationRejectsProspectiveOverlapsAcrossPolicyForms(t *testing.T) {
	value := kubernetesplugin.RemediationTargetValue("target-uid")
	tests := []struct {
		name   string
		policy *unstructured.Unstructured
	}{
		{name: "kubernetes network policy", policy: ciliumKubeNetworkPolicy("kube-future", metav1.LabelSelector{MatchLabels: map[string]string{ciliumTargetLabel: value}})},
		{name: "CNP spec prefixed label", policy: ciliumPolicyObject("CiliumNetworkPolicy", "cnp-spec", "demo", map[string]any{"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{"k8s:app": "target"}}, "ingress": []any{},
		}})},
		{name: "CNP specs namespace expression", policy: ciliumPolicyObject("CiliumNetworkPolicy", "cnp-specs", "demo", map[string]any{"specs": []any{map[string]any{
			"endpointSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "k8s:io.kubernetes.pod.namespace", "operator": "In", "values": []any{"demo"}}}}, "ingress": []any{},
		}}})},
		{name: "CCNP spec cluster", policy: ciliumPolicyObject("CiliumClusterwideNetworkPolicy", "ccnp-spec", "", map[string]any{"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{"k8s:io.cilium.k8s.policy.cluster": "cluster"}}, "ingressDeny": []any{},
		}})},
		{name: "CCNP specs prospective label expression", policy: ciliumPolicyObject("CiliumClusterwideNetworkPolicy", "ccnp-specs", "", map[string]any{"specs": []any{map[string]any{
			"endpointSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "k8s:" + ciliumTargetLabel, "operator": "In", "values": []any{value}}}}, "ingress": []any{},
		}}})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, ciliumFake(ciliumTestPod("target-uid", map[string]string{"app": "target"}), test.policy))})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := plugin.Plan(context.Background(), ciliumProposal(t, "target-uid"), ciliumRemediationActionID); err == nil || !strings.Contains(err.Error(), "already selects") {
				t.Fatalf("overlap error = %v", err)
			}
		})
	}
}

func TestCiliumPolicyDigestIncludesSpecs(t *testing.T) {
	left := ciliumPolicyObject("CiliumNetworkPolicy", "policy", "demo", map[string]any{
		"spec":  map[string]any{"endpointSelector": map[string]any{}},
		"specs": []any{map[string]any{"ingress": []any{}}},
	})
	right := left.DeepCopy()
	right.Object["specs"] = []any{map[string]any{"ingressDeny": []any{}}}

	leftDigest, err := ciliumPolicyDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := ciliumPolicyDigest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest == rightDigest {
		t.Fatal("policy digest ignored specs")
	}
}

func TestCiliumRemediationFailsClosedOnMalformedSelectorAndListError(t *testing.T) {
	malformed := ciliumPolicyObject("CiliumClusterwideNetworkPolicy", "malformed", "", map[string]any{"spec": map[string]any{
		"endpointSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "app", "operator": "Invalid"}}}, "ingress": []any{},
	}})
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, ciliumFake(ciliumTestPod("target-uid", map[string]string{"app": "target"}), malformed))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), ciliumProposal(t, "target-uid"), ciliumRemediationActionID); err == nil || !strings.Contains(err.Error(), "endpointSelector") {
		t.Fatalf("malformed selector error = %v", err)
	}

	client := ciliumFake(ciliumTestPod("target-uid", map[string]string{"app": "target"})).(*dynamicfake.FakeDynamicClient)
	client.PrependReactor("list", "ciliumclusterwidenetworkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	plugin, err = New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, client)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), ciliumProposal(t, "target-uid"), ciliumRemediationActionID); err == nil || !strings.Contains(err.Error(), "list CiliumClusterwideNetworkPolicies") {
		t.Fatalf("list error = %v", err)
	}
}

func TestCiliumRemediationRejectsDriftAndAdmissionMutation(t *testing.T) {
	base := ciliumFake(ciliumTestPod("target-uid", map[string]string{"app": "target"}))
	transport := &ciliumDryRunTransport{Interface: base}
	plugin, _ := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, transport)})
	registry, _ := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	proposal := ciliumProposal(t, "target-uid")
	executor, _ := remediation.NewExecutor(registry, ciliumGraphSource(proposal))
	plan, err := executor.Plan(context.Background(), proposal, PluginID, ciliumRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	pod, err := base.Resource(ciliumPodsGVR).Namespace("demo").Get(context.Background(), "target", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.SetLabels(map[string]string{"app": "changed"})
	if _, err := base.Resource(ciliumPodsGVR).Namespace("demo").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err == nil {
		t.Fatal("apply accepted provider drift")
	}

	mutating := &ciliumDryRunTransport{Interface: ciliumFake(ciliumTestPod("target-uid", map[string]string{"app": "target"})), mutate: func(resource string, object *unstructured.Unstructured) {
		if resource == ciliumNetworkPoliciesGVR.Resource {
			object.Object["specs"] = []any{map[string]any{"endpointSelector": map[string]any{}, "ingress": []any{}}}
		}
	}}
	plugin, _ = New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, mutating)})
	plan, err = plugin.Plan(context.Background(), proposal, ciliumRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Prepare(context.Background(), proposal, plan); err == nil || !strings.Contains(err.Error(), "admission mutated") {
		t.Fatalf("admission error = %v", err)
	}
}

func TestCiliumRemediationRejectsSpecsDriftBetweenDryRunAndApply(t *testing.T) {
	uid := "target-uid"
	policy := ciliumManagedPolicy(uid)
	base := ciliumFake(ciliumTestPod(uid, map[string]string{"app": "target"}), policy)
	transport := &ciliumDryRunTransport{Interface: base}
	plugin, _ := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, transport)})
	proposal := ciliumProposal(t, uid)
	plan, err := plugin.Plan(context.Background(), proposal, ciliumRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := plugin.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}

	current, err := base.Resource(ciliumNetworkPoliciesGVR).Namespace("demo").Get(context.Background(), policy.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current.Object["specs"] = []any{map[string]any{"endpointSelector": map[string]any{}, "ingressDeny": []any{}}}
	if _, err := base.Resource(ciliumNetworkPoliciesGVR).Namespace("demo").Update(context.Background(), current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Execute(context.Background(), proposal, plan, preparation); err == nil || !strings.Contains(err.Error(), "drifted controlled content") {
		t.Fatalf("apply error = %v", err)
	}
}

func TestCiliumRemediationVerifyDetectsSpecsDrift(t *testing.T) {
	base := ciliumFake(ciliumTestPod("target-uid", map[string]string{"app": "target"}))
	transport := &ciliumDryRunTransport{Interface: base}
	plugin, _ := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, transport)})
	proposal := ciliumProposal(t, "target-uid")
	plan, err := plugin.Plan(context.Background(), proposal, ciliumRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := plugin.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := plugin.Execute(context.Background(), proposal, plan, preparation)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, policyState, err := plugin.remediationAction().DecodeStates(result.ProviderState)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := base.Resource(ciliumNetworkPoliciesGVR).Namespace(policyState.Namespace).Get(context.Background(), policyState.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	policy.Object["specs"] = []any{map[string]any{"endpointSelector": map[string]any{}, "ingress": []any{}}}
	if _, err := base.Resource(ciliumNetworkPoliciesGVR).Namespace(policyState.Namespace).Update(context.Background(), policy, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	verification, err := plugin.Verify(context.Background(), proposal, plan, result)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Satisfied {
		t.Fatal("verification ignored specs drift")
	}
}

func TestCiliumRemediationRollsBackPodLabelOnPolicyFailure(t *testing.T) {
	base := ciliumFake(ciliumTestPod("target-uid", map[string]string{"app": "target"}))
	transport := &ciliumDryRunTransport{Interface: base, failPolicyApply: true}
	plugin, _ := New(Config{ClusterID: "cluster", SourceID: "source", Actions: ciliumActions(t, transport)})
	registry, _ := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	proposal := ciliumProposal(t, "target-uid")
	executor, _ := remediation.NewExecutor(registry, ciliumGraphSource(proposal))
	plan, err := executor.Plan(context.Background(), proposal, PluginID, ciliumRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("apply error = %v", err)
	}
	pod, err := base.Resource(ciliumPodsGVR).Namespace("demo").Get(context.Background(), "target", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := pod.GetLabels()[ciliumTargetLabel]; found {
		t.Fatal("Cilium target label remained after rollback")
	}
}

type ciliumDryRunTransport struct {
	dynamic.Interface
	observedDryRun  bool
	failPolicyApply bool
	mutate          func(string, *unstructured.Unstructured)
}

func ciliumActions(t *testing.T, client dynamic.Interface) kubernetesplugin.WriteTransport {
	t.Helper()
	transport, err := kubernetesplugin.NewDynamicTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func (client *ciliumDryRunTransport) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &ciliumNamespaceable{NamespaceableResourceInterface: client.Interface.Resource(gvr), client: client, resource: gvr.Resource}
}

type ciliumNamespaceable struct {
	dynamic.NamespaceableResourceInterface
	client   *ciliumDryRunTransport
	resource string
}

func (resource *ciliumNamespaceable) Namespace(namespace string) dynamic.ResourceInterface {
	return &ciliumResource{ResourceInterface: resource.NamespaceableResourceInterface.Namespace(namespace), client: resource.client, resource: resource.resource}
}

type ciliumResource struct {
	dynamic.ResourceInterface
	client   *ciliumDryRunTransport
	resource string
}

func (resource *ciliumResource) Create(ctx context.Context, object *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if slices.Contains(options.DryRun, metav1.DryRunAll) {
		resource.client.observedDryRun = true
		result := object.DeepCopy()
		if resource.client.mutate != nil {
			resource.client.mutate(resource.resource, result)
		}
		return result, nil
	}
	if resource.resource == ciliumNetworkPoliciesGVR.Resource && resource.client.failPolicyApply {
		return nil, errors.New("injected policy failure")
	}
	return resource.ResourceInterface.Create(ctx, object, options, subresources...)
}
func (resource *ciliumResource) Update(ctx context.Context, object *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if slices.Contains(options.DryRun, metav1.DryRunAll) {
		resource.client.observedDryRun = true
		result := object.DeepCopy()
		if resource.client.mutate != nil {
			resource.client.mutate(resource.resource, result)
		}
		return result, nil
	}
	return resource.ResourceInterface.Update(ctx, object, options, subresources...)
}

func ciliumFake(objects ...runtime.Object) dynamic.Interface {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		ciliumPodsGVR: "PodList", ciliumNetworkPoliciesGVR: "CiliumNetworkPolicyList", ciliumClusterwidePoliciesGVR: "CiliumClusterwideNetworkPolicyList", ciliumKubePoliciesGVR: "NetworkPolicyList",
	}, objects...)
}

func ciliumTestPod(uid string, labels map[string]string) *unstructured.Unstructured {
	pod := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "target", "namespace": "demo", "uid": uid, "resourceVersion": "1"}}}
	pod.SetUID(types.UID(uid))
	pod.SetLabels(labels)
	return pod
}

func ciliumPolicyObject(kind, name, namespace string, fields map[string]any) *unstructured.Unstructured {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": namespace, "uid": name + "-uid", "resourceVersion": "1"},
	}}
	for key, value := range fields {
		object.Object[key] = value
	}
	return object
}

func ciliumManagedPolicy(uid string) *unstructured.Unstructured {
	value := kubernetesplugin.RemediationTargetValue(uid)
	return ciliumPolicyObject("CiliumNetworkPolicy", ciliumPolicyName(uid), "demo", map[string]any{
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{ciliumTargetLabel: value}},
			"ingress":          []any{},
		},
		"metadata": map[string]any{
			"name": ciliumPolicyName(uid), "namespace": "demo", "uid": "policy-uid", "resourceVersion": "1",
			"labels": map[string]any{ciliumManagedByLabel: "agentshield"}, "annotations": map[string]any{ciliumTargetUIDAnnotation: uid},
		},
	})
}

func ciliumKubeNetworkPolicy(name string, selector metav1.LabelSelector) *unstructured.Unstructured {
	policy := &networkingv1.NetworkPolicy{TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: selector, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}}
	object, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(policy)
	return &unstructured.Unstructured{Object: object}
}

func ciliumProposal(t *testing.T, uid string) remediation.Proposal {
	t.Helper()
	proposal, err := remediation.NewProposal("finding", "analysis", remediationTestGraphSHA256,
		remediation.Suggestion{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}},
		remediation.Target{EntityID: "target", Kind: "kubernetes/pod", Identity: kubernetesplugin.ClaimForUID("cluster", "v1", "Pod", uid)}, []string{"evidence"})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func ciliumGraphSource(proposal remediation.Proposal) remediation.GraphSourceFunc {
	return func(context.Context) (remediation.GraphView, error) {
		return remediation.GraphView{SHA256: proposal.GraphSHA256, Snapshot: graph.Snapshot{Resources: []graph.Resource{{ID: proposal.Target.EntityID, Kind: proposal.Target.Kind, Identity: proposal.Target.Identity}}}}, nil
	}
}
