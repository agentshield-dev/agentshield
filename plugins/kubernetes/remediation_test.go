package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

const remediationTestGraphSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestKubernetesRemediationPrepareExecuteVerifyAndIdempotency(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target", "instance": "only"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod)
	recordingClient := &dryRunRecordingDynamic{Interface: client}
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: recordingClient}}
	proposal := kubernetesRemediationProposal(t, "target-uid")
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := remediation.NewExecutor(registry, kubernetesGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, "source", podRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
	if !recordingClient.observed {
		t.Fatal("Kubernetes dry-run did not use DryRunAll")
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
	verification, err := executor.Verify(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Satisfied {
		t.Fatal("remediation did not verify")
	}
	policies, err := client.Resource(networkPoliciesGVR).Namespace("demo").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(policies.Items) != 1 {
		t.Fatalf("NetworkPolicies = %d, want 1", len(policies.Items))
	}
	ingress, found, err := unstructured.NestedSlice(policies.Items[0].Object, "spec", "ingress")
	if err != nil || !found || len(ingress) != 0 {
		t.Fatalf("ingress isolation = %#v, found = %v, err = %v", ingress, found, err)
	}
	policyTypes, found, err := unstructured.NestedStringSlice(policies.Items[0].Object, "spec", "policyTypes")
	if err != nil || !found || !slices.Equal(policyTypes, []string{"Ingress"}) {
		t.Fatalf("policy types = %v, found = %v, err = %v", policyTypes, found, err)
	}
}

type dryRunRecordingDynamic struct {
	dynamic.Interface
	observed        bool
	mutate          func(*unstructured.Unstructured, bool)
	failPolicyApply bool
	// cancelOnPolicyFailure is called when an injected policy failure fires,
	// to model a client disconnect in the middle of execution.
	cancelOnPolicyFailure context.CancelFunc
	operations            []string
}

func (client *dryRunRecordingDynamic) Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &dryRunRecordingNamespaceable{NamespaceableResourceInterface: client.Interface.Resource(resource), client: client, resource: resource.Resource}
}

type dryRunRecordingNamespaceable struct {
	dynamic.NamespaceableResourceInterface
	client   *dryRunRecordingDynamic
	resource string
}

func (resource *dryRunRecordingNamespaceable) Namespace(namespace string) dynamic.ResourceInterface {
	return &dryRunRecordingResource{ResourceInterface: resource.NamespaceableResourceInterface.Namespace(namespace), client: resource.client, resource: resource.resource}
}

type dryRunRecordingResource struct {
	dynamic.ResourceInterface
	client   *dryRunRecordingDynamic
	resource string
}

func (resource *dryRunRecordingResource) Create(ctx context.Context, object *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	dryRun := slices.Contains(options.DryRun, metav1.DryRunAll)
	resource.client.operations = append(resource.client.operations, fmt.Sprintf("%t:create:%s", dryRun, resource.resource))
	if dryRun {
		resource.client.observed = true
		result := object.DeepCopy()
		resource.mutate(result, true)
		return result, nil
	}
	if resource.resource == networkPoliciesGVR.Resource && resource.client.failPolicyApply {
		if resource.client.cancelOnPolicyFailure != nil {
			resource.client.cancelOnPolicyFailure()
		}
		return nil, errors.New("injected NetworkPolicy create failure")
	}
	result, err := resource.ResourceInterface.Create(ctx, object, options, subresources...)
	if err == nil {
		resource.mutate(result, false)
	}
	return result, err
}

func (resource *dryRunRecordingResource) Update(ctx context.Context, object *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	dryRun := slices.Contains(options.DryRun, metav1.DryRunAll)
	resource.client.operations = append(resource.client.operations, fmt.Sprintf("%t:update:%s", dryRun, resource.resource))
	if dryRun {
		resource.client.observed = true
		result := object.DeepCopy()
		resource.mutate(result, true)
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := resource.ResourceInterface.Update(ctx, object, options, subresources...)
	if err == nil {
		resource.mutate(result, false)
	}
	return result, err
}

func (resource *dryRunRecordingResource) mutate(object *unstructured.Unstructured, dryRun bool) {
	if resource.client.mutate != nil {
		resource.client.mutate(object, dryRun)
	}
}

func TestKubernetesRemediationSelectsOnlyLabeledTargetAndRejectsStaleUID(t *testing.T) {
	first := remediationPod("target-uid", "target", map[string]string{"app": "shared"})
	second := remediationPod("other-uid", "other", map[string]string{"app": "shared"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, first, second)
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
	desired, err := plugin.desiredRemediation(context.Background(), kubernetesRemediationProposal(t, "target-uid"))
	if err != nil {
		t.Fatal(err)
	}
	selector, found, err := unstructured.NestedStringMap(desired.policy.Object, "spec", "podSelector", "matchLabels")
	if err != nil || !found || len(selector) != 1 || selector[remediationTargetLabel] != remediationTargetValue("target-uid") {
		t.Fatalf("exact remediation selector = %#v, found = %t, err = %v", selector, found, err)
	}
	if _, err := plugin.Plan(context.Background(), kubernetesRemediationProposal(t, "stale-uid"), podRemediationActionID); err == nil {
		t.Fatal("plan accepted a stale Pod UID")
	}
}

func TestKubernetesRemediationBindsTrustedOwnershipAndProposalCapability(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target", "instance": "only"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod)
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
	actions := plugin.RemediationDescriptor().Actions
	descriptor := plugin.RemediationDescriptor()
	if len(actions) != 2 || actions[0].ID != podRemediationActionID || actions[0].TargetKind != "kubernetes/pod" || actions[1].ID != serviceRemediationActionID || actions[1].TargetKind != "kubernetes/service" {
		t.Fatalf("remediation descriptor = %#v", descriptor)
	}
	for _, test := range []struct {
		name            string
		target          remediation.Target
		constructorFail bool
	}{
		{name: "authority", target: remediation.Target{EntityID: "target", Identity: ClaimForUID("other-cluster", "v1", "Pod", "target-uid"), Kind: "kubernetes/pod"}},
		{name: "kind", target: remediation.Target{EntityID: "target", Identity: ClaimForUID("cluster", "v1", "Pod", "target-uid"), Kind: "kubernetes/service"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			proposal, err := remediation.NewProposal("finding", "analysis", remediationTestGraphSHA256,
				remediation.Suggestion{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}},
				test.target, []string{"evidence"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := plugin.Plan(context.Background(), proposal, podRemediationActionID); err == nil || !strings.Contains(err.Error(), "supported by this Kubernetes provider") {
				t.Fatalf("capability error = %v", err)
			}
		})
	}
}

func TestKubernetesServiceRemediationPrepareExecuteVerify(t *testing.T) {
	service := remediationService("service-uid", "target", map[string]string{"app": "target"})
	pod := remediationPod("pod-uid", "target-pod", map[string]string{"app": "target"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		servicesGVR: "ServiceList", podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, service, pod)
	recordingClient := &dryRunRecordingDynamic{Interface: client}
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: recordingClient}}
	proposal := kubernetesServiceRemediationProposal(t, "service-uid")
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := remediation.NewExecutor(registry, kubernetesGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, "source", serviceRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
	verification, err := executor.Verify(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Satisfied || !recordingClient.observed {
		t.Fatalf("verification = %#v, dry-run observed = %t", verification, recordingClient.observed)
	}
	policies, err := client.Resource(networkPoliciesGVR).Namespace("demo").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(policies.Items) != 1 {
		t.Fatalf("NetworkPolicies = %d, want 1", len(policies.Items))
	}
	selector, found, err := unstructured.NestedStringMap(policies.Items[0].Object, "spec", "podSelector", "matchLabels")
	if err != nil || !found || !maps.Equal(selector, map[string]string{"app": "target"}) {
		t.Fatalf("Service remediation selector = %#v, found = %t, err = %v", selector, found, err)
	}
	currentPod, err := client.Resource(podsGVR).Namespace("demo").Get(context.Background(), "target-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := currentPod.GetLabels()[remediationTargetLabel]; found {
		t.Fatal("Service remediation labeled a Pod")
	}
}

func TestKubernetesRemediationRejectsOverlappingIngressPolicyAcrossLifecycle(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target", "instance": "only"})
	overlap := remediationNetworkPolicy(t, "existing-ingress", map[string]string{"app": "target"}, networkingv1.PolicyTypeIngress)
	t.Run("plan", func(t *testing.T) {
		client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
		}, pod.DeepCopy(), overlap.DeepCopy())
		plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
		if _, err := plugin.Plan(context.Background(), kubernetesRemediationProposal(t, "target-uid"), podRemediationActionID); err == nil || !strings.Contains(err.Error(), "already selects") {
			t.Fatalf("overlapping plan error = %v", err)
		}
	})

	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod.DeepCopy())
	recordingClient := &dryRunRecordingDynamic{Interface: client}
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: recordingClient}}
	proposal := kubernetesRemediationProposal(t, "target-uid")
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := remediation.NewExecutor(registry, kubernetesGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, podRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	policies := client.Resource(networkPoliciesGVR).Namespace("demo")
	createOverlap := func() {
		t.Helper()
		if _, err := policies.Create(context.Background(), overlap.DeepCopy(), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	deleteOverlap := func() {
		t.Helper()
		if err := policies.Delete(context.Background(), overlap.GetName(), metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	createOverlap()
	if _, err := executor.Prepare(context.Background(), proposal, plan); err == nil || !strings.Contains(err.Error(), "already selects") {
		t.Fatalf("overlapping dry-run error = %v", err)
	}
	deleteOverlap()
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	createOverlap()
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err == nil || !strings.Contains(err.Error(), "already selects") {
		t.Fatalf("overlapping apply error = %v", err)
	}
	deleteOverlap()
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
	createOverlap()
	verification, err := executor.Verify(context.Background(), proposal, plan)
	if err != nil || !verification.Satisfied {
		t.Fatalf("postcondition verification = %+v, err = %v", verification, err)
	}
}

func TestKubernetesRemediationOverlapPreflightUsesIngressDefaultsAndSelectors(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target", "instance": "only"})
	tests := []struct {
		name     string
		selector metav1.LabelSelector
		types    []networkingv1.PolicyType
		wantErr  bool
	}{
		{name: "omitted policy types and empty selector", selector: metav1.LabelSelector{}, wantErr: true},
		{name: "omitted policy types and expression selector", selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"target"}}}}, wantErr: true},
		{name: "explicit egress only", selector: metav1.LabelSelector{}, types: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := remediationNetworkPolicyWithSpec(t, "existing", networkingv1.NetworkPolicySpec{PodSelector: test.selector, PolicyTypes: test.types})
			client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
				podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
			}, pod.DeepCopy(), policy)
			plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
			_, err := plugin.Plan(context.Background(), kubernetesRemediationProposal(t, "target-uid"), podRemediationActionID)
			if (err != nil) != test.wantErr {
				t.Fatalf("plan error = %v, want error = %t", err, test.wantErr)
			}
		})
	}
}

func TestKubernetesRemediationRejectsPolicySelectingFutureRemediationLabel(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target"})
	policy := remediationNetworkPolicy(t, "future-label", map[string]string{remediationTargetLabel: remediationTargetValue("target-uid")}, networkingv1.PolicyTypeIngress)
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod, policy)
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
	if _, err := plugin.Plan(context.Background(), kubernetesRemediationProposal(t, "target-uid"), podRemediationActionID); err == nil || !strings.Contains(err.Error(), "already selects") {
		t.Fatalf("future-label conflict error = %v", err)
	}
}

func TestKubernetesRemediationRejectsAdmissionMutationOnCreate(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		t.Run(fmt.Sprintf("dry-run=%t", dryRun), func(t *testing.T) {
			pod := remediationPod("target-uid", "target", map[string]string{"app": "target", "instance": "only"})
			client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
				podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
			}, pod)
			recording := &dryRunRecordingDynamic{Interface: client, mutate: func(object *unstructured.Unstructured, returnedDryRun bool) {
				if returnedDryRun == dryRun {
					_ = unstructured.SetNestedStringSlice(object.Object, []string{"Egress"}, "spec", "policyTypes")
				}
			}}
			plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: recording}}
			desiredRemediation, err := plugin.desiredRemediation(context.Background(), kubernetesRemediationProposal(t, "target-uid"))
			if err != nil {
				t.Fatal(err)
			}
			desired := desiredRemediation.policy
			if _, err := plugin.writeNetworkPolicy(context.Background(), desired, dryRun); err == nil || !strings.Contains(err.Error(), "admission mutated") {
				t.Fatalf("write error = %v", err)
			}
		})
	}
}

func TestKubernetesRemediationRejectsTargetLabelDriftOrReplacement(t *testing.T) {
	t.Run("label drift", func(t *testing.T) {
		pod := remediationPod("target-uid", "target", map[string]string{"app": "target", "instance": "only"})
		client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
		}, pod)
		plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
		proposal := kubernetesRemediationProposal(t, "target-uid")
		plan, err := plugin.Plan(context.Background(), proposal, podRemediationActionID)
		if err != nil {
			t.Fatal(err)
		}
		pod.SetLabels(map[string]string{"app": "changed", "instance": "only"})
		if _, err := client.Resource(podsGVR).Namespace("demo").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := plugin.Prepare(context.Background(), proposal, plan); err == nil || !strings.Contains(err.Error(), "no longer matches") {
			t.Fatalf("label drift error = %v", err)
		}
	})

	t.Run("uid replacement", func(t *testing.T) {
		pod := remediationPod("target-uid", "target", map[string]string{"app": "target", "instance": "only"})
		client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
		}, pod)
		plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
		proposal := kubernetesRemediationProposal(t, "target-uid")
		plan, err := plugin.Plan(context.Background(), proposal, podRemediationActionID)
		if err != nil {
			t.Fatal(err)
		}
		pods := client.Resource(podsGVR).Namespace("demo")
		if err := pods.Delete(context.Background(), "target", metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := pods.Create(context.Background(), remediationPod("replacement-uid", "target", map[string]string{"app": "target", "instance": "only"}), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := plugin.Prepare(context.Background(), proposal, plan); err == nil || !strings.Contains(err.Error(), "was not found") {
			t.Fatalf("replacement error = %v", err)
		}
	})
}

func TestKubernetesRemediationRejectsProviderMutationAfterDryRun(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod)
	recording := &dryRunRecordingDynamic{Interface: client}
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: recording}}
	proposal := kubernetesRemediationProposal(t, "target-uid")
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := remediation.NewExecutor(registry, kubernetesGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, podRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	pod.SetLabels(map[string]string{"app": "mutated"})
	if _, err := client.Resource(podsGVR).Namespace("demo").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err == nil || !strings.Contains(err.Error(), "no longer matches desired state") {
		t.Fatalf("Pod post-dry-run mutation error = %v", err)
	}
}

func TestKubernetesRemediationRejectsManagedPolicyMutationAfterDryRun(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod)
	recording := &dryRunRecordingDynamic{Interface: client}
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: recording}}
	proposal := kubernetesRemediationProposal(t, "target-uid")
	desired, err := plugin.desiredRemediation(context.Background(), proposal)
	if err != nil {
		t.Fatal(err)
	}
	policies := client.Resource(networkPoliciesGVR).Namespace("demo")
	if _, err := policies.Create(context.Background(), desired.policy.DeepCopy(), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := remediation.NewExecutor(registry, kubernetesGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, podRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	current, err := policies.Get(context.Background(), desired.policy.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedStringSlice(current.Object, []string{"Ingress", "Egress"}, "spec", "policyTypes"); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Update(context.Background(), current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err == nil || !strings.Contains(err.Error(), "drifted controlled content") {
		t.Fatalf("managed policy post-dry-run mutation error = %v", err)
	}
}

func TestKubernetesRemediationReplacementPodWithOriginalLabelsIsNotSelected(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "shared"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod)
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: &dryRunRecordingDynamic{Interface: client}}}
	proposal := kubernetesRemediationProposal(t, "target-uid")
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := remediation.NewExecutor(registry, kubernetesGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, podRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err != nil {
		t.Fatal(err)
	}
	pods := client.Resource(podsGVR).Namespace("demo")
	if err := pods.Delete(context.Background(), "target", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := pods.Create(context.Background(), remediationPod("replacement-uid", "target", map[string]string{"app": "shared"}), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	matches, err := pods.List(context.Background(), metav1.ListOptions{LabelSelector: remediationTargetLabel + "=" + remediationTargetValue("target-uid")})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches.Items) != 0 {
		t.Fatalf("replacement Pods selected by remediation label = %d, want 0", len(matches.Items))
	}
}

func TestKubernetesRemediationRollsBackTargetLabelWhenPolicyWriteFails(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod)
	recording := &dryRunRecordingDynamic{Interface: client, failPolicyApply: true}
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: recording}}
	proposal := kubernetesRemediationProposal(t, "target-uid")
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := remediation.NewExecutor(registry, kubernetesGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, podRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err == nil || !strings.Contains(err.Error(), "target label rolled back") {
		t.Fatalf("partial apply error = %v", err)
	}
	wantTail := []string{"false:update:pods", "false:create:networkpolicies", "false:update:pods"}
	if len(recording.operations) < len(wantTail) || !slices.Equal(recording.operations[len(recording.operations)-len(wantTail):], wantTail) {
		t.Fatalf("apply operation order = %v, want tail %v", recording.operations, wantTail)
	}
	current, err := client.Resource(podsGVR).Namespace("demo").Get(context.Background(), "target", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := current.GetLabels()[remediationTargetLabel]; found {
		t.Fatal("remediation target label remained after policy write rollback")
	}
}

// A canceled execution context, such as a client disconnect after the label
// write, must not stop the label rollback.
func TestKubernetesRemediationRollsBackTargetLabelAfterExecutionContextCancel(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	recording := &dryRunRecordingDynamic{Interface: client, failPolicyApply: true, cancelOnPolicyFailure: cancel}
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: recording}}
	proposal := kubernetesRemediationProposal(t, "target-uid")
	plan, err := plugin.Plan(ctx, proposal, podRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := plugin.Prepare(ctx, proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Execute(ctx, proposal, plan, preparation); err == nil || !strings.Contains(err.Error(), "target label rolled back") {
		t.Fatalf("partial apply error = %v", err)
	}
	current, err := client.Resource(podsGVR).Namespace("demo").Get(context.Background(), "target", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := current.GetLabels()[remediationTargetLabel]; found {
		t.Fatal("remediation target label remained after canceled execution")
	}
}

func TestKubernetesRemediationRejectsUnmanagedDeterministicNameCollision(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target", "instance": "only"})
	collision := remediationNetworkPolicy(t, remediationPolicyName("target-uid"), map[string]string{"app": "other"}, networkingv1.PolicyTypeEgress)
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod, collision)
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
	if _, err := plugin.Plan(context.Background(), kubernetesRemediationProposal(t, "target-uid"), podRemediationActionID); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("unmanaged collision error = %v", err)
	}
}

func TestKubernetesRemediationRejectsSpoofedManagedPolicyDrift(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target"})
	policy := remediationNetworkPolicy(t, remediationPolicyName("target-uid"), map[string]string{remediationTargetLabel: remediationTargetValue("target-uid")}, networkingv1.PolicyTypeEgress)
	policy.SetLabels(map[string]string{managedByLabel: managedByValue})
	policy.SetAnnotations(map[string]string{targetUIDAnnotation: "target-uid"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod, policy)
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
	if _, err := plugin.Plan(context.Background(), kubernetesRemediationProposal(t, "target-uid"), podRemediationActionID); err == nil || !strings.Contains(err.Error(), "drifted controlled content") {
		t.Fatalf("spoofed managed policy error = %v", err)
	}
}

func TestKubernetesRemediationReusesIdenticalExistingManagedPolicy(t *testing.T) {
	pod := remediationPod("target-uid", "target", map[string]string{"app": "target"})
	policy := remediationNetworkPolicy(t, remediationPolicyName("target-uid"), map[string]string{remediationTargetLabel: remediationTargetValue("target-uid")}, networkingv1.PolicyTypeIngress)
	policy.SetLabels(map[string]string{managedByLabel: managedByValue})
	policy.SetAnnotations(map[string]string{targetUIDAnnotation: "target-uid"})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		podsGVR: "PodList", networkPoliciesGVR: "NetworkPolicyList",
	}, pod, policy)
	plugin := &Plugin{config: Config{ClusterID: "cluster", SourceID: "source", Dynamic: client}}
	proposal := kubernetesRemediationProposal(t, "target-uid")
	plan, err := plugin.Plan(context.Background(), proposal, podRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Prepare(context.Background(), proposal, plan); err != nil {
		t.Fatal(err)
	}
}

func remediationPod(uid, name string, labels map[string]string) *unstructured.Unstructured {
	pod := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"namespace": "demo", "name": name},
	}}
	pod.SetUID(types.UID(uid))
	pod.SetLabels(labels)
	return pod
}

func remediationService(uid, name string, selector map[string]string) *unstructured.Unstructured {
	service := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"namespace": "demo", "name": name}, "spec": map[string]any{},
	}}
	service.SetUID(types.UID(uid))
	if err := unstructured.SetNestedStringMap(service.Object, selector, "spec", "selector"); err != nil {
		panic(err)
	}
	return service
}

func kubernetesGraphSource(proposal remediation.Proposal) remediation.GraphSourceFunc {
	return func(context.Context) (remediation.GraphView, error) {
		return remediation.GraphView{SHA256: proposal.GraphSHA256, Snapshot: graph.Snapshot{Resources: []graph.Resource{{
			ID: proposal.Target.EntityID, Kind: proposal.Target.Kind, Identity: proposal.Target.Identity,
		}}}}, nil
	}
}

func remediationNetworkPolicy(t *testing.T, name string, selector map[string]string, policyType networkingv1.PolicyType) *unstructured.Unstructured {
	t.Helper()
	return remediationNetworkPolicyWithSpec(t, name, networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: selector},
		PolicyTypes: []networkingv1.PolicyType{policyType},
	})
}

func remediationNetworkPolicyWithSpec(t *testing.T, name string, spec networkingv1.NetworkPolicySpec) *unstructured.Unstructured {
	t.Helper()
	policy := &networkingv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "demo"},
		Spec:       spec,
	}
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policy)
	if err != nil {
		t.Fatal(err)
	}
	return &unstructured.Unstructured{Object: object}
}

func kubernetesRemediationProposal(t *testing.T, uid string) remediation.Proposal {
	t.Helper()
	proposal, err := remediation.NewProposal("finding", "analysis", remediationTestGraphSHA256,
		remediation.Suggestion{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}},
		remediation.Target{EntityID: "target", Identity: ClaimForUID("cluster", "v1", "Pod", uid), Kind: "kubernetes/pod"}, []string{"evidence"})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func kubernetesServiceRemediationProposal(t *testing.T, uid string) remediation.Proposal {
	t.Helper()
	proposal, err := remediation.NewProposal("finding", "analysis", remediationTestGraphSHA256,
		remediation.Suggestion{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}},
		remediation.Target{EntityID: "target", Identity: ClaimForUID("cluster", "v1", "Service", uid), Kind: "kubernetes/service"}, []string{"evidence"})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}
