package istio

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const remediationTestGraphSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestIstioRemediationLifecycleDeclaresStrictMTLS(t *testing.T) {
	base := istioFake(istioTestPod("target-uid", map[string]string{"app": "target"}), istioPeerAuthentication("namespace-default", nil, "PERMISSIVE"))
	transport := &istioDryRunTransport{Interface: base}
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, transport)})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	if err != nil {
		t.Fatal(err)
	}
	proposal := istioProposal(t, "target-uid")
	executor, err := remediation.NewExecutor(registry, istioGraphSource(proposal))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := executor.Plan(context.Background(), proposal, PluginID, istioRemediationActionID)
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
	policy, err := base.Resource(peerAuthenticationsGVR).Namespace("demo").Get(context.Background(), peerAuthenticationName("target-uid"), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mode, found, err := unstructured.NestedString(policy.Object, "spec", "mtls", "mode")
	if err != nil || !found || mode != "STRICT" {
		t.Fatalf("mTLS mode=%q found=%t err=%v", mode, found, err)
	}
}

func TestIstioProjectorOnlyConstructionAdvertisesNoRemediationAction(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source"})
	if err != nil {
		t.Fatal(err)
	}
	if actions := plugin.RemediationDescriptor().Actions; len(actions) != 0 {
		t.Fatalf("actions = %#v, want none without mutation transport", actions)
	}
}

func TestIstioRemediationRejectsUIDReplacementAndWorkloadConflict(t *testing.T) {
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, istioFake(istioTestPod("replacement-uid", map[string]string{"app": "target"})))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), istioProposal(t, "target-uid"), istioRemediationActionID); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("UID replacement error = %v", err)
	}
	conflict := istioPeerAuthentication("existing", map[string]string{"app": "target"}, "PERMISSIVE")
	plugin, err = New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, istioFake(istioTestPod("target-uid", map[string]string{"app": "target"}), conflict))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), istioProposal(t, "target-uid"), istioRemediationActionID); err == nil || !strings.Contains(err.Error(), "workload-scoped") {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestIstioRemediationRejectsPolicySelectingFutureRemediationLabel(t *testing.T) {
	policy := istioPeerAuthentication("future-label", map[string]string{istioTargetLabel: kubernetesplugin.RemediationTargetValue("target-uid")}, "PERMISSIVE")
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, istioFake(istioTestPod("target-uid", map[string]string{"app": "target"}), policy))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), istioProposal(t, "target-uid"), istioRemediationActionID); err == nil || !strings.Contains(err.Error(), "workload-scoped") {
		t.Fatalf("future-label conflict error = %v", err)
	}
}

func TestIstioRemediationRejectsSpoofedManagedPolicyDrift(t *testing.T) {
	pod := istioTestPod("target-uid", map[string]string{"app": "target"})
	policy := istioPeerAuthentication(peerAuthenticationName("target-uid"), map[string]string{istioTargetLabel: kubernetesplugin.RemediationTargetValue("target-uid")}, "PERMISSIVE")
	policy.SetLabels(map[string]string{istioManagedByLabel: "agentshield"})
	policy.SetAnnotations(map[string]string{istioTargetUIDAnnotation: "target-uid"})
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, istioFake(pod, policy))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Plan(context.Background(), istioProposal(t, "target-uid"), istioRemediationActionID); err == nil || !strings.Contains(err.Error(), "drifted controlled content") {
		t.Fatalf("spoofed managed policy error = %v", err)
	}
}

func TestIstioRemediationReusesIdenticalExistingManagedPolicy(t *testing.T) {
	pod := istioTestPod("target-uid", map[string]string{"app": "target"})
	policy := istioPeerAuthentication(peerAuthenticationName("target-uid"), map[string]string{istioTargetLabel: kubernetesplugin.RemediationTargetValue("target-uid")}, "STRICT")
	policy.SetLabels(map[string]string{istioManagedByLabel: "agentshield"})
	policy.SetAnnotations(map[string]string{istioTargetUIDAnnotation: "target-uid"})
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, istioFake(pod, policy))})
	if err != nil {
		t.Fatal(err)
	}
	proposal := istioProposal(t, "target-uid")
	plan, err := plugin.Plan(context.Background(), proposal, istioRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Prepare(context.Background(), proposal, plan); err != nil {
		t.Fatal(err)
	}
}

func TestIstioRemediationRejectsPolicyDriftBetweenPreparationAndExecution(t *testing.T) {
	uid := "target-uid"
	policy := istioPeerAuthentication(peerAuthenticationName(uid), map[string]string{istioTargetLabel: kubernetesplugin.RemediationTargetValue(uid)}, "STRICT")
	policy.SetLabels(map[string]string{istioManagedByLabel: "agentshield"})
	policy.SetAnnotations(map[string]string{istioTargetUIDAnnotation: uid})
	base := istioFake(istioTestPod(uid, map[string]string{"app": "target"}), policy)
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, base)})
	if err != nil {
		t.Fatal(err)
	}
	proposal := istioProposal(t, uid)
	plan, err := plugin.Plan(context.Background(), proposal, istioRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := plugin.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}

	current, err := base.Resource(peerAuthenticationsGVR).Namespace("demo").Get(context.Background(), policy.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(current.Object, "PERMISSIVE", "spec", "mtls", "mode"); err != nil {
		t.Fatal(err)
	}
	if _, err := base.Resource(peerAuthenticationsGVR).Namespace("demo").Update(context.Background(), current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Execute(context.Background(), proposal, plan, preparation); err == nil || !strings.Contains(err.Error(), "drifted controlled content") {
		t.Fatalf("execution drift error = %v", err)
	}
}

func TestIstioRemediationRejectsDriftAndAdmissionMutation(t *testing.T) {
	base := istioFake(istioTestPod("target-uid", map[string]string{"app": "target"}))
	transport := &istioDryRunTransport{Interface: base}
	plugin, _ := New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, transport)})
	proposal := istioProposal(t, "target-uid")
	registry, _ := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	executor, _ := remediation.NewExecutor(registry, istioGraphSource(proposal))
	plan, err := executor.Plan(context.Background(), proposal, PluginID, istioRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := executor.Prepare(context.Background(), proposal, plan)
	if err != nil {
		t.Fatal(err)
	}
	pod, err := base.Resource(istioPodsGVR).Namespace("demo").Get(context.Background(), "target", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.SetLabels(map[string]string{"app": "changed"})
	if _, err := base.Resource(istioPodsGVR).Namespace("demo").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), proposal, plan, preparation, plan.ID); err == nil {
		t.Fatal("apply accepted provider drift")
	}

	mutating := &istioDryRunTransport{Interface: istioFake(istioTestPod("target-uid", map[string]string{"app": "target"})), mutate: func(resource string, object *unstructured.Unstructured) {
		if resource == peerAuthenticationsGVR.Resource {
			_ = unstructured.SetNestedField(object.Object, "PERMISSIVE", "spec", "mtls", "mode")
		}
	}}
	plugin, _ = New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, mutating)})
	plan, err = plugin.Plan(context.Background(), proposal, istioRemediationActionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Prepare(context.Background(), proposal, plan); err == nil || !strings.Contains(err.Error(), "admission mutated") {
		t.Fatalf("admission error = %v", err)
	}
}

func TestIstioRemediationRollsBackPodLabelOnPolicyFailure(t *testing.T) {
	base := istioFake(istioTestPod("target-uid", map[string]string{"app": "target"}))
	transport := &istioDryRunTransport{Interface: base, failPolicyApply: true}
	plugin, _ := New(Config{ClusterID: "cluster", SourceID: "source", Actions: istioActions(t, transport)})
	proposal := istioProposal(t, "target-uid")
	registry, _ := remediation.NewRegistry(remediation.Registration{ProviderID: PluginID, SourceID: "source", Provider: plugin})
	executor, _ := remediation.NewExecutor(registry, istioGraphSource(proposal))
	plan, err := executor.Plan(context.Background(), proposal, PluginID, istioRemediationActionID)
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
	pod, err := base.Resource(istioPodsGVR).Namespace("demo").Get(context.Background(), "target", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := pod.GetLabels()[istioTargetLabel]; found {
		t.Fatal("Istio target label remained after rollback")
	}
}

type istioDryRunTransport struct {
	dynamic.Interface
	observedDryRun  bool
	failPolicyApply bool
	mutate          func(string, *unstructured.Unstructured)
}

func istioActions(t *testing.T, client dynamic.Interface) kubernetesplugin.WriteTransport {
	t.Helper()
	transport, err := kubernetesplugin.NewDynamicTransport(client)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func (client *istioDryRunTransport) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &istioNamespaceable{NamespaceableResourceInterface: client.Interface.Resource(gvr), client: client, resource: gvr.Resource}
}

type istioNamespaceable struct {
	dynamic.NamespaceableResourceInterface
	client   *istioDryRunTransport
	resource string
}

func (resource *istioNamespaceable) Namespace(namespace string) dynamic.ResourceInterface {
	return &istioResource{ResourceInterface: resource.NamespaceableResourceInterface.Namespace(namespace), client: resource.client, resource: resource.resource}
}

type istioResource struct {
	dynamic.ResourceInterface
	client   *istioDryRunTransport
	resource string
}

func (resource *istioResource) Create(ctx context.Context, object *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if slices.Contains(options.DryRun, metav1.DryRunAll) {
		resource.client.observedDryRun = true
		result := object.DeepCopy()
		if resource.client.mutate != nil {
			resource.client.mutate(resource.resource, result)
		}
		return result, nil
	}
	if resource.resource == peerAuthenticationsGVR.Resource && resource.client.failPolicyApply {
		return nil, errors.New("injected policy failure")
	}
	return resource.ResourceInterface.Create(ctx, object, options, subresources...)
}
func (resource *istioResource) Update(ctx context.Context, object *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error) {
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

func istioFake(objects ...runtime.Object) dynamic.Interface {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{istioPodsGVR: "PodList", peerAuthenticationsGVR: "PeerAuthenticationList"}, objects...)
}
func istioTestPod(uid string, objectLabels map[string]string) *unstructured.Unstructured {
	pod := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "target", "namespace": "demo", "uid": uid, "resourceVersion": "1"}}}
	pod.SetUID(types.UID(uid))
	pod.SetLabels(objectLabels)
	return pod
}
func istioPeerAuthentication(name string, selector map[string]string, mode string) *unstructured.Unstructured {
	spec := map[string]any{"mtls": map[string]any{"mode": mode}}
	if selector != nil {
		converted := make(map[string]any, len(selector))
		for key, value := range selector {
			converted[key] = value
		}
		spec["selector"] = map[string]any{"matchLabels": converted}
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication", "metadata": map[string]any{"name": name, "namespace": "demo", "uid": name + "-uid", "resourceVersion": "1"}, "spec": spec}}
}
func istioProposal(t *testing.T, uid string) remediation.Proposal {
	t.Helper()
	proposal, err := remediation.NewProposal("finding", "analysis", remediationTestGraphSHA256, remediation.Suggestion{Intent: remediation.IntentTransportRequireMutualTLS, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}}, remediation.Target{EntityID: "target", Kind: "kubernetes/pod", Identity: kubernetesplugin.ClaimForUID("cluster", "v1", "Pod", uid)}, []string{"evidence"})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}
func istioGraphSource(proposal remediation.Proposal) remediation.GraphSourceFunc {
	return func(context.Context) (remediation.GraphView, error) {
		return remediation.GraphView{SHA256: proposal.GraphSHA256, Snapshot: graph.Snapshot{Resources: []graph.Resource{{ID: proposal.Target.EntityID, Kind: proposal.Target.Kind, Identity: proposal.Target.Identity}}}}, nil
	}
}
