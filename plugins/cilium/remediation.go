package cilium

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

const (
	ciliumRemediationActionID = "cilium-network-policy/v1"
	ciliumTargetLabel         = "agentshield.io/cilium-remediation-target"
	ciliumManagedByLabel      = "app.kubernetes.io/managed-by"
	ciliumTargetUIDAnnotation = "agentshield.io/target-uid"
)

var (
	ciliumPodsGVR                = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	ciliumNetworkPoliciesGVR     = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}
	ciliumClusterwidePoliciesGVR = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}
	ciliumKubePoliciesGVR        = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
)

// RemediationDescriptor advertises the cilium-network-policy/v1 ingress
// isolation action for Kubernetes Pods when an action transport is configured.
func (p *Plugin) RemediationDescriptor() remediation.Descriptor {
	descriptor := remediation.Descriptor{}
	if p.config.Actions == nil {
		return descriptor
	}
	descriptor.Actions = []remediation.Action{{
		ID: ciliumRemediationActionID, Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetKind: "kubernetes/pod", Scheme: kubernetesplugin.IdentitySchemeDefinition().Scheme,
		AuthorityID: p.config.ClusterID, Mode: remediation.ModeExecutable,
	}}
	return descriptor
}

// Plan resolves the proposal's target Pod and derives the desired target label
// and CiliumNetworkPolicy, rejecting targets already selected by an
// overlapping policy. It writes nothing.
func (p *Plugin) Plan(ctx context.Context, proposal remediation.Proposal, actionID string) (remediation.Plan, error) {
	if actionID != ciliumRemediationActionID {
		return remediation.Plan{}, fmt.Errorf("unsupported Cilium remediation action %q", actionID)
	}
	return p.remediationAction().Plan(ctx, proposal, actionID)
}

// Prepare submits the desired Pod label and policy as server-side dry runs so
// admission can reject them before any change, and records the admitted
// state.
func (p *Plugin) Prepare(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan) (remediation.Preparation, error) {
	return p.remediationAction().Prepare(ctx, proposal, plan)
}

// Execute re-derives the plan, requires the provider state recorded by
// Prepare to be unchanged, labels the Pod, rechecks for overlapping policy,
// and creates the policy. If a step after labeling fails, the label is rolled
// back.
func (p *Plugin) Execute(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, preparation remediation.Preparation) (remediation.ExecutionResult, error) {
	return p.remediationAction().Execute(ctx, proposal, plan, preparation)
}

// Verify reports satisfied only while the live Pod label and policy still
// match the digests recorded at execution. It checks declared configuration,
// not dataplane enforcement.
func (p *Plugin) Verify(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, result remediation.ExecutionResult) (remediation.Verification, error) {
	return p.remediationAction().Verify(ctx, proposal, plan, result)
}

// remediationAction is the cilium-network-policy/v1 action: a target Pod
// label and a CiliumNetworkPolicy that isolates ingress to the Pod with that
// label.
func (p *Plugin) remediationAction() *kubernetesplugin.PodPolicyAction {
	return &kubernetesplugin.PodPolicyAction{
		Provider: "Cilium", ProviderID: PluginID, SourceID: p.config.SourceID, ClusterID: p.config.ClusterID,
		Intent: remediation.IntentNetworkDeclareIngressIsolation, Transport: p.config.Actions, TargetLabel: ciliumTargetLabel,
		PolicyKind: "CiliumNetworkPolicy", PolicyResource: ciliumNetworkPoliciesGVR, PolicyStateKey: "cilium-network-policy",
		PolicyName: ciliumPolicyName, BuildPolicy: buildCiliumPolicy, PolicyDigest: ciliumPolicyDigest,
		RejectConflicts: p.rejectCiliumOverlaps,
	}
}

func buildCiliumPolicy(namespace, name, uid, targetValue string) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name": name, "namespace": namespace,
			"labels":      map[string]any{ciliumManagedByLabel: "agentshield"},
			"annotations": map[string]any{ciliumTargetUIDAnnotation: uid},
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{ciliumTargetLabel: targetValue}},
			"ingress":          []any{},
		},
	}}, nil
}

func (p *Plugin) rejectCiliumOverlaps(ctx context.Context, target *unstructured.Unstructured, managedName string) error {
	kubePolicies, err := p.config.Actions.ReadResource(ciliumKubePoliciesGVR, target.GetNamespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list NetworkPolicies for Cilium remediation overlap: %w", err)
	}
	for index := range kubePolicies.Items {
		var policy networkingv1.NetworkPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(kubePolicies.Items[index].Object, &policy); err != nil {
			return fmt.Errorf("decode NetworkPolicy %s/%s: %w", target.GetNamespace(), kubePolicies.Items[index].GetName(), err)
		}
		if !ciliumKubePolicyHasIngress(policy.Spec) {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			return fmt.Errorf("decode NetworkPolicy %s/%s selector: %w", target.GetNamespace(), policy.Name, err)
		}
		if selector.Matches(labels.Set(target.GetLabels())) {
			return fmt.Errorf("overlap preflight: NetworkPolicy %s/%s already selects the remediation target for ingress", target.GetNamespace(), policy.Name)
		}
	}
	policies, err := p.config.Actions.ReadResource(ciliumNetworkPoliciesGVR, target.GetNamespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list CiliumNetworkPolicies for remediation overlap: %w", err)
	}
	for index := range policies.Items {
		policy := &policies.Items[index]
		if policy.GetName() == managedName {
			if kubernetesplugin.OwnedByRemediationTarget(policy, string(target.GetUID())) {
				continue
			}
			return fmt.Errorf("best-effort CiliumNetworkPolicy preflight: %s/%s collides with the deterministic remediation name and is not owned by this target", target.GetNamespace(), policy.GetName())
		}
		selected, err := ciliumPolicySelectsIngress(policy, p.config.ClusterID, target)
		if err != nil {
			return fmt.Errorf("decode CiliumNetworkPolicy %s/%s: %w", target.GetNamespace(), policy.GetName(), err)
		}
		if selected {
			return fmt.Errorf("overlap preflight: CiliumNetworkPolicy %s/%s already selects the remediation target for ingress", target.GetNamespace(), policy.GetName())
		}
	}
	clusterwide, err := p.config.Actions.ReadResource(ciliumClusterwidePoliciesGVR, "").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list CiliumClusterwideNetworkPolicies for remediation overlap: %w", err)
	}
	for index := range clusterwide.Items {
		policy := &clusterwide.Items[index]
		selected, err := ciliumPolicySelectsIngress(policy, p.config.ClusterID, target)
		if err != nil {
			return fmt.Errorf("decode CiliumClusterwideNetworkPolicy %s: %w", policy.GetName(), err)
		}
		if selected {
			return fmt.Errorf("overlap preflight: CiliumClusterwideNetworkPolicy %s already selects the remediation target for ingress", policy.GetName())
		}
	}
	return nil
}

func ciliumPolicySelectsIngress(policy *unstructured.Unstructured, clusterID string, pod *unstructured.Unstructured) (bool, error) {
	specs := make([]map[string]any, 0, 1)
	if spec, found, err := unstructured.NestedMap(policy.Object, "spec"); err != nil {
		return false, err
	} else if found {
		specs = append(specs, spec)
	}
	if rawSpecs, found, err := unstructured.NestedSlice(policy.Object, "specs"); err != nil {
		return false, err
	} else if found {
		for index, raw := range rawSpecs {
			spec, ok := raw.(map[string]any)
			if !ok {
				return false, fmt.Errorf("specs[%d] is not an object", index)
			}
			specs = append(specs, spec)
		}
	}
	for index, spec := range specs {
		if _, ingress := spec["ingress"]; !ingress {
			if _, deny := spec["ingressDeny"]; !deny {
				continue
			}
		}
		rawSelector, found := spec["endpointSelector"]
		if !found {
			return false, fmt.Errorf("spec %d has ingress rules without endpointSelector", index)
		}
		selectorMap, ok := rawSelector.(map[string]any)
		if !ok {
			return false, fmt.Errorf("spec %d endpointSelector is not an object", index)
		}
		var labelSelector metav1.LabelSelector
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(selectorMap, &labelSelector); err != nil {
			return false, fmt.Errorf("spec %d endpointSelector: %w", index, err)
		}
		selector, err := newCiliumEndpointSelector(labelSelector)
		if err != nil {
			return false, fmt.Errorf("spec %d endpointSelector: %w", index, err)
		}
		if selector.Matches(clusterID, pod) {
			return true, nil
		}
	}
	return false, nil
}

func ciliumKubePolicyHasIngress(spec networkingv1.NetworkPolicySpec) bool {
	if len(spec.Ingress) > 0 || len(spec.PolicyTypes) == 0 {
		return true
	}
	for _, policyType := range spec.PolicyTypes {
		if policyType == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

func ciliumPolicyDigest(policy *unstructured.Unstructured) (string, error) {
	encoded, err := json.Marshal(struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		Spec        any               `json:"spec"`
		Specs       any               `json:"specs"`
	}{policy.GetName(), policy.GetNamespace(), policy.GetLabels(), policy.GetAnnotations(), policy.Object["spec"], policy.Object["specs"]})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ciliumPolicyName(uid string) string {
	digest := sha256.Sum256([]byte(uid))
	return "agentshield-cilium-isolate-" + hex.EncodeToString(digest[:8])
}
