package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

const (
	podRemediationActionID     = "network-policy/v1"
	serviceRemediationActionID = "service-network-policy/v1"
	managedByLabel             = "app.kubernetes.io/managed-by"
	managedByValue             = "agentshield"
	remediationTargetLabel     = "agentshield.io/remediation-target"
	targetUIDAnnotation        = "agentshield.io/target-uid"
)

var (
	podsGVR            = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	servicesGVR        = schema.GroupVersionResource{Version: "v1", Resource: "services"}
	networkPoliciesGVR = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
)

// RemediationDescriptor advertises ingress isolation actions for Kubernetes
// Pods and Services.
func (p *Plugin) RemediationDescriptor() remediation.Descriptor {
	descriptor := remediation.Descriptor{}
	if p.actionTransport() == nil {
		return descriptor
	}
	descriptor.Actions = []remediation.Action{{
		ID: podRemediationActionID, Intent: remediation.IntentNetworkDeclareIngressIsolation, Scheme: IdentitySchemeDefinition().Scheme, AuthorityID: p.config.ClusterID,
		TargetKind: "kubernetes/pod", Mode: remediation.ModeExecutable,
	}, {
		ID: serviceRemediationActionID, Intent: remediation.IntentNetworkDeclareIngressIsolation, Scheme: IdentitySchemeDefinition().Scheme, AuthorityID: p.config.ClusterID,
		TargetKind: "kubernetes/service", Mode: remediation.ModeExecutable,
	}}
	return descriptor
}

// Plan resolves the proposal target and derives the desired NetworkPolicy,
// rejecting targets already selected by an overlapping ingress policy. It
// writes nothing.
func (p *Plugin) Plan(ctx context.Context, proposal remediation.Proposal, actionID string) (remediation.Plan, error) {
	switch actionID {
	case podRemediationActionID:
		return p.podAction().Plan(ctx, proposal, actionID)
	case serviceRemediationActionID:
		return p.planServiceRemediation(ctx, proposal)
	default:
		return remediation.Plan{}, fmt.Errorf("unsupported Kubernetes remediation action %q", actionID)
	}
}

// Prepare submits the desired Kubernetes writes as server-side dry runs so
// admission can reject them before any change, and records the admitted state.
func (p *Plugin) Prepare(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan) (remediation.Preparation, error) {
	if plan.ActionID == serviceRemediationActionID {
		return p.prepareServiceRemediation(ctx, proposal, plan)
	}
	return p.podAction().Prepare(ctx, proposal, plan)
}

// Execute re-derives the plan, requires the provider state recorded by
// Prepare to be unchanged, and applies the action's NetworkPolicy. Pod actions
// also label the target and roll that label back if the policy write fails.
func (p *Plugin) Execute(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, preparation remediation.Preparation) (remediation.ExecutionResult, error) {
	if plan.ActionID == serviceRemediationActionID {
		return p.executeServiceRemediation(ctx, proposal, plan, preparation)
	}
	return p.podAction().Execute(ctx, proposal, plan, preparation)
}

// Verify reports satisfied only while the live target and NetworkPolicy match
// the digests recorded at execution. It checks declared configuration, not CNI
// enforcement.
func (p *Plugin) Verify(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, result remediation.ExecutionResult) (remediation.Verification, error) {
	if plan.ActionID == serviceRemediationActionID {
		return p.verifyServiceRemediation(ctx, proposal, plan, result)
	}
	return p.podAction().Verify(ctx, proposal, plan, result)
}

func kubernetesVerification(plan remediation.Plan, result remediation.ExecutionResult, satisfied bool) remediation.Verification {
	return remediation.Verification{PlanID: plan.ID, ProviderID: PluginID, SourceID: plan.SourceID, ActionID: plan.ActionID, ExecutionResultID: result.ID, Satisfied: satisfied}
}

// podAction is the network-policy/v1 action: a target Pod label and a
// NetworkPolicy that isolates ingress to the Pod with that label.
func (p *Plugin) podAction() *PodPolicyAction {
	return &PodPolicyAction{
		Provider: "Kubernetes", ProviderID: PluginID, SourceID: p.config.SourceID, ClusterID: p.config.ClusterID,
		Intent: remediation.IntentNetworkDeclareIngressIsolation, Transport: p.actionTransport(), TargetLabel: remediationTargetLabel,
		PolicyKind: "NetworkPolicy", PolicyResource: networkPoliciesGVR, PolicyStateKey: "network-policy",
		PolicyName: remediationPolicyName, BuildPolicy: buildRemediationNetworkPolicy, PolicyDigest: networkPolicyDigest,
		RejectConflicts: p.rejectOverlappingIngressPolicies,
	}
}

func (p *Plugin) desiredRemediation(ctx context.Context, proposal remediation.Proposal) (*podPolicyDesired, error) {
	return p.podAction().desired(ctx, proposal)
}

// buildRemediationNetworkPolicy builds the managed NetworkPolicy that denies
// all ingress to Pods labeled with targetValue.
func buildRemediationNetworkPolicy(namespace, name, uid, targetValue string) (*unstructured.Unstructured, error) {
	policy := &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace,
			Labels: map[string]string{managedByLabel: managedByValue}, Annotations: map[string]string{targetUIDAnnotation: uid},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{remediationTargetLabel: targetValue}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{},
		},
	}
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policy)
	if err != nil {
		return nil, fmt.Errorf("encode remediation NetworkPolicy: %w", err)
	}
	if err := unstructured.SetNestedSlice(object, []any{}, "spec", "ingress"); err != nil {
		return nil, fmt.Errorf("encode empty remediation NetworkPolicy ingress rules: %w", err)
	}
	return &unstructured.Unstructured{Object: object}, nil
}

func (p *Plugin) rejectOverlappingIngressPolicies(ctx context.Context, target *unstructured.Unstructured, managedName string) error {
	return p.rejectOverlappingIngressPoliciesForUID(ctx, target, managedName, string(target.GetUID()))
}

func (p *Plugin) rejectOverlappingIngressPoliciesForUID(ctx context.Context, target *unstructured.Unstructured, managedName, targetUID string) error {
	policies, err := p.actionTransport().ReadResource(networkPoliciesGVR, target.GetNamespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list NetworkPolicies for remediation overlap: %w", err)
	}
	for index := range policies.Items {
		item := &policies.Items[index]
		if item.GetName() == managedName {
			if isManagedNetworkPolicyForTarget(item, targetUID) {
				continue
			}
			return fmt.Errorf("best-effort NetworkPolicy preflight: %s/%s collides with the deterministic remediation name and is not owned by this target", item.GetNamespace(), item.GetName())
		}
		var policy networkingv1.NetworkPolicy
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &policy); err != nil {
			return fmt.Errorf("decode NetworkPolicy %s/%s: %w", item.GetNamespace(), item.GetName(), err)
		}
		if !networkPolicySelectsIngress(policy.Spec) {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			return fmt.Errorf("decode NetworkPolicy %s/%s selector: %w", item.GetNamespace(), item.GetName(), err)
		}
		if selector.Matches(labels.Set(target.GetLabels())) {
			return fmt.Errorf("best-effort overlap preflight: NetworkPolicy %s/%s already selects the remediation target for ingress", item.GetNamespace(), item.GetName())
		}
	}
	return nil
}

func isManagedNetworkPolicyForTarget(policy *unstructured.Unstructured, targetUID string) bool {
	return ownedByTarget(policy, targetUID)
}

func networkPolicySelectsIngress(spec networkingv1.NetworkPolicySpec) bool {
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

func (p *Plugin) writeNetworkPolicy(ctx context.Context, desired *unstructured.Unstructured, dryRun bool) (*unstructured.Unstructured, error) {
	return p.podAction().WritePolicy(ctx, desired, dryRun)
}

func sameNetworkPolicy(current, desired *unstructured.Unstructured) (bool, error) {
	currentDigest, err := networkPolicyDigest(current)
	if err != nil {
		return false, err
	}
	desiredDigest, err := networkPolicyDigest(desired)
	return currentDigest == desiredDigest, err
}

func networkPolicyDigest(policy *unstructured.Unstructured) (string, error) {
	encodedSpec, found, err := unstructured.NestedMap(policy.Object, "spec")
	if err != nil {
		return "", fmt.Errorf("decode remediation NetworkPolicy spec: %w", err)
	}
	if !found {
		return "", errors.New("remediation NetworkPolicy has no spec")
	}
	var spec networkingv1.NetworkPolicySpec
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(encodedSpec, &spec); err != nil {
		return "", fmt.Errorf("decode typed remediation NetworkPolicy spec: %w", err)
	}
	controlled := struct {
		Name        string                         `json:"name"`
		Namespace   string                         `json:"namespace"`
		Labels      map[string]string              `json:"labels"`
		Annotations map[string]string              `json:"annotations"`
		Spec        networkingv1.NetworkPolicySpec `json:"spec"`
	}{Name: policy.GetName(), Namespace: policy.GetNamespace(), Labels: policy.GetLabels(), Annotations: policy.GetAnnotations(), Spec: spec}
	encoded, err := json.Marshal(controlled)
	if err != nil {
		return "", fmt.Errorf("encode remediation NetworkPolicy digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func podControlledDigest(pod *unstructured.Unstructured) (string, error) {
	encoded, err := json.Marshal(struct {
		Namespace string            `json:"namespace"`
		Name      string            `json:"name"`
		Labels    map[string]string `json:"labels"`
	}{Namespace: pod.GetNamespace(), Name: pod.GetName(), Labels: pod.GetLabels()})
	if err != nil {
		return "", fmt.Errorf("encode remediation Pod digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func remediationPolicyName(uid string) string {
	digest := sha256.Sum256([]byte(uid))
	return "agentshield-isolate-ingress-" + hex.EncodeToString(digest[:8])
}

func remediationTargetValue(uid string) string {
	digest := sha256.Sum256([]byte(uid))
	return hex.EncodeToString(digest[:16])
}
