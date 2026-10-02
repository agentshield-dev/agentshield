package istio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

const (
	istioRemediationActionID = "peer-authentication/v1"
	istioTargetLabel         = "agentshield.io/istio-remediation-target"
	istioManagedByLabel      = "app.kubernetes.io/managed-by"
	istioTargetUIDAnnotation = "agentshield.io/target-uid"
)

var (
	istioPodsGVR           = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	peerAuthenticationsGVR = schema.GroupVersionResource{Group: "security.istio.io", Version: "v1", Resource: "peerauthentications"}
)

// RemediationDescriptor advertises the peer-authentication/v1 mutual TLS
// action for Kubernetes Pods when an action transport is configured.
func (p *Plugin) RemediationDescriptor() remediation.Descriptor {
	descriptor := remediation.Descriptor{}
	if p.config.Actions == nil {
		return descriptor
	}
	descriptor.Actions = []remediation.Action{{
		ID: istioRemediationActionID, Intent: remediation.IntentTransportRequireMutualTLS, TargetKind: "kubernetes/pod", Scheme: kubernetesplugin.IdentitySchemeDefinition().Scheme,
		AuthorityID: p.config.ClusterID, Mode: remediation.ModeExecutable,
	}}
	return descriptor
}

// Plan resolves the proposal's target Pod and derives the desired target label
// and STRICT PeerAuthentication, rejecting conflicting existing policy. It
// writes nothing.
func (p *Plugin) Plan(ctx context.Context, proposal remediation.Proposal, actionID string) (remediation.Plan, error) {
	if actionID != istioRemediationActionID {
		return remediation.Plan{}, fmt.Errorf("unsupported Istio remediation action %q", actionID)
	}
	return p.remediationAction().Plan(ctx, proposal, actionID)
}

// Prepare submits the desired Pod label and PeerAuthentication as server-side
// dry runs so admission can reject them before any change, and records the
// admitted state.
func (p *Plugin) Prepare(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan) (remediation.Preparation, error) {
	return p.remediationAction().Prepare(ctx, proposal, plan)
}

// Execute re-derives the plan, requires the provider state recorded by
// Prepare to be unchanged, labels the Pod, rechecks for conflicting
// PeerAuthentication, and creates the policy. If a step after labeling fails,
// the label is rolled back.
func (p *Plugin) Execute(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, preparation remediation.Preparation) (remediation.ExecutionResult, error) {
	return p.remediationAction().Execute(ctx, proposal, plan, preparation)
}

// Verify reports satisfied only while the live Pod label and
// PeerAuthentication still match the digests recorded at execution. It checks
// declared configuration, not observed mTLS traffic.
func (p *Plugin) Verify(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, result remediation.ExecutionResult) (remediation.Verification, error) {
	return p.remediationAction().Verify(ctx, proposal, plan, result)
}

// remediationAction is the peer-authentication/v1 action: a target Pod label
// and a STRICT PeerAuthentication that selects the Pod with that label.
func (p *Plugin) remediationAction() *kubernetesplugin.PodPolicyAction {
	return &kubernetesplugin.PodPolicyAction{
		Provider: "Istio", ProviderID: PluginID, SourceID: p.config.SourceID, ClusterID: p.config.ClusterID,
		Intent: remediation.IntentTransportRequireMutualTLS, Transport: p.config.Actions, TargetLabel: istioTargetLabel,
		PolicyKind: "PeerAuthentication", PolicyResource: peerAuthenticationsGVR, PolicyStateKey: "peer-authentication",
		PolicyName: peerAuthenticationName, BuildPolicy: buildPeerAuthentication, PolicyDigest: peerAuthenticationDigest,
		RejectConflicts: p.rejectPeerAuthenticationConflicts,
	}
}

func buildPeerAuthentication(namespace, name, uid, targetValue string) (*unstructured.Unstructured, error) {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "security.istio.io/v1", "kind": "PeerAuthentication",
		"metadata": map[string]any{
			"name": name, "namespace": namespace,
			"labels":      map[string]any{istioManagedByLabel: "agentshield"},
			"annotations": map[string]any{istioTargetUIDAnnotation: uid},
		},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{istioTargetLabel: targetValue}},
			"mtls":     map[string]any{"mode": "STRICT"},
		},
	}}, nil
}

func (p *Plugin) rejectPeerAuthenticationConflicts(ctx context.Context, target *unstructured.Unstructured, managedName string) error {
	policies, err := p.config.Actions.ReadResource(peerAuthenticationsGVR, target.GetNamespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list PeerAuthentications for remediation conflict: %w", err)
	}
	for index := range policies.Items {
		policy := &policies.Items[index]
		if policy.GetName() == managedName {
			if kubernetesplugin.OwnedByRemediationTarget(policy, string(target.GetUID())) {
				continue
			}
			return fmt.Errorf("PeerAuthentication %s/%s collides with the deterministic remediation name and is not owned by this target", target.GetNamespace(), policy.GetName())
		}
		selector, found, err := unstructured.NestedStringMap(policy.Object, "spec", "selector", "matchLabels")
		if err != nil {
			return fmt.Errorf("decode PeerAuthentication %s/%s selector: %w", target.GetNamespace(), policy.GetName(), err)
		}
		if !found {
			continue
		}
		if labels.SelectorFromSet(selector).Matches(labels.Set(target.GetLabels())) {
			return fmt.Errorf("conflicting workload-scoped PeerAuthentication %s/%s already selects the remediation target", target.GetNamespace(), policy.GetName())
		}
	}
	return nil
}

func peerAuthenticationDigest(policy *unstructured.Unstructured) (string, error) {
	encoded, err := json.Marshal(struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		Spec        any               `json:"spec"`
	}{policy.GetName(), policy.GetNamespace(), policy.GetLabels(), policy.GetAnnotations(), policy.Object["spec"]})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func peerAuthenticationName(uid string) string {
	digest := sha256.Sum256([]byte(uid))
	return "agentshield-mtls-strict-" + hex.EncodeToString(digest[:8])
}
