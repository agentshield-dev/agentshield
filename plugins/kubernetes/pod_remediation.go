package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

// podLabelRollbackTimeout bounds the rollback of a target Pod label. The
// rollback runs detached from the execution context, so a canceled or
// expired execution still tries to undo its partial write.
const podLabelRollbackTimeout = 30 * time.Second

// PodPolicyAction is the shared plan, prepare, execute, and verify skeleton
// of a remediation that labels one target Pod and writes one managed policy
// whose selector matches only that label. The Kubernetes, Istio, and Cilium
// Pod actions differ only in the policy object they build and in which
// existing policies conflict with it.
//
// The policy is owned by the target when it carries the agentshield
// managed-by label and the target UID annotation. An existing policy with the
// deterministic name is reused only when it is owned and its controlled
// content matches.
type PodPolicyAction struct {
	// Provider names the provider in error messages, such as "Istio".
	Provider   string
	ProviderID string
	SourceID   string
	ClusterID  string
	Intent     remediation.Intent
	Transport  WriteTransport
	// TargetLabel is the Pod label the policy selects.
	TargetLabel string
	// PolicyKind and PolicyResource name the managed policy type, and
	// PolicyStateKey keys its entry in provider state.
	PolicyKind     string
	PolicyResource schema.GroupVersionResource
	PolicyStateKey string
	PolicyName     func(uid string) string
	// BuildPolicy returns the desired policy selecting TargetLabel=targetValue.
	// It must carry the managed-by label and the target UID annotation.
	BuildPolicy  func(namespace, name, uid, targetValue string) (*unstructured.Unstructured, error)
	PolicyDigest ControlledDigest
	// RejectConflicts fails when a policy other than the managed one already
	// covers pod. It runs at planning and again after the label write.
	RejectConflicts func(ctx context.Context, pod *unstructured.Unstructured, managedName string) error
}

// podPolicyDesired is the live and desired state of one Pod policy action.
type podPolicyDesired struct {
	originalPod   *unstructured.Unstructured
	pod           *unstructured.Unstructured
	currentPolicy *unstructured.Unstructured
	policy        *unstructured.Unstructured
}

// Plan resolves the proposal's target Pod and returns a plan over the digest
// of the desired label and policy. It writes nothing.
func (action *PodPolicyAction) Plan(ctx context.Context, proposal remediation.Proposal, actionID string) (remediation.Plan, error) {
	desired, err := action.desired(ctx, proposal)
	if err != nil {
		return remediation.Plan{}, err
	}
	digest, err := action.digest(desired)
	if err != nil {
		return remediation.Plan{}, err
	}
	return remediation.NewPlan(proposal, action.ProviderID, action.SourceID, actionID, digest)
}

// Prepare submits the desired Pod label and policy as server-side dry runs so
// admission can reject them before any change, and records the admitted
// state.
func (action *PodPolicyAction) Prepare(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan) (remediation.Preparation, error) {
	desired, err := action.desiredForPlan(ctx, proposal, plan)
	if err != nil {
		return remediation.Preparation{}, err
	}
	admittedPod, err := action.writePod(ctx, desired.pod, true)
	if err != nil {
		return remediation.Preparation{}, err
	}
	admittedPolicy, err := action.WritePolicy(ctx, desired.policy, true)
	if err != nil {
		return remediation.Preparation{}, err
	}
	states, err := action.preparedStates(desired, admittedPod, admittedPolicy)
	if err != nil {
		return remediation.Preparation{}, err
	}
	return remediation.NewPreparation(plan, true, states)
}

// Execute re-derives the plan, requires the provider state recorded by
// Prepare to be unchanged, labels the Pod, rechecks for conflicting policy,
// and writes the policy. If a step after labeling fails, the label is rolled
// back on a context detached from ctx.
func (action *PodPolicyAction) Execute(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, preparation remediation.Preparation) (remediation.ExecutionResult, error) {
	desired, err := action.desiredForPlan(ctx, proposal, plan)
	if err != nil {
		return remediation.ExecutionResult{}, err
	}
	if err := action.requireProviderState(desired, preparation.ProviderState); err != nil {
		return remediation.ExecutionResult{}, err
	}
	updatedPod, err := action.writePod(ctx, desired.pod, false)
	if err != nil {
		return remediation.ExecutionResult{}, err
	}
	if err := action.RejectConflicts(ctx, updatedPod, desired.policy.GetName()); err != nil {
		return remediation.ExecutionResult{}, action.rollbackAfter(ctx, fmt.Sprintf("recheck %s conflicts after target Pod label update", action.PolicyKind), err, desired.originalPod, updatedPod)
	}
	updatedPolicy, err := action.WritePolicy(ctx, desired.policy, false)
	if err != nil {
		return remediation.ExecutionResult{}, action.rollbackAfter(ctx, fmt.Sprintf("execute %s after target Pod label update", action.PolicyKind), err, desired.originalPod, updatedPod)
	}
	states, err := action.appliedStates(updatedPod, updatedPolicy)
	if err != nil {
		return remediation.ExecutionResult{}, err
	}
	return remediation.NewExecutionResult(plan, preparation, true, states)
}

// rollbackAfter restores the target Pod label after cause and reports both.
func (action *PodPolicyAction) rollbackAfter(ctx context.Context, step string, cause error, original, updated *unstructured.Unstructured) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), podLabelRollbackTimeout)
	defer cancel()
	if rollbackErr := RollbackPodLabel(rollbackCtx, action.Transport, podsGVR, original, updated, podControlledDigest, "rollback "+action.Provider+" remediation target Pod label"); rollbackErr != nil {
		return fmt.Errorf("%s; partial failure: target label rollback failed: %w", step, errors.Join(cause, rollbackErr))
	}
	return fmt.Errorf("%s: %w; target label rolled back", step, cause)
}

// Verify reports satisfied only while the live Pod label and policy still
// match the digests recorded at execution. It checks declared configuration,
// not enforcement.
func (action *PodPolicyAction) Verify(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, result remediation.ExecutionResult) (remediation.Verification, error) {
	_, podState, _, policyState, err := action.DecodeStates(result.ProviderState)
	if err != nil {
		return remediation.Verification{}, err
	}
	uid, err := action.proposalPodUID(proposal)
	if err != nil {
		return remediation.Verification{}, err
	}
	verification := remediation.Verification{PlanID: plan.ID, ProviderID: action.ProviderID, SourceID: plan.SourceID, ActionID: plan.ActionID, ExecutionResultID: result.ID}
	pod, err := action.Transport.ReadResource(podsGVR, podState.Namespace).Get(ctx, podState.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return verification, nil
	}
	if err != nil {
		return remediation.Verification{}, fmt.Errorf("get %s remediation target Pod: %w", action.Provider, err)
	}
	if string(pod.GetUID()) != uid || pod.GetLabels()[action.TargetLabel] != remediationTargetValue(uid) {
		return verification, nil
	}
	podDigest, err := podControlledDigest(pod)
	if err != nil {
		return remediation.Verification{}, err
	}
	policy, err := action.Transport.ReadResource(action.PolicyResource, policyState.Namespace).Get(ctx, policyState.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return verification, nil
	}
	if err != nil {
		return remediation.Verification{}, fmt.Errorf("get remediation %s: %w", action.PolicyKind, err)
	}
	policyDigest, err := action.PolicyDigest(policy)
	if err != nil {
		return remediation.Verification{}, err
	}
	verification.Satisfied = podDigest == podState.ControlledSHA256 && policyDigest == policyState.ControlledSHA256
	return verification, nil
}

func (action *PodPolicyAction) desiredForPlan(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan) (*podPolicyDesired, error) {
	desired, err := action.desired(ctx, proposal)
	if err != nil {
		return nil, err
	}
	digest, err := action.digest(desired)
	if err != nil {
		return nil, err
	}
	if digest != plan.DesiredSHA256 {
		return nil, fmt.Errorf("live %s remediation plan no longer matches desired state", action.Provider)
	}
	return desired, nil
}

func (action *PodPolicyAction) desired(ctx context.Context, proposal remediation.Proposal) (*podPolicyDesired, error) {
	if action.Transport == nil {
		return nil, fmt.Errorf("%s remediation requires the shared Kubernetes mutation transport", action.Provider)
	}
	uid, err := action.proposalPodUID(proposal)
	if err != nil {
		return nil, err
	}
	pods, err := action.Transport.ReadResource(podsGVR, metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Pods for %s remediation target: %w", action.Provider, err)
	}
	var target *unstructured.Unstructured
	for index := range pods.Items {
		if string(pods.Items[index].GetUID()) != uid {
			continue
		}
		if target != nil {
			return nil, fmt.Errorf("multiple live Pods have target UID %q", uid)
		}
		target = pods.Items[index].DeepCopy()
	}
	if target == nil {
		return nil, fmt.Errorf("live Pod with UID %q was not found", uid)
	}
	value := remediationTargetValue(uid)
	if existing, found := target.GetLabels()[action.TargetLabel]; found && existing != value {
		return nil, fmt.Errorf("target Pod has a conflicting %s remediation target label", action.Provider)
	}
	name := action.PolicyName(uid)
	desiredPod := target.DeepCopy()
	podLabels := desiredPod.GetLabels()
	if podLabels == nil {
		podLabels = map[string]string{}
	}
	podLabels[action.TargetLabel] = value
	desiredPod.SetLabels(podLabels)
	if err := action.RejectConflicts(ctx, desiredPod, name); err != nil {
		return nil, err
	}
	policy, err := action.BuildPolicy(target.GetNamespace(), name, uid, value)
	if err != nil {
		return nil, err
	}
	current, err := action.Transport.ReadResource(action.PolicyResource, target.GetNamespace()).Get(ctx, name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get existing remediation %s: %w", action.PolicyKind, err)
	}
	if apierrors.IsNotFound(err) {
		current = nil
	} else {
		matching, err := action.samePolicy(current, policy)
		if err != nil {
			return nil, err
		}
		if !ownedByTarget(current, uid) || !matching {
			return nil, fmt.Errorf("%s %s/%s collides with the deterministic remediation name or has drifted controlled content", action.PolicyKind, target.GetNamespace(), name)
		}
		policy.SetResourceVersion(current.GetResourceVersion())
	}
	return &podPolicyDesired{originalPod: target, pod: desiredPod, currentPolicy: current, policy: policy}, nil
}

func (action *PodPolicyAction) proposalPodUID(proposal remediation.Proposal) (string, error) {
	identity := proposal.Target.Identity
	if proposal.Intent != action.Intent || proposal.Target.Kind != "kubernetes/pod" || identity.Scheme != IdentitySchemeDefinition().Scheme || identity.AuthorityID != action.ClusterID {
		return "", fmt.Errorf("remediation proposal is not for a Pod supported by this %s provider", action.Provider)
	}
	parts := strings.Split(identity.ImmutableKey, "/")
	if len(parts) != 3 || !strings.EqualFold(parts[0], "v1") || !strings.EqualFold(parts[1], "pod") || strings.TrimSpace(parts[2]) == "" {
		return "", errors.New("remediation proposal has an invalid Kubernetes Pod identity")
	}
	return parts[2], nil
}

func (action *PodPolicyAction) digest(desired *podPolicyDesired) (string, error) {
	podDigest, err := podControlledDigest(desired.pod)
	if err != nil {
		return "", err
	}
	policyDigest, err := action.PolicyDigest(desired.policy)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal([]string{podDigest, policyDigest})
	if err != nil {
		return "", fmt.Errorf("encode remediation desired-state digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// observation records object's identity and the digest of its controlled
// fields.
func observation(resource string, object *unstructured.Unstructured, digest ControlledDigest) (ActionObservation, error) {
	controlled, err := digest(object)
	if err != nil {
		return ActionObservation{}, err
	}
	return ActionObservation{
		Resource: resource, Namespace: object.GetNamespace(), Name: object.GetName(), Exists: true,
		UID: string(object.GetUID()), ResourceVersion: object.GetResourceVersion(), ControlledSHA256: controlled,
	}, nil
}

func (action *PodPolicyAction) preparedStates(desired *podPolicyDesired, admittedPod, admittedPolicy *unstructured.Unstructured) ([]remediation.ProviderState, error) {
	podCurrent, err := observation(podsGVR.Resource, desired.originalPod, podControlledDigest)
	if err != nil {
		return nil, err
	}
	podAdmitted, err := observation(podsGVR.Resource, admittedPod, podControlledDigest)
	if err != nil {
		return nil, err
	}
	policyAdmitted, err := observation(action.PolicyResource.Resource, admittedPolicy, action.PolicyDigest)
	if err != nil {
		return nil, err
	}
	policyCurrent := ActionObservation{Resource: action.PolicyResource.Resource, Namespace: desired.policy.GetNamespace(), Name: desired.policy.GetName()}
	if desired.currentPolicy != nil {
		policyCurrent, err = observation(action.PolicyResource.Resource, desired.currentPolicy, action.PolicyDigest)
		if err != nil {
			return nil, err
		}
	}
	podState, err := ProviderState("pod", podCurrent, podAdmitted)
	if err != nil {
		return nil, err
	}
	policyState, err := ProviderState(action.PolicyStateKey, policyCurrent, policyAdmitted)
	return []remediation.ProviderState{podState, policyState}, err
}

func (action *PodPolicyAction) appliedStates(pod, policy *unstructured.Unstructured) ([]remediation.ProviderState, error) {
	podObservation, err := observation(podsGVR.Resource, pod, podControlledDigest)
	if err != nil {
		return nil, err
	}
	policyObservation, err := observation(action.PolicyResource.Resource, policy, action.PolicyDigest)
	if err != nil {
		return nil, err
	}
	podState, err := ProviderState("pod", podObservation, podObservation)
	if err != nil {
		return nil, err
	}
	policyState, err := ProviderState(action.PolicyStateKey, policyObservation, policyObservation)
	return []remediation.ProviderState{podState, policyState}, err
}

func (action *PodPolicyAction) requireProviderState(desired *podPolicyDesired, states []remediation.ProviderState) error {
	podCurrent, podPrepared, policyCurrent, policyPrepared, err := action.DecodeStates(states)
	if err != nil {
		return err
	}
	podCurrentDigest, err := podControlledDigest(desired.originalPod)
	if err != nil {
		return err
	}
	podDesiredDigest, err := podControlledDigest(desired.pod)
	if err != nil {
		return err
	}
	if !podCurrent.Exists || podCurrent.Namespace != desired.originalPod.GetNamespace() || podCurrent.Name != desired.originalPod.GetName() || podCurrent.UID != string(desired.originalPod.GetUID()) || podCurrent.ResourceVersion != desired.originalPod.GetResourceVersion() || podCurrent.ControlledSHA256 != podCurrentDigest || podPrepared.ControlledSHA256 != podDesiredDigest {
		return fmt.Errorf("target Pod changed after %s remediation preparation", action.Provider)
	}
	policyDesiredDigest, err := action.PolicyDigest(desired.policy)
	if err != nil {
		return err
	}
	if policyPrepared.Namespace != desired.policy.GetNamespace() || policyPrepared.Name != desired.policy.GetName() || policyPrepared.ControlledSHA256 != policyDesiredDigest {
		return fmt.Errorf("managed %s preparation state does not match the plan", action.PolicyKind)
	}
	if desired.currentPolicy == nil {
		if policyCurrent.Exists || policyCurrent.UID != "" || policyCurrent.ResourceVersion != "" || policyCurrent.ControlledSHA256 != "" {
			return fmt.Errorf("managed %s existence changed after remediation preparation", action.PolicyKind)
		}
		return nil
	}
	policyCurrentDigest, err := action.PolicyDigest(desired.currentPolicy)
	if err != nil {
		return err
	}
	if !policyCurrent.Exists || policyCurrent.UID != string(desired.currentPolicy.GetUID()) || policyCurrent.ResourceVersion != desired.currentPolicy.GetResourceVersion() || policyCurrent.ControlledSHA256 != policyCurrentDigest {
		return fmt.Errorf("managed %s changed after remediation preparation", action.PolicyKind)
	}
	return nil
}

// DecodeStates returns the current and prepared observations of the target
// Pod and the managed policy, in that order. It requires exactly one of each.
func (action *PodPolicyAction) DecodeStates(states []remediation.ProviderState) (ActionObservation, ActionObservation, ActionObservation, ActionObservation, error) {
	var podCurrent, podPrepared, policyCurrent, policyPrepared ActionObservation
	for _, state := range states {
		current, prepared, err := DecodeProviderState(state)
		if err != nil {
			return podCurrent, podPrepared, policyCurrent, policyPrepared, err
		}
		switch state.Key {
		case "pod":
			if podCurrent.Resource != "" {
				return podCurrent, podPrepared, policyCurrent, policyPrepared, fmt.Errorf("%s remediation state contains duplicate Pods", action.Provider)
			}
			podCurrent, podPrepared = current, prepared
		case action.PolicyStateKey:
			if policyCurrent.Resource != "" {
				return podCurrent, podPrepared, policyCurrent, policyPrepared, fmt.Errorf("%s remediation state contains duplicate %s objects", action.Provider, action.PolicyKind)
			}
			policyCurrent, policyPrepared = current, prepared
		default:
			return podCurrent, podPrepared, policyCurrent, policyPrepared, fmt.Errorf("%s remediation state contains unsupported key %q", action.Provider, state.Key)
		}
	}
	if podCurrent.Resource == "" || policyCurrent.Resource == "" || len(states) != 2 {
		return podCurrent, podPrepared, policyCurrent, policyPrepared, fmt.Errorf("%s remediation state requires exactly one Pod and one %s", action.Provider, action.PolicyKind)
	}
	return podCurrent, podPrepared, policyCurrent, policyPrepared, nil
}

func (action *PodPolicyAction) writePod(ctx context.Context, desired *unstructured.Unstructured, dryRun bool) (*unstructured.Unstructured, error) {
	return UpdatePodLabel(ctx, action.Transport, podsGVR, desired, dryRun, podControlledDigest, "update "+action.Provider+" remediation target Pod label")
}

// WritePolicy creates desired, optionally as a server-side dry run, and fails
// if admission changed its controlled content. An existing policy is accepted
// unchanged only when it is owned by the same target, has the observed
// resource version, and has the same controlled content; remediation never
// updates a policy.
func (action *PodPolicyAction) WritePolicy(ctx context.Context, desired *unstructured.Unstructured, dryRun bool) (*unstructured.Unstructured, error) {
	resource := action.Transport.WriteResource(action.PolicyResource, desired.GetNamespace())
	current, err := resource.Get(ctx, desired.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		options := metav1.CreateOptions{}
		if dryRun {
			options.DryRun = []string{metav1.DryRunAll}
		}
		created, err := resource.Create(ctx, desired.DeepCopy(), options)
		if err != nil {
			return nil, fmt.Errorf("create remediation %s: %w", action.PolicyKind, err)
		}
		matching, err := action.samePolicy(created, desired)
		if err != nil {
			return nil, err
		}
		if !matching {
			return nil, fmt.Errorf("Kubernetes admission mutated controlled remediation %s fields", action.PolicyKind)
		}
		return created, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get existing remediation %s: %w", action.PolicyKind, err)
	}
	if !ownedByTarget(current, desired.GetAnnotations()[targetUIDAnnotation]) {
		return nil, fmt.Errorf("refusing to replace a %s not owned by this remediation target", action.PolicyKind)
	}
	if current.GetResourceVersion() != desired.GetResourceVersion() {
		return nil, fmt.Errorf("managed %s changed after remediation state observation", action.PolicyKind)
	}
	matching, err := action.samePolicy(current, desired)
	if err != nil {
		return nil, err
	}
	if !matching {
		return nil, fmt.Errorf("refusing to update a managed %s with drifted controlled content", action.PolicyKind)
	}
	return current, nil
}

func (action *PodPolicyAction) samePolicy(left, right *unstructured.Unstructured) (bool, error) {
	leftDigest, err := action.PolicyDigest(left)
	if err != nil {
		return false, err
	}
	rightDigest, err := action.PolicyDigest(right)
	return leftDigest == rightDigest, err
}

// ownedByTarget reports whether object is managed by AgentShield for the
// target with targetUID.
func ownedByTarget(object *unstructured.Unstructured, targetUID string) bool {
	return object.GetLabels()[managedByLabel] == managedByValue && object.GetAnnotations()[targetUIDAnnotation] == targetUID
}

// OwnedByRemediationTarget reports whether object is managed by AgentShield
// for the remediation target with uid.
func OwnedByRemediationTarget(object *unstructured.Unstructured, uid string) bool {
	return ownedByTarget(object, uid)
}

// RemediationTargetValue is the value of a Pod action's target label for the
// Pod with uid.
func RemediationTargetValue(uid string) string {
	return remediationTargetValue(uid)
}
