package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

type desiredServiceRemediation struct {
	service       *unstructured.Unstructured
	currentPolicy *unstructured.Unstructured
	policy        *unstructured.Unstructured
}

func (p *Plugin) planServiceRemediation(ctx context.Context, proposal remediation.Proposal) (remediation.Plan, error) {
	desired, err := p.desiredServiceRemediation(ctx, proposal)
	if err != nil {
		return remediation.Plan{}, err
	}
	digest, err := desired.digest()
	if err != nil {
		return remediation.Plan{}, err
	}
	return remediation.NewPlan(proposal, PluginID, p.config.SourceID, serviceRemediationActionID, digest)
}

func (p *Plugin) prepareServiceRemediation(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan) (remediation.Preparation, error) {
	desired, err := p.desiredServiceForPlan(ctx, proposal, plan)
	if err != nil {
		return remediation.Preparation{}, err
	}
	admittedPolicy, err := p.writeNetworkPolicy(ctx, desired.policy, true)
	if err != nil {
		return remediation.Preparation{}, err
	}
	states, err := desired.providerStates(admittedPolicy)
	if err != nil {
		return remediation.Preparation{}, err
	}
	return remediation.NewPreparation(plan, true, states)
}

func (p *Plugin) executeServiceRemediation(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, preparation remediation.Preparation) (remediation.ExecutionResult, error) {
	desired, err := p.desiredServiceForPlan(ctx, proposal, plan)
	if err != nil {
		return remediation.ExecutionResult{}, err
	}
	if err := desired.requireProviderState(preparation.ProviderState); err != nil {
		return remediation.ExecutionResult{}, err
	}
	updatedPolicy, err := p.writeNetworkPolicy(ctx, desired.policy, false)
	if err != nil {
		return remediation.ExecutionResult{}, err
	}
	states, err := appliedServiceProviderStates(desired.service, updatedPolicy)
	if err != nil {
		return remediation.ExecutionResult{}, err
	}
	return remediation.NewExecutionResult(plan, preparation, true, states)
}

func (p *Plugin) verifyServiceRemediation(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan, result remediation.ExecutionResult) (remediation.Verification, error) {
	_, serviceState, _, policyState, err := serviceRemediationStates(result.ProviderState)
	if err != nil {
		return remediation.Verification{}, err
	}
	uid, err := p.proposalServiceUID(proposal)
	if err != nil {
		return remediation.Verification{}, err
	}
	service, err := p.actionTransport().ReadResource(servicesGVR, serviceState.Namespace).Get(ctx, serviceState.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return kubernetesVerification(plan, result, false), nil
	}
	if err != nil {
		return remediation.Verification{}, fmt.Errorf("get remediation target Service: %w", err)
	}
	if string(service.GetUID()) != uid {
		return kubernetesVerification(plan, result, false), nil
	}
	serviceDigest, err := serviceControlledDigest(service)
	if err != nil {
		return remediation.Verification{}, err
	}
	policy, err := p.actionTransport().ReadResource(networkPoliciesGVR, policyState.Namespace).Get(ctx, policyState.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return kubernetesVerification(plan, result, false), nil
	}
	if err != nil {
		return remediation.Verification{}, fmt.Errorf("get remediation NetworkPolicy: %w", err)
	}
	policyDigest, err := networkPolicyDigest(policy)
	if err != nil {
		return remediation.Verification{}, err
	}
	return kubernetesVerification(plan, result, serviceDigest == serviceState.ControlledSHA256 && policyDigest == policyState.ControlledSHA256), nil
}

func (p *Plugin) desiredServiceForPlan(ctx context.Context, proposal remediation.Proposal, plan remediation.Plan) (*desiredServiceRemediation, error) {
	desired, err := p.desiredServiceRemediation(ctx, proposal)
	if err != nil {
		return nil, err
	}
	digest, err := desired.digest()
	if err != nil {
		return nil, err
	}
	if digest != plan.DesiredSHA256 {
		return nil, errors.New("live Kubernetes remediation plan no longer matches desired state")
	}
	return desired, nil
}

func (p *Plugin) desiredServiceRemediation(ctx context.Context, proposal remediation.Proposal) (*desiredServiceRemediation, error) {
	uid, err := p.proposalServiceUID(proposal)
	if err != nil {
		return nil, err
	}
	services, err := p.actionTransport().ReadResource(servicesGVR, metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Services for remediation target: %w", err)
	}
	var target *unstructured.Unstructured
	for index := range services.Items {
		if string(services.Items[index].GetUID()) == uid {
			if target != nil {
				return nil, fmt.Errorf("multiple live Services have target UID %q", uid)
			}
			target = services.Items[index].DeepCopy()
		}
	}
	if target == nil {
		return nil, fmt.Errorf("live Service with UID %q was not found", uid)
	}
	selector, found, err := unstructured.NestedStringMap(target.Object, "spec", "selector")
	if err != nil {
		return nil, fmt.Errorf("decode remediation target Service selector: %w", err)
	}
	if !found || len(selector) == 0 {
		return nil, errors.New("remediation target Service has no Pod selector")
	}
	policyName := remediationPolicyName(uid)
	policy := &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{
			Name: policyName, Namespace: target.GetNamespace(),
			Labels: map[string]string{managedByLabel: managedByValue}, Annotations: map[string]string{targetUIDAnnotation: uid},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selector},
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
	policyObject := &unstructured.Unstructured{Object: object}
	if err := p.rejectServiceOverlappingIngressPolicies(ctx, target, selector, policyName); err != nil {
		return nil, err
	}
	currentPolicy, err := p.actionTransport().ReadResource(networkPoliciesGVR, target.GetNamespace()).Get(ctx, policyName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get existing remediation NetworkPolicy: %w", err)
	}
	if apierrors.IsNotFound(err) {
		currentPolicy = nil
	} else {
		matching, err := sameNetworkPolicy(currentPolicy, policyObject)
		if err != nil {
			return nil, err
		}
		if !isManagedNetworkPolicyForTarget(currentPolicy, uid) || !matching {
			return nil, fmt.Errorf("NetworkPolicy %s/%s collides with the deterministic remediation name or has drifted controlled content", target.GetNamespace(), policyName)
		}
		policyObject.SetResourceVersion(currentPolicy.GetResourceVersion())
	}
	return &desiredServiceRemediation{service: target, currentPolicy: currentPolicy, policy: policyObject}, nil
}

func (p *Plugin) proposalServiceUID(proposal remediation.Proposal) (string, error) {
	identity := proposal.Target.Identity
	if proposal.Intent != remediation.IntentNetworkDeclareIngressIsolation || proposal.Target.Kind != "kubernetes/service" || identity.Scheme != IdentitySchemeDefinition().Scheme || identity.AuthorityID != p.config.ClusterID {
		return "", errors.New("remediation proposal is not for a Service supported by this Kubernetes provider")
	}
	parts := strings.Split(identity.ImmutableKey, "/")
	if len(parts) != 3 || !strings.EqualFold(parts[0], "v1") || !strings.EqualFold(parts[1], "service") || strings.TrimSpace(parts[2]) == "" {
		return "", errors.New("remediation proposal has an invalid Kubernetes Service identity")
	}
	return parts[2], nil
}

func (p *Plugin) rejectServiceOverlappingIngressPolicies(ctx context.Context, service *unstructured.Unstructured, selector map[string]string, managedName string) error {
	pods, err := p.actionTransport().ReadResource(podsGVR, service.GetNamespace()).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(selector).String()})
	if err != nil {
		return fmt.Errorf("list Pods selected by remediation target Service: %w", err)
	}
	for index := range pods.Items {
		if err := p.rejectOverlappingIngressPoliciesForUID(ctx, &pods.Items[index], managedName, string(service.GetUID())); err != nil {
			return err
		}
	}
	return nil
}

func (desired *desiredServiceRemediation) digest() (string, error) {
	serviceDigest, err := serviceControlledDigest(desired.service)
	if err != nil {
		return "", err
	}
	policyDigest, err := networkPolicyDigest(desired.policy)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal([]string{serviceDigest, policyDigest})
	if err != nil {
		return "", fmt.Errorf("encode remediation desired-state digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func serviceControlledDigest(service *unstructured.Unstructured) (string, error) {
	selector, found, err := unstructured.NestedStringMap(service.Object, "spec", "selector")
	if err != nil {
		return "", fmt.Errorf("decode Service selector: %w", err)
	}
	if !found {
		selector = map[string]string{}
	}
	encoded, err := json.Marshal(struct {
		Namespace string            `json:"namespace"`
		Name      string            `json:"name"`
		Selector  map[string]string `json:"selector"`
	}{service.GetNamespace(), service.GetName(), selector})
	if err != nil {
		return "", fmt.Errorf("encode Service controlled state: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (desired *desiredServiceRemediation) providerStates(admittedPolicy *unstructured.Unstructured) ([]remediation.ProviderState, error) {
	serviceDigest, err := serviceControlledDigest(desired.service)
	if err != nil {
		return nil, err
	}
	serviceObservation := ActionObservation{Resource: "services", Namespace: desired.service.GetNamespace(), Name: desired.service.GetName(), Exists: true, UID: string(desired.service.GetUID()), ResourceVersion: desired.service.GetResourceVersion(), ControlledSHA256: serviceDigest}
	serviceState, err := ProviderState("service", serviceObservation, serviceObservation)
	if err != nil {
		return nil, err
	}
	policyCurrent := ActionObservation{Resource: "networkpolicies", Namespace: desired.policy.GetNamespace(), Name: desired.policy.GetName(), Exists: desired.currentPolicy != nil}
	if desired.currentPolicy != nil {
		policyCurrent.UID = string(desired.currentPolicy.GetUID())
		policyCurrent.ResourceVersion = desired.currentPolicy.GetResourceVersion()
		policyCurrent.ControlledSHA256, err = networkPolicyDigest(desired.currentPolicy)
		if err != nil {
			return nil, err
		}
	}
	policyDigest, err := networkPolicyDigest(admittedPolicy)
	if err != nil {
		return nil, err
	}
	policyPrepared := ActionObservation{Resource: "networkpolicies", Namespace: admittedPolicy.GetNamespace(), Name: admittedPolicy.GetName(), Exists: true, UID: string(admittedPolicy.GetUID()), ResourceVersion: admittedPolicy.GetResourceVersion(), ControlledSHA256: policyDigest}
	policyState, err := ProviderState("network-policy", policyCurrent, policyPrepared)
	return []remediation.ProviderState{serviceState, policyState}, err
}

func appliedServiceProviderStates(service, policy *unstructured.Unstructured) ([]remediation.ProviderState, error) {
	desired := &desiredServiceRemediation{service: service, currentPolicy: policy, policy: policy}
	return desired.providerStates(policy)
}

func (desired *desiredServiceRemediation) requireProviderState(states []remediation.ProviderState) error {
	serviceCurrent, servicePrepared, policyCurrent, policyPrepared, err := serviceRemediationStates(states)
	if err != nil {
		return err
	}
	serviceDigest, err := serviceControlledDigest(desired.service)
	if err != nil {
		return err
	}
	if !serviceCurrent.Exists || serviceCurrent.Namespace != desired.service.GetNamespace() || serviceCurrent.Name != desired.service.GetName() || serviceCurrent.UID != string(desired.service.GetUID()) || serviceCurrent.ResourceVersion != desired.service.GetResourceVersion() || serviceCurrent.ControlledSHA256 != serviceDigest || servicePrepared.ControlledSHA256 != serviceDigest {
		return errors.New("target Service changed after remediation preparation")
	}
	policyDesiredDigest, err := networkPolicyDigest(desired.policy)
	if err != nil {
		return err
	}
	if policyPrepared.Namespace != desired.policy.GetNamespace() || policyPrepared.Name != desired.policy.GetName() || policyPrepared.ControlledSHA256 != policyDesiredDigest {
		return errors.New("managed NetworkPolicy preparation state does not match the plan")
	}
	if desired.currentPolicy == nil {
		if policyCurrent.Exists || policyCurrent.UID != "" || policyCurrent.ResourceVersion != "" || policyCurrent.ControlledSHA256 != "" {
			return errors.New("managed NetworkPolicy existence changed after remediation preparation")
		}
		return nil
	}
	policyCurrentDigest, err := networkPolicyDigest(desired.currentPolicy)
	if err != nil {
		return err
	}
	if !policyCurrent.Exists || policyCurrent.UID != string(desired.currentPolicy.GetUID()) || policyCurrent.ResourceVersion != desired.currentPolicy.GetResourceVersion() || policyCurrent.ControlledSHA256 != policyCurrentDigest {
		return errors.New("managed NetworkPolicy changed after remediation preparation")
	}
	return nil
}

func serviceRemediationStates(states []remediation.ProviderState) (ActionObservation, ActionObservation, ActionObservation, ActionObservation, error) {
	var serviceCurrent, servicePrepared, policyCurrent, policyPrepared ActionObservation
	for _, state := range states {
		current, prepared, err := DecodeProviderState(state)
		if err != nil {
			return serviceCurrent, servicePrepared, policyCurrent, policyPrepared, err
		}
		switch state.Key {
		case "service":
			if serviceCurrent.Resource != "" {
				return serviceCurrent, servicePrepared, policyCurrent, policyPrepared, errors.New("remediation provider state contains duplicate Services")
			}
			serviceCurrent, servicePrepared = current, prepared
		case "network-policy":
			if policyCurrent.Resource != "" {
				return serviceCurrent, servicePrepared, policyCurrent, policyPrepared, errors.New("remediation provider state contains duplicate NetworkPolicies")
			}
			policyCurrent, policyPrepared = current, prepared
		default:
			return serviceCurrent, servicePrepared, policyCurrent, policyPrepared, fmt.Errorf("remediation provider state contains unsupported key %q", state.Key)
		}
	}
	if serviceCurrent.Resource == "" || policyCurrent.Resource == "" || len(states) != 2 {
		return serviceCurrent, servicePrepared, policyCurrent, policyPrepared, errors.New("remediation provider state requires exactly one Service and one NetworkPolicy")
	}
	return serviceCurrent, servicePrepared, policyCurrent, policyPrepared, nil
}
