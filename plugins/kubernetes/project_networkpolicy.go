package kubernetes

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

// maxPolicyRules caps the rules copied into each direction's attribute; the
// omitted count is recorded so truncation is visible.
const maxPolicyRules = 100

// networkPolicyAttributes describes the policy's normalized selector, types,
// and rules on its resource node.
func networkPolicyAttributes(policy *unstructured.Unstructured) (map[string]string, error) {
	result := attributes(policy)
	decoded, err := kubernetesapi.NetworkPolicy(policy)
	if err != nil {
		return nil, err
	}
	selector, types, ingress, egress := normalizeNetworkPolicy(&decoded.Value)
	result["kubernetes/pod-selector"] = projectkit.MustCanonicalJSON(selector)
	result["kubernetes/policy-types"] = projectkit.MustCanonicalJSON(types)
	result["kubernetes/ingress-rule-count"] = strconv.Itoa(len(ingress))
	result["kubernetes/egress-rule-count"] = strconv.Itoa(len(egress))
	result["kubernetes/ingress-rules"] = canonicalTypedList(limitTyped(ingress, maxPolicyRules))
	result["kubernetes/egress-rules"] = canonicalTypedList(limitTyped(egress, maxPolicyRules))
	if len(ingress) > maxPolicyRules {
		result["kubernetes/omitted-ingress-rules"] = strconv.Itoa(len(ingress) - maxPolicyRules)
	}
	if len(egress) > maxPolicyRules {
		result["kubernetes/omitted-egress-rules"] = strconv.Itoa(len(egress) - maxPolicyRules)
	}
	return result, nil
}

// projectNetworkPolicies emits a policy-targeting facet per NetworkPolicy and
// a governed-by edge from each Pod it selects. NetworkPolicy is
// namespace-scoped, so only Pods in the policy's namespace are considered, and
// an empty podSelector selects all of them (flagged by selector-empty).
//
// Membership is a label match against currently observed Pods. Labels carry
// no identity assurance: anyone who can write Pod labels can join or leave
// the selection. The state is declared because enforcement depends on the
// CNI, which this plugin does not observe.
func projectNetworkPolicies(clusterID, sourceID string, index objectIndex, input *graph.Input) error {
	for _, policy := range index.networkPolicies {
		decoded, err := kubernetesapi.NetworkPolicy(policy)
		if err != nil {
			return err
		}
		selector, types, ingress, egress := normalizeNetworkPolicy(&decoded.Value)
		labelSelector, err := metav1.LabelSelectorAsSelector(&selector)
		if err != nil {
			return fmt.Errorf("network policy %s pod selector: %w", projectkit.DisplayName(policy), err)
		}
		properties, err := networkPolicySecurityProperties(selector, types, ingress, egress)
		if err != nil {
			return fmt.Errorf("network policy %s semantics: %w", projectkit.DisplayName(policy), err)
		}
		targetingAttributes := map[string]string{
			"kubernetes/selector-basis":        "pod-labels",
			"kubernetes/membership-resolution": "observed-label-match",
			"kubernetes/identity-assurance":    "none",
			"kubernetes/selector-empty":        strconv.FormatBool(labelSelector.Empty()),
		}
		semantics, err := graph.DecodeSecuritySemantics(properties)
		if err != nil {
			return fmt.Errorf("network policy %s targeting semantics: %w", projectkit.DisplayName(policy), err)
		}
		targetingAttributes, err = graph.WithSecuritySemantics(targetingAttributes, *semantics)
		if err != nil {
			return fmt.Errorf("network policy %s targeting facet: %w", projectkit.DisplayName(policy), err)
		}
		input.Facets = append(input.Facets, graph.FacetAssertion{
			Resource: claimFor(clusterID, policy), Kind: "policy-targeting", Key: "networkpolicy", Attributes: targetingAttributes,
			PluginID: PluginID, SourceID: sourceID, RuleID: "kubernetes.networkpolicy.targeting",
			EvidenceIDs: evidenceIDs(policy),
		})
		for _, pod := range index.podsForLabels(policy.GetNamespace(), selector.MatchLabels) {
			if labelSelector.Matches(labels.Set(pod.GetLabels())) {
				relationshipProperties := make(map[string]string, len(properties)+4)
				for key, value := range properties {
					relationshipProperties[key] = value
				}
				relationshipProperties["kubernetes/selector-basis"] = "pod-labels"
				relationshipProperties["kubernetes/membership-resolution"] = "observed-label-match"
				relationshipProperties["kubernetes/identity-assurance"] = "none"
				relationshipProperties["kubernetes/selector-empty"] = strconv.FormatBool(labelSelector.Empty())
				input.Relationships = append(input.Relationships, relationshipAssertion(
					sourceID, "kubernetes.networkpolicy.target",
					claimFor(clusterID, pod), graph.PredicateGovernedBy, claimFor(clusterID, policy), "",
					relationshipProperties, pod, policy,
				))
			}
		}
	}
	return nil
}

// networkPolicySecurityProperties encodes the policy as a "restrict" effect:
// selecting a Pod isolates it in the listed directions, and the rules are
// the allow list on top of that isolation.
//
// Coverage drops to partial when the port list cannot be stated exactly: a
// rule with no ports or a port entry with no port (all ports), a named port
// (resolved per Pod by the CNI), an endPort range, or a capped list.
func networkPolicySecurityProperties(selector metav1.LabelSelector, types []string, ingress []networkingv1.NetworkPolicyIngressRule, egress []networkingv1.NetworkPolicyEgressRule) (map[string]string, error) {
	direction := "unknown"
	if slices.Contains(types, "Ingress") && slices.Contains(types, "Egress") {
		direction = "bidirectional"
	} else if len(types) == 1 {
		direction = strings.ToLower(types[0])
	}
	coverage := "complete"
	var protocols []string
	var ports []graph.SecurityPort
	collect := func(values []networkingv1.NetworkPolicyPort) {
		for _, value := range values {
			// The API defaults an unset protocol to TCP.
			protocol := string(corev1.ProtocolTCP)
			if value.Protocol != nil {
				protocol = string(*value.Protocol)
			}
			protocols = append(protocols, protocol)
			if value.Port == nil || value.Port.StrVal != "" || value.Port.IntVal < 1 || value.Port.IntVal > 65535 || value.EndPort != nil {
				coverage = "partial"
				continue
			}
			ports = append(ports, graph.SecurityPort{Protocol: protocol, Port: uint16(value.Port.IntVal)})
		}
	}
	for _, rule := range ingress {
		if len(rule.Ports) == 0 {
			coverage = "partial"
		}
		collect(rule.Ports)
	}
	for _, rule := range egress {
		if len(rule.Ports) == 0 {
			coverage = "partial"
		}
		collect(rule.Ports)
	}
	protocols, ports, truncated := boundedSecurityDetails(protocols, ports)
	if truncated {
		coverage = "partial"
	}
	semantics := graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
		State: graph.SecurityStateDeclared, Effect: "restrict", Scope: "workload", Direction: direction, Coverage: coverage,
		Protocols: protocols, Ports: ports, ConfigurationDigest: projectkit.SecurityDigest(map[string]any{
			"selector": selector, "types": types,
			"ingress": canonicalUnorderedJSON(ingress), "egress": canonicalUnorderedJSON(egress),
		}),
	}
	return graph.WithSecuritySemantics(map[string]string{"directions": projectkit.MustCanonicalJSON(types)}, semantics)
}

// normalizeNetworkPolicy sorts the selector so equal policies digest equally,
// and fills policyTypes when absent using the API server's defaulting rule:
// Ingress always, Egress only when an egress section is present.
func normalizeNetworkPolicy(policy *networkingv1.NetworkPolicy) (metav1.LabelSelector, []string, []networkingv1.NetworkPolicyIngressRule, []networkingv1.NetworkPolicyEgressRule) {
	selector := policy.Spec.PodSelector
	types := make([]string, 0, len(policy.Spec.PolicyTypes))
	for _, policyType := range policy.Spec.PolicyTypes {
		types = append(types, string(policyType))
	}
	if len(types) == 0 {
		types = []string{"Ingress"}
		if policy.Spec.Egress != nil {
			types = append(types, "Egress")
		}
	}
	types = uniqueSorted(types)
	for index := range selector.MatchExpressions {
		slices.Sort(selector.MatchExpressions[index].Values)
	}
	slices.SortFunc(selector.MatchExpressions, func(left, right metav1.LabelSelectorRequirement) int {
		return cmp.Compare(projectkit.MustCanonicalJSON(left), projectkit.MustCanonicalJSON(right))
	})
	return selector, types, policy.Spec.Ingress, policy.Spec.Egress
}

func limitTyped[T any](values []T, limit int) []T {
	if len(values) > limit {
		return values[:limit]
	}
	return values
}
