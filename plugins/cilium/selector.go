package cilium

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Cilium prefixes every endpoint label with its source ("k8s:app=web"). The
// namespace and cluster labels are ones Cilium adds to each Pod's endpoint.
const (
	ciliumLabelSourceAny = "any"
	ciliumLabelSourceK8s = "k8s"
	ciliumPodNamespace   = "io.kubernetes.pod.namespace"
	ciliumPolicyCluster  = "io.cilium.k8s.policy.cluster"
)

// ciliumLabelKey is a label key qualified by its Cilium source.
type ciliumLabelKey struct {
	source string
	key    string
}

type ciliumSelectorRequirement struct {
	key      ciliumLabelKey
	operator metav1.LabelSelectorOperator
	values   []string
}

// ciliumEndpointSelector evaluates a CiliumNetworkPolicy endpointSelector
// against a Pod, approximating how Cilium matches endpoint labels. Only Pod
// labels and the namespace and cluster labels are modeled; other labels
// Cilium derives (service account, namespace labels, reserved identities)
// are absent, so In and Exists on them never match and NotIn and
// DoesNotExist always do.
type ciliumEndpointSelector struct {
	requirements []ciliumSelectorRequirement
}

// newCiliumEndpointSelector validates and compiles a selector. matchLabels
// become In requirements, sorted for deterministic evaluation. Invalid keys,
// values, or operators return an error, which fails the projection instead of
// treating the policy as matching nothing.
func newCiliumEndpointSelector(selector metav1.LabelSelector) (ciliumEndpointSelector, error) {
	keys := make([]string, 0, len(selector.MatchLabels))
	for key := range selector.MatchLabels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := ciliumEndpointSelector{requirements: make([]ciliumSelectorRequirement, 0, len(keys)+len(selector.MatchExpressions))}
	for _, key := range keys {
		requirement, err := newCiliumSelectorRequirement(key, metav1.LabelSelectorOpIn, []string{selector.MatchLabels[key]})
		if err != nil {
			return ciliumEndpointSelector{}, err
		}
		result.requirements = append(result.requirements, requirement)
	}
	for _, expression := range selector.MatchExpressions {
		requirement, err := newCiliumSelectorRequirement(expression.Key, expression.Operator, expression.Values)
		if err != nil {
			return ciliumEndpointSelector{}, err
		}
		result.requirements = append(result.requirements, requirement)
	}
	return result, nil
}

func newCiliumSelectorRequirement(key string, operator metav1.LabelSelectorOperator, values []string) (ciliumSelectorRequirement, error) {
	parsed, err := parseCiliumLabelKey(key)
	if err != nil {
		return ciliumSelectorRequirement{}, err
	}
	for _, value := range values {
		if problems := validation.IsValidLabelValue(value); len(problems) > 0 {
			return ciliumSelectorRequirement{}, fmt.Errorf("invalid value %q for Cilium label %q: %s", value, key, strings.Join(problems, ", "))
		}
	}
	switch operator {
	case metav1.LabelSelectorOpIn, metav1.LabelSelectorOpNotIn:
		if len(values) == 0 {
			return ciliumSelectorRequirement{}, fmt.Errorf("Cilium label %q operator %q requires values", key, operator)
		}
	case metav1.LabelSelectorOpExists, metav1.LabelSelectorOpDoesNotExist:
		if len(values) != 0 {
			return ciliumSelectorRequirement{}, fmt.Errorf("Cilium label %q operator %q does not accept values", key, operator)
		}
	default:
		return ciliumSelectorRequirement{}, fmt.Errorf("Cilium label %q has unsupported operator %q", key, operator)
	}
	return ciliumSelectorRequirement{key: parsed, operator: operator, values: slices.Clone(values)}, nil
}

// parseCiliumLabelKey splits "source:key" as Cilium does. An unprefixed key
// matches any source, and a leading "$" is shorthand for the reserved source.
func parseCiliumLabelKey(value string) (ciliumLabelKey, error) {
	source := ciliumLabelSourceAny
	key := value
	if strings.HasPrefix(key, "$") {
		source, key = "reserved", strings.TrimPrefix(key, "$")
	} else if parsedSource, parsedKey, found := strings.Cut(key, ":"); found {
		source, key = parsedSource, parsedKey
	}
	if source == "" || len(validation.IsQualifiedName(key)) != 0 {
		return ciliumLabelKey{}, fmt.Errorf("invalid Cilium label key %q", value)
	}
	return ciliumLabelKey{source: source, key: key}, nil
}

// Matches reports whether every requirement holds for pod. An empty selector
// matches every Pod; the caller limits namespaced policies to their own
// namespace. The cluster label takes the AgentShield cluster ID, so a
// selector on it matches only when that ID equals Cilium's cluster name.
func (selector ciliumEndpointSelector) Matches(clusterID string, pod *unstructured.Unstructured) bool {
	labels := make(map[ciliumLabelKey]string, len(pod.GetLabels())+2)
	for key, value := range pod.GetLabels() {
		labels[ciliumLabelKey{source: ciliumLabelSourceK8s, key: key}] = value
	}
	labels[ciliumLabelKey{source: ciliumLabelSourceK8s, key: ciliumPodNamespace}] = pod.GetNamespace()
	labels[ciliumLabelKey{source: ciliumLabelSourceK8s, key: ciliumPolicyCluster}] = clusterID

	for _, requirement := range selector.requirements {
		key := requirement.key
		// Every modeled label has the k8s source, so "any" reduces to it.
		if key.source == ciliumLabelSourceAny {
			key.source = ciliumLabelSourceK8s
		}
		value, exists := labels[key]
		switch requirement.operator {
		case metav1.LabelSelectorOpIn:
			if !exists || !slices.Contains(requirement.values, value) {
				return false
			}
		case metav1.LabelSelectorOpNotIn:
			if exists && slices.Contains(requirement.values, value) {
				return false
			}
		case metav1.LabelSelectorOpExists:
			if !exists {
				return false
			}
		case metav1.LabelSelectorOpDoesNotExist:
			if exists {
				return false
			}
		}
	}
	return true
}
