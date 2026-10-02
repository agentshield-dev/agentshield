package kubernetes

import (
	"slices"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestProjectNetworkPolicySelectorsAndDirection(t *testing.T) {
	tests := []struct {
		name     string
		selector map[string]any
		labels   map[string]string
		matched  bool
	}{
		{name: "empty selects all", selector: map[string]any{}, labels: map[string]string{"app": "api"}, matched: true},
		{name: "match expressions", selector: map[string]any{"matchExpressions": []any{map[string]any{"key": "tier", "operator": "In", "values": []any{"edge", "api"}}, map[string]any{"key": "debug", "operator": "DoesNotExist"}}}, labels: map[string]string{"tier": "api"}, matched: true},
		{name: "namespace local mismatch", selector: map[string]any{"matchLabels": map[string]any{"app": "api"}}, labels: map[string]string{"app": "worker"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := testObject("v1", "Pod", "demo", "pod", "pod", nil)
			pod.SetLabels(test.labels)
			policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "policy", "policy", map[string]any{
				"spec": map[string]any{"podSelector": test.selector, "policyTypes": []any{"Ingress", "Egress"}, "ingress": []any{}, "egress": []any{}},
			})
			input, err := Project("cluster", "source", []*unstructured.Unstructured{pod, policy})
			if err != nil {
				t.Fatal(err)
			}
			matched := false
			for _, relationship := range input.Relationships {
				if relationship.Predicate == graph.PredicateGovernedBy {
					matched = true
					if relationship.Subject != ClaimFor("cluster", pod) || relationship.Object != ClaimFor("cluster", policy) {
						t.Fatalf("wrong governance direction: %#v", relationship)
					}
					semantics, err := graph.DecodeSecuritySemantics(relationship.Properties)
					if err != nil {
						t.Fatal(err)
					}
					if semantics == nil || semantics.Class != graph.SecurityClassGovernance || semantics.Domain != graph.SecurityDomainNetworkAccess || semantics.Effect != "restrict" {
						t.Fatalf("network policy semantics = %#v", semantics)
					}
				}
			}
			if matched != test.matched {
				t.Fatalf("matched = %t, want %t", matched, test.matched)
			}
			compileInput(t, input)
		})
	}
}

func TestProjectNetworkAddressPreservesPolicyPath(t *testing.T) {
	pod := testObject("v1", "Pod", "demo", "api", "pod", map[string]any{
		"status": map[string]any{"podIP": "10.2.0.4"},
	})
	pod.SetLabels(map[string]string{"app": "api"})
	policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "api", "policy", map[string]any{
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
			"policyTypes": []any{"Ingress"}, "ingress": []any{},
		},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{pod, policy})
	if err != nil {
		t.Fatal(err)
	}
	destination, err := graph.NetworkDestinationClaim("cluster", "ip/10.2.0.4")
	if err != nil {
		t.Fatal(err)
	}
	exposesEdge(t, input, ClaimFor("cluster", pod), destination)
	for _, relationship := range input.Relationships {
		if relationship.Subject == ClaimFor("cluster", pod) && relationship.Predicate == graph.PredicateGovernedBy && relationship.Object == ClaimFor("cluster", policy) {
			compileInput(t, input)
			return
		}
	}
	t.Fatal("addressable Pod governance relationship not found")
}

func TestNetworkPolicyAllPortsUsesPartialPortCoverage(t *testing.T) {
	pod := testObject("v1", "Pod", "demo", "pod", "pod", nil)
	policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "policy", "policy", map[string]any{
		"spec": map[string]any{
			"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"},
			"ingress": []any{map[string]any{"from": []any{}}},
		},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{pod, policy})
	if err != nil {
		t.Fatal(err)
	}
	for _, relationship := range input.Relationships {
		if relationship.Predicate != graph.PredicateGovernedBy {
			continue
		}
		semantics, err := graph.DecodeSecuritySemantics(relationship.Properties)
		if err != nil {
			t.Fatal(err)
		}
		if semantics == nil || semantics.Coverage != "partial" || len(semantics.Ports) != 0 {
			t.Fatalf("all-port policy semantics = %#v", semantics)
		}
		return
	}
	t.Fatal("network policy governance relationship not found")
}

func TestNetworkPolicyTargetingDistinguishesLabelMembershipFromIdentity(t *testing.T) {
	pod := testObject("v1", "Pod", "demo", "pod", "pod", nil)
	pod.SetLabels(map[string]string{"access": "allowed"})
	policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "policy", "policy", map[string]any{
		"spec": map[string]any{
			"podSelector": map[string]any{"matchLabels": map[string]any{"access": "allowed"}},
			"policyTypes": []any{"Ingress"}, "ingress": []any{},
		},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{pod, policy})
	if err != nil {
		t.Fatal(err)
	}
	foundFacet := false
	foundMembership := false
	for _, facet := range input.Facets {
		if facet.Resource != ClaimFor("cluster", policy) || facet.Kind != "policy-targeting" {
			continue
		}
		foundFacet = true
		if facet.Attributes["kubernetes/selector-basis"] != "pod-labels" || facet.Attributes["kubernetes/identity-assurance"] != "none" || facet.Attributes["kubernetes/selector-empty"] != "false" {
			t.Fatalf("targeting attributes = %#v", facet.Attributes)
		}
		semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
		if err != nil || semantics == nil || semantics.Domain != graph.SecurityDomainNetworkAccess {
			t.Fatalf("targeting semantics = %#v, err = %v", semantics, err)
		}
	}
	for _, relationship := range input.Relationships {
		if relationship.Subject == ClaimFor("cluster", pod) && relationship.Predicate == graph.PredicateGovernedBy && relationship.Object == ClaimFor("cluster", policy) {
			foundMembership = relationship.Properties["kubernetes/membership-resolution"] == "observed-label-match" && relationship.Properties["kubernetes/identity-assurance"] == "none"
		}
	}
	if !foundFacet || !foundMembership {
		t.Fatalf("targeting facet = %t, resolved membership = %t", foundFacet, foundMembership)
	}
	compileInput(t, input)
}

func TestNormalizeNetworkPolicyDefaultsPolicyTypes(t *testing.T) {
	tests := []struct {
		name string
		spec networkingv1.NetworkPolicySpec
		want []string
	}{
		{name: "omitted", spec: networkingv1.NetworkPolicySpec{}, want: []string{"Ingress"}},
		{name: "omitted with egress", spec: networkingv1.NetworkPolicySpec{Egress: []networkingv1.NetworkPolicyEgressRule{}}, want: []string{"Egress", "Ingress"}},
		{name: "explicit egress only", spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}}, want: []string{"Egress"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, types, _, _ := normalizeNetworkPolicy(&networkingv1.NetworkPolicy{Spec: test.spec})
			if !slices.Equal(types, test.want) {
				t.Fatalf("policy types = %v, want %v", types, test.want)
			}
		})
	}
}

func TestNetworkPolicySelectorNormalizationIsOrderIndependent(t *testing.T) {
	projectSelector := func(expressions []any) string {
		policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "policy", "policy", map[string]any{
			"spec": map[string]any{"podSelector": map[string]any{"matchExpressions": expressions}},
		})
		input, err := Project("cluster", "source", []*unstructured.Unstructured{policy})
		if err != nil {
			t.Fatal(err)
		}
		return resourceOfKind(t, input, "kubernetes/networkpolicy").Attributes["kubernetes/pod-selector"]
	}
	first := projectSelector([]any{
		map[string]any{"key": "tier", "operator": "In", "values": []any{"b", "c"}},
		map[string]any{"key": "tier", "operator": "In", "values": []any{"a", "d"}},
	})
	second := projectSelector([]any{
		map[string]any{"key": "tier", "operator": "In", "values": []any{"c", "b"}},
		map[string]any{"key": "tier", "operator": "In", "values": []any{"d", "a"}},
	})
	if first != second {
		t.Fatalf("equivalent selectors normalized differently:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestNetworkPolicyDigestIgnoresRulePeerAndPortOrder(t *testing.T) {
	pod := testObject("v1", "Pod", "demo", "pod", "pod", nil)
	projectDigest := func(ingress []any) string {
		policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "policy", "policy", map[string]any{
			"spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}, "ingress": ingress},
		})
		input, err := Project("cluster", "source", []*unstructured.Unstructured{pod, policy})
		if err != nil {
			t.Fatal(err)
		}
		for _, relationship := range input.Relationships {
			if relationship.Predicate == graph.PredicateGovernedBy {
				semantics, err := graph.DecodeSecuritySemantics(relationship.Properties)
				if err != nil {
					t.Fatal(err)
				}
				return semantics.ConfigurationDigest
			}
		}
		t.Fatal("network policy governance relationship not found")
		return ""
	}
	first := projectDigest([]any{map[string]any{
		"from":  []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "api"}}}, map[string]any{"namespaceSelector": map[string]any{}}},
		"ports": []any{map[string]any{"port": int64(443), "protocol": "TCP"}, map[string]any{"port": int64(80), "protocol": "TCP"}},
	}})
	second := projectDigest([]any{map[string]any{
		"ports": []any{map[string]any{"port": int64(80), "protocol": "TCP"}, map[string]any{"port": int64(443), "protocol": "TCP"}},
		"from":  []any{map[string]any{"namespaceSelector": map[string]any{}}, map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "api"}}}},
	}})
	if first != second {
		t.Fatalf("NetworkPolicy reorder changed digest from %s to %s", first, second)
	}
}
