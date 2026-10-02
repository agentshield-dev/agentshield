package istio

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAuthorizationPolicyScopesAndRuleForms(t *testing.T) {
	demo := testObject("v1", "Namespace", "", "demo", "ns-demo", nil)
	other := testObject("v1", "Namespace", "", "other", "ns-other", nil)
	root := testObject("v1", "Namespace", "", "istio-system", "ns-root", nil)
	pod := testObject("v1", "Pod", "demo", "app", "pod", nil)
	pod.SetLabels(map[string]string{"app": "demo"})
	service := testObject("v1", "Service", "demo", "app", "service", nil)
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "waypoint", "gateway", nil)
	serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "demo", "external", "se", map[string]any{"hosts": []any{"external.example.com"}})
	namespacePolicy := testObject("security.istio.io/v1", "AuthorizationPolicy", "demo", "namespace", "policy-namespace", map[string]any{
		"rules": []any{},
	})
	meshPolicy := testObject("security.istio.io/v1", "AuthorizationPolicy", "istio-system", "mesh", "policy-mesh", map[string]any{
		"selector": map[string]any{"matchLabels": map[string]any{}}, "rules": []any{map[string]any{}}, "action": "DENY",
	})
	selectorPolicy := testObject("security.istio.io/v1", "AuthorizationPolicy", "demo", "selector", "policy-selector", map[string]any{
		"selector": map[string]any{"matchLabels": map[string]any{"app": "demo"}},
		"rules": []any{
			map[string]any{
				"from": []any{
					map[string]any{"source": map[string]any{"namespaces": []any{"other"}}},
				},
			},
		},
	})
	targetPolicy := testObject("security.istio.io/v1", "AuthorizationPolicy", "demo", "targets", "policy-targets", map[string]any{
		"action": "CUSTOM", "provider": map[string]any{"name": "ext-authz"},
		"targetRefs": []any{
			map[string]any{"group": "core", "kind": "Service", "name": "app"},
			map[string]any{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "waypoint"},
			map[string]any{"group": "networking.istio.io", "kind": "ServiceEntry", "name": "external"},
		},
	})
	invalid := testObject("security.istio.io/v1", "AuthorizationPolicy", "demo", "invalid", "policy-invalid", map[string]any{
		"selector":   map[string]any{"matchLabels": map[string]any{"app": "demo"}},
		"targetRefs": []any{map[string]any{"group": "core", "kind": "Service", "name": "app"}},
	})
	emptySelectorInvalid := testObject("security.istio.io/v1", "AuthorizationPolicy", "demo", "empty-selector-invalid", "policy-empty-selector-invalid", map[string]any{
		"selector":   map[string]any{"matchLabels": map[string]any{}},
		"targetRefs": []any{map[string]any{"group": "core", "kind": "Service", "name": "app"}},
	})
	result, err := ProjectObserved(testContext(), testObserved(demo, other, root, pod, service, gateway, serviceEntry, namespacePolicy, meshPolicy, selectorPolicy, targetPolicy, invalid, emptySelectorInvalid))
	if err != nil {
		t.Fatal(err)
	}
	qualifiers := map[string]int{}
	targetScopes := map[string]bool{}
	for _, relation := range result.Input.Relationships {
		if relation.Predicate == "governed-by" && len(relation.Qualifier) >= len("istio-authz-") && relation.Qualifier[:len("istio-authz-")] == "istio-authz-" {
			qualifiers[relation.Qualifier]++
			semantics, err := graph.DecodeSecuritySemantics(relation.Properties)
			if err != nil {
				t.Fatal(err)
			}
			if semantics == nil || semantics.Domain != graph.SecurityDomainAuthorization || semantics.State != graph.SecurityStateDeclared || semantics.Coverage != "partial" {
				t.Fatalf("authorization semantics = %#v", semantics)
			}
			if relation.Qualifier == "istio-authz-targetref" {
				targetScopes[semantics.Scope] = true
			}
		}
	}
	if qualifiers["istio-authz-namespace"] != 1 || qualifiers["istio-authz-mesh"] != 3 || qualifiers["istio-authz-selector"] != 1 || qualifiers["istio-authz-targetref"] != 3 {
		t.Fatalf("authorization qualifiers = %#v", qualifiers)
	}
	if !targetScopes["service"] || !targetScopes["gateway"] {
		t.Fatalf("authorization target scopes = %#v", targetScopes)
	}
	for _, resource := range result.Input.Resources {
		if resource.DisplayName == "istio-system/mesh" && resource.Attributes["istio/rule-form"] != "single-empty-rule" {
			t.Fatalf("mesh rule form = %q", resource.Attributes["istio/rule-form"])
		}
		if resource.DisplayName == "demo/targets" && (resource.Attributes["istio/action"] != "CUSTOM" || resource.Attributes["istio/provider"] != "ext-authz") {
			t.Fatalf("CUSTOM policy attributes = %#v", resource.Attributes)
		}
		if resource.DisplayName == "demo/empty-selector-invalid" && resource.Attributes["istio/validation"] != "invalid-targeting" {
			t.Fatalf("empty selector with targetRefs validation = %q", resource.Attributes["istio/validation"])
		}
	}
	postures := map[string]string{}
	for _, facet := range result.Input.Facets {
		if facet.Kind != "authorization-posture" {
			continue
		}
		postures[facet.Attributes["istio/action"]] = facet.Attributes["istio/rule-breadth"]
		semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
		if err != nil || semantics == nil || semantics.Domain != graph.SecurityDomainAuthorization {
			t.Fatalf("authorization posture semantics = %#v, err = %v", semantics, err)
		}
	}
	if postures["DENY"] != "all-requests" || postures["CUSTOM"] != "no-requests" {
		t.Fatalf("authorization postures = %#v", postures)
	}
	compileProjection(t, result, demo, other, root, pod, service, gateway)
}

func TestRootNamespaceSelectorPoliciesMatchPodsInEveryNamespace(t *testing.T) {
	demo := testObject("v1", "Namespace", "", "demo", "ns-demo", nil)
	other := testObject("v1", "Namespace", "", "other", "ns-other", nil)
	root := testObject("v1", "Namespace", "", "istio-system", "ns-root", nil)
	demoPod := testObject("v1", "Pod", "demo", "app", "pod-demo", nil)
	demoPod.SetLabels(map[string]string{"app": "api"})
	otherPod := testObject("v1", "Pod", "other", "app", "pod-other", nil)
	otherPod.SetLabels(map[string]string{"app": "api"})
	unmatched := testObject("v1", "Pod", "other", "web", "pod-web", nil)
	unmatched.SetLabels(map[string]string{"app": "web"})
	selector := map[string]any{"matchLabels": map[string]any{"app": "api"}}
	authorization := testObject("security.istio.io/v1", "AuthorizationPolicy", "istio-system", "api", "policy-root-selector", map[string]any{
		"selector": selector, "action": "DENY", "rules": []any{map[string]any{}},
	})
	peer := testObject("security.istio.io/v1", "PeerAuthentication", "istio-system", "api", "peer-root-selector", map[string]any{
		"selector": selector, "mtls": map[string]any{"mode": "STRICT"},
	})
	// A selector policy outside the root namespace stays in its namespace.
	local := testObject("security.istio.io/v1", "AuthorizationPolicy", "demo", "local", "policy-local-selector", map[string]any{
		"selector": selector, "rules": []any{},
	})
	objects := []*unstructured.Unstructured{demo, other, root, demoPod, otherPod, unmatched, authorization, peer, local}
	result, err := ProjectObserved(testContext(), testObserved(objects...))
	if err != nil {
		t.Fatal(err)
	}
	governed := map[string][]string{}
	for _, relation := range result.Input.Relationships {
		if relation.Predicate != graph.PredicateGovernedBy {
			continue
		}
		semantics, err := graph.DecodeSecuritySemantics(relation.Properties)
		if err != nil || semantics == nil {
			t.Fatalf("governance semantics = %#v, err = %v", semantics, err)
		}
		if relation.Object.ImmutableKey == "security.istio.io/v1/authorizationpolicy/policy-root-selector" && semantics.Scope != "mesh" {
			t.Fatalf("root selector policy scope = %q", semantics.Scope)
		}
		governed[relation.Object.ImmutableKey] = append(governed[relation.Object.ImmutableKey], relation.Subject.ImmutableKey)
	}
	want := map[string][]string{
		"security.istio.io/v1/authorizationpolicy/policy-root-selector":  {"v1/pod/pod-demo", "v1/pod/pod-other"},
		"security.istio.io/v1/peerauthentication/peer-root-selector":     {"v1/pod/pod-demo", "v1/pod/pod-other"},
		"security.istio.io/v1/authorizationpolicy/policy-local-selector": {"v1/pod/pod-demo"},
	}
	for policy, pods := range want {
		got := governed[policy]
		slices.Sort(got)
		if !slices.Equal(got, pods) {
			t.Fatalf("%s governs %v, want %v (all: %v)", policy, got, pods, governed)
		}
	}
	compileProjection(t, result, demo, other, root, demoPod, otherPod, unmatched)
}

func TestAuthorizationRuleBreadthTreatsAnyEmptyRuleAsAllRequests(t *testing.T) {
	rules := []json.RawMessage{json.RawMessage(`{"to":[{"operation":{"methods":["GET"]}}]}`), json.RawMessage(`{}`)}
	if got := authorizationRuleBreadth(rules); got != "all-requests" {
		t.Fatalf("rule breadth = %q", got)
	}
	if got := authorizationRuleBreadth(nil); got != "no-requests" {
		t.Fatalf("omitted rule breadth = %q", got)
	}
}
