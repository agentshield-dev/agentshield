package istio

import (
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestPeerAuthenticationScopesModesAndAmbientCaveat(t *testing.T) {
	rootNamespace := testObject("v1", "Namespace", "", "istio-system", "ns-root", nil)
	demo := testObject("v1", "Namespace", "", "demo", "ns-demo", nil)
	demo.SetLabels(map[string]string{"istio.io/dataplane-mode": "ambient"})
	pod := testObject("v1", "Pod", "demo", "app", "pod", nil)
	pod.SetLabels(map[string]string{"app": "demo"})
	meshStrict := testObject("security.istio.io/v1", "PeerAuthentication", "istio-system", "mesh", "peer-mesh", map[string]any{
		"mtls": map[string]any{"mode": "STRICT"},
	})
	namespaceDisable := testObject("security.istio.io/v1", "PeerAuthentication", "demo", "namespace", "peer-namespace", map[string]any{
		"mtls": map[string]any{"mode": "DISABLE"},
	})
	selectorUnset := testObject("security.istio.io/v1", "PeerAuthentication", "demo", "selector", "peer-selector", map[string]any{
		"selector":      map[string]any{"matchLabels": map[string]any{"app": "demo"}},
		"mtls":          map[string]any{"mode": "UNSET"},
		"portLevelMtls": map[string]any{"8080": map[string]any{"mode": "PERMISSIVE"}},
	})
	selectorPermissive := testObject("security.istio.io/v1", "PeerAuthentication", "demo", "permissive", "peer-permissive", map[string]any{
		"selector": map[string]any{"matchLabels": map[string]any{"app": "demo"}},
		"mtls":     map[string]any{"mode": "PERMISSIVE"},
	})
	result, err := ProjectObserved(testContext(), testObserved(rootNamespace, demo, pod, meshStrict, namespaceDisable, selectorUnset, selectorPermissive))
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string]bool{}
	ambientDisable := false
	inheritedUnset := false
	for _, facet := range result.Input.Facets {
		if facet.Kind != "istio-mtls" {
			continue
		}
		if facet.Key == "" || facet.Attributes["policy"] == "" {
			t.Fatalf("facet lacks readable policy identity: %#v", facet)
		}
		modes[facet.Attributes["declared-mode"]] = true
		if facet.Attributes["declared-mode"] == "DISABLE" && facet.Attributes["compatibility"] == "unsupported-in-ambient" {
			ambientDisable = true
		}
		if facet.Attributes["declared-mode"] == "UNSET" && facet.Attributes["compatibility"] == "inherited" && facet.Attributes["effective-mode-evaluated"] == "false" {
			inheritedUnset = true
		}
	}
	governance := 0
	portOverridePartial := false
	for _, relation := range result.Input.Relationships {
		if relation.Predicate != graph.PredicateGovernedBy || relation.Qualifier[:min(len(relation.Qualifier), len("istio-peer-authentication-"))] != "istio-peer-authentication-" {
			continue
		}
		semantics, err := graph.DecodeSecuritySemantics(relation.Properties)
		if err != nil {
			t.Fatal(err)
		}
		if semantics == nil || semantics.Domain != graph.SecurityDomainTransportAuthentication || semantics.Protocols[0] != "MTLS" {
			t.Fatalf("peer authentication semantics = %#v", semantics)
		}
		if relation.Object.ImmutableKey == claimKeyForObject(selectorUnset) && semantics.Coverage == "partial" {
			portOverridePartial = true
		}
		governance++
	}
	if governance == 0 {
		t.Fatal("peer authentication governance semantics not found")
	}
	for _, mode := range []string{"STRICT", "DISABLE", "UNSET", "PERMISSIVE"} {
		if !modes[mode] {
			t.Fatalf("mode %s was not preserved: %#v", mode, modes)
		}
	}
	if !ambientDisable || !inheritedUnset {
		t.Fatalf("ambientDisable=%t inheritedUnset=%t", ambientDisable, inheritedUnset)
	}
	if !portOverridePartial {
		t.Fatal("port-level mTLS override was not marked partial")
	}
	compileProjection(t, result, rootNamespace, demo, pod)
}
