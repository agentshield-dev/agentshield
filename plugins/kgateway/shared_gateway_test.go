package kgateway

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

// sharedGatewayFixture: routes in namespace apps attach to a Gateway in
// gateway-system; /webhook is public, the dashboard and artifacts need auth.
func sharedGatewayFixture() []*unstructured.Unstructured {
	gateway := gatewayObject("gateway-system", "edge", "kgateway")
	gateway.Object["spec"].(map[string]any)["listeners"] = []any{map[string]any{"name": "http", "port": int64(80), "protocol": "HTTP", "allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "All"}}}}
	gateway.Object["spec"].(map[string]any)["infrastructure"] = map[string]any{"parametersRef": map[string]any{"group": kgatewayGroup, "kind": kindGatewayParams, "name": "edge"}}
	pathRule := func(path, service string, port int64) map[string]any {
		return map[string]any{
			"matches":     []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": path}}},
			"backendRefs": []any{map[string]any{"name": service, "port": port}},
		}
	}
	webhook := routeObject("apps", "webhook", nil, pathRule("/webhook", "webhook", 8888))
	dashboard := routeObject("apps", "dashboard", nil, pathRule("/", "dashboard", 80))
	artifacts := routeObject("apps", "artifacts", nil, pathRule("/artifacts/", "artifacts", 80))
	for _, route := range []*unstructured.Unstructured{webhook, dashboard, artifacts} {
		route.Object["spec"].(map[string]any)["parentRefs"] = []any{map[string]any{"name": "edge", "namespace": "gateway-system"}}
	}
	return []*unstructured.Unstructured{
		gatewayClassObject("kgateway", DefaultControllerName, nil),
		gateway,
		kgw(kindGatewayParams, "gateway-system", "edge", map[string]any{"kube": map[string]any{"service": map[string]any{"type": "ClusterIP"}}}),
		webhook, dashboard, artifacts,
		serviceObject("apps", "webhook"), serviceObject("apps", "dashboard"), serviceObject("apps", "artifacts"),
		kgw(kindGatewayExtension, "apps", "extauth", map[string]any{"type": "ExtAuth", "extAuth": map[string]any{}}),
		kgw(kindTrafficPolicy, "apps", "login", map[string]any{
			"targetRefs": []any{targetRef("HTTPRoute", "dashboard"), targetRef("HTTPRoute", "artifacts")},
			"extAuth":    map[string]any{"extensionRef": map[string]any{"name": "extauth"}},
		}),
	}
}

func TestProjectSharedGatewayGolden(t *testing.T) {
	objects := sharedGatewayFixture()
	result := mustProject(t, objects...)
	names := map[string]string{}
	for _, item := range objects {
		names[claimOf(item).ImmutableKey] = item.GetKind() + " " + projectkit.DisplayName(item)
	}
	label := func(claim graph.IdentityClaim) string {
		if name, found := names[claim.ImmutableKey]; found {
			return name
		}
		return claim.ImmutableKey
	}
	semantics := func(attributes map[string]string) string {
		decoded, err := graph.DecodeSecuritySemantics(attributes)
		if err != nil {
			t.Fatal(err)
		}
		if decoded == nil {
			return "-"
		}
		return fmt.Sprintf("%s/%s/%s/%s/%s", decoded.Class, decoded.Domain, decoded.Effect, decoded.Scope, decoded.Direction)
	}
	var lines []string
	for _, resource := range result.Input.Resources {
		lines = append(lines, fmt.Sprintf("resource %s %s", resource.Kind, label(resource.Claim)))
	}
	for _, facet := range result.Input.Facets {
		lines = append(lines, fmt.Sprintf("facet %s/%s on %s %s", facet.Kind, facet.Key, label(facet.Resource), semantics(facet.Attributes)))
	}
	for _, relationship := range result.Input.Relationships {
		lines = append(lines, fmt.Sprintf("edge %s %s %s %s", label(relationship.Subject), relationship.Predicate, label(relationship.Object), semantics(relationship.Properties)))
	}
	for _, diagnostic := range result.Diagnostics {
		lines = append(lines, fmt.Sprintf("diagnostic %s %s", diagnostic.Code, diagnostic.Resource))
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"

	path := filepath.Join("testdata", "shared-gateway.golden")
	if *updateGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("shared Gateway projection differs from %s:\n%s", path, got)
	}
	if strings.Contains(got, "HTTPRoute apps/webhook governed-by") {
		t.Fatal("ungated /webhook route gained a policy edge")
	}

	// The Kubernetes plugin owns route membership; all three routes must reach
	// the Gateway across namespaces for the gated/ungated split to mean anything.
	kubernetesInput, err := kubernetesplugin.Project("cluster", "source", objects)
	if err != nil {
		t.Fatal(err)
	}
	gateway := objects[1]
	for _, route := range objects[3:6] {
		if len(relationshipsBetween(kubernetesInput, route, graph.PredicateMemberOf, claimOf(gateway))) != 1 {
			t.Fatalf("%s is not member-of the Gateway", route.GetName())
		}
	}
	for _, relationship := range append(kubernetesInput.Relationships, result.Input.Relationships...) {
		if relationship.Subject == claimOf(objects[3]) && relationship.Predicate == graph.PredicateGovernedBy {
			t.Fatal("webhook is governed by a policy")
		}
	}
}
