package cilium

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestProjectCNIOnlyDeterministically(t *testing.T) {
	objects := []*unstructured.Unstructured{
		object("v1", "Pod", "shop", "frontend", "pod-1", map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "frontend"}}}),
		object("v1", "Pod", "shop", "frontend-canary", "pod-2", map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "frontend"}}}),
		object("v1", "Node", "", "worker-1", "node-1", nil),
		object("cilium.io/v2", "CiliumNetworkPolicy", "shop", "frontend-policy", "policy-1", map[string]any{"spec": map[string]any{"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "frontend"}}, "ingress": []any{map[string]any{}}}}),
		object("cilium.io/v2", "CiliumEndpoint", "shop", "frontend", "endpoint-1", map[string]any{"status": map[string]any{"id": int64(12), "state": "ready", "identity": map[string]any{"id": int64(4242)}, "policy": map[string]any{"realized": map[string]any{"policy-enabled": "both"}}}}),
		object("cilium.io/v2", "CiliumNode", "", "worker-1", "cilium-node-1", map[string]any{"spec": map[string]any{"addresses": []any{map[string]any{"type": "CiliumInternalIP", "ip": "10.0.0.1"}}, "ipam": map[string]any{"podCIDRs": []any{"10.2.0.0/16", "10.1.0.0/16", "10.2.0.0/16"}}}}),
		object("cilium.io/v2", "CiliumEnvoyConfig", "shop", "ignored", "envoy-1", map[string]any{"spec": map[string]any{"services": []any{}}}),
	}
	want, err := Project("cluster-a", "cilium-a", objects)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Facets) != 3 || len(want.Relationships) != 2 {
		t.Fatalf("facets=%d relationships=%d, want 3 and 2", len(want.Facets), len(want.Relationships))
	}
	if got := want.Facets[2].Attributes["cilium/pod-cidrs"]; got != `["10.1.0.0/16","10.2.0.0/16"]` {
		t.Fatalf("canonical pod CIDRs = %s", got)
	}
	for _, relationship := range want.Relationships {
		semantics, err := graph.DecodeSecuritySemantics(relationship.Properties)
		if err != nil {
			t.Fatal(err)
		}
		if semantics == nil || semantics.Class != graph.SecurityClassGovernance || semantics.Domain != graph.SecurityDomainNetworkAccess || semantics.State != graph.SecurityStateDeclared || semantics.Effect != "restrict" || semantics.Direction != "ingress" || semantics.Coverage != "partial" || semantics.ConfigurationDigest == "" {
			t.Fatalf("Cilium policy semantics = %#v", semantics)
		}
	}
	var endpointSemantics *graph.SecuritySemantics
	for _, projectedFacet := range want.Facets {
		if projectedFacet.Kind == "cilium-cni" && projectedFacet.Key == "endpoint" {
			endpointSemantics, err = graph.DecodeSecuritySemantics(projectedFacet.Attributes)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if endpointSemantics == nil || endpointSemantics.State != graph.SecurityStateObserved || endpointSemantics.Effect != "restrict" || endpointSemantics.Direction != "bidirectional" || endpointSemantics.Coverage != "partial" {
		t.Fatalf("Cilium endpoint semantics = %#v", endpointSemantics)
	}
	for seed := int64(0); seed < 20; seed++ {
		shuffled := append([]*unstructured.Unstructured(nil), objects...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(left, right int) { shuffled[left], shuffled[right] = shuffled[right], shuffled[left] })
		got, err := Project("cluster-a", "cilium-a", shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("projection changed for seed %d", seed)
		}
	}
	registry := graph.NewRegistry()
	if err := discovery.RegisterIdentitySchemes(registry, kubernetesplugin.Descriptor()); err != nil {
		t.Fatal(err)
	}
	if _, err := graph.NewCompiler(registry).Compile(want); err != nil {
		t.Fatalf("compile projected Cilium input: %v", err)
	}
}

func TestProjectBoundsCiliumPolicySecurityDetails(t *testing.T) {
	ports := make([]any, 0, 70)
	for port := 1; port <= 70; port++ {
		ports = append(ports, map[string]any{"port": fmt.Sprint(port), "protocol": "TCP"})
	}
	pod := object("v1", "Pod", "shop", "frontend", "pod-1", map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "frontend"}}})
	policy := object("cilium.io/v2", "CiliumNetworkPolicy", "shop", "frontend-policy", "policy-1", map[string]any{"spec": map[string]any{
		"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "frontend"}},
		"ingress":          []any{map[string]any{"toPorts": []any{map[string]any{"ports": ports}}}},
	}})
	input, err := Project("cluster-a", "cilium-a", []*unstructured.Unstructured{pod, policy})
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Relationships) != 1 {
		t.Fatalf("relationships = %d, want 1", len(input.Relationships))
	}
	semantics, err := graph.DecodeSecuritySemantics(input.Relationships[0].Properties)
	if err != nil {
		t.Fatal(err)
	}
	if semantics == nil || len(semantics.Ports) != 64 || semantics.Coverage != "partial" {
		t.Fatalf("bounded Cilium policy semantics = %#v", semantics)
	}
}

func TestCiliumPolicyDigestIgnoresRuleAndPortOrder(t *testing.T) {
	pod := object("v1", "Pod", "shop", "frontend", "pod-1", map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "frontend"}}})
	digest := func(ingress []any) string {
		policy := object("cilium.io/v2", "CiliumNetworkPolicy", "shop", "frontend-policy", "policy-1", map[string]any{"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "frontend"}}, "ingress": ingress,
		}})
		input, err := Project("cluster-a", "cilium-a", []*unstructured.Unstructured{pod, policy})
		if err != nil {
			t.Fatal(err)
		}
		semantics, err := graph.DecodeSecuritySemantics(input.Relationships[0].Properties)
		if err != nil {
			t.Fatal(err)
		}
		return semantics.ConfigurationDigest
	}
	first := digest([]any{
		map[string]any{"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "443", "protocol": "TCP"}, map[string]any{"port": "80", "protocol": "TCP"}}}}},
		map[string]any{"fromEndpoints": []any{map[string]any{"matchLabels": map[string]any{"role": "client"}}}},
	})
	second := digest([]any{
		map[string]any{"fromEndpoints": []any{map[string]any{"matchLabels": map[string]any{"role": "client"}}}},
		map[string]any{"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "80", "protocol": "TCP"}, map[string]any{"port": "443", "protocol": "TCP"}}}}},
	})
	if first != second {
		t.Fatalf("Cilium policy reorder changed digest from %s to %s", first, second)
	}
}

func TestProjectExcludesL7RulesAndReportsMissingIdentity(t *testing.T) {
	l7PortRule := map[string]any{
		"ports": []any{map[string]any{"port": "80", "protocol": "TCP"}},
		"rules": map[string]any{"http": []any{map[string]any{"method": "GET"}}},
	}
	policy := object("cilium.io/v2", "CiliumNetworkPolicy", "shop", "http-policy", "policy-1", map[string]any{"spec": map[string]any{
		"endpointSelector": map[string]any{},
		"ingress":          []any{map[string]any{"toPorts": []any{l7PortRule}}},
	}})
	endpoint := object("cilium.io/v2", "CiliumEndpoint", "shop", "missing", "endpoint-1", nil)
	result, err := ProjectObserved(ProjectionContext{ClusterID: "cluster-a", SourceID: "cilium-a"}, []ObservedObject{
		{Object: policy, EventID: "policy-event"}, {Object: endpoint, EventID: "endpoint-event"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Input.Relationships) != 0 || result.Input.Facets[0].Attributes["cilium/cni-rule-count"] != "0" {
		t.Fatalf("L7 rule entered CNI semantics: %#v", result.Input)
	}
	codes := []string{result.Diagnostics[0].Code, result.Diagnostics[1].Code}
	sort.Strings(codes)
	if !reflect.DeepEqual(codes, []string{"missing-kubernetes-identity", "unsupported-l7-policy"}) {
		t.Fatalf("diagnostics = %v", codes)
	}
	encoded := result.Input.Facets[0].Attributes
	for key, value := range encoded {
		if strings.Contains(strings.ToLower(key+value), "http") {
			t.Fatalf("L7 detail leaked through %q=%q", key, value)
		}
	}
}

func TestProjectRejectsMalformedPolicy(t *testing.T) {
	malformed := object("cilium.io/v2", "CiliumNetworkPolicy", "shop", "bad", "policy-1", map[string]any{"spec": map[string]any{
		"endpointSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "app", "operator": "invalid"}}},
	}})
	_, err := Project("cluster-a", "cilium-a", []*unstructured.Unstructured{malformed})
	if err == nil || !strings.Contains(err.Error(), "shop/bad rule 0 selector") {
		t.Fatalf("error = %v", err)
	}
}

func object(apiVersion, kind, namespace, name, uid string, fields map[string]any) *unstructured.Unstructured {
	value := map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name": name, "namespace": namespace, "uid": uid, "resourceVersion": "7",
		},
	}
	for key, field := range fields {
		if key == "metadata" {
			metadata := value["metadata"].(map[string]any)
			for metadataKey, metadataValue := range field.(map[string]any) {
				metadata[metadataKey] = metadataValue
			}
			continue
		}
		value[key] = field
	}
	result := &unstructured.Unstructured{Object: value}
	result.SetUID(types.UID(uid))
	return result
}
