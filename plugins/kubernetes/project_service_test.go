package kubernetes

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestProjectServiceVariants(t *testing.T) {
	tests := []struct {
		name string
		spec map[string]any
		want map[string]string
	}{
		{
			name: "cluster IP",
			spec: map[string]any{"type": "ClusterIP", "clusterIP": "10.0.0.1"},
			want: map[string]string{"kubernetes/service-type": "ClusterIP", "kubernetes/cluster-addresses": `[{"address":"10.0.0.1"}]`},
		},
		{
			name: "headless",
			spec: map[string]any{"clusterIP": "None", "clusterIPs": []any{"None"}},
			want: map[string]string{"kubernetes/cluster-addresses": `[{"address":"None"}]`},
		},
		{
			name: "node port",
			spec: map[string]any{"type": "NodePort", "ports": []any{map[string]any{"name": "http", "protocol": "TCP", "port": int64(80), "targetPort": "http", "nodePort": int64(30080)}}},
			want: map[string]string{"kubernetes/service-type": "NodePort", "kubernetes/ports": `[{"name":"http","nodePort":30080,"port":80,"protocol":"TCP","targetPort":"http"}]`},
		},
		{
			name: "load balancer",
			spec: map[string]any{"type": "LoadBalancer", "loadBalancerClass": "example.net/lb", "loadBalancerSourceRanges": []any{"192.0.2.0/24"}, "externalTrafficPolicy": "Local"},
			want: map[string]string{"kubernetes/load-balancer-class": "example.net/lb", "kubernetes/load-balancer-source-ranges": `["192.0.2.0/24"]`, "kubernetes/external-traffic-policy": "Local"},
		},
		{
			name: "external name",
			spec: map[string]any{"type": "ExternalName", "externalName": "db.example.net"},
			want: map[string]string{"kubernetes/external-name": "db.example.net"},
		},
		{
			name: "dual stack",
			spec: map[string]any{"clusterIP": "fd00::1", "clusterIPs": []any{"fd00::1", "10.0.0.2"}, "ipFamilies": []any{"IPv6", "IPv4"}, "ipFamilyPolicy": "RequireDualStack"},
			want: map[string]string{"kubernetes/cluster-addresses": `[{"address":"fd00::1","family":"IPv6"},{"address":"10.0.0.2","family":"IPv4"}]`, "kubernetes/ip-family-policy": "RequireDualStack"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := testObject("v1", "Service", "demo", "service", "service", map[string]any{"spec": test.spec})
			input, err := Project("cluster", "source", []*unstructured.Unstructured{service})
			if err != nil {
				t.Fatal(err)
			}
			resource := resourceOfKind(t, input, "kubernetes/service")
			attributes := resource.Attributes
			for key, want := range test.want {
				if got := attributes[key]; got != want {
					t.Fatalf("%s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestProjectDeploymentAuthoringContextIsMinimal(t *testing.T) {
	deployment := testObject("apps/v1", "Deployment", "prod", "payments", "deployment-uid", map[string]any{"spec": map[string]any{
		"template": map[string]any{"spec": map[string]any{
			"serviceAccountName": "payments-runtime",
			"containers": []any{map[string]any{
				"name": "api", "image": "registry.example/payments:v4",
				"env": []any{map[string]any{"name": "API_TOKEN", "value": "literal-secret-must-not-leak"}},
			}},
		}}}})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{deployment})
	if err != nil {
		t.Fatal(err)
	}
	resource := resourceOfKind(t, input, "kubernetes/deployment")
	if resource.RuleID != "kubernetes.deployment.authoring-context" {
		t.Fatalf("deployment provenance=%s", resource.RuleID)
	}
	if resource.Attributes["kubernetes/service-account-name"] != "payments-runtime" {
		t.Fatalf("attributes=%#v", resource.Attributes)
	}
	for key, value := range resource.Attributes {
		if strings.Contains(value, "literal-secret-must-not-leak") || strings.Contains(value, "registry.example") {
			t.Fatalf("attribute %s leaked container spec: %s", key, value)
		}
	}
}

func TestServiceExposureDigestIgnoresSetOrder(t *testing.T) {
	ports := []any{map[string]any{"name": "https", "port": int64(443)}, map[string]any{"name": "http", "port": int64(80)}}
	externalIPs := []any{"192.0.2.2", "192.0.2.1"}
	sourceRanges := []any{"198.51.100.0/24", "203.0.113.0/24"}
	digest := func() string {
		service := testObject("v1", "Service", "demo", "service", "service", map[string]any{"spec": map[string]any{
			"type": "LoadBalancer", "ports": ports, "externalIPs": externalIPs, "loadBalancerSourceRanges": sourceRanges,
		}})
		input, err := Project("cluster", "source", []*unstructured.Unstructured{service})
		if err != nil {
			t.Fatal(err)
		}
		semantics, err := graph.DecodeSecuritySemantics(input.Facets[0].Attributes)
		if err != nil {
			t.Fatal(err)
		}
		return semantics.ConfigurationDigest
	}
	before := digest()
	slices.Reverse(ports)
	slices.Reverse(externalIPs)
	slices.Reverse(sourceRanges)
	if after := digest(); before != after {
		t.Fatalf("Service reorder changed digest from %s to %s", before, after)
	}
}

func TestProjectServiceExposureBoundsPortSummary(t *testing.T) {
	ports := make([]any, 65)
	for index := range ports {
		ports[index] = map[string]any{"name": "port-" + strconv.Itoa(index), "port": int64(index + 1)}
	}
	service := testObject("v1", "Service", "demo", "many-ports", "service", map[string]any{
		"spec": map[string]any{"type": "LoadBalancer", "ports": ports},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{service})
	if err != nil {
		t.Fatal(err)
	}
	for _, facet := range input.Facets {
		if facet.Kind != "network-exposure" {
			continue
		}
		semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		if semantics == nil || semantics.Coverage != "partial" || len(semantics.Ports) != 64 {
			t.Fatalf("bounded service exposure semantics = %#v", semantics)
		}
		return
	}
	t.Fatal("network exposure facet not found")
}

func TestProjectServiceSelectorAndPodDeletion(t *testing.T) {
	service := testObject("v1", "Service", "demo", "api", "service", map[string]any{
		"spec": map[string]any{
			"type": "LoadBalancer", "clusterIPs": []any{"fd00::1", "10.0.0.1"}, "externalIPs": []any{"203.0.113.2"},
			"selector": map[string]any{"app": "api"}, "ports": []any{map[string]any{"name": "http", "port": int64(80), "targetPort": "http"}},
		},
	})
	pod := testObject("v1", "Pod", "demo", "api-1", "pod", nil)
	pod.SetLabels(map[string]string{"app": "api"})

	withPod, err := Project("cluster", "source", []*unstructured.Unstructured{service, pod})
	if err != nil {
		t.Fatal(err)
	}
	serviceResource := resourceOfKind(t, withPod, "kubernetes/service")
	if got := serviceResource.Attributes["kubernetes/cluster-addresses"]; got != `[{"address":"fd00::1"},{"address":"10.0.0.1"}]` {
		t.Fatalf("cluster addresses = %s", got)
	}
	edge := exposesEdge(t, withPod, ClaimFor("cluster", service), ClaimFor("cluster", pod))
	if edge.Properties["basis"] != "selector" {
		t.Fatalf("basis = %q", edge.Properties["basis"])
	}
	if len(edge.EvidenceIDs) != 2 {
		t.Fatalf("evidence = %v, want service and pod", edge.EvidenceIDs)
	}
	var exposure *graph.SecuritySemantics
	for _, facet := range withPod.Facets {
		if facet.Resource == ClaimFor("cluster", service) && facet.Kind == "network-exposure" {
			exposure, err = graph.DecodeSecuritySemantics(facet.Attributes)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if exposure == nil || exposure.Class != graph.SecurityClassExposure || exposure.Effect != "external-addressable" || exposure.Coverage != "complete" {
		t.Fatalf("service exposure semantics = %#v", exposure)
	}
	if len(exposure.Ports) != 1 || exposure.Ports[0] != (graph.SecurityPort{Protocol: "TCP", Port: 80}) {
		t.Fatalf("service exposure ports = %#v", exposure.Ports)
	}

	withoutPod, err := Project("cluster", "source", []*unstructured.Unstructured{service})
	if err != nil {
		t.Fatal(err)
	}
	for _, relationship := range withoutPod.Relationships {
		if relationship.Object == ClaimFor("cluster", pod) {
			t.Fatalf("Pod relationship retained after deletion: %#v", relationship)
		}
	}
	compileInput(t, withPod)
}

func TestProjectNetworkAddressMetadata(t *testing.T) {
	service := testObject("v1", "Service", "default", "kubernetes", "api-service", map[string]any{
		"spec": map[string]any{
			"clusterIP": "10.0.0.1", "clusterIPs": []any{"10.0.0.1"},
			"ports": []any{map[string]any{"port": int64(443)}},
		},
	})
	pod := testObject("v1", "Pod", "demo", "worker", "worker", map[string]any{
		"status": map[string]any{
			"podIP": "10.2.0.4", "podIPs": []any{map[string]any{"ip": "10.2.0.4"}},
		},
	})
	input, err := ProjectWithNetworkID("cluster", "network-a", "source", []*unstructured.Unstructured{service, pod})
	if err != nil {
		t.Fatal(err)
	}
	api := resourceOfKind(t, input, "kubernetes/service")
	if api.Attributes["network/role"] != "control-plane-api" || api.Attributes["network/addresses"] != `["ip/10.0.0.1"]` {
		t.Fatalf("API server network metadata = %#v", api.Attributes)
	}
	if _, found := api.Attributes["network/reachable"]; found {
		t.Fatalf("API server has deprecated network/reachable metadata: %#v", api.Attributes)
	}
	workload := resourceOfKind(t, input, "kubernetes/pod")
	if workload.Attributes["network/role"] != "workload" || workload.Attributes["network/addresses"] != `["ip/10.2.0.4"]` {
		t.Fatalf("Pod network metadata = %#v", workload.Attributes)
	}
	if _, found := workload.Attributes["network/reachable"]; found {
		t.Fatalf("Pod has deprecated network/reachable metadata: %#v", workload.Attributes)
	}
	serviceAddress, err := graph.NetworkDestinationClaim("network-a", "ip/10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	podAddress, err := graph.NetworkDestinationClaim("network-a", "ip/10.2.0.4")
	if err != nil {
		t.Fatal(err)
	}
	serviceEdge := exposesEdge(t, input, ClaimFor("cluster", service), serviceAddress)
	if serviceEdge.Qualifier != "kubernetes-network-address" || serviceEdge.Properties["basis"] != "network/addresses" {
		t.Fatalf("Service address edge = %#v", serviceEdge)
	}
	exposesEdge(t, input, ClaimFor("cluster", pod), podAddress)
	if resourceOfClaim(t, input, podAddress).Kind != "network/destination" {
		t.Fatalf("Pod address destination missing: %#v", podAddress)
	}

	withoutPod, err := ProjectWithNetworkID("cluster", "network-a", "source", []*unstructured.Unstructured{service})
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range withoutPod.Resources {
		if resource.Claim == podAddress {
			t.Fatalf("Pod address retained after Pod deletion: %#v", resource)
		}
	}
	compileInput(t, input)
}

func TestProjectNetworkAddressConvergesAcrossResources(t *testing.T) {
	service := testObject("v1", "Service", "demo", "api", "service", map[string]any{
		"spec": map[string]any{"clusterIP": "10.0.0.1"},
	})
	pod := testObject("v1", "Pod", "demo", "api", "pod", map[string]any{
		"status": map[string]any{"podIP": "10.0.0.1"},
	})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{service, pod})
	if err != nil {
		t.Fatal(err)
	}
	destination, err := graph.NetworkDestinationClaim("cluster", "ip/10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	exposesEdge(t, input, ClaimFor("cluster", service), destination)
	exposesEdge(t, input, ClaimFor("cluster", pod), destination)

	registry := graph.NewRegistry()
	if err := registry.Register(IdentitySchemeDefinition()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	destinations := 0
	for _, resource := range snapshot.Resources {
		if resource.Identity == destination {
			destinations++
			if len(resource.Assertions) != 2 {
				t.Fatalf("destination assertions = %d, want 2", len(resource.Assertions))
			}
		}
	}
	if destinations != 1 {
		t.Fatalf("compiled destinations = %d, want 1", destinations)
	}
}

func testObject(apiVersion, kind, namespace, name, uid string, fields map[string]any) *unstructured.Unstructured {
	object := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": name, "namespace": namespace, "uid": uid}}
	for key, value := range fields {
		object[key] = value
	}
	return &unstructured.Unstructured{Object: object}
}

func resourceOfKind(t *testing.T, input graph.Input, kind string) graph.ResourceAssertion {
	t.Helper()
	for _, resource := range input.Resources {
		if resource.Kind == kind {
			return resource
		}
	}
	t.Fatalf("resource %s not found", kind)
	return graph.ResourceAssertion{}
}

func resourceOfClaim(t *testing.T, input graph.Input, claim graph.IdentityClaim) graph.ResourceAssertion {
	t.Helper()
	for _, resource := range input.Resources {
		if resource.Claim == claim {
			return resource
		}
	}
	t.Fatalf("resource %#v not found", claim)
	return graph.ResourceAssertion{}
}

func exposesEdge(t *testing.T, input graph.Input, subject, object graph.IdentityClaim) graph.RelationshipAssertion {
	t.Helper()
	for _, relationship := range input.Relationships {
		if relationship.Predicate == graph.PredicateExposes && relationship.Subject == subject && relationship.Object == object {
			return relationship
		}
	}
	t.Fatal("exposes edge not found")
	return graph.RelationshipAssertion{}
}

func compileInput(t *testing.T, input graph.Input) {
	t.Helper()
	registry := graph.NewRegistry()
	if err := registry.Register(IdentitySchemeDefinition()); err != nil {
		t.Fatal(err)
	}
	if _, err := graph.NewCompiler(registry).Compile(input); err != nil {
		t.Fatal(err)
	}
}

func TestProjectDeploymentPodTemplateDigestTracksRevisions(t *testing.T) {
	digest := func(mutate func(template map[string]any)) string {
		t.Helper()
		template := map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"app": "payments"}, "annotations": map[string]any{"team": "payments"}},
			"spec":     map[string]any{"containers": []any{map[string]any{"name": "api", "image": "registry.example/payments:v4"}}},
		}
		if mutate != nil {
			mutate(template)
		}
		deployment := testObject("apps/v1", "Deployment", "prod", "payments", "deployment-uid", map[string]any{"spec": map[string]any{"replicas": int64(2), "template": template}})
		input, err := Project("cluster", "source", []*unstructured.Unstructured{deployment})
		if err != nil {
			t.Fatal(err)
		}
		value := resourceOfKind(t, input, "kubernetes/deployment").Attributes["kubernetes/pod-template-sha256"]
		if len(value) != 64 {
			t.Fatalf("pod template digest = %q", value)
		}
		return value
	}
	base := digest(nil)
	restarted := digest(func(template map[string]any) {
		template["metadata"].(map[string]any)["annotations"].(map[string]any)["kubectl.kubernetes.io/restartedAt"] = "2026-10-18T00:00:00Z"
	})
	if restarted != base {
		t.Fatal("a rollout restart annotation changed the Pod template digest")
	}
	if digest(func(template map[string]any) {
		template["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = "registry.example/payments:v5"
	}) == base {
		t.Fatal("an image change did not change the Pod template digest")
	}
	if digest(func(template map[string]any) {
		template["metadata"].(map[string]any)["labels"].(map[string]any)["version"] = "v5"
	}) == base {
		t.Fatal("a Pod label change did not change the Pod template digest")
	}
}
