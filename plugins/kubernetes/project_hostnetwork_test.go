package kubernetes

import (
	"maps"
	"math/rand"
	"slices"
	"strconv"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func findHostNetworkFacet(input graph.Input, pod *unstructured.Unstructured) (graph.FacetAssertion, bool) {
	for _, facet := range input.Facets {
		if facet.Resource == ClaimFor("cluster", pod) && facet.Kind == "network-exposure" && facet.Key == "host-network" {
			return facet, true
		}
	}
	return graph.FacetAssertion{}, false
}

func requireHostNetworkPostureFacet(t *testing.T, input graph.Input, pod *unstructured.Unstructured) graph.FacetAssertion {
	t.Helper()
	facet, found := findHostNetworkFacet(input, pod)
	if !found {
		t.Fatal("host-network posture facet not found")
	}
	return facet
}

func hasRunsOn(input graph.Input, pod, node *unstructured.Unstructured) bool {
	for _, relationship := range input.Relationships {
		if relationship.Predicate == graph.PredicateRunsOn && relationship.Subject == ClaimFor("cluster", pod) && relationship.Object == ClaimFor("cluster", node) {
			return true
		}
	}
	return false
}

func TestHostNetworkPodKeepsPodIPAndRunsOnWithoutClaimingNodeAddress(t *testing.T) {
	node := testObject("v1", "Node", "", "worker-a", "node", nil)
	pod := testObject("v1", "Pod", "kube-system", "kube-proxy", "kube-proxy", map[string]any{
		"spec":   map[string]any{"hostNetwork": true, "nodeName": "worker-a"},
		"status": map[string]any{"podIP": "10.142.0.5", "podIPs": []any{map[string]any{"ip": "10.142.0.5"}}},
	})
	input, err := ProjectWithNetworkID("cluster", "network-a", "source", []*unstructured.Unstructured{pod, node})
	if err != nil {
		t.Fatal(err)
	}
	workload := resourceOfClaim(t, input, ClaimFor("cluster", pod))
	if workload.Attributes["kubernetes/pod-ip"] != "10.142.0.5" {
		t.Fatalf("pod-ip = %q", workload.Attributes["kubernetes/pod-ip"])
	}
	if _, found := workload.Attributes["network/addresses"]; found {
		t.Fatalf("host-network Pod claims the Node address: %#v", workload.Attributes)
	}
	for _, resource := range input.Resources {
		if resource.Kind == "network/destination" {
			t.Fatalf("host-network Pod produced an address destination: %#v", resource)
		}
	}
	for _, relationship := range input.Relationships {
		if relationship.Predicate == graph.PredicateExposes {
			t.Fatalf("host-network Pod exposes an address: %#v", relationship)
		}
	}
	if !hasRunsOn(input, pod, node) {
		t.Fatal("host-network Pod lost its runs-on edge")
	}
	facet := requireHostNetworkPostureFacet(t, input, pod)
	if facet.RuleID != "kubernetes.pod.host-network-posture" || !slices.Equal(facet.EvidenceIDs, evidenceIDs(pod)) {
		t.Fatalf("facet provenance = %s %v", facet.RuleID, facet.EvidenceIDs)
	}
	if facet.Attributes["kubernetes/host-network"] != "true" || facet.Attributes["kubernetes/node-name"] != "worker-a" ||
		facet.Attributes["kubernetes/network-policy-applicability"] != "implementation-defined" {
		t.Fatalf("facet attributes = %#v", facet.Attributes)
	}
	semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	want := graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
		State: graph.SecurityStateDeclared, Effect: "unknown", Scope: "workload", Direction: "bidirectional", Coverage: "partial",
		ConfigurationDigest: semantics.ConfigurationDigest,
	}
	if semantics.ConfigurationDigest == "" || !equalSemantics(*semantics, want) {
		t.Fatalf("semantics = %#v", semantics)
	}
	compileInput(t, input)

	unscheduled := testObject("v1", "Pod", "kube-system", "pending", "pending", map[string]any{"spec": map[string]any{"hostNetwork": true}})
	input, err = Project("cluster", "source", []*unstructured.Unstructured{unscheduled, node})
	if err != nil {
		t.Fatal(err)
	}
	facet = requireHostNetworkPostureFacet(t, input, unscheduled)
	if _, found := facet.Attributes["kubernetes/node-name"]; found {
		t.Fatalf("unscheduled Pod has node-name: %#v", facet.Attributes)
	}
	if hasRunsOn(input, unscheduled, node) {
		t.Fatal("unscheduled Pod has a runs-on edge")
	}
	compileInput(t, input)
}

func equalSemantics(left, right graph.SecuritySemantics) bool {
	return left.Version == right.Version && left.Class == right.Class && left.Domain == right.Domain && left.State == right.State &&
		left.Effect == right.Effect && left.Scope == right.Scope && left.Direction == right.Direction && left.Coverage == right.Coverage &&
		slices.Equal(left.Protocols, right.Protocols) && slices.Equal(left.Ports, right.Ports) && left.ConfigurationDigest == right.ConfigurationDigest
}

func TestHostNetworkPostureCoFactorsAreDeterministicAndBounded(t *testing.T) {
	container := func(name string, securityContext map[string]any, ports ...any) map[string]any {
		result := map[string]any{"name": name, "image": "example"}
		if securityContext != nil {
			result["securityContext"] = securityContext
		}
		if len(ports) > 0 {
			result["ports"] = ports
		}
		return result
	}
	port := func(protocol string, number int64) map[string]any {
		result := map[string]any{"containerPort": number, "hostPort": number}
		if protocol != "" {
			result["protocol"] = protocol
		}
		return result
	}
	containers := []any{
		container("agent", map[string]any{"capabilities": map[string]any{"add": []any{"NET_ADMIN", "CAP_NET_RAW"}}}, port("UDP", 53), port("", 9100)),
		container("confined", map[string]any{"seccompProfile": map[string]any{"type": "RuntimeDefault"}, "capabilities": map[string]any{"add": []any{"sys_admin"}}}),
		container("inherits", nil, port("TCP", 9100)),
	}
	initContainers := []any{container("setup", map[string]any{"privileged": true})}
	ephemeralContainers := []any{container("debug", map[string]any{"capabilities": map[string]any{"add": []any{"ALL"}}})}
	spec := func(containers, initContainers, ephemeralContainers []any) map[string]any {
		return map[string]any{"spec": map[string]any{
			"hostNetwork": true, "hostPID": true, "hostIPC": false,
			"securityContext":     map[string]any{"seccompProfile": map[string]any{"type": "Unconfined"}},
			"containers":          containers,
			"initContainers":      initContainers,
			"ephemeralContainers": ephemeralContainers,
		}}
	}
	pod := testObject("v1", "Pod", "kube-system", "agent", "agent", spec(containers, initContainers, ephemeralContainers))
	input, err := Project("cluster", "source", []*unstructured.Unstructured{pod})
	if err != nil {
		t.Fatal(err)
	}
	facet := requireHostNetworkPostureFacet(t, input, pod)
	want := map[string]string{
		"kubernetes/host-network":                       "true",
		"kubernetes/network-policy-applicability":       "implementation-defined",
		"kubernetes/host-pid":                           "true",
		"kubernetes/host-ipc":                           "false",
		"kubernetes/host-network-ports":                 `[{"protocol":"TCP","port":9100},{"protocol":"UDP","port":53}]`,
		"kubernetes/privileged-container-count":         "1",
		"kubernetes/net-admin-container-count":          "3",
		"kubernetes/net-raw-container-count":            "3",
		"kubernetes/sys-admin-container-count":          "3",
		"kubernetes/unconfined-seccomp-container-count": "4",
	}
	for key, value := range want {
		if facet.Attributes[key] != value {
			t.Errorf("%s = %q, want %q", key, facet.Attributes[key], value)
		}
	}
	if _, found := facet.Attributes["kubernetes/omitted-host-network-values"]; found {
		t.Errorf("unexpected omission marker: %#v", facet.Attributes)
	}
	semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if semantics.Effect != "unknown" || semantics.Coverage != "partial" || !slices.Equal(semantics.Protocols, []string{"TCP", "UDP"}) ||
		!slices.Equal(semantics.Ports, []graph.SecurityPort{{Protocol: "TCP", Port: 9100}, {Protocol: "UDP", Port: 53}}) {
		t.Fatalf("declared ports changed semantics: %#v", semantics)
	}

	reordered := testObject("v1", "Pod", "kube-system", "agent", "agent", spec(
		[]any{containers[2], containers[0], containers[1]}, initContainers, ephemeralContainers,
	))
	reorderedInput, err := Project("cluster", "source", []*unstructured.Unstructured{reordered})
	if err != nil {
		t.Fatal(err)
	}
	if got := requireHostNetworkPostureFacet(t, reorderedInput, reordered); !maps.Equal(got.Attributes, facet.Attributes) {
		t.Fatalf("container order changed posture:\n%#v\n%#v", got.Attributes, facet.Attributes)
	}

	relaxed := testObject("v1", "Pod", "kube-system", "agent", "agent", spec(containers[:2], initContainers, ephemeralContainers))
	relaxedInput, err := Project("cluster", "source", []*unstructured.Unstructured{relaxed})
	if err != nil {
		t.Fatal(err)
	}
	relaxedSemantics, err := graph.DecodeSecuritySemantics(requireHostNetworkPostureFacet(t, relaxedInput, relaxed).Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if relaxedSemantics.ConfigurationDigest == semantics.ConfigurationDigest {
		t.Fatal("posture digest ignored a removed container")
	}

	var manyPorts []any
	for number := int64(1); number <= 70; number++ {
		manyPorts = append(manyPorts, port("TCP", number))
	}
	bounded := testObject("v1", "Pod", "kube-system", "bounded", "bounded", spec([]any{container("many", nil, manyPorts...)}, nil, nil))
	boundedInput, err := Project("cluster", "source", []*unstructured.Unstructured{bounded})
	if err != nil {
		t.Fatal(err)
	}
	boundedFacet := requireHostNetworkPostureFacet(t, boundedInput, bounded)
	if boundedFacet.Attributes["kubernetes/omitted-host-network-values"] != "6" {
		t.Fatalf("omitted = %q", boundedFacet.Attributes["kubernetes/omitted-host-network-values"])
	}
	boundedSemantics, err := graph.DecodeSecuritySemantics(boundedFacet.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if len(boundedSemantics.Ports) != 64 || boundedSemantics.Ports[63].Port != 64 {
		t.Fatalf("bounded ports = %#v", boundedSemantics.Ports)
	}
	compileInput(t, input)
	compileInput(t, boundedInput)
}

func TestNetworkPolicyHostNetworkTargetIsImplementationDefined(t *testing.T) {
	normal := testObject("v1", "Pod", "demo", "normal", "normal", nil)
	host := testObject("v1", "Pod", "demo", "host", "host", map[string]any{"spec": map[string]any{"hostNetwork": true}})
	for _, pod := range []*unstructured.Unstructured{normal, host} {
		pod.SetLabels(map[string]string{"app": "api"})
	}
	policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "api", "policy", map[string]any{"spec": map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
		"policyTypes": []any{"Ingress", "Egress"},
		"ingress":     []any{map[string]any{"ports": []any{map[string]any{"port": int64(443)}}}},
		"egress":      []any{map[string]any{"ports": []any{map[string]any{"protocol": "UDP", "port": int64(53)}}}},
	}})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{host, policy, normal})
	if err != nil {
		t.Fatal(err)
	}
	edges := map[graph.IdentityClaim]graph.RelationshipAssertion{}
	for _, relationship := range input.Relationships {
		if relationship.Predicate == graph.PredicateGovernedBy && relationship.Object == ClaimFor("cluster", policy) {
			edges[relationship.Subject] = relationship
		}
	}
	normalEdge, hostEdge := edges[ClaimFor("cluster", normal)], edges[ClaimFor("cluster", host)]
	if normalEdge.RuleID != "kubernetes.networkpolicy.target" || hostEdge.RuleID != "kubernetes.networkpolicy.host-network-target" {
		t.Fatalf("rule IDs = %q, %q", normalEdge.RuleID, hostEdge.RuleID)
	}
	normalSemantics, err := graph.DecodeSecuritySemantics(normalEdge.Properties)
	if err != nil {
		t.Fatal(err)
	}
	hostSemantics, err := graph.DecodeSecuritySemantics(hostEdge.Properties)
	if err != nil {
		t.Fatal(err)
	}
	if normalSemantics.State != graph.SecurityStateDeclared || normalSemantics.Effect != "restrict" || normalSemantics.Coverage != "complete" {
		t.Fatalf("normal Pod semantics = %#v", normalSemantics)
	}
	if _, found := normalEdge.Properties["kubernetes/network-policy-applicability"]; found {
		t.Fatalf("normal Pod carries the host-network marker: %#v", normalEdge.Properties)
	}
	want := *normalSemantics
	want.Effect, want.Coverage = "unknown", "unknown"
	if !equalSemantics(*hostSemantics, want) {
		t.Fatalf("host-network semantics = %#v, want %#v", hostSemantics, want)
	}
	if hostEdge.Properties["kubernetes/network-policy-applicability"] != "implementation-defined" {
		t.Fatalf("host-network marker missing: %#v", hostEdge.Properties)
	}
	for _, key := range []string{"directions", "kubernetes/selector-basis", "kubernetes/membership-resolution", "kubernetes/identity-assurance", "kubernetes/selector-empty"} {
		if hostEdge.Properties[key] != normalEdge.Properties[key] {
			t.Errorf("%s = %q, want %q", key, hostEdge.Properties[key], normalEdge.Properties[key])
		}
	}
	compileInput(t, input)
}

func TestHostNetworkTransitionAndPodDeletionRetract(t *testing.T) {
	node := testObject("v1", "Node", "", "worker-a", "node", nil)
	policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "all", "policy", map[string]any{"spec": map[string]any{"podSelector": map[string]any{}, "ingress": []any{}}})
	pod := func(hostNetwork bool) *unstructured.Unstructured {
		return testObject("v1", "Pod", "demo", "api", "pod", map[string]any{
			"spec":   map[string]any{"hostNetwork": hostNetwork, "nodeName": "worker-a"},
			"status": map[string]any{"podIP": "10.2.0.4"},
		})
	}
	hostInput, err := Project("cluster", "source", []*unstructured.Unstructured{pod(true), node, policy})
	if err != nil {
		t.Fatal(err)
	}
	requireHostNetworkPostureFacet(t, hostInput, pod(true))

	normalPod := pod(false)
	normalInput, err := Project("cluster", "source", []*unstructured.Unstructured{normalPod, node, policy})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := findHostNetworkFacet(normalInput, normalPod); found {
		t.Fatal("host-network facet retained after hostNetwork=false")
	}
	if got := resourceOfClaim(t, normalInput, ClaimFor("cluster", normalPod)).Attributes["network/addresses"]; got != `["ip/10.2.0.4"]` {
		t.Fatalf("network/addresses = %q", got)
	}
	destination, err := graph.NetworkDestinationClaim("cluster", "ip/10.2.0.4")
	if err != nil {
		t.Fatal(err)
	}
	exposesEdge(t, normalInput, ClaimFor("cluster", normalPod), destination)
	for _, relationship := range normalInput.Relationships {
		if relationship.RuleID == "kubernetes.networkpolicy.host-network-target" {
			t.Fatalf("host-network policy target retained: %#v", relationship)
		}
	}

	deleted, err := Project("cluster", "source", []*unstructured.Unstructured{node, policy})
	if err != nil {
		t.Fatal(err)
	}
	podClaim := ClaimFor("cluster", normalPod)
	for _, resource := range deleted.Resources {
		if resource.Claim == podClaim || resource.Kind == "network/destination" {
			t.Fatalf("resource retained after Pod deletion: %#v", resource)
		}
	}
	for _, facet := range deleted.Facets {
		if facet.Resource == podClaim {
			t.Fatalf("facet retained after Pod deletion: %#v", facet)
		}
	}
	for _, relationship := range deleted.Relationships {
		if relationship.Subject == podClaim || relationship.Object == podClaim {
			t.Fatalf("relationship retained after Pod deletion: %#v", relationship)
		}
	}
	compileInput(t, hostInput)
	compileInput(t, normalInput)
	compileInput(t, deleted)
}

func TestHostNetworkProjectionDeterministicUnderShuffledInput(t *testing.T) {
	objects := []*unstructured.Unstructured{
		testObject("v1", "Node", "", "worker-a", "node", nil),
		testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "all", "policy", map[string]any{"spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}, "ingress": []any{}}}),
		testObject("v1", "Pod", "demo", "normal", "normal", map[string]any{"spec": map[string]any{"nodeName": "worker-a"}, "status": map[string]any{"podIP": "10.2.0.4"}}),
	}
	for index := range 4 {
		name := "host-" + strconv.Itoa(index)
		objects = append(objects, testObject("v1", "Pod", "demo", name, name, map[string]any{
			"spec": map[string]any{
				"hostNetwork": true, "hostPID": index%2 == 0, "nodeName": "worker-a",
				"containers": []any{
					map[string]any{"name": "a", "securityContext": map[string]any{"capabilities": map[string]any{"add": []any{"NET_RAW", "NET_ADMIN"}}}, "ports": []any{map[string]any{"containerPort": int64(9000 + index)}, map[string]any{"containerPort": int64(53), "protocol": "UDP"}}},
					map[string]any{"name": "b", "securityContext": map[string]any{"privileged": index%2 == 1}},
				},
			},
			"status": map[string]any{"podIP": "10.142.0.5"},
		}))
	}
	want, err := Project("cluster", "source", objects)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := compiledCanonical(t, want)
	random := rand.New(rand.NewSource(7))
	for iteration := range 100 {
		shuffled := slices.Clone(objects)
		random.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got, err := Project("cluster", "source", shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if gotHash := compiledCanonical(t, got); gotHash != wantHash {
			t.Fatalf("hash for shuffle %d changed", iteration)
		}
	}
}
