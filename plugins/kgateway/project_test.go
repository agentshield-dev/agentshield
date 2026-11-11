package kgateway

import (
	"math/rand"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func fullFixture() []*unstructured.Unstructured {
	return []*unstructured.Unstructured{
		gatewayClassObject("kgateway", DefaultControllerName, map[string]any{"group": kgatewayGroup, "kind": kindGatewayParams, "name": "kgateway", "namespace": "kgateway-system"}),
		gatewayObject("kgateway-system", "edge", "kgateway"),
		kgw(kindGatewayParams, "kgateway-system", "kgateway", map[string]any{"kube": map[string]any{"service": map[string]any{"type": "LoadBalancer"}}}),
		kgw(kindListenerPolicy, "kgateway-system", "logs", map[string]any{
			"targetRefs": []any{targetRef("Gateway", "edge")},
			"default":    map[string]any{"httpSettings": map[string]any{"xffNumTrustedHops": int64(1), "accessLog": []any{map[string]any{"openTelemetry": map[string]any{}}}}},
		}),
		routeObject("apps", "api", nil, serviceRule("api"), map[string]any{"backendRefs": []any{map[string]any{"group": kgatewayGroup, "kind": kindBackend, "name": "external"}}}),
		routeObject("apps", "blocked", nil, map[string]any{"filters": []any{map[string]any{"type": "ExtensionRef", "extensionRef": map[string]any{"group": kgatewayGroup, "kind": kindDirectResponse, "name": "deny"}}}}),
		serviceObject("apps", "api"),
		kgw(kindTrafficPolicy, "apps", "auth", map[string]any{
			"targetRefs": []any{targetRef("HTTPRoute", "api")},
			"basicAuth":  map[string]any{"users": []any{"user:$apr1$hash"}},
		}),
		kgw(kindBackend, "apps", "external", map[string]any{"type": "Static", "static": map[string]any{"hosts": []any{map[string]any{"host": "api.example.com", "port": int64(443)}}}}),
		kgw(kindBackend, "apps", "open", map[string]any{"type": "DynamicForwardProxy", "dynamicForwardProxy": map[string]any{}}),
		kgw(kindBackendConfig, "apps", "tls", map[string]any{"targetRefs": []any{targetRef(kindBackend, "external")}, "tls": map[string]any{"insecureSkipVerify": true}}),
		kgw(kindDirectResponse, "apps", "deny", map[string]any{"status": int64(403)}),
		kgw(kindGatewayExtension, "apps", "authz", map[string]any{"type": "ExtAuth", "extAuth": map[string]any{}}),
	}
}

func TestProjectKgatewaySemanticsCompileAndRemainDeterministic(t *testing.T) {
	objects := fullFixture()
	registry := graph.NewRegistry()
	if err := discovery.RegisterIdentitySchemes(registry, kubernetesplugin.Descriptor()); err != nil {
		t.Fatal(err)
	}
	compiler := graph.NewCompiler(registry)
	var expected string
	for seed := int64(0); seed < 10; seed++ {
		shuffled := append([]*unstructured.Unstructured(nil), objects...)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		input, err := Project("cluster", "source", shuffled)
		if err != nil {
			t.Fatal(err)
		}
		predicates := map[graph.Predicate]int{}
		for _, relationship := range input.Relationships {
			predicates[relationship.Predicate]++
			if relationship.PluginID != PluginID || relationship.SourceID != "source" || relationship.RuleID == "" || len(relationship.EvidenceIDs) == 0 {
				t.Fatalf("relationship provenance = %#v", relationship)
			}
		}
		// governed-by: route<-auth, gateway<-logs, backend<-tls; exposes: route->backend, backend->host.
		if predicates[graph.PredicateGovernedBy] != 3 || predicates[graph.PredicateExposes] != 2 || len(predicates) != 2 {
			t.Fatalf("predicates = %#v", predicates)
		}
		for _, resource := range input.Resources {
			if resource.Kind == "kubernetes/gateway" || resource.Kind == "kubernetes/httproute" || resource.Kind == "kubernetes/service" {
				t.Fatalf("re-emitted Kubernetes-owned resource %s", resource.Kind)
			}
		}
		if len(input.Telemetry) != 0 {
			t.Fatal("projection fabricated telemetry")
		}
		snapshot, err := compiler.Compile(input)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		kubernetesInput, err := kubernetesplugin.Project("cluster", "source", shuffled)
		if err != nil {
			t.Fatal(err)
		}
		combined, err := compiler.Compile(graph.Input{
			Resources:     append(kubernetesInput.Resources, input.Resources...),
			Facets:        append(kubernetesInput.Facets, input.Facets...),
			Relationships: append(kubernetesInput.Relationships, input.Relationships...),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(combined.Conflicts) != 0 {
			t.Fatalf("kind conflicts with the Kubernetes plugin: %#v", combined.Conflicts[0].Kinds)
		}
		encoded, err := snapshot.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if seed == 0 {
			expected = string(encoded)
		} else if string(encoded) != expected {
			t.Fatalf("seed %d produced a different graph", seed)
		}
	}
}

func TestProjectIdentitySurvivesRename(t *testing.T) {
	before := testObject(kgatewayAPIVersion, kindTrafficPolicy, "apps", "old", "policy", map[string]any{"spec": map[string]any{"rbac": map[string]any{"policy": map[string]any{"matchExpressions": []any{"true"}}}}})
	after := testObject(kgatewayAPIVersion, kindTrafficPolicy, "apps", "new", "policy", map[string]any{"spec": map[string]any{"rbac": map[string]any{"policy": map[string]any{"matchExpressions": []any{"true"}}}}})
	beforeInput, err := Project("cluster", "source", []*unstructured.Unstructured{before})
	if err != nil {
		t.Fatal(err)
	}
	afterInput, err := Project("cluster", "source", []*unstructured.Unstructured{after})
	if err != nil {
		t.Fatal(err)
	}
	if beforeInput.Resources[0].Claim != afterInput.Resources[0].Claim {
		t.Fatal("rename changed identity")
	}
	if beforeInput.Resources[0].DisplayName == afterInput.Resources[0].DisplayName {
		t.Fatal("rename did not update display name")
	}
}

func TestProjectMalformedObjectsFailProjection(t *testing.T) {
	missingUID := testObject(kgatewayAPIVersion, kindTrafficPolicy, "apps", "auth", "", map[string]any{"spec": map[string]any{}})
	if _, err := Project("cluster", "source", []*unstructured.Unstructured{missingUID}); err == nil {
		t.Fatal("missing UID did not fail projection")
	}
	badSpec := kgw(kindTrafficPolicy, "apps", "auth", map[string]any{"targetRefs": "not-a-list"})
	if _, err := Project("cluster", "source", []*unstructured.Unstructured{badSpec}); err == nil {
		t.Fatal("malformed TrafficPolicy did not fail projection")
	}
	if _, err := ProjectObserved(ProjectionContext{SourceID: "source"}, nil); err == nil {
		t.Fatal("missing cluster ID accepted")
	}
}

func TestProjectTrafficPolicyTargetsStayInPolicyNamespace(t *testing.T) {
	local := routeObject("apps", "api", map[string]any{"auth": "required"}, serviceRule("api"))
	unlabeled := routeObject("apps", "public", nil, serviceRule("api"))
	foreignLabeled := routeObject("other", "api", map[string]any{"auth": "required"}, serviceRule("api"))
	gatewayInOtherNamespace := gatewayObject("kgateway-system", "edge", "kgateway")
	policy := kgw(kindTrafficPolicy, "apps", "auth", map[string]any{
		"targetRefs":      []any{targetRef("Gateway", "edge"), targetRef("GRPCRoute", "grpc")},
		"targetSelectors": []any{map[string]any{"group": gatewayAPIGroup, "kind": "HTTPRoute", "matchLabels": map[string]any{"auth": "required"}, "sectionName": "rule-a"}},
		"jwtAuth":         map[string]any{"extensionRef": map[string]any{"name": "jwt"}},
	})
	result := mustProject(t, local, unlabeled, foreignLabeled, gatewayInOtherNamespace, policy)
	if edges := relationshipsBetween(result.Input, local, graph.PredicateGovernedBy, claimOf(policy)); len(edges) != 1 || edges[0].Properties["kgateway/target-mechanism"] != "targetSelector" || edges[0].Properties["kgateway/section-name"] != "rule-a" {
		t.Fatalf("selector edges = %#v", edges)
	}
	for _, other := range []*unstructured.Unstructured{unlabeled, foreignLabeled, gatewayInOtherNamespace} {
		if edges := relationshipsBetween(result.Input, other, graph.PredicateGovernedBy, claimOf(policy)); len(edges) != 0 {
			t.Fatalf("%s attached across a selector or namespace boundary", other.GetName())
		}
	}
	if !hasDiagnostic(result, "target-unresolved") || !hasDiagnostic(result, "unsupported-target-kind") {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}
	for _, resource := range result.Input.Resources {
		if resource.Kind == "kubernetes/trafficpolicy" && resource.Attributes["kgateway/auth-extensions-resolved"] != "false" {
			t.Fatalf("unresolved jwt extension reported as resolved: %#v", resource.Attributes)
		}
	}
}

func TestProjectTrafficPolicySecuritySemantics(t *testing.T) {
	tests := []struct {
		name       string
		spec       map[string]any
		domain     graph.SecurityDomain
		effect     string
		facetKind  string
		mechanisms string
		disabled   string
	}{
		{name: "basic", spec: map[string]any{"basicAuth": map[string]any{"users": []any{"u:h"}}}, domain: graph.SecurityDomainAuthorization, effect: "allow", facetKind: "authorization-posture", mechanisms: `["basic"]`, disabled: `[]`},
		{name: "api key", spec: map[string]any{"apiKeyAuth": map[string]any{}}, domain: graph.SecurityDomainAuthorization, effect: "allow", facetKind: "authorization-posture", mechanisms: `["api-key"]`, disabled: `[]`},
		{name: "ext auth", spec: map[string]any{"extAuth": map[string]any{"extensionRef": map[string]any{"name": "authz"}}}, domain: graph.SecurityDomainAuthorization, effect: "custom", facetKind: "authorization-posture", mechanisms: `["ext-auth"]`, disabled: `[]`},
		{name: "oauth2", spec: map[string]any{"oauth2": map[string]any{"extensionRef": map[string]any{"name": "oidc"}}}, domain: graph.SecurityDomainAuthorization, effect: "custom", facetKind: "authorization-posture", mechanisms: `["oauth2"]`, disabled: `[]`},
		{name: "rbac deny wins", spec: map[string]any{"jwtAuth": map[string]any{"extensionRef": map[string]any{"name": "jwt"}}, "rbac": map[string]any{"action": "Deny", "policy": map[string]any{"matchExpressions": []any{"true"}}}}, domain: graph.SecurityDomainAuthorization, effect: "deny", facetKind: "authorization-posture", mechanisms: `["jwt","rbac"]`, disabled: `[]`},
		{name: "acl only", spec: map[string]any{"acl": map[string]any{"defaultAction": "Deny", "rules": []any{map[string]any{"action": "Allow"}}}}, domain: graph.SecurityDomainNetworkAccess, effect: "restrict", facetKind: "network-access-posture", mechanisms: `[]`, disabled: `[]`},
		{name: "acl deny rules", spec: map[string]any{"acl": map[string]any{"defaultAction": "Allow", "rules": []any{map[string]any{"action": "Deny"}}}}, domain: graph.SecurityDomainNetworkAccess, effect: "deny", facetKind: "network-access-posture", mechanisms: `[]`, disabled: `[]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			route := routeObject("apps", "api", nil, serviceRule("api"))
			spec := map[string]any{"targetRefs": []any{targetRef("HTTPRoute", "api")}}
			for key, value := range test.spec {
				spec[key] = value
			}
			policy := kgw(kindTrafficPolicy, "apps", "policy", spec)
			result := mustProject(t, route, policy)
			facet, found := facetOf(result.Input, policy, test.facetKind)
			if !found {
				t.Fatalf("no %s facet", test.facetKind)
			}
			semantics := mustSemantics(t, facet.Attributes)
			if semantics.Class != graph.SecurityClassGovernance || semantics.Domain != test.domain || semantics.Effect != test.effect || semantics.Coverage != "partial" || semantics.ConfigurationDigest == "" {
				t.Fatalf("semantics = %#v", semantics)
			}
			edges := relationshipsBetween(result.Input, route, graph.PredicateGovernedBy, claimOf(policy))
			if len(edges) != 1 {
				t.Fatalf("edges = %#v", edges)
			}
			edgeSemantics := mustSemantics(t, edges[0].Properties)
			if edgeSemantics.Domain != test.domain || edgeSemantics.Scope != "service" {
				t.Fatalf("edge semantics = %#v", edgeSemantics)
			}
			if edges[0].Properties["kgateway/auth-mechanisms"] != test.mechanisms || edges[0].Properties["kgateway/auth-disabled"] != test.disabled {
				t.Fatalf("edge properties = %#v", edges[0].Properties)
			}
		})
	}
}

func TestProjectDisabledAuthCarriesNoSemantics(t *testing.T) {
	gateway := gatewayObject("apps", "edge", "kgateway")
	policy := kgw(kindTrafficPolicy, "apps", "public", map[string]any{
		"targetRefs": []any{targetRef("Gateway", "edge")},
		"extAuth":    map[string]any{"disable": map[string]any{}},
	})
	result := mustProject(t, gateway, policy)
	if _, found := facetOf(result.Input, policy, "authorization-posture"); found {
		t.Fatal("disabled ext auth produced an authorization facet")
	}
	edges := relationshipsBetween(result.Input, gateway, graph.PredicateGovernedBy, claimOf(policy))
	if len(edges) != 1 || edges[0].Properties["kgateway/auth-disabled"] != `["ext-auth"]` || edges[0].Properties[graph.SecuritySemanticsAttribute] != "" {
		t.Fatalf("edges = %#v", edges)
	}
}

func TestProjectBackendEgress(t *testing.T) {
	open := kgw(kindBackend, "apps", "open", map[string]any{"dynamicForwardProxy": map[string]any{}})
	static := kgw(kindBackend, "apps", "static", map[string]any{"type": "Static", "static": map[string]any{"hosts": []any{
		map[string]any{"host": "API.Example.com.", "port": int64(443)},
		map[string]any{"host": "10.0.0.7", "port": int64(8080)},
		map[string]any{"host": "bad host/path", "port": int64(80)},
	}}})
	route := routeObject("apps", "api", nil, map[string]any{"backendRefs": []any{
		map[string]any{"group": kgatewayGroup, "kind": kindBackend, "name": "static"},
		map[string]any{"group": kgatewayGroup, "kind": kindBackend, "name": "remote", "namespace": "other"},
		map[string]any{"group": kgatewayGroup, "kind": kindBackend, "name": "missing"},
	}})
	result := mustProject(t, open, static, route)

	facet, _ := facetOf(result.Input, open, "kgateway-egress")
	if semantics := mustSemantics(t, facet.Attributes); semantics.Effect != "external-addressable" || semantics.Direction != "egress" || facet.Attributes["kgateway/open-egress"] != "true" {
		t.Fatalf("open egress facet = %#v", facet.Attributes)
	}
	facet, _ = facetOf(result.Input, static, "kgateway-egress")
	if semantics := mustSemantics(t, facet.Attributes); semantics.Effect != "unknown" || len(semantics.Ports) != 2 || facet.Attributes["kgateway/static-hosts"] != `["10.0.0.7","api.example.com"]` {
		t.Fatalf("static egress facet = %#v", facet.Attributes)
	}
	dns, _ := graph.NetworkDestinationClaim("cluster", "dns/api.example.com")
	ip, _ := graph.NetworkDestinationClaim("cluster", "ip/10.0.0.7")
	for _, destination := range []graph.IdentityClaim{dns, ip} {
		if len(relationshipsBetween(result.Input, static, graph.PredicateExposes, destination)) != 1 {
			t.Fatalf("missing exposes edge to %s", destination.ImmutableKey)
		}
	}
	if len(relationshipsBetween(result.Input, route, graph.PredicateExposes, claimOf(static))) != 1 {
		t.Fatal("missing HTTPRoute exposes Backend")
	}
	for _, code := range []string{"invalid-backend-host", "reference-grant-unknown", "backend-unresolved"} {
		if !hasDiagnostic(result, code) {
			t.Fatalf("missing diagnostic %s in %#v", code, result.Diagnostics)
		}
	}
}

func TestProjectBackendConfigPolicyTLSPosture(t *testing.T) {
	service := serviceObject("apps", "api")
	backendObject := kgw(kindBackend, "apps", "external", map[string]any{"static": map[string]any{"hosts": []any{map[string]any{"host": "api.example.com", "port": int64(443)}}}})
	insecure := kgw(kindBackendConfig, "apps", "insecure", map[string]any{"targetRefs": []any{targetRef(kindBackend, "external")}, "tls": map[string]any{"insecureSkipVerify": true}})
	verified := kgw(kindBackendConfig, "apps", "verified", map[string]any{
		"targetSelectors": []any{map[string]any{"group": "", "kind": "Service", "matchLabels": map[string]any{}}},
		"tls":             map[string]any{"wellKnownCACertificates": "System", "sni": "api.internal"},
	})
	timeouts := kgw(kindBackendConfig, "apps", "timeouts", map[string]any{"targetRefs": []any{targetRef("Service", "api")}})
	result := mustProject(t, service, backendObject, insecure, verified, timeouts)

	for _, test := range []struct {
		policy, target *unstructured.Unstructured
		effect         string
	}{{insecure, backendObject, "permit"}, {verified, service, "require"}} {
		edges := relationshipsBetween(result.Input, test.target, graph.PredicateGovernedBy, claimOf(test.policy))
		if len(edges) != 1 {
			t.Fatalf("%s edges = %#v", test.policy.GetName(), edges)
		}
		semantics := mustSemantics(t, edges[0].Properties)
		if semantics.Domain != graph.SecurityDomainTransportAuthentication || semantics.Effect != test.effect || semantics.Direction != "egress" {
			t.Fatalf("%s semantics = %#v", test.policy.GetName(), semantics)
		}
	}
	if _, found := facetOf(result.Input, timeouts, "transport-posture"); found {
		t.Fatal("policy without TLS produced a transport facet")
	}
	if edges := relationshipsBetween(result.Input, service, graph.PredicateGovernedBy, claimOf(timeouts)); len(edges) != 1 || edges[0].Properties[graph.SecuritySemanticsAttribute] != "" {
		t.Fatalf("timeouts edges = %#v", edges)
	}
}

func TestProjectDirectResponseAndGatewayService(t *testing.T) {
	deny := kgw(kindDirectResponse, "apps", "deny", map[string]any{"status": int64(403), "body": "no"})
	route := routeObject("apps", "blocked", nil,
		map[string]any{"filters": []any{map[string]any{"type": "ExtensionRef", "extensionRef": map[string]any{"group": kgatewayGroup, "kind": kindDirectResponse, "name": "deny"}}}},
		map[string]any{"filters": []any{map[string]any{"type": "ExtensionRef", "extensionRef": map[string]any{"group": kgatewayGroup, "kind": kindDirectResponse, "name": "gone"}}}},
		serviceRule("api"),
	)
	class := gatewayClassObject("kgateway", DefaultControllerName, map[string]any{"group": kgatewayGroup, "kind": kindGatewayParams, "name": "class-default", "namespace": "kgateway-system"})
	classDefault := kgw(kindGatewayParams, "kgateway-system", "class-default", map[string]any{"kube": map[string]any{"service": map[string]any{"type": "LoadBalancer"}}})
	internal := kgw(kindGatewayParams, "kgateway-system", "internal", map[string]any{"kube": map[string]any{"service": map[string]any{"type": "ClusterIP"}}})
	byClass := gatewayObject("kgateway-system", "public", "kgateway")
	byGateway := gatewayObject("kgateway-system", "private", "kgateway")
	byGateway.Object["spec"].(map[string]any)["infrastructure"] = map[string]any{"parametersRef": map[string]any{"group": kgatewayGroup, "kind": kindGatewayParams, "name": "internal"}}
	result := mustProject(t, deny, route, class, classDefault, internal, byClass, byGateway)

	facet, found := facetOf(result.Input, route, "kgateway-direct-response")
	if !found || facet.Attributes["kgateway/direct-response-rules"] != "1" || facet.Attributes["kgateway/direct-response-statuses"] != `["403"]` || len(facet.EvidenceIDs) != 2 {
		t.Fatalf("direct response facet = %#v", facet)
	}
	if !hasDiagnostic(result, "direct-response-unresolved") {
		t.Fatalf("diagnostics = %#v", result.Diagnostics)
	}
	for _, test := range []struct {
		gateway        *unstructured.Unstructured
		effect, source string
	}{{byClass, "external-addressable", "gatewayclass"}, {byGateway, "internal", "gateway"}} {
		facet, found := facetOf(result.Input, test.gateway, "kgateway-gateway-service")
		if !found || facet.Attributes["kgateway/parameters-source"] != test.source {
			t.Fatalf("%s service facet = %#v", test.gateway.GetName(), facet)
		}
		if semantics := mustSemantics(t, facet.Attributes); semantics.Effect != test.effect || semantics.Class != graph.SecurityClassExposure {
			t.Fatalf("%s semantics = %#v", test.gateway.GetName(), semantics)
		}
	}
}

func TestProjectCoverageNotInstalledIsNotNoPolicy(t *testing.T) {
	class := gatewayClassObject("kgateway", DefaultControllerName, nil)
	otherClass := gatewayClassObject("other", "example.net/other", nil)
	managed := gatewayObject("kgateway-system", "edge", "kgateway")
	foreign := gatewayObject("kgateway-system", "foreign", "other")
	coverage := allCovered()
	coverage["kgateway-trafficpolicies-v1alpha1"] = CoverageStateNotInstalled
	delete(coverage, "kgateway-listenerpolicies-v1alpha1")
	var observations []ObservedObject
	for _, item := range []*unstructured.Unstructured{class, otherClass, managed, foreign} {
		observations = append(observations, observed(item, "event:"+item.GetName()))
	}
	result, err := ProjectObserved(ProjectionContext{ClusterID: "cluster", SourceID: "source", Coverage: coverage}, observations)
	if err != nil {
		t.Fatal(err)
	}
	facet, found := facetOf(result.Input, managed, "kgateway-coverage")
	if !found || facet.Attributes["kgateway/coverage/trafficpolicies"] != "not-installed" || facet.Attributes["kgateway/coverage/listenerpolicies"] != "unknown" || facet.Attributes["kgateway/coverage/backends"] != "covered" {
		t.Fatalf("coverage facet = %#v", facet)
	}
	if _, found := facetOf(result.Input, foreign, "kgateway-coverage"); found {
		t.Fatal("Gateway of another controller got a kgateway coverage facet")
	}
	for _, item := range result.Input.Facets {
		if item.Kind == "authorization-posture" {
			t.Fatal("absent TrafficPolicy API produced an authorization claim")
		}
	}
}
