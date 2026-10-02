package istio

import (
	"math/rand"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestProjectForNetworkUsesNetworkAuthorityAndRootNamespace(t *testing.T) {
	root := testObject("v1", "Namespace", "", "mesh-root", "ns-root", nil)
	demo := testObject("v1", "Namespace", "", "demo", "ns-demo", nil)
	serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "demo", "external", "service-entry", map[string]any{
		"hosts": []any{"external.example.com"},
	})
	meshPolicy := testObject("security.istio.io/v1", "AuthorizationPolicy", "mesh-root", "mesh", "policy-mesh", nil)

	input, err := ProjectForNetwork("cluster", "network", "mesh-root", "source", []*unstructured.Unstructured{root, demo, serviceEntry, meshPolicy})
	if err != nil {
		t.Fatal(err)
	}
	var foundNetworkClaim bool
	var meshGovernance int
	for _, resource := range input.Resources {
		if resource.Kind == "network/destination" {
			foundNetworkClaim = true
			if resource.Claim.AuthorityID != "network" {
				t.Fatalf("ServiceEntry destination authority = %q, want network", resource.Claim.AuthorityID)
			}
		}
	}
	for _, relation := range input.Relationships {
		if relation.Qualifier == "istio-authz-mesh" {
			meshGovernance++
		}
	}
	if !foundNetworkClaim {
		t.Fatal("missing ServiceEntry destination claim")
	}
	if meshGovernance != 2 {
		t.Fatalf("mesh governance relationships = %d, want 2", meshGovernance)
	}
}

func TestProjectCompatibilityDefaults(t *testing.T) {
	root := testObject("v1", "Namespace", "", "istio-system", "ns-root", nil)
	serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "istio-system", "external", "service-entry", map[string]any{
		"hosts": []any{"external.example.com"},
	})
	meshPolicy := testObject("security.istio.io/v1", "AuthorizationPolicy", "istio-system", "mesh", "policy-mesh", nil)

	input, err := Project("cluster", "source", []*unstructured.Unstructured{root, serviceEntry, meshPolicy})
	if err != nil {
		t.Fatal(err)
	}
	var foundClusterClaim, foundMeshGovernance bool
	for _, resource := range input.Resources {
		if resource.Kind == "network/destination" {
			foundClusterClaim = resource.Claim.AuthorityID == "cluster"
		}
	}
	for _, relation := range input.Relationships {
		foundMeshGovernance = foundMeshGovernance || relation.Qualifier == "istio-authz-mesh"
	}
	if !foundClusterClaim {
		t.Fatal("compatibility projection did not default mesh authority to cluster ID")
	}
	if !foundMeshGovernance {
		t.Fatal("compatibility projection did not default root namespace to istio-system")
	}
}

func TestProjectDeterminismCompilerIntegrationAndRetraction(t *testing.T) {
	namespace := testObject("v1", "Namespace", "", "demo", "namespace", nil)
	service := testObject("v1", "Service", "demo", "app", "service", nil)
	serviceEntry := testObject("networking.istio.io/v1", "ServiceEntry", "demo", "external", "service-entry", map[string]any{"hosts": []any{"external.example.com"}})
	virtualService := testObject("networking.istio.io/v1", "VirtualService", "demo", "route", "virtual-service", map[string]any{
		"http": []any{map[string]any{"route": []any{map[string]any{"destination": map[string]any{"host": "external.example.com"}}}}},
	})
	observations := testObserved(namespace, service, serviceEntry, virtualService)
	baseline, err := ProjectObserved(testContext(), observations)
	if err != nil {
		t.Fatal(err)
	}
	baselineSnapshot := compileProjection(t, baseline, namespace, service)
	baselineHash, err := baselineSnapshot.Hash()
	if err != nil {
		t.Fatal(err)
	}
	for seed := int64(0); seed < 10; seed++ {
		shuffled := slices.Clone(observations)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		result, err := ProjectObserved(testContext(), shuffled)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := compileProjection(t, result, namespace, service)
		hash, err := snapshot.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if hash != baselineHash {
			t.Fatalf("seed %d hash = %s, want %s", seed, hash, baselineHash)
		}
	}

	withoutServiceEntry, err := ProjectObserved(testContext(), testObserved(namespace, service, virtualService))
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range withoutServiceEntry.Input.Resources {
		if resource.Kind == "network/destination" {
			t.Fatal("deleted ServiceEntry destination remained in replacement output")
		}
	}
	for _, relation := range withoutServiceEntry.Input.Relationships {
		if relation.Qualifier == "istio-serviceentry-host" || relation.Qualifier == "istio-route-http" {
			t.Fatalf("deleted ServiceEntry relationship remained: %#v", relation)
		}
	}
}
