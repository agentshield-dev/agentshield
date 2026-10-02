package kubernetes

import (
	"math/rand"
	"reflect"
	"slices"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

type identityResolverFunc func(string) (graph.IdentityClaim, bool, error)

func (resolve identityResolverFunc) ResolveIdentityReference(reference string) (graph.IdentityClaim, bool, error) {
	return resolve(reference)
}

func TestProjectCollapsesReplicaSetsAndExcludesIstioResources(t *testing.T) {
	object := func(apiVersion, kind, namespace, name, uid string) *unstructured.Unstructured {
		item := &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": name, "uid": uid}}}
		item.SetNamespace(namespace)
		return item
	}
	namespace := object("v1", "Namespace", "", "demo", "ns")
	deployment := object("apps/v1", "Deployment", "demo", "app", "deployment")
	replicaSet := object("apps/v1", "ReplicaSet", "demo", "app-abc", "replicaset")
	replicaSet.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "app", UID: types.UID("deployment")}})
	pod := object("v1", "Pod", "demo", "app-123", "pod")
	pod.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "app-abc", UID: types.UID("replicaset")}})
	policy := object("security.istio.io/v1", "AuthorizationPolicy", "demo", "deny", "policy")

	input, err := Project("cluster", "source", []*unstructured.Unstructured{policy, pod, replicaSet, deployment, namespace})
	if err != nil {
		t.Fatal(err)
	}
	if len(input.Resources) != 3 {
		t.Fatalf("resources = %d, want namespace, deployment, and pod", len(input.Resources))
	}
	for _, resource := range input.Resources {
		if resource.Kind == "kubernetes/replicaset" || resource.Kind == "kubernetes/authorizationpolicy" {
			t.Fatalf("unexpected transient or Istio resource: %s", resource.Kind)
		}
	}
	var collapsed bool
	for _, relationship := range input.Relationships {
		if relationship.Predicate == "instantiates" && relationship.Subject.ImmutableKey == ClaimFor("cluster", deployment).ImmutableKey && relationship.Object.ImmutableKey == ClaimFor("cluster", pod).ImmutableKey {
			collapsed = true
		}
	}
	if !collapsed {
		t.Fatal("Deployment-to-Pod ownership was not collapsed through ReplicaSet")
	}
	registry := graph.NewRegistry()
	if err := registry.Register(IdentitySchemeDefinition()); err != nil {
		t.Fatal(err)
	}
	if _, err := graph.NewCompiler(registry).Compile(input); err != nil {
		t.Fatal(err)
	}
}

func TestProjectPodRunsOnObservedNode(t *testing.T) {
	node := testObject("v1", "Node", "", "worker-a", "node", map[string]any{"spec": map[string]any{"providerID": "aws:///us-east-1a/i-123"}})
	pod := testObject("v1", "Pod", "demo", "api", "pod", map[string]any{"spec": map[string]any{"nodeName": "worker-a"}})
	backend := graph.IdentityClaim{Scheme: graph.IdentityScheme{Group: "aws.amazon.com", Version: "v1", Kind: "Resource"}, AuthorityID: "111111111111", ImmutableKey: "aws/ec2/us-east-1/instance/i-123"}

	input, err := projectWithIdentityResolvers("cluster", "cluster", "source", []*unstructured.Unstructured{pod, node}, []discovery.IdentityReferenceResolver{identityResolverFunc(func(providerID string) (graph.IdentityClaim, bool, error) {
		return backend, providerID == "aws:///us-east-1a/i-123", nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	var runsOn, backedBy bool
	for _, relationship := range input.Relationships {
		runsOn = runsOn || relationship.Predicate == graph.PredicateRunsOn && relationship.Subject == ClaimFor("cluster", pod) && relationship.Object == ClaimFor("cluster", node)
		backedBy = backedBy || relationship.Predicate == graph.PredicateBackedBy && relationship.Subject == ClaimFor("cluster", node) && relationship.Object == backend
	}
	if !runsOn || !backedBy {
		t.Fatalf("missing runtime topology: %#v", input.Relationships)
	}
}

func TestProjectDeterministicUnderShuffledInput(t *testing.T) {
	namespace := testObject("v1", "Namespace", "", "demo", "namespace", nil)
	account := testObject("v1", "ServiceAccount", "demo", "default", "account", nil)
	pod := testObject("v1", "Pod", "demo", "api", "pod", map[string]any{"spec": map[string]any{"serviceAccountName": "default"}})
	pod.SetLabels(map[string]string{"app": "api", "tier": "edge"})
	service := testObject("v1", "Service", "demo", "api", "service", map[string]any{"spec": map[string]any{"selector": map[string]any{"app": "api"}, "ports": []any{map[string]any{"port": int64(80)}}}})
	ingress := testObject("networking.k8s.io/v1", "Ingress", "demo", "api", "ingress", map[string]any{"spec": map[string]any{"defaultBackend": map[string]any{"service": map[string]any{"name": "api", "port": map[string]any{"number": int64(80)}}}}})
	policy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "api", "policy", map[string]any{"spec": map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "api"}}, "ingress": []any{}}})
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "demo", "edge", "gateway", map[string]any{"spec": map[string]any{"gatewayClassName": "prod"}})
	route := testObject("gateway.networking.k8s.io/v1", "HTTPRoute", "demo", "api", "route", map[string]any{"spec": map[string]any{"parentRefs": []any{map[string]any{"name": "edge"}}, "rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "api", "port": int64(80)}}}}}})
	objects := []*unstructured.Unstructured{route, policy, service, namespace, gateway, pod, account, ingress}

	wantInput, err := Project("cluster", "source", objects)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := compiledHash(t, wantInput)
	random := rand.New(rand.NewSource(42))
	for iteration := 0; iteration < 100; iteration++ {
		shuffled := slices.Clone(objects)
		random.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		gotInput, projectErr := Project("cluster", "source", shuffled)
		if projectErr != nil {
			t.Fatal(projectErr)
		}
		if !reflect.DeepEqual(gotInput, wantInput) {
			t.Fatalf("projection changed for shuffle %d", iteration)
		}
		if gotHash := compiledHash(t, gotInput); gotHash != wantHash {
			t.Fatalf("hash for shuffle %d = %s, want %s", iteration, gotHash, wantHash)
		}
	}
}

func TestProjectMalformedAndUnsafeReferences(t *testing.T) {
	service := testObject("v1", "Service", "other", "api", "service", nil)
	gateway := testObject("gateway.networking.k8s.io/v1", "Gateway", "other", "edge", "gateway", nil)
	route := testObject("gateway.networking.k8s.io/v1", "HTTPRoute", "demo", "api", "route", map[string]any{"spec": map[string]any{
		"parentRefs": []any{map[string]any{"name": "edge", "namespace": "other"}},
		"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "api", "namespace": "other"}}}},
	}})
	input, err := Project("cluster", "source", []*unstructured.Unstructured{route, gateway, service})
	if err != nil {
		t.Fatal(err)
	}
	for _, relationship := range input.Relationships {
		if relationship.Subject == ClaimFor("cluster", route) {
			t.Fatalf("unsafe cross-namespace edge emitted: %#v", relationship)
		}
	}
	resource := resourceOfKind(t, input, "kubernetes/httproute")
	if resource.Attributes["kubernetes/unresolved-references"] == "" {
		t.Fatal("unsafe references were not retained as bounded diagnostics")
	}

	badPolicy := testObject("networking.k8s.io/v1", "NetworkPolicy", "demo", "bad", "bad-policy", map[string]any{"spec": map[string]any{"podSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "app", "operator": "NotAnOperator"}}}}})
	if _, err := Project("cluster", "source", []*unstructured.Unstructured{badPolicy}); err == nil {
		t.Fatal("malformed NetworkPolicy selector did not fail projection")
	}
}

func compiledHash(t *testing.T, input graph.Input) string {
	t.Helper()
	registry := graph.NewRegistry()
	if err := registry.Register(IdentitySchemeDefinition()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := snapshot.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
