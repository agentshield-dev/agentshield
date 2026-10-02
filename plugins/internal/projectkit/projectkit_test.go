package projectkit

import (
	"math"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// These literals are published in graph qualifiers, digests, and evidence IDs.
// A change here retracts and re-asserts existing graph facts, so update them
// only together with new projector rule IDs.
func TestEncodingIsStable(t *testing.T) {
	first := map[string]any{"b": []string{"x", "y"}, "a": 1, "c": map[string]string{"z": "1", "k": "2"}}
	second := map[string]any{"c": map[string]string{"k": "2", "z": "1"}, "a": 1, "b": []string{"x", "y"}}
	const (
		wantJSON   = `{"a":1,"b":["x","y"],"c":{"k":"2","z":"1"}}`
		wantDigest = "5d4ce3948da4a0448c60b7315a8fb3cd64040a2eac41b4bf5a584cd21ca53d7f"
	)
	for _, value := range []any{first, second} {
		if got := MustCanonicalJSON(value); got != wantJSON {
			t.Fatalf("MustCanonicalJSON = %s, want %s", got, wantJSON)
		}
		if got := Digest(value); got != wantDigest {
			t.Fatalf("Digest = %s, want %s", got, wantDigest)
		}
		if got := SecurityDigest(value); got != "sha256:"+wantDigest {
			t.Fatalf("SecurityDigest = %s", got)
		}
		if got := Qualifier(value); got != wantDigest[:24] {
			t.Fatalf("Qualifier = %s, want %s", got, wantDigest[:24])
		}
	}
}

func TestKubernetesObjectHelpersAreStable(t *testing.T) {
	item := &unstructured.Unstructured{}
	item.SetAPIVersion("networking.k8s.io/v1")
	item.SetKind("NetworkPolicy")
	item.SetNamespace("payments")
	item.SetName("deny-all")
	item.SetUID("0B1C-UID")

	if got, want := ObjectKey(item), "networking.k8s.io/v1/networkpolicy/0b1c-uid"; got != want {
		t.Fatalf("ObjectKey = %s, want %s", got, want)
	}
	if got := ObjectKey(nil); got != "" {
		t.Fatalf("ObjectKey(nil) = %q", got)
	}
	if got, want := DisplayName(item), "payments/deny-all"; got != want {
		t.Fatalf("DisplayName = %s, want %s", got, want)
	}
	if got, want := KubernetesEvidenceID(item), "kubernetes:0B1C-UID"; got != want {
		t.Fatalf("KubernetesEvidenceID without revision = %s, want %s", got, want)
	}
	item.SetResourceVersion("42")
	if got, want := KubernetesEvidenceID(item), "kubernetes:networking.k8s.io/v1/networkpolicy/0b1c-uid:42:upsert"; got != want {
		t.Fatalf("KubernetesEvidenceID = %s, want %s", got, want)
	}

	cluster := &unstructured.Unstructured{}
	cluster.SetName("worker-1")
	if got := DisplayName(cluster); got != "worker-1" {
		t.Fatalf("cluster-scoped DisplayName = %s", got)
	}
}

func TestMustCanonicalJSONPanicsOnUnsupportedValue(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for a non-finite float")
		}
	}()
	MustCanonicalJSON(math.NaN())
}
