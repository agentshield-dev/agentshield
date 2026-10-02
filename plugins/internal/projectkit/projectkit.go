// Package projectkit holds the deterministic encoding and Kubernetes object
// helpers shared by AgentShield plugin projectors.
//
// Every value produced here feeds graph identity qualifiers, configuration
// digests, attributes, or evidence IDs, so the output format is a stability
// contract: changing it changes published assertions and retracts the previous
// ones on the next contribution replacement. Treat any change as a new rule ID
// in every affected projector.
package projectkit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// MustCanonicalJSON encodes value with encoding/json, which sorts map keys and
// emits struct fields in declaration order. Callers sort set-like slices first.
//
// Projector inputs are plain strings, numbers, bools, slices, string-keyed maps,
// and values already decoded from provider JSON, none of which can fail to
// marshal. A failure therefore means a projector passed an unsupported type
// such as a channel, func, or non-finite float; MustCanonicalJSON panics rather
// than returning an empty string that would silently collapse distinct
// qualifiers and digests into one.
func MustCanonicalJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("projectkit: canonical JSON encoding of %T: %v", value, err))
	}
	return string(encoded)
}

// Digest returns the hex SHA-256 of the canonical JSON encoding of value. It
// panics under the same conditions as MustCanonicalJSON.
func Digest(value any) string {
	sum := sha256.Sum256([]byte(MustCanonicalJSON(value)))
	return hex.EncodeToString(sum[:])
}

// SecurityDigest returns Digest prefixed with "sha256:", the form used for
// graph.SecuritySemantics configuration digests.
func SecurityDigest(value any) string {
	return "sha256:" + Digest(value)
}

// Qualifier returns a 24-hex-character SHA-256 prefix of the canonical JSON
// encoding of value. Relationship and facet qualifiers use it to distinguish
// semantically different assertions between the same endpoints without
// depending on input order or slice positions.
func Qualifier(value any) string {
	sum := sha256.Sum256([]byte(MustCanonicalJSON(value)))
	return hex.EncodeToString(sum[:12])
}

// ObjectKey returns the lowercased apiVersion/kind/UID of item, or "" for nil.
// The UID makes it stable across renames and distinct across delete/recreate.
func ObjectKey(item *unstructured.Unstructured) string {
	if item == nil {
		return ""
	}
	return strings.ToLower(item.GetAPIVersion() + "/" + item.GetKind() + "/" + string(item.GetUID()))
}

// KubernetesEventID is the native event ID the Kubernetes plugin publishes for
// one operation ("upsert" or "delete") on one revision of the object with
// [ObjectKey] key. Projectors cite the same ID through [KubernetesEvidenceID]
// or the collection change's EventID, so evidence resolves to its receipt.
func KubernetesEventID(key, resourceVersion, operation string) string {
	return "kubernetes:" + key + ":" + resourceVersion + ":" + operation
}

// KubernetesEvidenceID names the Kubernetes observation that supports an
// assertion. With a resource version it is the [KubernetesEventID] of that
// revision's upsert; without one, typically for fixture or synthesized
// objects, it falls back to the UID alone.
func KubernetesEvidenceID(item *unstructured.Unstructured) string {
	if item.GetResourceVersion() == "" {
		return "kubernetes:" + string(item.GetUID())
	}
	return KubernetesEventID(ObjectKey(item), item.GetResourceVersion(), "upsert")
}

// DisplayName returns namespace/name for namespaced objects and name for
// cluster-scoped ones. Display names are mutable attributes, never identity.
func DisplayName(item *unstructured.Unstructured) string {
	if item.GetNamespace() == "" {
		return item.GetName()
	}
	return item.GetNamespace() + "/" + item.GetName()
}
