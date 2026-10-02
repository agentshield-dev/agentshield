package api

import (
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Decoded wraps a typed provider object and, when present, its raw spec. The
// raw spec feeds configuration digests so fields the typed subset omits still
// change the digest.
type Decoded[T any] struct {
	Value    T
	SpecJSON json.RawMessage
}

// Decode round-trips object through JSON into T and captures the raw spec.
// Unknown fields are ignored; a field with the wrong JSON type is an error.
func Decode[T any](object *unstructured.Unstructured) (Decoded[T], error) {
	var result Decoded[T]
	if object == nil {
		return result, fmt.Errorf("decode provider object: object is nil")
	}
	data, err := json.Marshal(object.Object)
	if err != nil {
		return result, fmt.Errorf("encode %s/%s: %w", object.GetKind(), object.GetName(), err)
	}
	if err := json.Unmarshal(data, &result.Value); err != nil {
		return result, fmt.Errorf("decode %s %s/%s: %w", object.GetKind(), object.GetNamespace(), object.GetName(), err)
	}
	if spec, found := object.Object["spec"]; found {
		result.SpecJSON, err = json.Marshal(spec)
		if err != nil {
			return result, fmt.Errorf("encode %s %s/%s spec: %w", object.GetKind(), object.GetNamespace(), object.GetName(), err)
		}
	}
	return result, nil
}

// WorkloadSelector selects workloads by exact label match.
type WorkloadSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// PolicyTargetReference attaches a policy to a named resource, such as a
// Gateway or waypoint Service, instead of a label selector.
type PolicyTargetReference struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// AuthorizationPolicy is a security.istio.io/v1 AuthorizationPolicy.
type AuthorizationPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AuthorizationPolicySpec `json:"spec,omitempty"`
}

// AuthorizationPolicySpec decodes scope and action. Rules stay raw;
// projection derives only their count, digest, and coarse breadth.
type AuthorizationPolicySpec struct {
	Selector   *WorkloadSelector       `json:"selector,omitempty"`
	TargetRefs []PolicyTargetReference `json:"targetRefs,omitempty"`
	Action     string                  `json:"action,omitempty"`
	Provider   *ExtensionProvider      `json:"provider,omitempty"`
	Rules      *[]json.RawMessage      `json:"rules,omitempty"`
}

// ExtensionProvider names the external authorizer for CUSTOM policies.
type ExtensionProvider struct {
	Name string `json:"name"`
}

// PeerAuthentication is a security.istio.io/v1 PeerAuthentication.
type PeerAuthentication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PeerAuthenticationSpec `json:"spec,omitempty"`
}

// PeerAuthenticationSpec decodes scope and mTLS modes, including per-port
// overrides.
type PeerAuthenticationSpec struct {
	Selector      *WorkloadSelector    `json:"selector,omitempty"`
	Mtls          *MutualTLS           `json:"mtls,omitempty"`
	PortLevelMtls map[string]MutualTLS `json:"portLevelMtls,omitempty"`
}

// MutualTLS is a PeerAuthentication mode: UNSET, DISABLE, PERMISSIVE, or
// STRICT.
type MutualTLS struct {
	Mode string `json:"mode,omitempty"`
}

// ServiceEntry is a networking.istio.io/v1 ServiceEntry.
type ServiceEntry struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ServiceEntrySpec `json:"spec,omitempty"`
}

// ServiceEntrySpec decodes the hosts, ports, endpoints, location,
// resolution, and visibility that determine registry bindings.
type ServiceEntrySpec struct {
	Hosts      []string               `json:"hosts,omitempty"`
	ExportTo   []string               `json:"exportTo,omitempty"`
	Ports      []ServicePort          `json:"ports,omitempty"`
	Endpoints  []ServiceEntryEndpoint `json:"endpoints,omitempty"`
	Location   string                 `json:"location,omitempty"`
	Resolution string                 `json:"resolution,omitempty"`
}

// ServicePort is one ServiceEntry port.
type ServicePort struct {
	Number   uint32 `json:"number,omitempty"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// ServiceEntryEndpoint is one static ServiceEntry endpoint.
type ServiceEntryEndpoint struct {
	Address  string            `json:"address,omitempty"`
	Ports    map[string]uint32 `json:"ports,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Network  string            `json:"network,omitempty"`
	Locality string            `json:"locality,omitempty"`
	Weight   uint32            `json:"weight,omitempty"`
}

// VirtualService is a networking.istio.io/v1 VirtualService.
type VirtualService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              VirtualServiceSpec `json:"spec,omitempty"`
}

// VirtualServiceSpec decodes hosts, gateways, visibility, and route
// destinations.
type VirtualServiceSpec struct {
	Hosts    []string    `json:"hosts,omitempty"`
	Gateways []string    `json:"gateways,omitempty"`
	ExportTo []string    `json:"exportTo,omitempty"`
	HTTP     []HTTPRoute `json:"http,omitempty"`
	TLS      []L4Route   `json:"tls,omitempty"`
	TCP      []L4Route   `json:"tcp,omitempty"`
}

// HTTPRoute is one VirtualService HTTP route; match conditions are not
// decoded.
type HTTPRoute struct {
	Route   []HTTPRouteDestination `json:"route,omitempty"`
	Mirror  *Destination           `json:"mirror,omitempty"`
	Mirrors []MirrorPolicy         `json:"mirrors,omitempty"`
}

// L4Route is one VirtualService TCP or TLS route.
type L4Route struct {
	Route []RouteDestination `json:"route,omitempty"`
}

// HTTPRouteDestination is a weighted HTTP destination.
type HTTPRouteDestination struct {
	Destination *Destination `json:"destination,omitempty"`
	Weight      *int32       `json:"weight,omitempty"`
}

// RouteDestination is a weighted TCP or TLS destination.
type RouteDestination struct {
	Destination *Destination `json:"destination,omitempty"`
	Weight      *int32       `json:"weight,omitempty"`
}

// MirrorPolicy is one HTTP mirror target. Mirrors receive traffic copies
// and are projected as destinations.
type MirrorPolicy struct {
	Destination *Destination    `json:"destination,omitempty"`
	Percentage  json.RawMessage `json:"percentage,omitempty"`
}

// Destination names a registry host, optional subset, and port.
type Destination struct {
	Host   string        `json:"host"`
	Subset string        `json:"subset,omitempty"`
	Port   *PortSelector `json:"port,omitempty"`
}

// PortSelector selects a destination port by number.
type PortSelector struct {
	Number uint32 `json:"number,omitempty"`
}

// AuthorizationPolicyObject decodes an AuthorizationPolicy.
func AuthorizationPolicyObject(object *unstructured.Unstructured) (Decoded[AuthorizationPolicy], error) {
	return Decode[AuthorizationPolicy](object)
}

// PeerAuthenticationObject decodes a PeerAuthentication.
func PeerAuthenticationObject(object *unstructured.Unstructured) (Decoded[PeerAuthentication], error) {
	return Decode[PeerAuthentication](object)
}

// ServiceEntryObject decodes a ServiceEntry.
func ServiceEntryObject(object *unstructured.Unstructured) (Decoded[ServiceEntry], error) {
	return Decode[ServiceEntry](object)
}

// VirtualServiceObject decodes a VirtualService.
func VirtualServiceObject(object *unstructured.Unstructured) (Decoded[VirtualService], error) {
	return Decode[VirtualService](object)
}
