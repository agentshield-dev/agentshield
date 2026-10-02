package api

import (
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Decoded wraps a typed object and, when present, its raw spec. The raw spec
// feeds configuration digests so fields the typed form omits still change the
// digest.
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

// Service decodes a core/v1 Service.
func Service(object *unstructured.Unstructured) (Decoded[corev1.Service], error) {
	return Decode[corev1.Service](object)
}

// Pod decodes a core/v1 Pod.
func Pod(object *unstructured.Unstructured) (Decoded[corev1.Pod], error) {
	return Decode[corev1.Pod](object)
}

// Node decodes a core/v1 Node.
func Node(object *unstructured.Unstructured) (Decoded[corev1.Node], error) {
	return Decode[corev1.Node](object)
}

// Deployment decodes an apps/v1 Deployment.
func Deployment(object *unstructured.Unstructured) (Decoded[appsv1.Deployment], error) {
	return Decode[appsv1.Deployment](object)
}

// Ingress decodes a networking.k8s.io/v1 Ingress.
func Ingress(object *unstructured.Unstructured) (Decoded[networkingv1.Ingress], error) {
	return Decode[networkingv1.Ingress](object)
}

// NetworkPolicy decodes a networking.k8s.io/v1 NetworkPolicy.
func NetworkPolicy(object *unstructured.Unstructured) (Decoded[networkingv1.NetworkPolicy], error) {
	return Decode[networkingv1.NetworkPolicy](object)
}

// Gateway is the decoded subset of a gateway.networking.k8s.io/v1 Gateway.
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GatewaySpec   `json:"spec,omitempty"`
	Status            GatewayStatus `json:"status,omitempty"`
}

// GatewaySpec decodes the class, listeners, and requested addresses.
type GatewaySpec struct {
	GatewayClassName string            `json:"gatewayClassName"`
	Addresses        []json.RawMessage `json:"addresses,omitempty"`
	Listeners        []GatewayListener `json:"listeners,omitempty"`
}

// GatewayListener is one Gateway listener.
type GatewayListener struct {
	Name          string          `json:"name"`
	Port          int32           `json:"port"`
	Protocol      string          `json:"protocol"`
	AllowedRoutes *AllowedRoutes  `json:"allowedRoutes,omitempty"`
	TLS           json.RawMessage `json:"tls,omitempty"`
	Hostname      *string         `json:"hostname,omitempty"`
}

// AllowedRoutes limits which namespaces may attach routes to a listener.
type AllowedRoutes struct {
	Namespaces *RouteNamespaces `json:"namespaces,omitempty"`
}

// RouteNamespaces is the namespace policy for route attachment.
type RouteNamespaces struct {
	From     string                `json:"from,omitempty"`
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// GatewayStatus holds controller-reported addresses and conditions. They are
// observed controller state, not proof of reachability.
type GatewayStatus struct {
	Addresses  []json.RawMessage  `json:"addresses,omitempty"`
	Listeners  []json.RawMessage  `json:"listeners,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// HTTPRoute is the decoded subset of a gateway.networking.k8s.io/v1
// HTTPRoute.
type HTTPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              HTTPRouteSpec   `json:"spec,omitempty"`
	Status            HTTPRouteStatus `json:"status,omitempty"`
}

// HTTPRouteSpec decodes hostnames, parent references, and backend rules.
type HTTPRouteSpec struct {
	Hostnames  []string          `json:"hostnames,omitempty"`
	ParentRefs []ParentReference `json:"parentRefs,omitempty"`
	Rules      []HTTPRouteRule   `json:"rules,omitempty"`
}

// ParentReference names a Gateway or other parent a route attaches to.
type ParentReference struct {
	Group       string `json:"group,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	SectionName string `json:"sectionName,omitempty"`
	Port        *int32 `json:"port,omitempty"`
}

// HTTPRouteRule holds one rule's backends. Matches and filters stay raw for
// digests and are not interpreted.
type HTTPRouteRule struct {
	Matches     []json.RawMessage  `json:"matches,omitempty"`
	Filters     []json.RawMessage  `json:"filters,omitempty"`
	BackendRefs []BackendReference `json:"backendRefs,omitempty"`
}

// BackendReference names one route backend, by default a Service.
type BackendReference struct {
	Group     string            `json:"group,omitempty"`
	Kind      string            `json:"kind,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Name      string            `json:"name"`
	Port      *int32            `json:"port,omitempty"`
	Weight    *int32            `json:"weight,omitempty"`
	Filters   []json.RawMessage `json:"filters,omitempty"`
}

// HTTPRouteStatus holds raw per-parent status entries.
type HTTPRouteStatus struct {
	Parents []json.RawMessage `json:"parents,omitempty"`
}

// GatewayObject decodes a Gateway.
func GatewayObject(object *unstructured.Unstructured) (Decoded[Gateway], error) {
	return Decode[Gateway](object)
}

// HTTPRouteObject decodes an HTTPRoute.
func HTTPRouteObject(object *unstructured.Unstructured) (Decoded[HTTPRoute], error) {
	return Decode[HTTPRoute](object)
}
