package agentgateway

import (
	"encoding/json"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/coherentcache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ObservedObject is one cached Kubernetes observation with the event ID used
// as assertion evidence.
type ObservedObject = coherentcache.Object

// ProjectionContext configures projection. Empty ControllerNames and
// GatewayClasses use [DefaultControllerName] and [DefaultGatewayClass].
type ProjectionContext struct {
	ClusterID       string
	SourceID        string
	ControllerNames []string
	GatewayClasses  []string
}

// ProjectionResult is the complete semantics contribution input plus
// diagnostics for references that could not be projected.
type ProjectionResult struct {
	Input       graph.Input
	Diagnostics []Diagnostic
}

// Diagnostic records a skipped or unresolved provider reference. Diagnostics
// are not graph facts and never imply that a reference is safe or absent.
type Diagnostic struct {
	Resource string
	Code     string
	Message  string
}

type gatewayClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              gatewayClassSpec   `json:"spec,omitempty"`
	Status            gatewayClassStatus `json:"status,omitempty"`
}

type gatewayClassSpec struct {
	ControllerName string `json:"controllerName"`
}

type gatewayClassStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              gatewaySpec   `json:"spec,omitempty"`
	Status            gatewayStatus `json:"status,omitempty"`
}

type gatewaySpec struct {
	GatewayClassName string            `json:"gatewayClassName"`
	Listeners        []gatewayListener `json:"listeners,omitempty"`
}

type gatewayListener struct {
	Name     string  `json:"name"`
	Hostname *string `json:"hostname,omitempty"`
	Port     int32   `json:"port"`
	Protocol string  `json:"protocol"`
}

type gatewayStatus struct {
	Addresses  []json.RawMessage  `json:"addresses,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type httpRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              httpRouteSpec   `json:"spec,omitempty"`
	Status            httpRouteStatus `json:"status,omitempty"`
}

type httpRouteSpec struct {
	Hostnames  []string          `json:"hostnames,omitempty"`
	ParentRefs []parentReference `json:"parentRefs,omitempty"`
	Rules      []httpRouteRule   `json:"rules,omitempty"`
}

type parentReference struct {
	Group       string `json:"group,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	SectionName string `json:"sectionName,omitempty"`
}

type httpRouteRule struct {
	BackendRefs []backendReference `json:"backendRefs,omitempty"`
}

type backendReference struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Port      *int32 `json:"port,omitempty"`
	Weight    *int32 `json:"weight,omitempty"`
}

type httpRouteStatus struct {
	Parents []routeParentStatus `json:"parents,omitempty"`
}

type routeParentStatus struct {
	ParentRef      parentReference    `json:"parentRef"`
	ControllerName string             `json:"controllerName"`
	Conditions     []metav1.Condition `json:"conditions,omitempty"`
}
