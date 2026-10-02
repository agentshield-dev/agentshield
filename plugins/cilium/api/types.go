package api

import (
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Decoded wraps a typed provider object decoded from its unstructured form.
type Decoded[T any] struct {
	Value T
}

// Decode round-trips object through JSON into T. Unknown fields are ignored;
// a field with the wrong JSON type is an error.
func Decode[T any](object *unstructured.Unstructured) (Decoded[T], error) {
	var result Decoded[T]
	if object == nil {
		return result, fmt.Errorf("decode Cilium provider object: object is nil")
	}
	data, err := json.Marshal(object.Object)
	if err != nil {
		return result, fmt.Errorf("encode %s %s/%s: %w", object.GetKind(), object.GetNamespace(), object.GetName(), err)
	}
	if err := json.Unmarshal(data, &result.Value); err != nil {
		return result, fmt.Errorf("decode %s %s/%s: %w", object.GetKind(), object.GetNamespace(), object.GetName(), err)
	}
	return result, nil
}

// Policy is a CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy.
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              *Rule  `json:"spec,omitempty"`
	Specs             []Rule `json:"specs,omitempty"`
}

// Rule is one policy rule. Only selectors and port-level structure are
// decoded; peer selectors are not interpreted.
type Rule struct {
	EndpointSelector metav1.LabelSelector `json:"endpointSelector"`
	Ingress          []IngressRule        `json:"ingress,omitempty"`
	Egress           []EgressRule         `json:"egress,omitempty"`
}

// IngressRule holds the port rules of one ingress section.
type IngressRule struct {
	ToPorts []PortRule `json:"toPorts,omitempty"`
}

// EgressRule holds the port rules of one egress section.
type EgressRule struct {
	ToPorts []PortRule `json:"toPorts,omitempty"`
}

// PortRule is one toPorts entry. Rules is kept raw only to detect L7 rules;
// its contents are never interpreted or copied to the graph.
type PortRule struct {
	Ports []PortProtocol  `json:"ports,omitempty"`
	Rules json.RawMessage `json:"rules,omitempty"`
}

// PortProtocol is one port and optional protocol. Port may be a number,
// range, or name.
type PortProtocol struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// Rules returns the specs list followed by the single spec, matching how
// Cilium combines them.
func (policy Policy) Rules() []Rule {
	rules := append([]Rule(nil), policy.Specs...)
	if policy.Spec != nil {
		rules = append(rules, *policy.Spec)
	}
	return rules
}

// HasL7Rules reports whether any port rule carries a non-empty L7 section.
// Such rules are excluded from CNI summaries.
func (rule Rule) HasL7Rules() bool {
	for _, ingress := range rule.Ingress {
		for _, ports := range ingress.ToPorts {
			if hasValue(ports.Rules) {
				return true
			}
		}
	}
	for _, egress := range rule.Egress {
		for _, ports := range egress.ToPorts {
			if hasValue(ports.Rules) {
				return true
			}
		}
	}
	return false
}

func hasValue(value json.RawMessage) bool {
	return len(value) != 0 && string(value) != "null" && string(value) != "{}"
}

// Endpoint is a CiliumEndpoint, named after the Pod it represents.
type Endpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            EndpointStatus `json:"status,omitempty"`
}

// EndpointStatus is the agent-reported endpoint state.
type EndpointStatus struct {
	ID       int64            `json:"id,omitempty"`
	State    string           `json:"state,omitempty"`
	Identity EndpointIdentity `json:"identity,omitempty"`
	Policy   EndpointPolicy   `json:"policy,omitempty"`
}

// EndpointIdentity is the numeric Cilium security identity.
type EndpointIdentity struct {
	ID int64 `json:"id,omitempty"`
}

// EndpointPolicy holds the policy state the agent realized.
type EndpointPolicy struct {
	Realized EndpointRealizedPolicy `json:"realized,omitempty"`
}

// EndpointRealizedPolicy reports the agent's realized policy-enabled mode.
// It is recorded verbatim, not interpreted as proof of enforcement.
type EndpointRealizedPolicy struct {
	PolicyEnabled string `json:"policy-enabled,omitempty"`
}

// Node is a CiliumNode, named after the Kubernetes Node it represents.
type Node struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NodeSpec `json:"spec,omitempty"`
}

// NodeSpec holds node addresses and IPAM allocation.
type NodeSpec struct {
	Addresses []NodeAddress `json:"addresses,omitempty"`
	IPAM      NodeIPAM      `json:"ipam,omitempty"`
}

// NodeAddress is one typed node address.
type NodeAddress struct {
	Type string `json:"type,omitempty"`
	IP   string `json:"ip,omitempty"`
}

// NodeIPAM holds the Pod CIDRs allocated to the node.
type NodeIPAM struct {
	PodCIDRs []string `json:"podCIDRs,omitempty"`
}

// PolicyObject decodes a Cilium policy object.
func PolicyObject(object *unstructured.Unstructured) (Decoded[Policy], error) {
	return Decode[Policy](object)
}

// EndpointObject decodes a CiliumEndpoint.
func EndpointObject(object *unstructured.Unstructured) (Decoded[Endpoint], error) {
	return Decode[Endpoint](object)
}

// NodeObject decodes a CiliumNode.
func NodeObject(object *unstructured.Unstructured) (Decoded[Node], error) {
	return Decode[Node](object)
}
