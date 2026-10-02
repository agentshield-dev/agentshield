package cilium

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	ciliumapi "github.com/agentshield-dev/agentshield/plugins/cilium/api"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type indexedObject struct {
	ObservedObject
	claim graph.IdentityClaim
}

type objectIndex struct {
	items    []indexedObject
	podItems []indexedObject
	pods     map[string][]indexedObject
	nodes    map[string][]indexedObject
}

// Project projects bare objects, deriving evidence IDs from their identity
// and resource version. It exists for tests and offline evaluation; the plugin
// uses [ProjectObserved] with collection event IDs.
func Project(clusterID, sourceID string, objects []*unstructured.Unstructured) (graph.Input, error) {
	observations := make([]ObservedObject, 0, len(objects))
	for _, object := range objects {
		if object != nil {
			observations = append(observations, ObservedObject{Key: projectkit.ObjectKey(object), Object: object, EventID: projectkit.KubernetesEvidenceID(object), Revision: object.GetResourceVersion()})
		}
	}
	result, err := ProjectObserved(ProjectionContext{ClusterID: clusterID, SourceID: sourceID}, observations)
	return result.Input, err
}

// ProjectObserved deterministically projects one coherent snapshot. The
// result is independent of observation order.
func ProjectObserved(scope ProjectionContext, observations []ObservedObject) (ProjectionResult, error) {
	if strings.TrimSpace(scope.ClusterID) == "" || strings.TrimSpace(scope.SourceID) == "" {
		return ProjectionResult{}, errors.New("Cilium projection requires cluster and source IDs")
	}
	index := newObjectIndex(scope.ClusterID, observations)
	var result ProjectionResult
	for _, item := range index.items {
		switch {
		case item.Object.GetAPIVersion() == "cilium.io/v2" && (item.Object.GetKind() == "CiliumNetworkPolicy" || item.Object.GetKind() == "CiliumClusterwideNetworkPolicy"):
			if err := projectPolicy(scope, index, item, &result); err != nil {
				return ProjectionResult{}, err
			}
		case item.Object.GetAPIVersion() == "cilium.io/v2" && item.Object.GetKind() == "CiliumEndpoint":
			if err := projectEndpoint(scope, index, item, &result); err != nil {
				return ProjectionResult{}, err
			}
		case item.Object.GetAPIVersion() == "cilium.io/v2" && item.Object.GetKind() == "CiliumNode":
			if err := projectNode(scope, index, item, &result); err != nil {
				return ProjectionResult{}, err
			}
		}
	}
	return result, nil
}

func newObjectIndex(clusterID string, observations []ObservedObject) objectIndex {
	items := make([]ObservedObject, 0, len(observations))
	for _, observation := range observations {
		if observation.Object == nil || string(observation.Object.GetUID()) == "" {
			continue
		}
		items = append(items, observation)
	}
	sort.Slice(items, func(left, right int) bool {
		leftKey, rightKey := projectkit.ObjectKey(items[left].Object), projectkit.ObjectKey(items[right].Object)
		if leftKey == rightKey {
			return items[left].Key < items[right].Key
		}
		return leftKey < rightKey
	})
	index := objectIndex{pods: make(map[string][]indexedObject), nodes: make(map[string][]indexedObject)}
	for _, observation := range items {
		item := indexedObject{ObservedObject: observation, claim: kubernetesplugin.ClaimFor(clusterID, observation.Object)}
		index.items = append(index.items, item)
		switch {
		case observation.Object.GetAPIVersion() == "v1" && observation.Object.GetKind() == "Pod":
			key := observation.Object.GetNamespace() + "/" + observation.Object.GetName()
			index.pods[key] = append(index.pods[key], item)
			index.podItems = append(index.podItems, item)
		case observation.Object.GetAPIVersion() == "v1" && observation.Object.GetKind() == "Node":
			index.nodes[observation.Object.GetName()] = append(index.nodes[observation.Object.GetName()], item)
		}
	}
	return index
}

func projectPolicy(scope ProjectionContext, index objectIndex, item indexedObject, result *ProjectionResult) error {
	decoded, err := ciliumapi.PolicyObject(item.Object)
	if err != nil {
		return err
	}
	rules := decoded.Value.Rules()
	if len(rules) == 0 {
		return fmt.Errorf("project Cilium policy %s: spec or specs is required", projectkit.DisplayName(item.Object))
	}
	policyScope := "namespace"
	if item.Object.GetKind() == "CiliumClusterwideNetworkPolicy" {
		policyScope = "cluster"
	}
	cniRules := 0
	type selectedPod struct {
		pod       indexedObject
		ingress   bool
		egress    bool
		restricts bool
		protocols []string
		ports     []graph.SecurityPort
	}
	selectedPods := make(map[string]*selectedPod)
	for ruleIndex, rule := range rules {
		selector, err := newCiliumEndpointSelector(rule.EndpointSelector)
		if err != nil {
			return fmt.Errorf("project Cilium policy %s rule %d selector: %w", projectkit.DisplayName(item.Object), ruleIndex, err)
		}
		if rule.HasL7Rules() {
			result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: "unsupported-l7-policy", Resource: projectkit.DisplayName(item.Object)})
			continue
		}
		cniRules++
		directionIngress := len(rule.Ingress) > 0
		directionEgress := len(rule.Egress) > 0
		protocols, ports := ciliumRuleSecurityDetails(rule)
		for _, pod := range index.podItems {
			if policyScope == "namespace" && pod.Object.GetNamespace() != item.Object.GetNamespace() {
				continue
			}
			if selector.Matches(scope.ClusterID, pod.Object) {
				selected := selectedPods[pod.claim.ImmutableKey]
				if selected == nil {
					selected = &selectedPod{pod: pod}
					selectedPods[pod.claim.ImmutableKey] = selected
				}
				selected.ingress = selected.ingress || directionIngress
				selected.egress = selected.egress || directionEgress
				selected.restricts = selected.restricts || directionIngress || directionEgress
				selected.protocols = append(selected.protocols, protocols...)
				selected.ports = append(selected.ports, ports...)
			}
		}
	}
	selectedKeys := make([]string, 0, len(selectedPods))
	for key := range selectedPods {
		selectedKeys = append(selectedKeys, key)
	}
	sort.Strings(selectedKeys)
	for _, key := range selectedKeys {
		selected := selectedPods[key]
		protocols, ports := boundedCiliumSecurityDetails(selected.protocols, selected.ports)
		effect := "unknown"
		if selected.restricts {
			effect = "restrict"
		}
		properties, err := graph.WithSecuritySemantics(nil, graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
			State: graph.SecurityStateDeclared, Effect: effect, Scope: "workload", Direction: securityDirection(selected.ingress, selected.egress), Coverage: "partial",
			Protocols: protocols, Ports: ports, ConfigurationDigest: ciliumSecurityDigest(map[string]any{"spec": item.Object.Object["spec"], "specs": item.Object.Object["specs"]}),
		})
		if err != nil {
			return fmt.Errorf("project Cilium policy %s semantics: %w", projectkit.DisplayName(item.Object), err)
		}
		result.Input.Relationships = append(result.Input.Relationships, relationship(scope.SourceID, "cilium.policy.selects-pod", selected.pod.claim, graph.PredicateGovernedBy, item.claim, "", properties, item.EventID, selected.pod.EventID))
	}
	result.Input.Facets = append(result.Input.Facets, facet(scope.SourceID, "cilium.policy.cni", item.claim, "cilium-cni-policy", projectkit.DisplayName(item.Object), map[string]string{
		"cilium/cni-rule-count": strconv.Itoa(cniRules),
		"cilium/scope":          policyScope,
	}, item.EventID))
	return nil
}

func projectEndpoint(scope ProjectionContext, index objectIndex, item indexedObject, result *ProjectionResult) error {
	decoded, err := ciliumapi.EndpointObject(item.Object)
	if err != nil {
		return err
	}
	candidates := index.pods[item.Object.GetNamespace()+"/"+item.Object.GetName()]
	if len(candidates) != 1 {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: resolutionCode(candidates), Resource: projectkit.DisplayName(item.Object)})
		return nil
	}
	attributes := map[string]string{}
	if decoded.Value.Status.ID != 0 {
		attributes["cilium/endpoint-id"] = strconv.FormatInt(decoded.Value.Status.ID, 10)
	}
	if decoded.Value.Status.Identity.ID != 0 {
		attributes["cilium/security-identity"] = strconv.FormatInt(decoded.Value.Status.Identity.ID, 10)
	}
	if state := strings.TrimSpace(decoded.Value.Status.State); state != "" {
		attributes["cilium/state"] = state
	}
	if enabled := strings.TrimSpace(decoded.Value.Status.Policy.Realized.PolicyEnabled); enabled != "" {
		attributes["cilium/policy-enabled"] = enabled
		effect, direction := ciliumEndpointPolicySemantics(enabled)
		attributes, err = graph.WithSecuritySemantics(attributes, graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
			State: graph.SecurityStateObserved, Effect: effect, Scope: "workload", Direction: direction, Coverage: "partial",
		})
		if err != nil {
			return fmt.Errorf("project Cilium endpoint %s semantics: %w", projectkit.DisplayName(item.Object), err)
		}
	}
	result.Input.Facets = append(result.Input.Facets, facet(scope.SourceID, "cilium.endpoint.cni", candidates[0].claim, "cilium-cni", "endpoint", attributes, item.EventID, candidates[0].EventID))
	return nil
}

func ciliumRuleSecurityDetails(rule ciliumapi.Rule) ([]string, []graph.SecurityPort) {
	var protocols []string
	var ports []graph.SecurityPort
	add := func(portRules []ciliumapi.PortRule) {
		for _, portRule := range portRules {
			for _, declared := range portRule.Ports {
				protocol := strings.ToUpper(strings.TrimSpace(declared.Protocol))
				if protocol == "" {
					protocol = "TCP"
				}
				protocols = append(protocols, protocol)
				value, err := strconv.ParseUint(declared.Port, 10, 16)
				if err == nil && value > 0 {
					ports = append(ports, graph.SecurityPort{Protocol: protocol, Port: uint16(value)})
				}
			}
		}
	}
	for _, ingress := range rule.Ingress {
		add(ingress.ToPorts)
	}
	for _, egress := range rule.Egress {
		add(egress.ToPorts)
	}
	return protocols, ports
}

func boundedCiliumSecurityDetails(protocols []string, ports []graph.SecurityPort) ([]string, []graph.SecurityPort) {
	protocolSet := make(map[string]struct{}, len(protocols))
	for _, protocol := range protocols {
		if protocol = strings.ToUpper(strings.TrimSpace(protocol)); protocol != "" {
			protocolSet[protocol] = struct{}{}
		}
	}
	protocols = protocols[:0]
	for protocol := range protocolSet {
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	portSet := make(map[graph.SecurityPort]struct{}, len(ports))
	for _, port := range ports {
		portSet[port] = struct{}{}
	}
	ports = ports[:0]
	for port := range portSet {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(left, right int) bool {
		if ports[left].Protocol != ports[right].Protocol {
			return ports[left].Protocol < ports[right].Protocol
		}
		return ports[left].Port < ports[right].Port
	})
	if len(protocols) > 16 {
		protocols = protocols[:16]
	}
	if len(ports) > 64 {
		ports = ports[:64]
	}
	return protocols, ports
}

func securityDirection(ingress, egress bool) string {
	switch {
	case ingress && egress:
		return "bidirectional"
	case ingress:
		return "ingress"
	case egress:
		return "egress"
	default:
		return "unknown"
	}
}

func ciliumEndpointPolicySemantics(value string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "both":
		return "restrict", "bidirectional"
	case "ingress":
		return "restrict", "ingress"
	case "egress":
		return "restrict", "egress"
	case "none", "disabled":
		return "allow", "bidirectional"
	default:
		return "unknown", "unknown"
	}
}

func ciliumSecurityDigest(value any) string {
	encoded, _ := json.Marshal(value)
	var decoded any
	_ = json.Unmarshal(encoded, &decoded)
	encoded, _ = json.Marshal(normalizeCiliumSecurityConfiguration(decoded))
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func normalizeCiliumSecurityConfiguration(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			typed[key] = normalizeCiliumSecurityConfiguration(nested)
		}
		return typed
	case []any:
		for index, nested := range typed {
			typed[index] = normalizeCiliumSecurityConfiguration(nested)
		}
		sort.Slice(typed, func(left, right int) bool {
			leftJSON, _ := json.Marshal(typed[left])
			rightJSON, _ := json.Marshal(typed[right])
			return string(leftJSON) < string(rightJSON)
		})
		return typed
	default:
		return value
	}
}

func projectNode(scope ProjectionContext, index objectIndex, item indexedObject, result *ProjectionResult) error {
	decoded, err := ciliumapi.NodeObject(item.Object)
	if err != nil {
		return err
	}
	candidates := index.nodes[item.Object.GetName()]
	if len(candidates) != 1 {
		result.Diagnostics = append(result.Diagnostics, Diagnostic{Code: resolutionCode(candidates), Resource: item.Object.GetName()})
		return nil
	}
	podCIDRs := append([]string(nil), decoded.Value.Spec.IPAM.PodCIDRs...)
	podCIDRs = sortedUnique(podCIDRs)
	encodedCIDRs, err := json.Marshal(podCIDRs)
	if err != nil {
		return fmt.Errorf("encode CiliumNode %s pod CIDRs: %w", item.Object.GetName(), err)
	}
	attributes := map[string]string{
		"cilium/address-count": strconv.Itoa(len(decoded.Value.Spec.Addresses)),
		"cilium/pod-cidrs":     string(encodedCIDRs),
	}
	result.Input.Facets = append(result.Input.Facets, facet(scope.SourceID, "cilium.node.cni", candidates[0].claim, "cilium-cni", "node", attributes, item.EventID, candidates[0].EventID))
	return nil
}

func facet(sourceID, ruleID string, resource graph.IdentityClaim, kind, key string, attributes map[string]string, evidence ...string) graph.FacetAssertion {
	return graph.FacetAssertion{Resource: resource, Kind: kind, Key: key, Attributes: attributes, PluginID: PluginID, SourceID: sourceID, RuleID: ruleID, EvidenceIDs: sortedUnique(evidence)}
}

func relationship(sourceID, ruleID string, subject graph.IdentityClaim, predicate graph.Predicate, object graph.IdentityClaim, qualifier string, properties map[string]string, evidence ...string) graph.RelationshipAssertion {
	return graph.RelationshipAssertion{Subject: subject, Predicate: predicate, Object: object, Qualifier: qualifier, Properties: properties, PluginID: PluginID, SourceID: sourceID, RuleID: ruleID, EvidenceIDs: sortedUnique(evidence)}
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value != "" && (len(result) == 0 || result[len(result)-1] != value) {
			result = append(result, value)
		}
	}
	return result
}

func resolutionCode(candidates []indexedObject) string {
	if len(candidates) == 0 {
		return "missing-kubernetes-identity"
	}
	return "ambiguous-kubernetes-identity"
}
