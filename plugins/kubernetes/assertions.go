package kubernetes

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func resourceAssertion(clusterID, sourceID, ruleID string, item *unstructured.Unstructured, attrs map[string]string) graph.ResourceAssertion {
	return graph.ResourceAssertion{
		Claim: claimFor(clusterID, item), Kind: "kubernetes/" + strings.ToLower(item.GetKind()), DisplayName: projectkit.DisplayName(item),
		Attributes: attrs, PluginID: PluginID, SourceID: sourceID, RuleID: ruleID, EvidenceIDs: evidenceIDs(item),
	}
}

func relationshipAssertion(sourceID, ruleID string, subject graph.IdentityClaim, predicate graph.Predicate, object graph.IdentityClaim, qualifier string, properties map[string]string, evidence ...*unstructured.Unstructured) graph.RelationshipAssertion {
	return graph.RelationshipAssertion{
		Subject: subject, Predicate: predicate, Object: object, Qualifier: qualifier, Properties: properties,
		PluginID: PluginID, SourceID: sourceID, RuleID: ruleID, EvidenceIDs: evidenceIDs(evidence...),
	}
}

func evidenceIDs(items ...*unstructured.Unstructured) []string {
	unique := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item != nil {
			unique[projectkit.KubernetesEvidenceID(item)] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for id := range unique {
		result = append(result, id)
	}
	slices.Sort(result)
	return result
}

// canonicalUnorderedJSON converts value to generic JSON with set-like arrays
// sorted. Decoding cannot fail because the input was just encoded.
func canonicalUnorderedJSON(value any) any {
	var decoded any
	_ = json.Unmarshal([]byte(projectkit.MustCanonicalJSON(value)), &decoded)
	return normalizeUnorderedJSON(decoded)
}

func normalizeUnorderedJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			typed[key] = normalizeUnorderedJSON(nested)
		}
		return typed
	case []any:
		for index, nested := range typed {
			typed[index] = normalizeUnorderedJSON(nested)
		}
		slices.SortFunc(typed, func(left, right any) int {
			return strings.Compare(projectkit.MustCanonicalJSON(left), projectkit.MustCanonicalJSON(right))
		})
		return typed
	default:
		return value
	}
}

func boundedSecurityDetails(protocols []string, ports []graph.SecurityPort) ([]string, []graph.SecurityPort, bool) {
	protocolSet := make(map[string]struct{}, len(protocols))
	for _, protocol := range protocols {
		protocolSet[strings.ToUpper(strings.TrimSpace(protocol))] = struct{}{}
	}
	protocols = protocols[:0]
	for protocol := range protocolSet {
		protocols = append(protocols, protocol)
	}
	slices.Sort(protocols)

	portSet := make(map[graph.SecurityPort]struct{}, len(ports))
	for _, port := range ports {
		port.Protocol = strings.ToUpper(strings.TrimSpace(port.Protocol))
		portSet[port] = struct{}{}
	}
	ports = ports[:0]
	for port := range portSet {
		ports = append(ports, port)
	}
	slices.SortFunc(ports, func(left, right graph.SecurityPort) int {
		if comparison := strings.Compare(left.Protocol, right.Protocol); comparison != 0 {
			return comparison
		}
		return int(left.Port) - int(right.Port)
	})
	truncated := len(protocols) > 16 || len(ports) > 64
	if len(protocols) > 16 {
		protocols = protocols[:16]
	}
	if len(ports) > 64 {
		ports = ports[:64]
	}
	return protocols, ports, truncated
}
