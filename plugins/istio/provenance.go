package istio

import (
	"slices"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
)

func provenance(sourceID string, evidence ...string) (string, string, []string) {
	return PluginID, sourceID, sortedUnique(evidence)
}

func sortedUnique(values []string) []string {
	slices.Sort(values)
	result := values[:0]
	for _, value := range values {
		if value == "" || (len(result) > 0 && result[len(result)-1] == value) {
			continue
		}
		result = append(result, value)
	}
	return result
}

func relationship(sourceID, ruleID string, subject graph.IdentityClaim, predicate graph.Predicate, object graph.IdentityClaim, qualifier string, properties map[string]string, evidence ...string) graph.RelationshipAssertion {
	pluginID, source, evidenceIDs := provenance(sourceID, evidence...)
	return graph.RelationshipAssertion{
		Subject: subject, Predicate: predicate, Object: object, Qualifier: qualifier, Properties: properties,
		PluginID: pluginID, SourceID: source, RuleID: ruleID, EvidenceIDs: evidenceIDs,
	}
}

func projectedResourceAssertion(sourceID string, observed indexedObject, kind, ruleID string, attributes map[string]string) graph.ResourceAssertion {
	pluginID, source, evidence := provenance(sourceID, observed.EventID)
	return graph.ResourceAssertion{
		Claim: observed.Claim, Kind: kind, DisplayName: projectkit.DisplayName(observed.Object), Attributes: attributes,
		PluginID: pluginID, SourceID: source, RuleID: ruleID, EvidenceIDs: evidence,
	}
}
