package kubernetes

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func projectNetworkAddresses(clusterID, networkID, sourceID string, item *unstructured.Unstructured, attributes map[string]string, input *graph.Input) error {
	encoded := attributes["network/addresses"]
	if encoded == "" {
		return nil
	}
	var addresses []string
	if err := json.Unmarshal([]byte(encoded), &addresses); err != nil {
		return fmt.Errorf("decode network addresses for %s: %w", projectkit.DisplayName(item), err)
	}
	for _, address := range addresses {
		claim, err := graph.NetworkDestinationClaim(networkID, address)
		if err != nil {
			return fmt.Errorf("project network address %q for %s: %w", address, projectkit.DisplayName(item), err)
		}
		input.Resources = append(input.Resources, graph.ResourceAssertion{
			Claim: claim, Kind: "network/destination", DisplayName: strings.TrimSpace(address),
			Attributes: map[string]string{"network/address": strings.TrimSpace(address)},
			PluginID:   PluginID, SourceID: sourceID, RuleID: "kubernetes.network-address",
			EvidenceIDs: evidenceIDs(item),
		})
		input.Relationships = append(input.Relationships, relationshipAssertion(
			sourceID, "kubernetes.resource-exposes-address",
			claimFor(clusterID, item), graph.PredicateExposes, claim,
			"kubernetes-network-address", map[string]string{"basis": "network/addresses"}, item,
		))
	}
	return nil
}
