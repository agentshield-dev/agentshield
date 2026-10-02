package graph

import "encoding/json"

// Values of the provider-neutral network/role resource attribute.
const (
	NetworkRoleControlPlaneAPI = "control-plane-api"
	NetworkRoleService         = "service"
	NetworkRoleWorkload        = "workload"
)

// NetworkRoleDescription pairs a network/role value with its meaning.
type NetworkRoleDescription struct {
	Role        string
	Description string
}

// NetworkRoles lists the values providers may publish in the network/role attribute.
func NetworkRoles() []NetworkRoleDescription {
	return []NetworkRoleDescription{
		{NetworkRoleControlPlaneAPI, "an address of the cluster's Kubernetes API service"},
		{NetworkRoleService, "an address of another cluster Service"},
		{NetworkRoleWorkload, "an address of a cluster workload Pod"},
	}
}

// ResourceNetworkRoles maps resource IDs to network/role, including network
// destinations whose address appears in another resource's network/addresses.
func ResourceNetworkRoles(snapshot Snapshot) map[string]string {
	roles := make(map[string]string)
	addressRoles := make(map[string]string)
	for _, resource := range snapshot.Resources {
		for _, assertion := range resource.Assertions {
			role := assertion.Attributes["network/role"]
			if role == "" {
				continue
			}
			roles[resource.ID] = role
			var addresses []string
			if json.Unmarshal([]byte(assertion.Attributes["network/addresses"]), &addresses) == nil {
				for _, address := range addresses {
					addressRoles[address] = role
					addressRoles["ip/"+address] = role
					addressRoles["dns/"+address] = role
				}
			}
		}
	}
	for _, resource := range snapshot.Resources {
		if resource.Kind != "network/destination" {
			continue
		}
		if role := addressRoles[resource.Identity.ImmutableKey]; role != "" {
			roles[resource.ID] = role
		}
	}
	return roles
}
