package gcp

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
)

const (
	// PluginID is the plugin and contribution owner ID.
	PluginID           = "gcp"
	maxNativePeers     = 100
	maxNativeRules     = 100
	maxGoverningRules  = 100
	maxDiagnosticItems = 100
)

var resourceScheme = graph.IdentityScheme{Group: "cloud.google.com", Version: "v1", Kind: "Resource"}

// IdentitySchemeDefinition normalizes cloud.google.com/v1 Resource claims: a
// numeric project number authority and a lowercased key of one of the forms
// compute/<zone>/instance/<name>,
// compute/<zone>/instance/<name>/network-interface/<nic>, or
// compute/global/firewall/<numeric-id>.
func IdentitySchemeDefinition() graph.SchemeDefinition {
	return graph.SchemeDefinition{
		Scheme: resourceScheme,
		Normalize: func(claim graph.IdentityClaim) (graph.IdentityClaim, error) {
			claim.AuthorityID = strings.TrimSpace(claim.AuthorityID)
			parts := strings.Split(claim.ImmutableKey, "/")
			for index := range parts {
				parts[index] = strings.ToLower(strings.TrimSpace(parts[index]))
			}
			if claim.Scheme != resourceScheme || !validNumericID(claim.AuthorityID) || !validResourceKey(parts) {
				return graph.IdentityClaim{}, errors.New("invalid cloud.google.com/v1 Resource identity claim")
			}
			claim.ImmutableKey = strings.Join(parts, "/")
			return claim, nil
		},
	}
}

func validResourceKey(parts []string) bool {
	if len(parts) < 4 || parts[0] != "compute" {
		return false
	}
	for _, part := range parts {
		if !validGCPName(part) {
			return false
		}
	}
	switch {
	case len(parts) == 4 && parts[1] == "global" && parts[2] == "firewall":
		return validNumericID(parts[3])
	case len(parts) == 4 && parts[2] == "instance":
		return parts[1] != "global"
	case len(parts) == 6 && parts[2] == "instance" && parts[4] == "network-interface":
		return parts[1] != "global" && strings.HasPrefix(parts[5], "nic")
	default:
		return false
	}
}

// ProjectionContext scopes projection to one project and source.
type ProjectionContext struct {
	ProjectNumber string
	SourceID      string
}

// ProjectionResult is the complete inventory contribution input.
type ProjectionResult struct {
	Input graph.Input
}

// Project deterministically projects one coherent snapshot into the inventory
// contribution. GCP firewall rules have no attachment, so governed-by edges
// are computed from each rule's network and targets.
func Project(scope ProjectionContext, snapshot Snapshot) (ProjectionResult, error) {
	scope.ProjectNumber = strings.TrimSpace(scope.ProjectNumber)
	scope.SourceID = strings.TrimSpace(scope.SourceID)
	if !validNumericID(scope.ProjectNumber) || scope.SourceID == "" {
		return ProjectionResult{}, errors.New("GCP projection requires a numeric project number and source ID")
	}
	instances := slices.Clone(snapshot.Instances)
	firewalls := slices.Clone(snapshot.Firewalls)
	subnetworks := slices.Clone(snapshot.Subnetworks)
	slices.SortFunc(instances, func(left, right Instance) int {
		return cmp.Or(strings.Compare(left.Zone, right.Zone), strings.Compare(left.Name, right.Name))
	})
	slices.SortFunc(firewalls, compareFirewallPrecedence)
	subnetworkIndex := make(map[string]Subnetwork, len(subnetworks))
	for _, subnetwork := range subnetworks {
		subnetworkIndex[subnetworkPath(subnetwork)] = subnetwork
	}
	result := ProjectionResult{}
	for index := range firewalls {
		firewall, err := canonicalFirewall(firewalls[index])
		if err != nil {
			return ProjectionResult{}, err
		}
		firewalls[index] = firewall
		resource, facet, err := firewallAssertions(scope, firewall)
		if err != nil {
			return ProjectionResult{}, err
		}
		result.Input.Resources = append(result.Input.Resources, resource)
		result.Input.Facets = append(result.Input.Facets, facet)
	}
	for _, instance := range instances {
		if err := validateInstance(instance); err != nil {
			return ProjectionResult{}, err
		}
		instance.Tags = uniqueSorted(slices.Clone(instance.Tags))
		instance.ServiceAccounts = uniqueSorted(slices.Clone(instance.ServiceAccounts))
		claim := instanceClaim(scope, instance)
		attributes := stringAttributes(
			"gcp/instance-id", instance.ID, "gcp/name", instance.Name, "gcp/zone", instance.Zone,
			"gcp/region", zoneRegion(instance.Zone), "gcp/machine-type", instance.MachineType, "gcp/status", instance.Status,
		)
		if len(instance.Tags) > 0 {
			attributes["gcp/network-tags"] = projectkit.MustCanonicalJSON(bounded(instance.Tags, maxDiagnosticItems))
		}
		if len(instance.ServiceAccounts) > 0 {
			attributes["gcp/service-accounts"] = projectkit.MustCanonicalJSON(bounded(instance.ServiceAccounts, maxDiagnosticItems))
		}
		result.Input.Resources = append(result.Input.Resources, graph.ResourceAssertion{
			Claim: claim, Kind: "gcp/compute-instance", DisplayName: instance.Name, Attributes: attributes,
			PluginID: PluginID, SourceID: scope.SourceID, RuleID: "gcp.compute.instance", EvidenceIDs: []string{instance.EventID},
		})
		nics := slices.Clone(instance.NetworkInterfaces)
		slices.SortFunc(nics, func(left, right NetworkInterface) int { return strings.Compare(left.Name, right.Name) })
		for _, nic := range nics {
			if err := projectNetworkInterface(scope, instance, claim, nic, firewalls, subnetworkIndex, &result.Input); err != nil {
				return ProjectionResult{}, err
			}
		}
	}
	return result, nil
}

func projectNetworkInterface(scope ProjectionContext, instance Instance, instanceClaim graph.IdentityClaim, nic NetworkInterface, firewalls []Firewall, subnetworks map[string]Subnetwork, input *graph.Input) error {
	nic.Name = strings.ToLower(strings.TrimSpace(nic.Name))
	networkProject, networkName, ok := parseNetworkPath(nic.Network)
	if !strings.HasPrefix(nic.Name, "nic") || !validGCPName(nic.Name) || !ok {
		return fmt.Errorf("GCP instance %s/%s has invalid network interface %q on network %q", instance.Zone, instance.Name, nic.Name, nic.Network)
	}
	addresses := make([]string, 0, len(nic.Addresses))
	for _, address := range nic.Addresses {
		parsed, err := netip.ParseAddr(strings.TrimSpace(address))
		if err != nil {
			return fmt.Errorf("GCP instance %s/%s %s has invalid address %q", instance.Zone, instance.Name, nic.Name, address)
		}
		addresses = append(addresses, parsed.String())
	}
	addresses = uniqueSorted(addresses)
	claim := networkInterfaceClaim(scope, instance, nic.Name)
	attributes := stringAttributes(
		"gcp/instance-id", instance.ID, "gcp/instance-name", instance.Name, "gcp/zone", instance.Zone,
		"gcp/network", nic.Network, "gcp/subnetwork", nic.Subnetwork, "gcp/interface", nic.Name,
	)
	if len(addresses) > 0 {
		attributes["network/addresses"] = projectkit.MustCanonicalJSON(addresses)
	}
	if aliases := uniqueSorted(slices.Clone(nic.AliasIPRanges)); len(aliases) > 0 {
		attributes["gcp/alias-ip-ranges"] = projectkit.MustCanonicalJSON(bounded(aliases, maxDiagnosticItems))
	}
	if subnetwork, found := subnetworks[nic.Subnetwork]; found {
		attributes["gcp/subnetwork-id"] = subnetwork.ID
		if subnetwork.IPCIDRRange != "" {
			attributes["gcp/subnetwork-ip-cidr-range"] = subnetwork.IPCIDRRange
		}
	}
	governing := governingFirewalls(instance, nic, firewalls)
	if len(governing) > maxGoverningRules {
		attributes["gcp/omitted-firewall-rules"] = strconv.Itoa(len(governing) - maxGoverningRules)
		governing = governing[:maxGoverningRules]
	}
	input.Resources = append(input.Resources, graph.ResourceAssertion{
		Claim: claim, Kind: "gcp/compute-network-interface", DisplayName: instance.Name + "/" + nic.Name, Attributes: attributes,
		PluginID: PluginID, SourceID: scope.SourceID, RuleID: "gcp.compute.network-interface", EvidenceIDs: []string{instance.EventID},
	})
	input.Relationships = append(input.Relationships, graph.RelationshipAssertion{
		Subject: instanceClaim, Predicate: graph.PredicateContains, Object: claim,
		PluginID: PluginID, SourceID: scope.SourceID, RuleID: "gcp.compute.instance-network-interface", EvidenceIDs: []string{instance.EventID},
	})
	for _, match := range governing {
		properties, err := graph.WithSecuritySemantics(map[string]string{
			"gcp/priority": strconv.FormatInt(match.firewall.Priority, 10), "gcp/target": match.target,
		}, graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
			State: graph.SecurityStateDeclared, Effect: firewallAction(match.firewall), Scope: "unknown",
			Direction: strings.ToLower(match.firewall.Direction), Coverage: "partial",
		})
		if err != nil {
			return err
		}
		input.Relationships = append(input.Relationships, graph.RelationshipAssertion{
			Subject: claim, Predicate: graph.PredicateGovernedBy, Object: firewallClaim(scope, match.firewall), Properties: properties,
			PluginID: PluginID, SourceID: scope.SourceID, RuleID: "gcp.compute.network-interface-firewall",
			EvidenceIDs: []string{instance.EventID, match.firewall.EventID},
		})
	}
	authority := networkAuthority(networkProject, networkName)
	for _, address := range addresses {
		destination, err := graph.NetworkDestinationClaim(authority, "ip/"+address)
		if err != nil {
			return fmt.Errorf("project GCP network interface address %q: %w", address, err)
		}
		input.Resources = append(input.Resources, graph.ResourceAssertion{
			Claim: destination, Kind: "network/destination", DisplayName: address,
			Attributes: map[string]string{"network/address": address},
			PluginID:   PluginID, SourceID: scope.SourceID, RuleID: "gcp.compute.network-address", EvidenceIDs: []string{instance.EventID},
		})
		input.Relationships = append(input.Relationships, graph.RelationshipAssertion{
			Subject: claim, Predicate: graph.PredicateExposes, Object: destination, Qualifier: "gcp-network-address",
			PluginID: PluginID, SourceID: scope.SourceID, RuleID: "gcp.compute.network-interface-exposes-address", EvidenceIDs: []string{instance.EventID},
		})
	}
	return nil
}

type firewallMatch struct {
	firewall Firewall
	target   string
}

// governingFirewalls returns the enabled rules on nic's network whose targets
// match the instance, in evaluation order (priority, then ID).
func governingFirewalls(instance Instance, nic NetworkInterface, firewalls []Firewall) []firewallMatch {
	var result []firewallMatch
	for _, firewall := range firewalls {
		if firewall.Disabled || firewall.Network != nic.Network {
			continue
		}
		switch {
		case len(firewall.TargetTags) == 0 && len(firewall.TargetServiceAccounts) == 0:
			result = append(result, firewallMatch{firewall: firewall, target: "all-instances"})
		case intersects(firewall.TargetTags, instance.Tags):
			result = append(result, firewallMatch{firewall: firewall, target: "network-tag"})
		case intersects(firewall.TargetServiceAccounts, instance.ServiceAccounts):
			result = append(result, firewallMatch{firewall: firewall, target: "service-account"})
		}
	}
	return result
}

func firewallAssertions(scope ProjectionContext, firewall Firewall) (graph.ResourceAssertion, graph.FacetAssertion, error) {
	claim := firewallClaim(scope, firewall)
	resource := graph.ResourceAssertion{
		Claim: claim, Kind: "gcp/compute-firewall", DisplayName: firewall.Name,
		Attributes: stringAttributes("gcp/firewall-id", firewall.ID, "gcp/name", firewall.Name, "gcp/network", firewall.Network),
		PluginID:   PluginID, SourceID: scope.SourceID, RuleID: "gcp.compute.firewall", EvidenceIDs: []string{firewall.EventID},
	}
	direction := strings.ToLower(firewall.Direction)
	permissions := firewall.Allowed
	if firewallAction(firewall) == "deny" {
		permissions = firewall.Denied
	}
	protocols, ports := securityDetails(permissions)
	boundedPermissions, omitted := boundedFirewallPermissions(permissions)
	attributes := map[string]string{
		"gcp/action": firewallAction(firewall), "gcp/priority": strconv.FormatInt(firewall.Priority, 10),
		"gcp/disabled": strconv.FormatBool(firewall.Disabled), "gcp/permissions": projectkit.MustCanonicalJSON(boundedPermissions),
		"gcp/permission-count": strconv.Itoa(len(permissions)),
	}
	for _, field := range []struct {
		key    string
		values []string
	}{
		{"gcp/source-ranges", firewall.SourceRanges}, {"gcp/destination-ranges", firewall.DestinationRanges},
		{"gcp/source-tags", firewall.SourceTags}, {"gcp/source-service-accounts", firewall.SourceServiceAccounts},
		{"gcp/target-tags", firewall.TargetTags}, {"gcp/target-service-accounts", firewall.TargetServiceAccounts},
	} {
		if len(field.values) == 0 {
			continue
		}
		attributes[field.key] = projectkit.MustCanonicalJSON(bounded(field.values, maxNativePeers))
		omitted += max(0, len(field.values)-maxNativePeers)
	}
	if omitted > 0 {
		attributes["gcp/omitted-values"] = strconv.Itoa(omitted)
	}
	attributes, err := graph.WithSecuritySemantics(attributes, graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
		State: graph.SecurityStateDeclared, Effect: firewallAction(firewall), Scope: "unknown", Direction: direction, Coverage: "partial",
		Protocols: protocols, Ports: ports, ConfigurationDigest: projectkit.Digest(firewall),
	})
	if err != nil {
		return graph.ResourceAssertion{}, graph.FacetAssertion{}, fmt.Errorf("firewall %s semantics: %w", firewall.Name, err)
	}
	facet := graph.FacetAssertion{
		Resource: claim, Kind: "gcp-firewall-rule", Key: direction, Attributes: attributes,
		PluginID: PluginID, SourceID: scope.SourceID, RuleID: "gcp.compute.firewall-" + direction,
		EvidenceIDs: []string{firewall.EventID},
	}
	return resource, facet, nil
}

// canonicalFirewall validates a firewall and sorts its lists, so the projector
// does not depend on capture having canonicalized it.
func canonicalFirewall(firewall Firewall) (Firewall, error) {
	firewall.Direction = strings.ToUpper(strings.TrimSpace(firewall.Direction))
	_, _, validNetwork := parseNetworkPath(firewall.Network)
	if !validNumericID(firewall.ID) || strings.TrimSpace(firewall.Name) == "" || strings.TrimSpace(firewall.EventID) == "" || !validNetwork ||
		firewall.Direction != "INGRESS" && firewall.Direction != "EGRESS" || (len(firewall.Allowed) > 0) == (len(firewall.Denied) > 0) {
		return Firewall{}, fmt.Errorf("GCP firewall %q requires numeric ID, name, network, direction, one action, and evidence event", firewall.Name)
	}
	firewall.Allowed = canonicalPermissions(firewall.Allowed)
	firewall.Denied = canonicalPermissions(firewall.Denied)
	firewall.SourceRanges = uniqueSorted(slices.Clone(firewall.SourceRanges))
	firewall.DestinationRanges = uniqueSorted(slices.Clone(firewall.DestinationRanges))
	firewall.SourceTags = uniqueSorted(slices.Clone(firewall.SourceTags))
	firewall.SourceServiceAccounts = uniqueSorted(slices.Clone(firewall.SourceServiceAccounts))
	firewall.TargetTags = uniqueSorted(slices.Clone(firewall.TargetTags))
	firewall.TargetServiceAccounts = uniqueSorted(slices.Clone(firewall.TargetServiceAccounts))
	return firewall, nil
}

func canonicalPermissions(values []Permission) []Permission {
	result := slices.Clone(values)
	for index := range result {
		result[index].Protocol = strings.ToLower(strings.TrimSpace(result[index].Protocol))
		result[index].Ports = uniqueSorted(slices.Clone(result[index].Ports))
	}
	slices.SortFunc(result, func(left, right Permission) int {
		return strings.Compare(projectkit.MustCanonicalJSON(left), projectkit.MustCanonicalJSON(right))
	})
	return slices.CompactFunc(result, func(left, right Permission) bool {
		return left.Protocol == right.Protocol && slices.Equal(left.Ports, right.Ports)
	})
}

func compareFirewallPrecedence(left, right Firewall) int {
	if order := cmp.Compare(left.Priority, right.Priority); order != 0 {
		return order
	}
	return compareNumericIDs(left.ID, right.ID)
}

// firewallAction is deny for a rule with denied entries; GCP requires exactly
// one of allowed or denied.
func firewallAction(firewall Firewall) string {
	if len(firewall.Denied) > 0 {
		return "deny"
	}
	return "allow"
}

func securityDetails(permissions []Permission) ([]string, []graph.SecurityPort) {
	var protocols []string
	var ports []graph.SecurityPort
	for _, permission := range permissions {
		protocol := strings.ToUpper(permission.Protocol)
		if protocol != "" {
			protocols = append(protocols, protocol)
		}
		if permission.Protocol != "tcp" && permission.Protocol != "udp" && permission.Protocol != "sctp" {
			continue
		}
		for _, value := range permission.Ports {
			port, err := strconv.ParseUint(value, 10, 16)
			if err == nil && port > 0 {
				ports = append(ports, graph.SecurityPort{Protocol: protocol, Port: uint16(port)})
			}
		}
	}
	protocols = uniqueSorted(protocols)
	if len(protocols) > 16 {
		protocols = protocols[:16]
	}
	slices.SortFunc(ports, func(left, right graph.SecurityPort) int {
		return cmp.Or(strings.Compare(left.Protocol, right.Protocol), cmp.Compare(left.Port, right.Port))
	})
	ports = slices.Compact(ports)
	if len(ports) > 64 {
		ports = ports[:64]
	}
	return protocols, ports
}

func boundedFirewallPermissions(permissions []Permission) ([]Permission, int) {
	limit := min(len(permissions), maxNativeRules)
	result := make([]Permission, limit)
	omitted := len(permissions) - limit
	for index := 0; index < limit; index++ {
		result[index] = permissions[index]
		if len(result[index].Ports) > maxNativePeers {
			omitted += len(result[index].Ports) - maxNativePeers
			result[index].Ports = result[index].Ports[:maxNativePeers]
		}
	}
	return result, omitted
}

func instanceClaim(scope ProjectionContext, instance Instance) graph.IdentityClaim {
	return resourceClaim(scope.ProjectNumber, "compute/"+instance.Zone+"/instance/"+instance.Name)
}

func networkInterfaceClaim(scope ProjectionContext, instance Instance, nic string) graph.IdentityClaim {
	return resourceClaim(scope.ProjectNumber, "compute/"+instance.Zone+"/instance/"+instance.Name+"/network-interface/"+nic)
}

func firewallClaim(scope ProjectionContext, firewall Firewall) graph.IdentityClaim {
	return resourceClaim(scope.ProjectNumber, "compute/global/firewall/"+firewall.ID)
}

func resourceClaim(projectNumber, key string) graph.IdentityClaim {
	return graph.IdentityClaim{Scheme: resourceScheme, AuthorityID: projectNumber, ImmutableKey: key}
}

// instanceClaimFromProviderID resolves gce://<project-id>/<zone>/<name>. A
// reference to another project or to a zone outside the region filter is no
// match rather than an error, because it belongs to another source and one
// Node must not fail the whole Kubernetes projection.
func instanceClaimFromProviderID(projectID, projectNumber, region, providerID string) (graph.IdentityClaim, bool, error) {
	providerID = strings.TrimSpace(providerID)
	if !strings.HasPrefix(strings.ToLower(providerID), "gce://") {
		return graph.IdentityClaim{}, false, nil
	}
	parts := strings.Split(providerID[len("gce://"):], "/")
	if len(parts) != 3 || parts[0] != projectID || !validGCPName(parts[1]) || !validGCPName(parts[2]) {
		return graph.IdentityClaim{}, false, nil
	}
	if region != "" && zoneRegion(parts[1]) != region {
		return graph.IdentityClaim{}, false, nil
	}
	claim, err := IdentitySchemeDefinition().Normalize(resourceClaim(projectNumber, "compute/"+parts[1]+"/instance/"+parts[2]))
	if err != nil {
		return graph.IdentityClaim{}, false, err
	}
	return claim, true, nil
}

// networkAuthority is the network realm for addresses on one VPC network. It
// is keyed by the network's host project ID because flow logs and Shared VPC
// service projects name the network that way.
func networkAuthority(project, network string) string {
	return "gcp/" + project + "/" + network
}

func subnetworkPath(subnetwork Subnetwork) string {
	return "projects/" + subnetwork.projectID() + "/regions/" + subnetwork.Region + "/subnetworks/" + subnetwork.Name
}

func (subnetwork Subnetwork) projectID() string {
	project, _, _ := parseNetworkPath(subnetwork.Network)
	return project
}

// parseNetworkPath splits projects/<project>/global/networks/<name>.
func parseNetworkPath(path string) (string, string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) != 5 || parts[0] != "projects" || parts[2] != "global" || parts[3] != "networks" || parts[1] == "" || !validGCPName(parts[4]) {
		return "", "", false
	}
	return parts[1], parts[4], true
}

// zoneRegion maps a zone such as us-east1-b to its region us-east1.
func zoneRegion(zone string) string {
	if index := strings.LastIndexByte(zone, '-'); index > 0 {
		return zone[:index]
	}
	return ""
}

func validateInstance(instance Instance) error {
	if !validNumericID(instance.ID) || !validGCPName(instance.Name) || !validGCPName(instance.Zone) || zoneRegion(instance.Zone) == "" || strings.TrimSpace(instance.EventID) == "" {
		return fmt.Errorf("GCP instance %q requires numeric ID, name, zone, and evidence event", instance.Name)
	}
	return nil
}

func validGCPName(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validNumericID(value string) bool {
	if value == "" || len(value) > 20 || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func intersects(left, right []string) bool {
	for _, value := range left {
		if slices.Contains(right, value) {
			return true
		}
	}
	return false
}

func bounded(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func stringAttributes(values ...string) map[string]string {
	result := make(map[string]string, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		if values[index+1] != "" {
			result[values[index]] = values[index+1]
		}
	}
	return result
}

func uniqueSorted(values []string) []string {
	for index := range values {
		values[index] = strings.TrimSpace(values[index])
	}
	values = slices.DeleteFunc(values, func(value string) bool { return value == "" })
	slices.Sort(values)
	return slices.Compact(values)
}
