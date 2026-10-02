package aws

import (
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
	PluginID         = "aws"
	maxNativeRules   = 100
	maxNativePeers   = 100
	maxDiagnosticIDs = 100
)

var resourceScheme = graph.IdentityScheme{Group: "aws.amazon.com", Version: "v1", Kind: "Resource"}

// IdentitySchemeDefinition normalizes aws.amazon.com/v1 Resource claims: a
// 12-digit owner account authority and a lowercased
// <partition>/ec2/<region>/<type>/<id> key for instances, network
// interfaces, and security groups.
func IdentitySchemeDefinition() graph.SchemeDefinition {
	return graph.SchemeDefinition{
		Scheme: resourceScheme,
		Normalize: func(claim graph.IdentityClaim) (graph.IdentityClaim, error) {
			claim.AuthorityID = strings.TrimSpace(claim.AuthorityID)
			parts := strings.Split(claim.ImmutableKey, "/")
			if claim.Scheme != resourceScheme || !validAccountID(claim.AuthorityID) || len(parts) != 5 {
				return graph.IdentityClaim{}, errors.New("invalid aws.amazon.com/v1 Resource identity claim")
			}
			for index := range parts {
				parts[index] = strings.ToLower(strings.TrimSpace(parts[index]))
			}
			validKind := parts[3] == "network-interface" && len(parts[4]) > len("eni-") && strings.HasPrefix(parts[4], "eni-") || parts[3] == "security-group" && len(parts[4]) > len("sg-") && strings.HasPrefix(parts[4], "sg-") || parts[3] == "instance" && len(parts[4]) > len("i-") && strings.HasPrefix(parts[4], "i-")
			if !strings.HasPrefix(parts[0], "aws") || !validAWSComponent(parts[0]) || parts[1] != "ec2" || !validAWSComponent(parts[2]) || !validAWSComponent(parts[4]) || !validKind {
				return graph.IdentityClaim{}, errors.New("invalid aws.amazon.com/v1 Resource identity claim")
			}
			claim.ImmutableKey = strings.Join(parts, "/")
			return claim, nil
		},
	}
}

func validAWSComponent(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' {
					return false
				}
			}
		}
	}
	return true
}

// ProjectionContext scopes projection to one partition, region, and source.
type ProjectionContext struct {
	Partition string
	Region    string
	SourceID  string
}

// ProjectionResult is the complete inventory contribution input.
type ProjectionResult struct {
	Input graph.Input
}

// Project deterministically projects one coherent snapshot into the inventory
// contribution. Security group attachments are emitted only for groups present
// in the same snapshot with a known owner; others become bounded attributes.
func Project(scope ProjectionContext, snapshot Snapshot) (ProjectionResult, error) {
	scope.Partition = strings.TrimSpace(scope.Partition)
	scope.Region = strings.TrimSpace(scope.Region)
	scope.SourceID = strings.TrimSpace(scope.SourceID)
	if scope.Partition == "" || scope.Region == "" || scope.SourceID == "" {
		return ProjectionResult{}, errors.New("AWS projection requires partition, region, and source ID")
	}
	interfaces := slices.Clone(snapshot.NetworkInterfaces)
	instances := slices.Clone(snapshot.Instances)
	groups := slices.Clone(snapshot.SecurityGroups)
	slices.SortFunc(interfaces, func(left, right NetworkInterface) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(instances, func(left, right Instance) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(groups, func(left, right SecurityGroup) int { return strings.Compare(left.ID, right.ID) })
	groupIndex := make(map[string]SecurityGroup, len(groups))
	result := ProjectionResult{}
	for _, instance := range instances {
		if err := validateInstance(instance); err != nil {
			return ProjectionResult{}, err
		}
		result.Input.Resources = append(result.Input.Resources, graph.ResourceAssertion{
			Claim: instanceClaim(scope, instance), Kind: "aws/ec2-instance", DisplayName: instance.ID,
			Attributes: stringAttributes(
				"aws/instance-id", instance.ID, "aws/vpc-id", instance.VPCID, "aws/subnet-id", instance.SubnetID,
				"aws/availability-zone", instance.AvailabilityZone, "aws/instance-type", instance.InstanceType,
				"aws/state", instance.State, "aws/region", scope.Region,
			),
			PluginID: PluginID, SourceID: scope.SourceID, RuleID: "aws.ec2.instance", EvidenceIDs: []string{instance.EventID},
		})
	}
	for _, group := range groups {
		if err := validateGroup(group); err != nil {
			return ProjectionResult{}, err
		}
		group.Ingress = canonicalRules(group.Ingress)
		group.Egress = canonicalRules(group.Egress)
		groupIndex[group.ID] = group
		claim := securityGroupClaim(scope, group)
		result.Input.Resources = append(result.Input.Resources, graph.ResourceAssertion{
			Claim: claim, Kind: "aws/ec2-security-group", DisplayName: firstNonempty(group.Name, group.ID),
			Attributes: stringAttributes("aws/group-id", group.ID, "aws/vpc-id", group.VPCID, "aws/region", scope.Region),
			PluginID:   PluginID, SourceID: scope.SourceID, RuleID: "aws.ec2.security-group", EvidenceIDs: []string{group.EventID},
		})
		for _, direction := range []struct {
			name  string
			rules []Rule
		}{{"ingress", group.Ingress}, {"egress", group.Egress}} {
			facet, err := securityGroupFacet(scope, group, claim, direction.name, direction.rules)
			if err != nil {
				return ProjectionResult{}, err
			}
			result.Input.Facets = append(result.Input.Facets, facet)
		}
	}
	for _, item := range interfaces {
		if err := validateInterface(item); err != nil {
			return ProjectionResult{}, err
		}
		claim := networkInterfaceClaim(scope, item)
		for index, address := range item.Addresses {
			parsed, err := netip.ParseAddr(strings.TrimSpace(address))
			if err != nil {
				return ProjectionResult{}, fmt.Errorf("AWS network interface %s has invalid address %q", item.ID, address)
			}
			item.Addresses[index] = parsed.String()
		}
		item.Addresses = uniqueSorted(item.Addresses)
		attributes := stringAttributes(
			"aws/network-interface-id", item.ID, "aws/vpc-id", item.VPCID, "aws/subnet-id", item.SubnetID,
			"aws/availability-zone", item.AvailabilityZone, "aws/interface-type", item.InterfaceType,
			"aws/status", item.Status, "aws/attachment-instance-id", item.AttachmentInstanceID,
			"aws/region", scope.Region, "aws/requester-managed", strconv.FormatBool(item.RequesterManaged),
		)
		if len(item.Addresses) > 0 {
			attributes["network/addresses"] = projectkit.MustCanonicalJSON(item.Addresses)
		}
		var unresolved []string
		for _, groupID := range uniqueSorted(slices.Clone(item.SecurityGroupIDs)) {
			group, found := groupIndex[groupID]
			if !found {
				unresolved = append(unresolved, groupID)
				continue
			}
			properties, err := graph.WithSecuritySemantics(map[string]string{"aws/attachment": "network-interface"}, graph.SecuritySemantics{
				Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
				State: graph.SecurityStateDeclared, Effect: "unknown", Scope: "unknown", Direction: "bidirectional", Coverage: "partial",
			})
			if err != nil {
				return ProjectionResult{}, err
			}
			result.Input.Relationships = append(result.Input.Relationships, graph.RelationshipAssertion{
				Subject: claim, Predicate: graph.PredicateGovernedBy, Object: securityGroupClaim(scope, group), Properties: properties,
				PluginID: PluginID, SourceID: scope.SourceID, RuleID: "aws.ec2.network-interface-security-group",
				EvidenceIDs: []string{item.EventID, group.EventID},
			})
		}
		if len(unresolved) > 0 {
			bounded := unresolved
			if len(bounded) > maxDiagnosticIDs {
				bounded = bounded[:maxDiagnosticIDs]
				attributes["aws/omitted-security-group-ids"] = strconv.Itoa(len(unresolved) - len(bounded))
			}
			attributes["aws/unresolved-security-group-ids"] = projectkit.MustCanonicalJSON(bounded)
		}
		result.Input.Resources = append(result.Input.Resources, graph.ResourceAssertion{
			Claim: claim, Kind: "aws/ec2-network-interface", DisplayName: item.ID, Attributes: attributes,
			PluginID: PluginID, SourceID: scope.SourceID, RuleID: "aws.ec2.network-interface", EvidenceIDs: []string{item.EventID},
		})
		for _, address := range item.Addresses {
			destination, err := graph.NetworkDestinationClaim(networkAuthority(scope, item), "ip/"+address)
			if err != nil {
				return ProjectionResult{}, fmt.Errorf("project EC2 network interface address %q: %w", address, err)
			}
			result.Input.Resources = append(result.Input.Resources, graph.ResourceAssertion{
				Claim: destination, Kind: "network/destination", DisplayName: address,
				Attributes: map[string]string{"network/address": address},
				PluginID:   PluginID, SourceID: scope.SourceID, RuleID: "aws.ec2.network-address", EvidenceIDs: []string{item.EventID},
			})
			result.Input.Relationships = append(result.Input.Relationships, graph.RelationshipAssertion{
				Subject: claim, Predicate: graph.PredicateExposes, Object: destination, Qualifier: "aws-network-address",
				PluginID: PluginID, SourceID: scope.SourceID, RuleID: "aws.ec2.network-interface-exposes-address", EvidenceIDs: []string{item.EventID},
			})
		}
	}
	return result, nil
}

func canonicalRules(rules []Rule) []Rule {
	result := slices.Clone(rules)
	for index := range result {
		result[index].Protocol = strings.ToLower(strings.TrimSpace(result[index].Protocol))
		if result[index].Protocol == "-1" {
			result[index].Protocol = "all"
		}
		result[index].IPv4Ranges = uniqueSorted(slices.Clone(result[index].IPv4Ranges))
		result[index].IPv6Ranges = uniqueSorted(slices.Clone(result[index].IPv6Ranges))
		result[index].PrefixListIDs = uniqueSorted(slices.Clone(result[index].PrefixListIDs))
		result[index].SecurityGroupIDs = uniqueSorted(slices.Clone(result[index].SecurityGroupIDs))
	}
	slices.SortFunc(result, func(left, right Rule) int {
		return strings.Compare(projectkit.MustCanonicalJSON(left), projectkit.MustCanonicalJSON(right))
	})
	return result
}

func securityGroupFacet(scope ProjectionContext, group SecurityGroup, claim graph.IdentityClaim, direction string, rules []Rule) (graph.FacetAssertion, error) {
	protocols, ports := securityDetails(rules)
	effect := "allow"
	if len(rules) == 0 {
		effect = "restrict"
	}
	bounded, omittedPeers := boundedRules(rules)
	attributes := map[string]string{
		"aws/rules": projectkit.MustCanonicalJSON(bounded), "aws/rule-count": strconv.Itoa(len(rules)),
	}
	if omitted := len(rules) - len(bounded); omitted > 0 {
		attributes["aws/omitted-rules"] = strconv.Itoa(omitted)
	}
	if omittedPeers > 0 {
		attributes["aws/omitted-peer-values"] = strconv.Itoa(omittedPeers)
	}
	attributes, err := graph.WithSecuritySemantics(attributes, graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
		State: graph.SecurityStateDeclared, Effect: effect, Scope: "unknown", Direction: direction, Coverage: "partial",
		Protocols: protocols, Ports: ports, ConfigurationDigest: projectkit.Digest(rules),
	})
	if err != nil {
		return graph.FacetAssertion{}, fmt.Errorf("security group %s %s semantics: %w", group.ID, direction, err)
	}
	return graph.FacetAssertion{
		Resource: claim, Kind: "aws-security-group-rules", Key: direction, Attributes: attributes,
		PluginID: PluginID, SourceID: scope.SourceID, RuleID: "aws.ec2.security-group-" + direction,
		EvidenceIDs: []string{group.EventID},
	}, nil
}

func securityDetails(rules []Rule) ([]string, []graph.SecurityPort) {
	var protocols []string
	var ports []graph.SecurityPort
	for _, rule := range rules {
		protocol := strings.ToUpper(rule.Protocol)
		if protocol != "" {
			protocols = append(protocols, protocol)
		}
		if (rule.Protocol == "tcp" || rule.Protocol == "udp") && rule.FromPort != nil && rule.ToPort != nil && *rule.FromPort == *rule.ToPort && *rule.FromPort > 0 && *rule.FromPort <= 65535 {
			ports = append(ports, graph.SecurityPort{Protocol: protocol, Port: uint16(*rule.FromPort)})
		}
	}
	protocols = uniqueSorted(protocols)
	if len(protocols) > 16 {
		protocols = protocols[:16]
	}
	slices.SortFunc(ports, func(left, right graph.SecurityPort) int {
		if order := strings.Compare(left.Protocol, right.Protocol); order != 0 {
			return order
		}
		return int(left.Port) - int(right.Port)
	})
	ports = slices.Compact(ports)
	if len(ports) > 64 {
		ports = ports[:64]
	}
	return protocols, ports
}

func boundedRules(rules []Rule) ([]Rule, int) {
	limit := min(len(rules), maxNativeRules)
	result := make([]Rule, limit)
	omitted := 0
	for index := 0; index < limit; index++ {
		result[index] = rules[index]
		result[index].IPv4Ranges, omitted = boundedStrings(result[index].IPv4Ranges, omitted)
		result[index].IPv6Ranges, omitted = boundedStrings(result[index].IPv6Ranges, omitted)
		result[index].PrefixListIDs, omitted = boundedStrings(result[index].PrefixListIDs, omitted)
		result[index].SecurityGroupIDs, omitted = boundedStrings(result[index].SecurityGroupIDs, omitted)
	}
	return result, omitted
}

func boundedStrings(values []string, omitted int) ([]string, int) {
	if len(values) <= maxNativePeers {
		return values, omitted
	}
	return values[:maxNativePeers], omitted + len(values) - maxNativePeers
}

func networkInterfaceClaim(scope ProjectionContext, item NetworkInterface) graph.IdentityClaim {
	return resourceClaim(scope, item.OwnerID, "network-interface", item.ID)
}

func securityGroupClaim(scope ProjectionContext, item SecurityGroup) graph.IdentityClaim {
	return resourceClaim(scope, item.OwnerID, "security-group", item.ID)
}

func instanceClaim(scope ProjectionContext, item Instance) graph.IdentityClaim {
	return resourceClaim(scope, item.OwnerID, "instance", item.ID)
}

// instanceClaimFromProviderID resolves aws:///<zone>/<instance-id>. Any other
// AWS form is no match rather than an error, because one Node must not fail
// the whole Kubernetes projection: a zone in another region belongs to another
// source, and other forms (for example the three-segment EKS Fargate
// aws:///<zone>/<id>/fargate-<host>) do not name an EC2 instance. The Node
// keeps its kubernetes/provider-id attribute either way.
func instanceClaimFromProviderID(partition, accountID, region, providerID string) (graph.IdentityClaim, bool, error) {
	providerID = strings.TrimSpace(providerID)
	if !strings.HasPrefix(strings.ToLower(providerID), "aws://") {
		return graph.IdentityClaim{}, false, nil
	}
	parts := strings.Split(strings.Trim(providerID[len("aws://"):], "/"), "/")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], region) || !strings.HasPrefix(parts[1], "i-") {
		return graph.IdentityClaim{}, false, nil
	}
	claim := resourceClaim(ProjectionContext{Partition: partition, Region: region}, accountID, "instance", parts[1])
	if _, err := IdentitySchemeDefinition().Normalize(claim); err != nil {
		return graph.IdentityClaim{}, false, err
	}
	return claim, true, nil
}

func networkAuthority(scope ProjectionContext, item NetworkInterface) string {
	return "aws/" + scope.Partition + "/" + item.OwnerID + "/" + scope.Region + "/" + item.VPCID
}

func resourceClaim(scope ProjectionContext, ownerID, kind, id string) graph.IdentityClaim {
	return graph.IdentityClaim{Scheme: resourceScheme, AuthorityID: ownerID, ImmutableKey: scope.Partition + "/ec2/" + scope.Region + "/" + kind + "/" + id}
}

func validateInterface(item NetworkInterface) error {
	if strings.TrimSpace(item.ID) == "" || !validAccountID(item.OwnerID) || strings.TrimSpace(item.EventID) == "" {
		return fmt.Errorf("AWS network interface requires ID, owner account, and evidence event")
	}
	return nil
}

func validateGroup(item SecurityGroup) error {
	if strings.TrimSpace(item.ID) == "" || !validAccountID(item.OwnerID) || strings.TrimSpace(item.EventID) == "" {
		return fmt.Errorf("AWS security group requires ID, owner account, and evidence event")
	}
	return nil
}

func validateInstance(item Instance) error {
	if strings.TrimSpace(item.ID) == "" || !validAccountID(item.OwnerID) || strings.TrimSpace(item.EventID) == "" {
		return fmt.Errorf("AWS instance requires ID, owner account, and evidence event")
	}
	return nil
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

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
