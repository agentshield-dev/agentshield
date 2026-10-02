package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EC2API is the subset of the EC2 client used for inventory. Every method is
// fully paginated on each poll.
type EC2API interface {
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// describeTimeout bounds one Describe page request, so a stalled call fails
// the poll (and leaves SQS messages for redelivery) instead of blocking the
// plugin. It is per page, not per poll, so large accounts are not cut off.
var describeTimeout = time.Minute

// nextPage fetches one page under describeTimeout.
func nextPage[T any](ctx context.Context, fetch func(context.Context, ...func(*ec2.Options)) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, describeTimeout)
	defer cancel()
	return fetch(ctx)
}

func capture(ctx context.Context, client EC2API, region string) (Snapshot, error) {
	interfaces, err := captureNetworkInterfaces(ctx, client, region)
	if err != nil {
		return Snapshot{}, err
	}
	instances, err := captureInstances(ctx, client, region)
	if err != nil {
		return Snapshot{}, err
	}
	groups, err := captureSecurityGroups(ctx, client, region)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{NetworkInterfaces: interfaces, Instances: instances, SecurityGroups: groups}, nil
}

func captureInstances(ctx context.Context, client EC2API, region string) ([]Instance, error) {
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{MaxResults: awsdk.Int32(1000)})
	var result []Instance
	for paginator.HasMorePages() {
		page, err := nextPage(ctx, paginator.NextPage)
		if err != nil {
			return nil, fmt.Errorf("describe EC2 instances in %s: %w", region, err)
		}
		for _, reservation := range page.Reservations {
			for _, value := range reservation.Instances {
				item := Instance{
					ID: awsdk.ToString(value.InstanceId), OwnerID: awsdk.ToString(reservation.OwnerId),
					VPCID: awsdk.ToString(value.VpcId), SubnetID: awsdk.ToString(value.SubnetId), InstanceType: string(value.InstanceType),
				}
				if value.Placement != nil {
					item.AvailabilityZone = awsdk.ToString(value.Placement.AvailabilityZone)
				}
				if value.State != nil {
					item.State = string(value.State.Name)
				}
				if err := finalizeInstance(&item, region); err != nil {
					return nil, err
				}
				result = append(result, item)
			}
		}
	}
	slices.SortFunc(result, func(left, right Instance) int { return strings.Compare(left.ID, right.ID) })
	return result, nil
}

func captureNetworkInterfaces(ctx context.Context, client EC2API, region string) ([]NetworkInterface, error) {
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(client, &ec2.DescribeNetworkInterfacesInput{MaxResults: awsdk.Int32(1000)})
	var result []NetworkInterface
	for paginator.HasMorePages() {
		page, err := nextPage(ctx, paginator.NextPage)
		if err != nil {
			return nil, fmt.Errorf("describe EC2 network interfaces in %s: %w", region, err)
		}
		for _, value := range page.NetworkInterfaces {
			item := NetworkInterface{
				ID: awsdk.ToString(value.NetworkInterfaceId), OwnerID: awsdk.ToString(value.OwnerId),
				VPCID: awsdk.ToString(value.VpcId), SubnetID: awsdk.ToString(value.SubnetId),
				AvailabilityZone: awsdk.ToString(value.AvailabilityZone), InterfaceType: string(value.InterfaceType),
				Status: string(value.Status), RequesterManaged: awsdk.ToBool(value.RequesterManaged),
			}
			if value.Attachment != nil {
				item.AttachmentInstanceID = awsdk.ToString(value.Attachment.InstanceId)
			}
			item.Addresses = appendNonempty(item.Addresses, awsdk.ToString(value.PrivateIpAddress))
			for _, address := range value.PrivateIpAddresses {
				item.Addresses = appendNonempty(item.Addresses, awsdk.ToString(address.PrivateIpAddress))
				if address.Association != nil {
					item.Addresses = appendNonempty(item.Addresses, awsdk.ToString(address.Association.PublicIp))
				}
			}
			for _, address := range value.Ipv6Addresses {
				item.Addresses = appendNonempty(item.Addresses, awsdk.ToString(address.Ipv6Address))
			}
			item.Addresses = uniqueSorted(item.Addresses)
			for _, group := range value.Groups {
				if id := strings.TrimSpace(awsdk.ToString(group.GroupId)); id != "" {
					item.SecurityGroupIDs = append(item.SecurityGroupIDs, id)
				}
			}
			item.SecurityGroupIDs = uniqueSorted(item.SecurityGroupIDs)
			if err := finalizeNetworkInterface(&item, region); err != nil {
				return nil, err
			}
			result = append(result, item)
		}
	}
	slices.SortFunc(result, func(left, right NetworkInterface) int { return strings.Compare(left.ID, right.ID) })
	return result, nil
}

func captureSecurityGroups(ctx context.Context, client EC2API, region string) ([]SecurityGroup, error) {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{MaxResults: awsdk.Int32(1000)})
	var result []SecurityGroup
	for paginator.HasMorePages() {
		page, err := nextPage(ctx, paginator.NextPage)
		if err != nil {
			return nil, fmt.Errorf("describe EC2 security groups in %s: %w", region, err)
		}
		for _, value := range page.SecurityGroups {
			item := SecurityGroup{
				ID: awsdk.ToString(value.GroupId), OwnerID: awsdk.ToString(value.OwnerId),
				VPCID: awsdk.ToString(value.VpcId), Name: awsdk.ToString(value.GroupName),
				Ingress: normalizeRules(value.IpPermissions), Egress: normalizeRules(value.IpPermissionsEgress),
			}
			if err := finalizeSecurityGroup(&item, region); err != nil {
				return nil, err
			}
			result = append(result, item)
		}
	}
	slices.SortFunc(result, func(left, right SecurityGroup) int { return strings.Compare(left.ID, right.ID) })
	return result, nil
}

func finalizeNetworkInterface(item *NetworkInterface, region string) error {
	if strings.TrimSpace(item.ID) == "" || !validAccountID(item.OwnerID) {
		return fmt.Errorf("EC2 network interface in %s requires ID and 12-digit owner account", region)
	}
	revision, err := contentRevision(*item)
	if err != nil {
		return err
	}
	item.Revision = revision
	item.EventID = eventID(networkInterfacesCollection(region), item.ID, revision, "upsert")
	return nil
}

func finalizeInstance(item *Instance, region string) error {
	if strings.TrimSpace(item.ID) == "" || !validAccountID(item.OwnerID) {
		return fmt.Errorf("EC2 instance in %s requires ID and 12-digit owner account", region)
	}
	revision, err := contentRevision(*item)
	if err != nil {
		return err
	}
	item.Revision = revision
	item.EventID = eventID(instancesCollection(region), item.ID, revision, "upsert")
	return nil
}

func finalizeSecurityGroup(item *SecurityGroup, region string) error {
	if strings.TrimSpace(item.ID) == "" || !validAccountID(item.OwnerID) {
		return fmt.Errorf("EC2 security group in %s requires ID and 12-digit owner account", region)
	}
	revision, err := contentRevision(*item)
	if err != nil {
		return err
	}
	item.Revision = revision
	item.EventID = eventID(securityGroupsCollection(region), item.ID, revision, "upsert")
	return nil
}

func normalizeRules(values []types.IpPermission) []Rule {
	result := make([]Rule, 0, len(values))
	for _, value := range values {
		rule := Rule{Protocol: strings.ToLower(strings.TrimSpace(awsdk.ToString(value.IpProtocol))), FromPort: value.FromPort, ToPort: value.ToPort}
		if rule.Protocol == "-1" {
			rule.Protocol = "all"
		}
		for _, item := range value.IpRanges {
			rule.IPv4Ranges = appendNonempty(rule.IPv4Ranges, awsdk.ToString(item.CidrIp))
		}
		for _, item := range value.Ipv6Ranges {
			rule.IPv6Ranges = appendNonempty(rule.IPv6Ranges, awsdk.ToString(item.CidrIpv6))
		}
		for _, item := range value.PrefixListIds {
			rule.PrefixListIDs = appendNonempty(rule.PrefixListIDs, awsdk.ToString(item.PrefixListId))
		}
		for _, item := range value.UserIdGroupPairs {
			owner := strings.TrimSpace(awsdk.ToString(item.UserId))
			group := strings.TrimSpace(awsdk.ToString(item.GroupId))
			if owner != "" && group != "" {
				rule.SecurityGroupIDs = append(rule.SecurityGroupIDs, owner+"/"+group)
			} else {
				rule.SecurityGroupIDs = appendNonempty(rule.SecurityGroupIDs, group)
			}
		}
		rule.IPv4Ranges = uniqueSorted(rule.IPv4Ranges)
		rule.IPv6Ranges = uniqueSorted(rule.IPv6Ranges)
		rule.PrefixListIDs = uniqueSorted(rule.PrefixListIDs)
		rule.SecurityGroupIDs = uniqueSorted(rule.SecurityGroupIDs)
		result = append(result, rule)
	}
	slices.SortFunc(result, func(left, right Rule) int {
		leftJSON, _ := json.Marshal(left)
		rightJSON, _ := json.Marshal(right)
		return strings.Compare(string(leftJSON), string(rightJSON))
	})
	return result
}

func contentRevision(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode AWS observation: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func appendNonempty(values []string, value string) []string {
	if value = strings.TrimSpace(value); value != "" {
		return append(values, value)
	}
	return values
}

func uniqueSorted(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

func validAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validateClient(client EC2API) error {
	if client == nil {
		return errors.New("AWS EC2 client is required")
	}
	return nil
}
