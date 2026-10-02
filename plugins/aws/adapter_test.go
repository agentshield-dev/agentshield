package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestCapturePaginatesAndCanonicalizes(t *testing.T) {
	client := &pagedEC2{}
	snapshot, err := capture(context.Background(), client, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if client.interfaceCalls != 2 || client.groupCalls != 2 {
		t.Fatalf("interface calls=%d group calls=%d", client.interfaceCalls, client.groupCalls)
	}
	if len(snapshot.NetworkInterfaces) != 2 || snapshot.NetworkInterfaces[0].ID != "eni-a" || snapshot.NetworkInterfaces[0].SecurityGroupIDs[0] != "sg-a" {
		t.Fatalf("unexpected network interfaces: %#v", snapshot.NetworkInterfaces)
	}
	if len(snapshot.SecurityGroups) != 2 || snapshot.SecurityGroups[0].ID != "sg-a" || snapshot.SecurityGroups[0].Ingress[0].Protocol != "all" {
		t.Fatalf("unexpected security groups: %#v", snapshot.SecurityGroups)
	}
	if len(snapshot.Instances) != 1 || snapshot.Instances[0].ID != "i-a" || snapshot.Instances[0].OwnerID != "111111111111" {
		t.Fatalf("unexpected instances: %#v", snapshot.Instances)
	}
	if snapshot.NetworkInterfaces[0].Revision == "" || snapshot.NetworkInterfaces[0].EventID == "" {
		t.Fatal("stable revision and event ID were not assigned")
	}
}

func TestCaptureBoundsEachDescribeCall(t *testing.T) {
	previous := describeTimeout
	describeTimeout = 10 * time.Millisecond
	t.Cleanup(func() { describeTimeout = previous })
	if _, err := capture(context.Background(), stalledEC2{}, "us-east-1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capture error = %v, want deadline exceeded", err)
	}
}

// stalledEC2 blocks every call until its context ends.
type stalledEC2 struct{}

func (stalledEC2) DescribeNetworkInterfaces(ctx context.Context, _ *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stalledEC2) DescribeInstances(ctx context.Context, _ *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stalledEC2) DescribeSecurityGroups(ctx context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type pagedEC2 struct {
	interfaceCalls int
	groupCalls     int
}

func (p *pagedEC2) DescribeInstances(_ context.Context, input *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if awsdk.ToInt32(input.MaxResults) != 1000 {
		return nil, errors.New("instance page size was not set")
	}
	return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{OwnerId: awsdk.String("111111111111"), Instances: []types.Instance{{
		InstanceId: awsdk.String("i-a"), VpcId: awsdk.String("vpc-a"),
	}}}}}, nil
}

func (p *pagedEC2) DescribeNetworkInterfaces(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	p.interfaceCalls++
	if awsdk.ToInt32(input.MaxResults) != 1000 {
		return nil, errors.New("network interface page size was not set")
	}
	if awsdk.ToString(input.NextToken) == "" {
		return &ec2.DescribeNetworkInterfacesOutput{
			NetworkInterfaces: []types.NetworkInterface{{
				NetworkInterfaceId: awsdk.String("eni-b"), OwnerId: awsdk.String("111111111111"),
				Groups: []types.GroupIdentifier{{GroupId: awsdk.String("sg-b")}},
			}}, NextToken: awsdk.String("next"),
		}, nil
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []types.NetworkInterface{{
		NetworkInterfaceId: awsdk.String("eni-a"), OwnerId: awsdk.String("111111111111"),
		Groups: []types.GroupIdentifier{{GroupId: awsdk.String("sg-z")}, {GroupId: awsdk.String("sg-a")}},
	}}}, nil
}

func (p *pagedEC2) DescribeSecurityGroups(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	p.groupCalls++
	if awsdk.ToInt32(input.MaxResults) != 1000 {
		return nil, errors.New("security group page size was not set")
	}
	if awsdk.ToString(input.NextToken) == "" {
		return &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []types.SecurityGroup{{GroupId: awsdk.String("sg-b"), OwnerId: awsdk.String("111111111111")}},
			NextToken:      awsdk.String("next"),
		}, nil
	}
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{
		GroupId: awsdk.String("sg-a"), OwnerId: awsdk.String("111111111111"),
		IpPermissions: []types.IpPermission{{IpProtocol: awsdk.String("-1")}},
	}}}, nil
}
