package aws

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	awsdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/agentshield-dev/agentshield/pkg/discovery"
)

func TestPluginPublishesReplacementAndRetraction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &changingEC2{}
	runtime := &recordingRuntime{generation: 7, cancelAfterReplacements: 2, cancel: cancel}
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1",
		EC2: client, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = plugin.Run(ctx, runtime)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.replacements) != 2 || runtime.replacements[0].Generation != 8 || runtime.replacements[1].Generation != 9 {
		t.Fatalf("replacements = %#v", runtime.replacements)
	}
	if len(runtime.replacements[0].Input.Resources) != 2 || len(runtime.replacements[1].Input.Resources) != 1 {
		t.Fatalf("resource counts = %d, %d", len(runtime.replacements[0].Input.Resources), len(runtime.replacements[1].Input.Resources))
	}
	var deleted bool
	for _, change := range runtime.changes {
		if change.Operation == discovery.OperationDelete && change.Key == "eni-1" {
			deleted = true
			if change.EventID != eventID(networkInterfacesCollection("us-east-1"), "eni-1", change.Revision, "delete") {
				t.Fatalf("unstable delete event ID %q", change.EventID)
			}
		}
	}
	if !deleted {
		t.Fatal("network interface omission did not publish a delete")
	}
	if len(runtime.ready) != 6 {
		t.Fatalf("ready markers = %d, want 6", len(runtime.ready))
	}
	if !ordered(runtime.operations, "publish", "replace", "ready", "ready", "ready") {
		t.Fatalf("initial operation order = %v", runtime.operations)
	}
}

func TestPluginRetainsLastContributionOnPollFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &failingEC2{}
	runtime := &recordingRuntime{cancelAfterReplacements: 2, cancel: cancel}
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "source", EC2: client, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = plugin.Run(ctx, runtime)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.replacements) != 2 || runtime.replacements[0].SourceHealth != "healthy" || runtime.replacements[1].SourceHealth != "degraded" {
		t.Fatalf("health transitions = %#v", runtime.replacements)
	}
	if runtime.replacements[0].SourceObservedAt != runtime.replacements[1].SourceObservedAt {
		t.Fatal("degraded transition changed the last successful observation time")
	}
	if len(runtime.replacements[1].Input.Resources) != len(runtime.replacements[0].Input.Resources) {
		t.Fatal("degraded transition did not retain the last coherent input")
	}
}

func TestPluginDoesNotPublishPartialInitialSnapshot(t *testing.T) {
	runtime := &recordingRuntime{}
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "source", EC2: initialFailureEC2{},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = plugin.Run(context.Background(), runtime)
	if err == nil {
		t.Fatal("initial Security Group failure was accepted")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.changes) != 0 || len(runtime.replacements) != 0 || len(runtime.ready) != 0 {
		t.Fatalf("partial snapshot was published: changes=%d replacements=%d ready=%d", len(runtime.changes), len(runtime.replacements), len(runtime.ready))
	}
}

func TestPluginReconcilesEventBeforeAcknowledging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &changingEC2{}
	runtime := &recordingRuntime{}
	subscriber := &fakeSubscriber{batch: ChangeBatch{Subscriptions: []string{"network-interfaces"}}, acknowledge: func() {
		runtime.mu.Lock()
		runtime.operations = append(runtime.operations, "acknowledge")
		runtime.mu.Unlock()
		cancel()
	}}
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "source", EC2: client, Subscriber: subscriber, PollInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = plugin.Run(ctx, runtime)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.replacements) != 2 || subscriber.acknowledged != 1 {
		t.Fatalf("replacements = %d, acknowledgements = %d", len(runtime.replacements), subscriber.acknowledged)
	}
	if !ordered(runtime.operations, "replace", "ready", "ready", "ready", "replace", "ready", "ready", "ready", "acknowledge") {
		t.Fatalf("operation order = %v", runtime.operations)
	}
}

func TestPluginLeavesEventUnacknowledgedWhenReconciliationFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &recordingRuntime{cancelAfterReplacements: 2, cancel: cancel}
	subscriber := &fakeSubscriber{batch: ChangeBatch{Subscriptions: []string{"security-groups"}}}
	plugin, err := New(Config{
		Partition: "aws", Region: "us-east-1", SourceID: "source", EC2: &failingEC2{}, Subscriber: subscriber, PollInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = plugin.Run(ctx, runtime)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
	if subscriber.acknowledged != 0 {
		t.Fatalf("acknowledgements = %d", subscriber.acknowledged)
	}
}

func TestSourceID(t *testing.T) {
	value, err := SourceID(" aws-us-gov ", " 111111111111 ", " us-gov-west-1 ")
	if err != nil {
		t.Fatal(err)
	}
	if value != "aws/aws-us-gov/111111111111/us-gov-west-1" {
		t.Fatalf("source ID = %q", value)
	}
	if _, err := SourceID("aws", "caller", "us-east-1"); err == nil {
		t.Fatal("invalid account ID was accepted")
	}
}

type changingEC2 struct {
	mu    sync.Mutex
	cycle int
}

func (c *changingEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{}, nil
}

func (c *changingEC2) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cycle == 0 {
		return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []types.NetworkInterface{{
			NetworkInterfaceId: awsdk.String("eni-1"), OwnerId: awsdk.String("111111111111"),
			Groups: []types.GroupIdentifier{{GroupId: awsdk.String("sg-1")}},
		}}}, nil
	}
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func (c *changingEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cycle++
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{
		GroupId: awsdk.String("sg-1"), OwnerId: awsdk.String("111111111111"),
	}}}, nil
}

type failingEC2 struct {
	mu     sync.Mutex
	failed bool
}

type initialFailureEC2 struct{}

func (initialFailureEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{}, nil
}

func (initialFailureEC2) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func (initialFailureEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return nil, errors.New("Security Groups unavailable")
}

func (f *failingEC2) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed {
		return nil, errors.New("EC2 unavailable")
	}
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func (f *failingEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{}, nil
}

func (f *failingEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = true
	return &ec2.DescribeSecurityGroupsOutput{}, nil
}

type readyCall struct {
	collection string
	generation uint64
}

type fakeSubscriber struct {
	mu           sync.Mutex
	delivered    bool
	batch        ChangeBatch
	acknowledged int
	acknowledge  func()
}

func (s *fakeSubscriber) Receive(ctx context.Context) (ChangeBatch, error) {
	s.mu.Lock()
	if !s.delivered {
		s.delivered = true
		batch := s.batch
		s.mu.Unlock()
		return batch, nil
	}
	s.mu.Unlock()
	<-ctx.Done()
	return ChangeBatch{}, ctx.Err()
}

func (s *fakeSubscriber) Acknowledge(context.Context, ChangeBatch) error {
	s.mu.Lock()
	s.acknowledged++
	acknowledge := s.acknowledge
	s.mu.Unlock()
	if acknowledge != nil {
		acknowledge()
	}
	return nil
}

type recordingRuntime struct {
	mu                      sync.Mutex
	generation              uint64
	changes                 []discovery.Change
	replacements            []discovery.ContributionOutput
	ready                   []readyCall
	operations              []string
	cancelAfterReplacements int
	cancel                  context.CancelFunc
}

func (r *recordingRuntime) Publish(_ context.Context, change discovery.Change) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes = append(r.changes, change)
	r.operations = append(r.operations, "publish")
	return nil
}

func (r *recordingRuntime) MarkReady(_ context.Context, _, _, collection string, generation uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = append(r.ready, readyCall{collection: collection, generation: generation})
	r.operations = append(r.operations, "ready")
	return nil
}

func (r *recordingRuntime) Subscribe(context.Context, string) (<-chan discovery.Change, error) {
	return nil, errors.New("unexpected subscription")
}

func (r *recordingRuntime) ReplaceContribution(_ context.Context, _, _ string, output discovery.ContributionOutput) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replacements = append(r.replacements, output)
	r.operations = append(r.operations, "replace")
	if len(r.replacements) == r.cancelAfterReplacements {
		r.cancel()
	}
	return nil
}

func (r *recordingRuntime) ContributionGeneration(context.Context, string, string) (uint64, error) {
	return r.generation, nil
}

func ordered(values []string, sequence ...string) bool {
	index := 0
	for _, value := range values {
		if value == sequence[index] {
			index++
			if index == len(sequence) {
				return true
			}
		}
	}
	return false
}
