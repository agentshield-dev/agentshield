package gcp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	compute "google.golang.org/api/compute/v1"
)

func TestPluginPublishesReplacementAndRetraction(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &changingCompute{}
	runtime := &recordingRuntime{generation: 7, cancelAfterReplacements: 2, cancel: cancel}
	plugin, err := New(testConfig(client, time.Millisecond))
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
	// instance, NIC, and firewall, then the firewall alone
	if len(runtime.replacements[0].Input.Resources) != 3 || len(runtime.replacements[1].Input.Resources) != 1 {
		t.Fatalf("resource counts = %d, %d", len(runtime.replacements[0].Input.Resources), len(runtime.replacements[1].Input.Resources))
	}
	var deleted bool
	for _, change := range runtime.changes {
		if change.Operation == discovery.OperationDelete && change.Key == "1" {
			deleted = true
			if change.Collection != instancesCollection || change.EventID != eventID(change.SourceID, instancesCollection, "1", change.Revision, "delete") {
				t.Fatalf("unstable delete event %#v", change)
			}
		}
	}
	if !deleted {
		t.Fatal("instance omission did not publish a delete")
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
	runtime := &recordingRuntime{cancelAfterReplacements: 2, cancel: cancel}
	plugin, err := New(testConfig(&failingCompute{}, time.Millisecond))
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
	plugin, err := New(testConfig(initialFailureCompute{}, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := plugin.Run(context.Background(), runtime); err == nil {
		t.Fatal("initial subnetwork failure was accepted")
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.changes) != 0 || len(runtime.replacements) != 0 || len(runtime.ready) != 0 {
		t.Fatalf("partial snapshot was published: changes=%d replacements=%d ready=%d", len(runtime.changes), len(runtime.replacements), len(runtime.ready))
	}
}

func TestSourceID(t *testing.T) {
	for _, test := range []struct{ number, region, want string }{
		{" 111111111111 ", "", "gcp/111111111111"},
		{"111111111111", " us-east1 ", "gcp/111111111111/us-east1"},
	} {
		value, err := SourceID(test.number, test.region)
		if err != nil || value != test.want {
			t.Fatalf("SourceID(%q, %q) = %q, %v", test.number, test.region, value, err)
		}
	}
	for _, test := range []struct{ number, region string }{{"my-project", ""}, {"0123", ""}, {"111111111111", "US_EAST1"}} {
		if _, err := SourceID(test.number, test.region); err == nil {
			t.Fatalf("SourceID(%q, %q) was accepted", test.number, test.region)
		}
	}
}

func TestCLIConfigPollDuration(t *testing.T) {
	if value, err := (CLIConfig{PollInterval: " 90s "}).PollDuration(); err != nil || value != 90*time.Second {
		t.Fatalf("poll duration = %v, %v", value, err)
	}
	for _, value := range []string{"", "0s", "-1m", "five"} {
		if _, err := (CLIConfig{PollInterval: value}).PollDuration(); err == nil {
			t.Fatalf("poll interval %q was accepted", value)
		}
	}
}

func testConfig(client ComputeAPI, pollInterval time.Duration) Config {
	return Config{
		ProjectID: "example-project", ProjectNumber: testProjectNumber, SourceID: "gcp/" + testProjectNumber,
		Compute: client, PollInterval: pollInterval,
	}
}

type emptyCompute struct{}

func (emptyCompute) AggregatedListInstances(context.Context, PageRequest) (*compute.InstanceAggregatedList, error) {
	return &compute.InstanceAggregatedList{}, nil
}

func (emptyCompute) ListFirewalls(context.Context, PageRequest) (*compute.FirewallList, error) {
	return &compute.FirewallList{}, nil
}

func (emptyCompute) AggregatedListSubnetworks(context.Context, PageRequest) (*compute.SubnetworkAggregatedList, error) {
	return &compute.SubnetworkAggregatedList{}, nil
}

// changingCompute returns one instance on the first poll and none afterwards.
type changingCompute struct {
	emptyCompute
	mu    sync.Mutex
	cycle int
}

func (c *changingCompute) AggregatedListInstances(context.Context, PageRequest) (*compute.InstanceAggregatedList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cycle++
	if c.cycle > 1 {
		return &compute.InstanceAggregatedList{}, nil
	}
	return &compute.InstanceAggregatedList{Items: map[string]compute.InstancesScopedList{"zones/us-east1-b": {Instances: []*compute.Instance{{
		Id: 1, Name: "vm", Zone: "zones/us-east1-b",
		NetworkInterfaces: []*compute.NetworkInterface{{Name: "nic0", Network: testSelfLinkPrefix + testNetwork}},
	}}}}}, nil
}

func (c *changingCompute) ListFirewalls(context.Context, PageRequest) (*compute.FirewallList, error) {
	return &compute.FirewallList{Items: []*compute.Firewall{{
		Id: 2, Name: "allow", Network: testSelfLinkPrefix + testNetwork, Direction: "INGRESS", Priority: 1000,
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}},
	}}}, nil
}

// failingCompute succeeds once, then fails every firewall list.
type failingCompute struct {
	emptyCompute
	mu    sync.Mutex
	calls int
}

func (f *failingCompute) ListFirewalls(context.Context, PageRequest) (*compute.FirewallList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls > 1 {
		return nil, errors.New("Compute unavailable")
	}
	return &compute.FirewallList{}, nil
}

type initialFailureCompute struct{ emptyCompute }

func (initialFailureCompute) AggregatedListSubnetworks(context.Context, PageRequest) (*compute.SubnetworkAggregatedList, error) {
	return nil, errors.New("subnetworks unavailable")
}

type readyCall struct {
	collection string
	generation uint64
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

func TestEventIDIncludesSource(t *testing.T) {
	project := eventID("gcp/"+testProjectNumber, instancesCollection, "1", "rev", "upsert")
	regional := eventID("gcp/"+testProjectNumber+"/us-east1", instancesCollection, "1", "rev", "upsert")
	if project == regional {
		t.Fatalf("event ID %q shared by two sources", project)
	}
}
