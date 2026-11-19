package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

const testSelfLinkPrefix = "https://www.googleapis.com/compute/v1/"

func TestCapturePaginatesAndCanonicalizes(t *testing.T) {
	client := &pagedCompute{}
	snapshot, err := capture(context.Background(), client, "gcp/123", "example-project", "")
	if err != nil {
		t.Fatal(err)
	}
	if client.instanceCalls != 2 || client.firewallCalls != 2 || client.subnetworkCalls != 1 {
		t.Fatalf("instance calls=%d firewall calls=%d subnetwork calls=%d", client.instanceCalls, client.firewallCalls, client.subnetworkCalls)
	}
	if len(snapshot.Instances) != 2 || snapshot.Instances[0].ID != "9" || snapshot.Instances[1].ID != "10" {
		t.Fatalf("instances not sorted by numeric ID: %#v", snapshot.Instances)
	}
	instance := snapshot.Instances[1]
	if instance.Zone != "us-east1-b" || instance.MachineType != "e2-small" || strings.Join(instance.Tags, ",") != "a,b" {
		t.Fatalf("unexpected instance: %#v", instance)
	}
	nic := instance.NetworkInterfaces[0]
	if nic.Name != "nic0" || nic.Network != testNetwork || nic.Subnetwork != testSubnetwork ||
		strings.Join(nic.Addresses, ",") != "10.0.0.2,34.1.2.3" || strings.Join(nic.AliasIPRanges, ",") != "10.4.0.0/24" {
		t.Fatalf("unexpected network interface: %#v", nic)
	}
	if len(snapshot.Firewalls) != 2 || snapshot.Firewalls[0].ID != "20" || snapshot.Firewalls[1].Allowed[0].Protocol != "tcp" {
		t.Fatalf("unexpected firewalls: %#v", snapshot.Firewalls)
	}
	if len(snapshot.Subnetworks) != 2 || snapshot.Subnetworks[0].Region != "europe-west1" || snapshot.Subnetworks[1].SecondaryRanges[0].Name != "pods" {
		t.Fatalf("unexpected subnetworks: %#v", snapshot.Subnetworks)
	}
	if instance.Revision == "" || instance.EventID == "" || snapshot.Firewalls[0].EventID == "" {
		t.Fatal("stable revision and event ID were not assigned")
	}
	if _, err := Project(testScope(), snapshot); err != nil {
		t.Fatalf("captured snapshot does not project: %v", err)
	}
}

func TestCaptureFiltersRegion(t *testing.T) {
	snapshot, err := capture(context.Background(), &pagedCompute{}, "gcp/123", "example-project", "europe-west1")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Instances) != 1 || snapshot.Instances[0].Zone != "europe-west1-c" {
		t.Fatalf("instances = %#v", snapshot.Instances)
	}
	if len(snapshot.Subnetworks) != 1 || snapshot.Subnetworks[0].Region != "europe-west1" {
		t.Fatalf("subnetworks = %#v", snapshot.Subnetworks)
	}
	if len(snapshot.Firewalls) != 2 {
		t.Fatalf("global firewalls were filtered: %#v", snapshot.Firewalls)
	}
}

func TestCaptureRejectsUnreachableScopes(t *testing.T) {
	client := &pagedCompute{unreachable: []string{"zones/us-east1-d"}}
	if _, err := capture(context.Background(), client, "gcp/123", "example-project", ""); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("capture error = %v, want unreachable scope failure", err)
	}
}

func TestCaptureBoundsEachListCall(t *testing.T) {
	previous := listTimeout
	listTimeout = 10 * time.Millisecond
	t.Cleanup(func() { listTimeout = previous })
	if _, err := capture(context.Background(), stalledCompute{}, "gcp/123", "example-project", ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capture error = %v, want deadline exceeded", err)
	}
}

func TestComputeAPISendsPageRequest(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		queries = append(queries, request.URL.Path+"?"+request.URL.RawQuery)
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(map[string]any{}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	service, err := compute.NewService(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication(), option.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capture(context.Background(), NewComputeAPI(service), "gcp/123", "example-project", ""); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 3 {
		t.Fatalf("requests = %v", queries)
	}
	for _, query := range queries {
		if !strings.Contains(query, "projects/example-project/") || !strings.Contains(query, "maxResults=500") {
			t.Fatalf("request %q lacks project or page size", query)
		}
	}
}

// stalledCompute blocks every call until its context ends.
type stalledCompute struct{}

func (stalledCompute) AggregatedListInstances(ctx context.Context, _ PageRequest) (*compute.InstanceAggregatedList, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stalledCompute) ListFirewalls(ctx context.Context, _ PageRequest) (*compute.FirewallList, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stalledCompute) AggregatedListSubnetworks(ctx context.Context, _ PageRequest) (*compute.SubnetworkAggregatedList, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type pagedCompute struct {
	instanceCalls   int
	firewallCalls   int
	subnetworkCalls int
	unreachable     []string
}

func (p *pagedCompute) AggregatedListInstances(_ context.Context, request PageRequest) (*compute.InstanceAggregatedList, error) {
	p.instanceCalls++
	if request.MaxResults != pageSize || request.Project != "example-project" {
		return nil, errors.New("instance page request was not set")
	}
	if request.PageToken == "" {
		return &compute.InstanceAggregatedList{
			Items: map[string]compute.InstancesScopedList{"zones/us-east1-b": {Instances: []*compute.Instance{{
				Id: 10, Name: "web", Zone: testSelfLinkPrefix + "projects/example-project/zones/us-east1-b",
				MachineType: testSelfLinkPrefix + "projects/example-project/zones/us-east1-b/machineTypes/e2-small",
				Tags:        &compute.Tags{Items: []string{"b", "a", "b"}},
				NetworkInterfaces: []*compute.NetworkInterface{{
					Name: "nic0", Network: testSelfLinkPrefix + testNetwork, Subnetwork: testSelfLinkPrefix + testSubnetwork, NetworkIP: "10.0.0.2",
					AccessConfigs: []*compute.AccessConfig{{NatIP: "34.1.2.3"}}, AliasIpRanges: []*compute.AliasIpRange{{IpCidrRange: "10.4.0.0/24"}},
				}},
			}}}},
			NextPageToken: "next", Unreachables: p.unreachable,
		}, nil
	}
	return &compute.InstanceAggregatedList{Items: map[string]compute.InstancesScopedList{
		"zones/europe-west1-c": {Instances: []*compute.Instance{{Id: 9, Name: "db", Zone: "zones/europe-west1-c"}}},
		"zones/us-east1-c":     {},
	}}, nil
}

func (p *pagedCompute) ListFirewalls(_ context.Context, request PageRequest) (*compute.FirewallList, error) {
	p.firewallCalls++
	if request.MaxResults != pageSize {
		return nil, errors.New("firewall page size was not set")
	}
	if request.PageToken == "" {
		return &compute.FirewallList{Items: []*compute.Firewall{{
			Id: 21, Name: "allow-web", Network: testSelfLinkPrefix + testNetwork, Direction: "INGRESS", Priority: 1000,
			Allowed: []*compute.FirewallAllowed{{IPProtocol: "TCP", Ports: []string{"443", "80"}}},
		}}, NextPageToken: "next"}, nil
	}
	return &compute.FirewallList{Items: []*compute.Firewall{{
		Id: 20, Name: "deny-all", Network: testSelfLinkPrefix + testNetwork, Direction: "EGRESS", Priority: 65534,
		Denied: []*compute.FirewallDenied{{IPProtocol: "all"}},
	}}}, nil
}

func (p *pagedCompute) AggregatedListSubnetworks(_ context.Context, request PageRequest) (*compute.SubnetworkAggregatedList, error) {
	p.subnetworkCalls++
	if request.MaxResults != pageSize {
		return nil, errors.New("subnetwork page size was not set")
	}
	return &compute.SubnetworkAggregatedList{Items: map[string]compute.SubnetworksScopedList{
		"regions/us-east1": {Subnetworks: []*compute.Subnetwork{{
			Id: 31, Name: "subnet-a", Region: testSelfLinkPrefix + "projects/host-project/regions/us-east1", Network: testSelfLinkPrefix + testNetwork,
			IpCidrRange: "10.0.0.0/20", SecondaryIpRanges: []*compute.SubnetworkSecondaryRange{{RangeName: "services", IpCidrRange: "10.8.0.0/20"}, {RangeName: "pods", IpCidrRange: "10.4.0.0/14"}},
		}}},
		"regions/europe-west1": {Subnetworks: []*compute.Subnetwork{{
			Id: 30, Name: "subnet-b", Region: "regions/europe-west1", Network: testSelfLinkPrefix + testNetwork,
		}}},
	}}, nil
}
