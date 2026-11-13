package gcp

import (
	"math/rand"
	"slices"
	"strconv"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

const (
	testNetwork       = "projects/host-project/global/networks/vpc-a"
	testOtherNetwork  = "projects/host-project/global/networks/vpc-b"
	testSubnetwork    = "projects/host-project/regions/us-east1/subnetworks/subnet-a"
	testProjectNumber = "111111111111"
)

func testScope() ProjectionContext {
	return ProjectionContext{ProjectNumber: testProjectNumber, SourceID: "gcp/" + testProjectNumber}
}

func TestProjectComputeNetworkSecurity(t *testing.T) {
	instance := Instance{
		ID: "1001", Name: "web-1", Zone: "us-east1-b", MachineType: "e2-small", Status: "RUNNING", EventID: "instance-event",
		Tags: []string{"web"}, ServiceAccounts: []string{"web@example-project.iam.gserviceaccount.com"},
		NetworkInterfaces: []NetworkInterface{{
			Name: "nic0", Network: testNetwork, Subnetwork: testSubnetwork,
			Addresses: []string{"10.0.0.10", "34.1.2.3"}, AliasIPRanges: []string{"10.4.0.0/24"},
		}},
	}
	firewalls := []Firewall{
		{ID: "2001", Name: "allow-ssh", Network: testNetwork, Direction: "INGRESS", Priority: 1000, EventID: "fw-ssh",
			Allowed: []Permission{{Protocol: "tcp", Ports: []string{"22"}}}, SourceRanges: []string{"0.0.0.0/0"}},
		{ID: "2002", Name: "deny-egress-web", Network: testNetwork, Direction: "EGRESS", Priority: 100, EventID: "fw-deny",
			Denied: []Permission{{Protocol: "all"}}, DestinationRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"web"}},
		{ID: "2003", Name: "allow-sa", Network: testNetwork, Direction: "INGRESS", Priority: 900, EventID: "fw-sa",
			Allowed: []Permission{{Protocol: "tcp", Ports: []string{"8080-8090"}}}, TargetServiceAccounts: []string{"web@example-project.iam.gserviceaccount.com"}},
		{ID: "2004", Name: "other-tag", Network: testNetwork, Direction: "INGRESS", Priority: 1000, EventID: "fw-other",
			Allowed: []Permission{{Protocol: "udp"}}, TargetTags: []string{"db"}},
		{ID: "2005", Name: "other-network", Network: testOtherNetwork, Direction: "INGRESS", Priority: 1000, EventID: "fw-net",
			Allowed: []Permission{{Protocol: "tcp"}}},
		{ID: "2006", Name: "disabled", Network: testNetwork, Direction: "INGRESS", Priority: 1000, EventID: "fw-off", Disabled: true,
			Allowed: []Permission{{Protocol: "tcp"}}},
	}
	subnetwork := Subnetwork{ID: "3001", Name: "subnet-a", Region: "us-east1", Network: testNetwork, IPCIDRRange: "10.0.0.0/20", EventID: "subnet-event"}
	result, err := Project(testScope(), Snapshot{Instances: []Instance{instance}, Firewalls: firewalls, Subnetworks: []Subnetwork{subnetwork}})
	if err != nil {
		t.Fatal(err)
	}
	// instance, NIC, six firewalls, two addresses
	if len(result.Input.Resources) != 10 || len(result.Input.Facets) != 6 || len(result.Input.Relationships) != 6 {
		t.Fatalf("resources=%d facets=%d relationships=%d", len(result.Input.Resources), len(result.Input.Facets), len(result.Input.Relationships))
	}
	governed := map[string]graph.RelationshipAssertion{}
	var exposes, contains int
	for _, relationship := range result.Input.Relationships {
		switch relationship.Predicate {
		case graph.PredicateGovernedBy:
			governed[relationship.Object.ImmutableKey] = relationship
		case graph.PredicateExposes:
			exposes++
			if relationship.Object.AuthorityID != "gcp/host-project/vpc-a" {
				t.Fatalf("address authority = %q", relationship.Object.AuthorityID)
			}
		case graph.PredicateContains:
			contains++
		}
	}
	if exposes != 2 || contains != 1 {
		t.Fatalf("exposes=%d contains=%d", exposes, contains)
	}
	for id, target := range map[string]string{"2001": "all-instances", "2002": "network-tag", "2003": "service-account"} {
		relationship, found := governed["compute/global/firewall/"+id]
		if !found || relationship.Properties["gcp/target"] != target {
			t.Fatalf("firewall %s governed-by = %#v", id, relationship)
		}
	}
	if len(governed) != 3 {
		t.Fatalf("governed-by edges = %d, want 3", len(governed))
	}
	denySemantics, err := graph.DecodeSecuritySemantics(governed["compute/global/firewall/2002"].Properties)
	if err != nil {
		t.Fatal(err)
	}
	if denySemantics.Effect != "deny" || denySemantics.Direction != "egress" || denySemantics.Coverage != "partial" {
		t.Fatalf("deny edge semantics = %#v", denySemantics)
	}
	ssh := facetFor(t, result.Input, "compute/global/firewall/2001")
	sshSemantics, err := graph.DecodeSecuritySemantics(ssh.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if sshSemantics.Effect != "allow" || sshSemantics.Direction != "ingress" || len(sshSemantics.Ports) != 1 || sshSemantics.Ports[0].Port != 22 {
		t.Fatalf("ssh semantics = %#v", sshSemantics)
	}
	if ssh.Attributes["gcp/priority"] != "1000" || ssh.Attributes["gcp/source-ranges"] != `["0.0.0.0/0"]` {
		t.Fatalf("ssh facet attributes = %#v", ssh.Attributes)
	}
	rangeSemantics, err := graph.DecodeSecuritySemantics(facetFor(t, result.Input, "compute/global/firewall/2003").Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if len(rangeSemantics.Ports) != 0 || !slices.Equal(rangeSemantics.Protocols, []string{"TCP"}) {
		t.Fatalf("port range semantics = %#v", rangeSemantics)
	}
	nic := resourceByKind(t, result.Input, "gcp/compute-network-interface")
	if nic.Attributes["gcp/subnetwork-id"] != "3001" || nic.Attributes["gcp/alias-ip-ranges"] != `["10.4.0.0/24"]` {
		t.Fatalf("NIC attributes = %#v", nic.Attributes)
	}
	compileCanonical(t, result.Input)
	for _, resource := range result.Input.Resources {
		if resource.Kind == "gcp/compute-network" || resource.Kind == "gcp/compute-subnetwork" {
			t.Fatalf("invented referenced resource %q", resource.Kind)
		}
	}
	for _, facet := range result.Input.Facets {
		semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		if semantics.Class == graph.SecurityClassExposure {
			t.Fatal("firewall rule produced an exposure claim")
		}
	}
}

func TestProjectBoundsGoverningRules(t *testing.T) {
	var firewalls []Firewall
	for index := range maxGoverningRules + 5 {
		id := strconv.Itoa(5000 + index)
		firewalls = append(firewalls, Firewall{
			ID: id, Name: "rule-" + id, Network: testNetwork, Direction: "INGRESS", Priority: int64(2000 - index),
			EventID: "fw-" + id, Allowed: []Permission{{Protocol: "tcp"}},
		})
	}
	instance := Instance{ID: "1", Name: "vm", Zone: "us-east1-b", EventID: "vm", NetworkInterfaces: []NetworkInterface{{Name: "nic0", Network: testNetwork}}}
	result, err := Project(testScope(), Snapshot{Instances: []Instance{instance}, Firewalls: firewalls})
	if err != nil {
		t.Fatal(err)
	}
	var governed []string
	for _, relationship := range result.Input.Relationships {
		if relationship.Predicate == graph.PredicateGovernedBy {
			governed = append(governed, relationship.Object.ImmutableKey)
		}
	}
	if len(governed) != maxGoverningRules || slices.Contains(governed, "compute/global/firewall/5000") {
		t.Fatalf("governed-by edges = %d, lowest-precedence rule kept = %t", len(governed), slices.Contains(governed, "compute/global/firewall/5000"))
	}
	if got := resourceByKind(t, result.Input, "gcp/compute-network-interface").Attributes["gcp/omitted-firewall-rules"]; got != "5" {
		t.Fatalf("omitted firewall rules = %q", got)
	}
}

func TestProjectDeterministicUnderShuffledInput(t *testing.T) {
	instances := []Instance{
		{ID: "12", Name: "b", Zone: "us-east1-c", EventID: "b-event", Tags: []string{"z", "a"}, NetworkInterfaces: []NetworkInterface{
			{Name: "nic1", Network: testOtherNetwork, Addresses: []string{"10.1.0.2"}},
			{Name: "nic0", Network: testNetwork, Addresses: []string{"34.0.0.1", "10.0.0.2"}, AliasIPRanges: []string{"10.9.0.0/24", "10.8.0.0/24"}},
		}},
		{ID: "11", Name: "a", Zone: "us-east1-b", EventID: "a-event", NetworkInterfaces: []NetworkInterface{{Name: "nic0", Network: testNetwork}}},
	}
	firewalls := []Firewall{
		{ID: "22", Name: "b", Network: testNetwork, Direction: "INGRESS", Priority: 10, EventID: "fw-b", TargetTags: []string{"z", "y"},
			Allowed:      []Permission{{Protocol: "udp", Ports: []string{"53", "123"}}, {Protocol: "tcp", Ports: []string{"443", "22"}}},
			SourceRanges: []string{"10.1.0.0/16", "10.0.0.0/16"}},
		{ID: "21", Name: "a", Network: testNetwork, Direction: "EGRESS", Priority: 10, EventID: "fw-a", Denied: []Permission{{Protocol: "all"}}},
	}
	subnetworks := []Subnetwork{
		{ID: "32", Name: "b", Region: "us-east1", Network: testNetwork, EventID: "s-b"},
		{ID: "31", Name: "a", Region: "us-east1", Network: testNetwork, EventID: "s-a"},
	}
	want, err := Project(testScope(), Snapshot{Instances: instances, Firewalls: firewalls, Subnetworks: subnetworks})
	if err != nil {
		t.Fatal(err)
	}
	wantHash := compileCanonical(t, want.Input)
	random := rand.New(rand.NewSource(42))
	for iteration := range 50 {
		shuffledInstances := slices.Clone(instances)
		shuffledFirewalls := slices.Clone(firewalls)
		shuffledSubnetworks := slices.Clone(subnetworks)
		random.Shuffle(len(shuffledInstances), func(i, j int) {
			shuffledInstances[i], shuffledInstances[j] = shuffledInstances[j], shuffledInstances[i]
		})
		random.Shuffle(len(shuffledFirewalls), func(i, j int) {
			shuffledFirewalls[i], shuffledFirewalls[j] = shuffledFirewalls[j], shuffledFirewalls[i]
		})
		random.Shuffle(len(shuffledSubnetworks), func(i, j int) {
			shuffledSubnetworks[i], shuffledSubnetworks[j] = shuffledSubnetworks[j], shuffledSubnetworks[i]
		})
		for index := range shuffledInstances {
			instance := &shuffledInstances[index]
			instance.Tags = reversed(instance.Tags)
			instance.NetworkInterfaces = slices.Clone(instance.NetworkInterfaces)
			slices.Reverse(instance.NetworkInterfaces)
			for nicIndex := range instance.NetworkInterfaces {
				nic := &instance.NetworkInterfaces[nicIndex]
				nic.Addresses = reversed(nic.Addresses)
				nic.AliasIPRanges = reversed(nic.AliasIPRanges)
			}
		}
		for index := range shuffledFirewalls {
			firewall := &shuffledFirewalls[index]
			firewall.Allowed = slices.Clone(firewall.Allowed)
			slices.Reverse(firewall.Allowed)
			for permissionIndex := range firewall.Allowed {
				firewall.Allowed[permissionIndex].Ports = reversed(firewall.Allowed[permissionIndex].Ports)
			}
			firewall.SourceRanges = reversed(firewall.SourceRanges)
			firewall.TargetTags = reversed(firewall.TargetTags)
		}
		got, projectErr := Project(testScope(), Snapshot{Instances: shuffledInstances, Firewalls: shuffledFirewalls, Subnetworks: shuffledSubnetworks})
		if projectErr != nil {
			t.Fatal(projectErr)
		}
		if gotHash := compileCanonical(t, got.Input); gotHash != wantHash {
			t.Fatalf("shuffle %d hash = %s, want %s", iteration, gotHash, wantHash)
		}
	}
}

func TestProjectRejectsIncompleteIdentity(t *testing.T) {
	for name, snapshot := range map[string]Snapshot{
		"instance without numeric ID": {Instances: []Instance{{ID: "web", Name: "web", Zone: "us-east1-b", EventID: "event"}}},
		"instance without zone":       {Instances: []Instance{{ID: "1", Name: "web", EventID: "event"}}},
		"network interface without network": {Instances: []Instance{{ID: "1", Name: "web", Zone: "us-east1-b", EventID: "event",
			NetworkInterfaces: []NetworkInterface{{Name: "nic0"}}}}},
		"firewall without numeric ID": {Firewalls: []Firewall{{ID: "allow", Name: "allow", Network: testNetwork, Direction: "INGRESS", EventID: "event",
			Allowed: []Permission{{Protocol: "tcp"}}}}},
		"firewall with both actions": {Firewalls: []Firewall{{ID: "1", Name: "both", Network: testNetwork, Direction: "INGRESS", EventID: "event",
			Allowed: []Permission{{Protocol: "tcp"}}, Denied: []Permission{{Protocol: "udp"}}}}},
	} {
		if _, err := Project(testScope(), snapshot); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, err := Project(ProjectionContext{ProjectNumber: "my-project", SourceID: "source"}, Snapshot{}); err == nil {
		t.Fatal("non-numeric project number was accepted")
	}
}

func TestGCPIdentitySchemeRejectsInvalidAuthority(t *testing.T) {
	registry := graph.NewRegistry()
	if err := registry.Register(IdentitySchemeDefinition()); err != nil {
		t.Fatal(err)
	}
	_, err := graph.NewCompiler(registry).Compile(graph.Input{Resources: []graph.ResourceAssertion{{
		Claim: graph.IdentityClaim{Scheme: resourceScheme, AuthorityID: "my-project", ImmutableKey: "compute/global/firewall/1"},
		Kind:  "gcp/compute-firewall", PluginID: "test", SourceID: "test", RuleID: "test", EvidenceIDs: []string{"event"},
	}}})
	if err == nil {
		t.Fatal("GCP identity scheme accepted a project ID authority")
	}
	normalize := IdentitySchemeDefinition().Normalize
	normalized, err := normalize(graph.IdentityClaim{
		Scheme: resourceScheme, AuthorityID: " 111111111111 ", ImmutableKey: " Compute/US-EAST1-B /Instance/Web-1/Network-Interface/NIC0 ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.ImmutableKey != "compute/us-east1-b/instance/web-1/network-interface/nic0" {
		t.Fatalf("normalized key = %q", normalized.ImmutableKey)
	}
	for _, key := range []string{
		"storage/global/bucket/example",
		"compute/global/firewall/allow-ssh",
		"compute/global/instance/web",
		"compute/us-east1-b/instance/web/network-interface/eth0",
		"compute/us-east1-b/instance",
	} {
		if _, err := normalize(graph.IdentityClaim{Scheme: resourceScheme, AuthorityID: testProjectNumber, ImmutableKey: key}); err == nil {
			t.Fatalf("GCP identity scheme accepted %q", key)
		}
	}
}

func TestInstanceClaimFromKubernetesProviderID(t *testing.T) {
	plugin := &Plugin{config: Config{ProjectID: "example-project", ProjectNumber: testProjectNumber, Region: "us-east1", SourceID: "gcp/111111111111/us-east1"}}
	claim, matched, err := plugin.ResolveIdentityReference("gce://example-project/us-east1-b/gke-pool-1-abcd")
	if err != nil || !matched || claim.AuthorityID != testProjectNumber || claim.ImmutableKey != "compute/us-east1-b/instance/gke-pool-1-abcd" {
		t.Fatalf("claim = %#v, matched = %t, err = %v", claim, matched, err)
	}
	for _, reference := range []string{
		"aws:///us-east-1a/i-123",
		"gce://other-project/us-east1-b/vm",
		"gce://example-project/europe-west1-b/vm",
		"gce://example-project/us-east1-b",
		"gce://example-project/us-east1-b/vm/extra",
		"gce://example-project/us-east1-b/VM_1",
	} {
		if _, matched, err := plugin.ResolveIdentityReference(reference); err != nil || matched {
			t.Fatalf("%s matched: %t, err = %v", reference, matched, err)
		}
	}
}

func compileCanonical(t *testing.T, input graph.Input) string {
	t.Helper()
	registry := graph.NewRegistry()
	if err := registry.Register(Descriptor().IdentitySchemes[0]); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := snapshot.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func resourceByKind(t *testing.T, input graph.Input, kind string) graph.ResourceAssertion {
	t.Helper()
	for _, resource := range input.Resources {
		if resource.Kind == kind {
			return resource
		}
	}
	t.Fatalf("resource kind %q not found", kind)
	return graph.ResourceAssertion{}
}

func facetFor(t *testing.T, input graph.Input, key string) graph.FacetAssertion {
	t.Helper()
	for _, facet := range input.Facets {
		if facet.Resource.ImmutableKey == key {
			return facet
		}
	}
	t.Fatalf("facet for %q not found", key)
	return graph.FacetAssertion{}
}

func reversed(values []string) []string {
	result := slices.Clone(values)
	slices.Reverse(result)
	return result
}
