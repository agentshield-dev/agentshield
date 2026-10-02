package aws

import (
	"math/rand"
	"slices"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func TestProjectEC2NetworkSecurity(t *testing.T) {
	port22 := int32(22)
	port80 := int32(80)
	port90 := int32(90)
	group := SecurityGroup{
		ID: "sg-123", OwnerID: "222222222222", VPCID: "vpc-1", Name: "web", EventID: "sg-event",
		Ingress: []Rule{
			{Protocol: "all", IPv4Ranges: []string{"0.0.0.0/0"}},
			{Protocol: "icmp", FromPort: int32Pointer(-1), ToPort: int32Pointer(-1), IPv6Ranges: []string{"::/0"}},
			{Protocol: "tcp", FromPort: &port22, ToPort: &port22, SecurityGroupIDs: []string{"333333333333/sg-peer"}},
			{Protocol: "tcp", FromPort: &port80, ToPort: &port90, PrefixListIDs: []string{"pl-1"}},
		},
	}
	item := NetworkInterface{
		ID: "eni-123", OwnerID: "111111111111", VPCID: "vpc-1", SubnetID: "subnet-1", EventID: "eni-event",
		AttachmentInstanceID: "i-123", SecurityGroupIDs: []string{"sg-123", "sg-unresolved"}, Addresses: []string{"10.0.0.10"},
	}
	instance := Instance{ID: "i-123", OwnerID: "111111111111", VPCID: "vpc-1", EventID: "instance-event"}
	result, err := Project(ProjectionContext{Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1"}, Snapshot{
		NetworkInterfaces: []NetworkInterface{item}, Instances: []Instance{instance}, SecurityGroups: []SecurityGroup{group},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Input.Resources) != 4 || len(result.Input.Facets) != 2 || len(result.Input.Relationships) != 2 {
		t.Fatalf("resources=%d facets=%d relationships=%d", len(result.Input.Resources), len(result.Input.Facets), len(result.Input.Relationships))
	}
	var governed, exposes bool
	for _, relationship := range result.Input.Relationships {
		governed = governed || relationship.Predicate == graph.PredicateGovernedBy && relationship.Object.AuthorityID == group.OwnerID
		exposes = exposes || relationship.Predicate == graph.PredicateExposes && relationship.Object.ImmutableKey == "ip/10.0.0.10"
	}
	if !governed || !exposes {
		t.Fatalf("missing EC2 topology relationships: %#v", result.Input.Relationships)
	}
	interfaceResource := resourceByKind(t, result.Input, "aws/ec2-network-interface")
	if interfaceResource.Attributes["aws/unresolved-security-group-ids"] != `["sg-unresolved"]` {
		t.Fatalf("unresolved groups = %q", interfaceResource.Attributes["aws/unresolved-security-group-ids"])
	}
	ingress := facetByKey(t, result.Input, "ingress")
	ingressSemantics, err := graph.DecodeSecuritySemantics(ingress.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if ingressSemantics.Effect != "allow" || ingressSemantics.Coverage != "partial" || len(ingressSemantics.Ports) != 1 || ingressSemantics.Ports[0].Port != 22 {
		t.Fatalf("unexpected ingress semantics: %#v", ingressSemantics)
	}
	egress := facetByKey(t, result.Input, "egress")
	egressSemantics, err := graph.DecodeSecuritySemantics(egress.Attributes)
	if err != nil {
		t.Fatal(err)
	}
	if egressSemantics.Effect != "restrict" || egress.Attributes["aws/rules"] != "[]" {
		t.Fatalf("unexpected empty egress posture: %#v", egress)
	}
	registry := graph.NewRegistry()
	if err := discoveryRegister(registry); err != nil {
		t.Fatal(err)
	}
	if _, err := graph.NewCompiler(registry).Compile(result.Input); err != nil {
		t.Fatal(err)
	}
	for _, resource := range result.Input.Resources {
		if resource.Kind == "aws/vpc" || resource.Kind == "aws/subnet" {
			t.Fatalf("invented referenced resource %q", resource.Kind)
		}
	}
	for _, facet := range result.Input.Facets {
		semantics, err := graph.DecodeSecuritySemantics(facet.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		if semantics.Class == graph.SecurityClassExposure {
			t.Fatal("security group rule produced an exposure claim")
		}
	}
}

func TestProjectDeterministicUnderShuffledInput(t *testing.T) {
	port := int32(443)
	groups := []SecurityGroup{
		{ID: "sg-b", OwnerID: "111111111111", EventID: "sg-b-event", Ingress: []Rule{
			{Protocol: "tcp", FromPort: &port, ToPort: &port, IPv4Ranges: []string{"10.1.0.0/16", "10.0.0.0/16"}},
			{Protocol: "udp", PrefixListIDs: []string{"pl-b", "pl-a"}, SecurityGroupIDs: []string{"sg-z", "sg-y"}},
		}},
		{ID: "sg-a", OwnerID: "111111111111", EventID: "sg-a-event"},
	}
	interfaces := []NetworkInterface{
		{ID: "eni-b", OwnerID: "111111111111", EventID: "eni-b-event", SecurityGroupIDs: []string{"sg-b"}},
		{ID: "eni-a", OwnerID: "111111111111", EventID: "eni-a-event", SecurityGroupIDs: []string{"sg-a"}},
	}
	scope := ProjectionContext{Partition: "aws", Region: "us-west-2", SourceID: "source"}
	want, err := Project(scope, Snapshot{NetworkInterfaces: interfaces, SecurityGroups: groups})
	if err != nil {
		t.Fatal(err)
	}
	wantHash := compileHash(t, want.Input)
	random := rand.New(rand.NewSource(42))
	for iteration := 0; iteration < 50; iteration++ {
		shuffledInterfaces := slices.Clone(interfaces)
		shuffledGroups := slices.Clone(groups)
		random.Shuffle(len(shuffledInterfaces), func(i, j int) {
			shuffledInterfaces[i], shuffledInterfaces[j] = shuffledInterfaces[j], shuffledInterfaces[i]
		})
		random.Shuffle(len(shuffledGroups), func(i, j int) { shuffledGroups[i], shuffledGroups[j] = shuffledGroups[j], shuffledGroups[i] })
		for index := range shuffledGroups {
			shuffledGroups[index].Ingress = slices.Clone(shuffledGroups[index].Ingress)
			slices.Reverse(shuffledGroups[index].Ingress)
			for ruleIndex := range shuffledGroups[index].Ingress {
				rule := &shuffledGroups[index].Ingress[ruleIndex]
				rule.IPv4Ranges = reversed(rule.IPv4Ranges)
				rule.IPv6Ranges = reversed(rule.IPv6Ranges)
				rule.PrefixListIDs = reversed(rule.PrefixListIDs)
				rule.SecurityGroupIDs = reversed(rule.SecurityGroupIDs)
			}
		}
		got, projectErr := Project(scope, Snapshot{NetworkInterfaces: shuffledInterfaces, SecurityGroups: shuffledGroups})
		if projectErr != nil {
			t.Fatal(projectErr)
		}
		if gotHash := compileHash(t, got.Input); gotHash != wantHash {
			t.Fatalf("shuffle %d hash = %s, want %s", iteration, gotHash, wantHash)
		}
	}
}

func TestProjectRejectsIncompleteIdentity(t *testing.T) {
	_, err := Project(ProjectionContext{Partition: "aws", Region: "us-east-1", SourceID: "source"}, Snapshot{
		SecurityGroups: []SecurityGroup{{ID: "sg-1", OwnerID: "not-an-account", EventID: "event"}},
	})
	if err == nil {
		t.Fatal("invalid AWS owner account was accepted")
	}
}

func TestAWSIdentitySchemeRejectsInvalidAuthority(t *testing.T) {
	registry := graph.NewRegistry()
	if err := registry.Register(IdentitySchemeDefinition()); err != nil {
		t.Fatal(err)
	}
	_, err := graph.NewCompiler(registry).Compile(graph.Input{Resources: []graph.ResourceAssertion{{
		Claim: graph.IdentityClaim{Scheme: resourceScheme, AuthorityID: "caller", ImmutableKey: "aws/ec2/us-east-1/security-group/sg-1"},
		Kind:  "aws/ec2-security-group", PluginID: "test", SourceID: "test", RuleID: "test", EvidenceIDs: []string{"event"},
	}}})
	if err == nil {
		t.Fatal("AWS identity scheme accepted a non-account authority")
	}
	normalize := IdentitySchemeDefinition().Normalize
	normalized, err := normalize(graph.IdentityClaim{
		Scheme: resourceScheme, AuthorityID: " 111111111111 ", ImmutableKey: " AWS/ EC2 /US-EAST-1/Security-Group/SG-1 ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.ImmutableKey != "aws/ec2/us-east-1/security-group/sg-1" {
		t.Fatalf("normalized key = %q", normalized.ImmutableKey)
	}
	if _, err := normalize(graph.IdentityClaim{
		Scheme: resourceScheme, AuthorityID: "111111111111", ImmutableKey: "aws/s3/us-east-1/bucket/example",
	}); err == nil {
		t.Fatal("AWS identity scheme accepted a non-EC2 key")
	}
}

func TestInstanceClaimFromKubernetesProviderID(t *testing.T) {
	plugin := &Plugin{config: Config{Partition: "aws", Region: "us-east-1", SourceID: "aws/aws/111111111111/us-east-1"}}
	claim, matched, err := plugin.ResolveIdentityReference("aws:///us-east-1a/i-123")
	if err != nil || !matched || claim.ImmutableKey != "aws/ec2/us-east-1/instance/i-123" {
		t.Fatalf("claim = %#v, matched = %t, err = %v", claim, matched, err)
	}
	for _, reference := range []string{
		"gce://project/zone/instance",
		"aws:///eu-west-1a/i-123",
		"aws:///us-east-1a/a1b2c3-d4e5/fargate-ip-10-0-0-1.ec2.internal",
		"aws:///us-east-1a",
		"aws:///us-east-1a/eni-123",
	} {
		if _, matched, err := plugin.ResolveIdentityReference(reference); err != nil || matched {
			t.Fatalf("%s matched: %t, err = %v", reference, matched, err)
		}
	}
}

func discoveryRegister(registry *graph.Registry) error {
	return registry.Register(Descriptor().IdentitySchemes[0])
}

func compileHash(t *testing.T, input graph.Input) string {
	t.Helper()
	registry := graph.NewRegistry()
	if err := discoveryRegister(registry); err != nil {
		t.Fatal(err)
	}
	snapshot, err := graph.NewCompiler(registry).Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := snapshot.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
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

func facetByKey(t *testing.T, input graph.Input, key string) graph.FacetAssertion {
	t.Helper()
	for _, facet := range input.Facets {
		if facet.Key == key {
			return facet
		}
	}
	t.Fatalf("facet key %q not found", key)
	return graph.FacetAssertion{}
}

func int32Pointer(value int32) *int32 { return &value }

func reversed(values []string) []string {
	result := slices.Clone(values)
	slices.Reverse(result)
	return result
}
