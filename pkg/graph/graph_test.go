package graph

import (
	"slices"
	"testing"
)

var testIdentityScheme = IdentityScheme{Group: "test.agentshield.io", Version: "v1", Kind: "Resource"}

func TestCompileIsOrderAndDuplicateIndependent(t *testing.T) {
	compiler := testCompiler(t)
	a := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "a"}
	b := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "b"}
	resourceA := assertion(a, "machine", "event-a")
	resourceB := assertion(b, "machine", "event-b")
	relation := RelationshipAssertion{
		Subject: a, Predicate: PredicateContains, Object: b,
		PluginID: "test", SourceID: "fixture", RuleID: "test.contains",
		EvidenceIDs: []string{"event-b", "event-a"},
	}
	facet := FacetAssertion{
		Resource: a, Kind: "coverage", Key: "network", Attributes: map[string]string{"level": "l4"},
		PluginID: "test", SourceID: "fixture", RuleID: "test.coverage",
		EvidenceIDs: []string{"event-a"},
	}
	telemetry := TelemetryAssertion{
		EventID: "probe-a-b", Kind: "active-probe", Subject: a, Object: b, Operation: "GET /", Outcome: "allowed", Coverage: "l4", Count: 2,
		PluginID: "test", SourceID: "fixture", RuleID: "test.probe", EvidenceIDs: []string{"probe-a-b"},
	}
	first, err := compiler.Compile(Input{
		Resources:     []ResourceAssertion{resourceA, resourceB, resourceA},
		Facets:        []FacetAssertion{facet, facet},
		Relationships: []RelationshipAssertion{relation, relation},
		Telemetry:     []TelemetryAssertion{telemetry, telemetry},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := compiler.Compile(Input{
		Resources:     []ResourceAssertion{resourceB, resourceA},
		Facets:        []FacetAssertion{facet},
		Relationships: []RelationshipAssertion{relation},
		Telemetry:     []TelemetryAssertion{telemetry},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := first.CanonicalJSON()
	secondJSON, _ := second.CanonicalJSON()
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("canonical snapshots differ\n%s\n%s", firstJSON, secondJSON)
	}
	if len(first.Facets) != 1 {
		t.Fatalf("got %d facets, want 1", len(first.Facets))
	}
	if len(first.Telemetry) != 1 {
		t.Fatalf("got %d telemetry events, want 1", len(first.Telemetry))
	}
}

func TestCompileOmitsTelemetryUntilCrossContributionEndpointsAreObserved(t *testing.T) {
	compiler := testCompiler(t)
	subject := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "subject"}
	object := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "object"}
	input := Input{Telemetry: []TelemetryAssertion{{
		EventID: "probe", Kind: "active-probe", Subject: subject, Object: object,
		Operation: "GET /", Outcome: "allowed", Coverage: "l7", Count: 1,
		PluginID: "test", SourceID: "fixture", RuleID: "test.probe",
	}}}
	composed, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(composed.Telemetry) != 0 {
		t.Fatalf("telemetry events = %d, want 0", len(composed.Telemetry))
	}
	snapshot, err := compiler.CompileContribution(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Telemetry) != 1 {
		t.Fatalf("telemetry events = %d, want 1", len(snapshot.Telemetry))
	}
}

func TestIdentitySchemesDoNotSilentlyMerge(t *testing.T) {
	registry := NewRegistry()
	awsScheme := IdentityScheme{Group: "aws.amazon.com", Version: "v1", Kind: "Resource"}
	configuredHostScheme := IdentityScheme{Group: "agentshield.io", Version: "v1", Kind: "ConfiguredHost"}
	for _, scheme := range []IdentityScheme{awsScheme, configuredHostScheme} {
		if err := registry.Register(TrimmedIdentityScheme(scheme)); err != nil {
			t.Fatal(err)
		}
	}
	compiler := NewCompiler(registry)
	input := Input{Resources: []ResourceAssertion{
		assertion(IdentityClaim{Scheme: awsScheme, AuthorityID: "account", ImmutableKey: "server-1"}, "machine", "aws"),
		assertion(IdentityClaim{Scheme: configuredHostScheme, AuthorityID: "basement", ImmutableKey: "server-1"}, "machine", "local"),
	}}
	snapshot, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 2 || snapshot.Resources[0].ID == snapshot.Resources[1].ID {
		t.Fatalf("cross-scheme claims merged: %#v", snapshot.Resources)
	}
}

func TestAddingHubEdgePreservesExistingRelationshipIDs(t *testing.T) {
	compiler := testCompiler(t)
	service := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "service"}
	firstNode := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "node-1"}
	secondNode := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "node-2"}
	base := Input{
		Resources:     []ResourceAssertion{assertion(service, "service", "service"), assertion(firstNode, "machine", "node-1")},
		Relationships: []RelationshipAssertion{relationship(service, firstNode)},
	}
	before, err := compiler.Compile(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Resources = append(base.Resources, assertion(secondNode, "machine", "node-2"))
	base.Relationships = append(base.Relationships, relationship(service, secondNode))
	after, err := compiler.Compile(base)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(after.Relationships, func(item Relationship) bool { return item.ID == before.Relationships[0].ID }) {
		t.Fatal("adding a hub edge rewrote an existing relationship ID")
	}
}

func TestCompileRetainsUnresolvedReferencesAndResolvesThemLater(t *testing.T) {
	compiler := testCompiler(t)
	service := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "service"}
	policy := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "policy"}
	input := Input{
		Facets: []FacetAssertion{{
			Resource: service, Kind: "protection", Key: "mesh", PluginID: "test", SourceID: "fixture",
			RuleID: "test.protection",
		}},
		Relationships: []RelationshipAssertion{{
			Subject: policy, Predicate: PredicateGovernedBy, Object: service,
			PluginID: "test", SourceID: "fixture", RuleID: "test.governs",
		}},
	}
	unresolved, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(unresolved.Facets) != 1 || unresolved.Facets[0].ResolutionStatus != ResolutionUnresolved {
		t.Fatalf("unresolved facet = %#v", unresolved.Facets)
	}
	if len(unresolved.Relationships) != 1 || unresolved.Relationships[0].ResolutionStatus != ResolutionUnresolved {
		t.Fatalf("unresolved relationship = %#v", unresolved.Relationships)
	}

	input.Resources = []ResourceAssertion{assertion(service, "service", "service"), assertion(policy, "policy", "policy")}
	resolved, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Facets[0].ResolutionStatus != ResolutionResolved || resolved.Relationships[0].ResolutionStatus != ResolutionResolved {
		t.Fatalf("late materialization did not resolve references: facets=%#v relationships=%#v", resolved.Facets, resolved.Relationships)
	}
}

func TestCompileQuarantinesConflictingResourceKinds(t *testing.T) {
	compiler := testCompiler(t)
	claim := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "shared"}
	first := assertion(claim, "machine", "machine")
	second := assertion(claim, "service", "service")
	snapshot, err := compiler.Compile(Input{Resources: []ResourceAssertion{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 0 || len(snapshot.Conflicts) != 1 {
		t.Fatalf("conflict was not quarantined: resources=%#v conflicts=%#v", snapshot.Resources, snapshot.Conflicts)
	}
	if !slices.Equal(snapshot.Conflicts[0].Kinds, []string{"machine", "service"}) {
		t.Fatalf("conflict kinds = %v", snapshot.Conflicts[0].Kinds)
	}
	reversed, err := compiler.Compile(Input{Resources: []ResourceAssertion{second, first}})
	if err != nil {
		t.Fatal(err)
	}
	left, _ := snapshot.CanonicalJSON()
	right, _ := reversed.CanonicalJSON()
	if string(left) != string(right) {
		t.Fatalf("conflict output depends on input order\n%s\n%s", left, right)
	}
}

func testCompiler(t *testing.T) *Compiler {
	t.Helper()
	registry := NewRegistry()
	if err := registry.Register(TrimmedIdentityScheme(testIdentityScheme)); err != nil {
		t.Fatal(err)
	}
	return NewCompiler(registry)
}

func assertion(claim IdentityClaim, kind, eventID string) ResourceAssertion {
	return ResourceAssertion{
		Claim: claim, Kind: kind, DisplayName: claim.ImmutableKey,
		PluginID: "test", SourceID: "fixture", RuleID: "test.resource",
		EvidenceIDs: []string{eventID},
	}
}

func relationship(subject, object IdentityClaim) RelationshipAssertion {
	return RelationshipAssertion{
		Subject: subject, Predicate: PredicateExposes, Object: object,
		PluginID: "test", SourceID: "fixture", RuleID: "test.exposes",
		EvidenceIDs: []string{subject.ImmutableKey, object.ImmutableKey},
	}
}

func TestCompileRejectsUnregisteredPredicate(t *testing.T) {
	claim := IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "lab", ImmutableKey: "resource"}
	_, err := testCompiler(t).Compile(Input{Relationships: []RelationshipAssertion{{
		Subject: claim, Predicate: Predicate("plugin-specific"), Object: claim,
		PluginID: "test", SourceID: "fixture", RuleID: "test.edge",
	}}})
	if err == nil {
		t.Fatal("unregistered predicate succeeded")
	}
}
