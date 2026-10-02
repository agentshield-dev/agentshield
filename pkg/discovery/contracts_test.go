package discovery

import (
	"context"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

type descriptorPlugin struct {
	descriptor Descriptor
	sourceID   string
}

func (plugin descriptorPlugin) Descriptor() Descriptor      { return plugin.descriptor }
func (plugin descriptorPlugin) SourceID() string            { return plugin.sourceID }
func (descriptorPlugin) Run(context.Context, Runtime) error { return nil }

func TestRegisterIdentitySchemesSupportsZeroOrMoreDefinitions(t *testing.T) {
	firstScheme := graph.IdentityScheme{Group: "first.example.io", Version: "v1", Kind: "Resource"}
	secondScheme := graph.IdentityScheme{Group: "second.example.io", Version: "v1beta1", Kind: "Asset"}
	registry := graph.NewRegistry()
	if err := RegisterIdentitySchemes(registry,
		Descriptor{ID: "consumer"},
		Descriptor{ID: "provider", IdentitySchemes: []graph.SchemeDefinition{
			graph.TrimmedIdentityScheme(firstScheme),
			graph.TrimmedIdentityScheme(secondScheme),
		}},
	); err != nil {
		t.Fatal(err)
	}
	_, err := graph.NewCompiler(registry).Compile(graph.Input{Resources: []graph.ResourceAssertion{
		{Claim: graph.IdentityClaim{Scheme: firstScheme, AuthorityID: "first", ImmutableKey: "resource"}, Kind: "test/resource", PluginID: "consumer", SourceID: "test", RuleID: "test.first"},
		{Claim: graph.IdentityClaim{Scheme: secondScheme, AuthorityID: "second", ImmutableKey: "asset"}, Kind: "test/asset", PluginID: "consumer", SourceID: "test", RuleID: "test.second"},
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRegisterIdentitySchemesRejectsDuplicateKeys(t *testing.T) {
	scheme := graph.IdentityScheme{Group: "duplicate.example.io", Version: "v1", Kind: "Resource"}
	err := RegisterIdentitySchemes(graph.NewRegistry(),
		Descriptor{ID: "first", IdentitySchemes: []graph.SchemeDefinition{graph.TrimmedIdentityScheme(scheme)}},
		Descriptor{ID: "second", IdentitySchemes: []graph.SchemeDefinition{graph.TrimmedIdentityScheme(scheme)}},
	)
	if err == nil {
		t.Fatal("duplicate identity scheme registration succeeded")
	}
}

func TestIdentityReferenceResolversRejectConflictingClaims(t *testing.T) {
	first := graph.IdentityClaim{Scheme: graph.IdentityScheme{Group: "first.example.io", Version: "v1", Kind: "Resource"}, AuthorityID: "first", ImmutableKey: "resource"}
	second := graph.IdentityClaim{Scheme: graph.IdentityScheme{Group: "second.example.io", Version: "v1", Kind: "Resource"}, AuthorityID: "second", ImmutableKey: "resource"}
	plugins := []Plugin{
		descriptorPlugin{sourceID: "plain", descriptor: Descriptor{ID: "plain", Version: "1"}},
		referenceResolverPlugin{descriptorPlugin: descriptorPlugin{sourceID: "first", descriptor: Descriptor{ID: "first", Version: "1"}}, claim: first},
	}
	resolvers := IdentityReferenceResolvers(plugins...)
	resolved, found, err := ResolveIdentityReference("provider://resource", resolvers...)
	if err != nil || !found || resolved != first {
		t.Fatalf("resolved = %#v, found = %t, err = %v", resolved, found, err)
	}
	resolvers = append(resolvers, referenceResolverPlugin{claim: second})
	if _, _, err := ResolveIdentityReference("provider://resource", resolvers...); err == nil {
		t.Fatal("conflicting provider claims were accepted")
	}
}

func TestManagerRejectsConsumedCollectionWithoutPublisher(t *testing.T) {
	_, err := NewManager(&RuntimeService{}, descriptorPlugin{sourceID: "source", descriptor: Descriptor{
		ID: "consumer", Version: "1.0.0", Consumes: []string{"kubernetes/resources/example.io/v1/foos"},
	}})
	if err == nil {
		t.Fatal("manager accepted a consumed collection with no publisher")
	}
}

func TestManagerKeysPluginsAndCollectionsBySource(t *testing.T) {
	first := descriptorPlugin{sourceID: "one", descriptor: Descriptor{ID: "same", Version: "1", Publishes: []string{"objects"}}}
	second := descriptorPlugin{sourceID: "two", descriptor: Descriptor{ID: "same", Version: "1", Publishes: []string{"objects"}}}
	if _, err := NewManager(&RuntimeService{}, first, second); err != nil {
		t.Fatalf("distinct source instances rejected: %v", err)
	}
	if _, err := NewManager(&RuntimeService{}, first, first); err == nil {
		t.Fatal("same plugin and source instance was accepted twice")
	}
	conflictingPublisher := descriptorPlugin{sourceID: "one", descriptor: Descriptor{ID: "other", Version: "1", Publishes: []string{"objects"}}}
	if _, err := NewManager(&RuntimeService{}, first, conflictingPublisher); err == nil {
		t.Fatal("same-source collection publisher conflict was accepted")
	}
	consumer := descriptorPlugin{sourceID: "two", descriptor: Descriptor{ID: "consumer", Version: "1", Consumes: []string{"objects"}}}
	if _, err := NewManager(&RuntimeService{}, first, consumer); err == nil {
		t.Fatal("consumer accepted a publisher from a different source")
	}
}

func TestScopedRuntimeRejectsSpoofedProvenance(t *testing.T) {
	runtime := scopedRuntime{runtime: &RuntimeService{hub: NewHub()}, pluginID: "plugin", sourceID: "source"}
	if err := runtime.Publish(context.Background(), Change{PluginID: "other", SourceID: "source"}); err == nil {
		t.Fatal("scoped runtime accepted spoofed publish provenance")
	}
	if err := runtime.MarkReady(context.Background(), "plugin", "other", "objects", 1); err == nil {
		t.Fatal("scoped runtime accepted spoofed readiness provenance")
	}
	if err := runtime.ReplaceContribution(context.Background(), "other", "source", ContributionOutput{}); err == nil {
		t.Fatal("scoped runtime accepted spoofed contribution provenance")
	}
	if _, err := runtime.ContributionGeneration(context.Background(), "plugin", "other"); err == nil {
		t.Fatal("scoped runtime accepted spoofed generation provenance")
	}
}

func TestManagerAttestsOverlappingRemediationProvidersFromPluginRegistration(t *testing.T) {
	scheme := graph.IdentityScheme{Group: "example.io", Version: "v1", Kind: "Object"}
	action := remediation.Action{ID: "network-policy/v1", Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetKind: "kubernetes/pod", Scheme: scheme, AuthorityID: "authority", Mode: remediation.ModeExecutable}
	first := remediationPlugin{descriptorPlugin: descriptorPlugin{sourceID: "source", descriptor: Descriptor{ID: "first", Version: "1"}}, action: action}
	second := remediationPlugin{descriptorPlugin: descriptorPlugin{sourceID: "source", descriptor: Descriptor{ID: "second", Version: "1"}}, action: action}
	manager, err := NewManager(&RuntimeService{}, first, second)
	if err != nil {
		t.Fatalf("manager rejected overlapping remediation providers: %v", err)
	}
	proposal, err := remediation.NewProposal("finding", "analysis", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		remediation.Suggestion{Intent: remediation.IntentNetworkDeclareIngressIsolation, TargetEntityIDs: []string{"target"}, SupportingIDs: []string{"evidence"}},
		remediation.Target{EntityID: "target", Kind: "kubernetes/pod", Identity: graph.IdentityClaim{Scheme: scheme, AuthorityID: "authority", ImmutableKey: "object/uid"}}, []string{"evidence"})
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := manager.Remediations().Candidates(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].ProviderID != "first" || candidates[0].SourceID != "source" || candidates[1].ProviderID != "second" || candidates[1].SourceID != "source" {
		t.Fatalf("host-attested candidates = %#v", candidates)
	}
}

type remediationPlugin struct {
	descriptorPlugin
	action remediation.Action
}

type referenceResolverPlugin struct {
	descriptorPlugin
	claim graph.IdentityClaim
}

func (plugin referenceResolverPlugin) ResolveIdentityReference(string) (graph.IdentityClaim, bool, error) {
	return plugin.claim, true, nil
}

func (plugin remediationPlugin) RemediationDescriptor() remediation.Descriptor {
	return remediation.Descriptor{Actions: []remediation.Action{plugin.action}}
}

func (plugin remediationPlugin) Plan(_ context.Context, proposal remediation.Proposal, actionID string) (remediation.Plan, error) {
	return remediation.NewPlan(proposal, plugin.descriptor.ID, plugin.sourceID, actionID, "desired")
}

func (remediationPlugin) Prepare(_ context.Context, _ remediation.Proposal, plan remediation.Plan) (remediation.Preparation, error) {
	return remediation.NewPreparation(plan, true, nil)
}

func (remediationPlugin) Execute(_ context.Context, _ remediation.Proposal, plan remediation.Plan, preparation remediation.Preparation) (remediation.ExecutionResult, error) {
	return remediation.NewExecutionResult(plan, preparation, true, nil)
}

func (plugin remediationPlugin) Verify(_ context.Context, _ remediation.Proposal, plan remediation.Plan, result remediation.ExecutionResult) (remediation.Verification, error) {
	return remediation.Verification{PlanID: plan.ID, ProviderID: plugin.descriptor.ID, SourceID: plugin.sourceID, ActionID: plan.ActionID, ExecutionResultID: result.ID}, nil
}
