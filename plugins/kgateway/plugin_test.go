package kgateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type fakeRuntime struct {
	objects    map[string]chan discovery.Change
	coverage   chan discovery.Change
	outputs    chan discovery.ContributionOutput
	generation uint64
}

func newFakeRuntime() *fakeRuntime {
	runtime := &fakeRuntime{
		objects: make(map[string]chan discovery.Change), coverage: make(chan discovery.Change, 64),
		outputs: make(chan discovery.ContributionOutput, 32), generation: 11,
	}
	for _, requirement := range resourceRequirements {
		runtime.objects[requirement.Collection()] = make(chan discovery.Change, 32)
	}
	return runtime
}

func (runtime *fakeRuntime) Publish(context.Context, discovery.Change) error { return nil }
func (runtime *fakeRuntime) MarkReady(context.Context, string, string, string, uint64) error {
	return nil
}
func (runtime *fakeRuntime) Subscribe(_ context.Context, collection string) (<-chan discovery.Change, error) {
	if changes := runtime.objects[collection]; changes != nil {
		return changes, nil
	}
	if collection == kubernetesplugin.CollectionResourceCoverage {
		return runtime.coverage, nil
	}
	return nil, errors.New("unexpected collection")
}
func (runtime *fakeRuntime) ReplaceContribution(_ context.Context, _, _ string, output discovery.ContributionOutput) error {
	runtime.outputs <- output
	return nil
}
func (runtime *fakeRuntime) ContributionGeneration(context.Context, string, string) (uint64, error) {
	return runtime.generation, nil
}

var resourceByKind = map[string]string{
	"Service": "services", "GatewayClass": "gatewayclasses", "Gateway": "gateways", "HTTPRoute": "httproutes",
	kindTrafficPolicy: "trafficpolicies", kindListenerPolicy: "listenerpolicies", kindBackendConfig: "backendconfigpolicies",
	kindBackend: "backends", kindDirectResponse: "directresponses", kindGatewayExtension: "gatewayextensions", kindGatewayParams: "gatewayparameters",
}

func collectionForKind(kind string) string {
	for _, requirement := range resourceRequirements {
		if requirement.GVR.Resource == resourceByKind[kind] {
			return requirement.Collection()
		}
	}
	return ""
}

func (runtime *fakeRuntime) sendObject(t *testing.T, item *unstructured.Unstructured, operation discovery.Operation, observedAt time.Time) {
	t.Helper()
	payload, err := json.Marshal(item.UnstructuredContent())
	if err != nil {
		t.Fatal(err)
	}
	collection := collectionForKind(item.GetKind())
	runtime.objects[collection] <- discovery.Change{Collection: collection, EventID: "event:" + string(item.GetUID()), Key: projectkit.ObjectKey(item), Operation: operation, ObservedAt: observedAt, Payload: payload}
}

func (runtime *fakeRuntime) syncResources(generation uint64, observedAt time.Time) {
	for collection, changes := range runtime.objects {
		changes <- discovery.Change{Collection: collection, Generation: generation, Operation: discovery.OperationSync, ObservedAt: observedAt}
	}
}

func (runtime *fakeRuntime) sendCoverage(t *testing.T, records []kubernetesplugin.ResourceCoverage, generation uint64, observedAt time.Time) {
	t.Helper()
	for _, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		runtime.coverage <- discovery.Change{Key: record.Capability + "/" + record.GVR, Operation: discovery.OperationUpsert, Payload: payload, ObservedAt: observedAt}
	}
	runtime.coverage <- discovery.Change{Generation: generation, Operation: discovery.OperationSync, ObservedAt: observedAt}
}

func TestPluginReplayReadinessGenerationAndDeleteRetraction(t *testing.T) {
	runtime := newFakeRuntime()
	plugin, err := New(Config{ClusterID: "cluster", SourceID: "source"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- plugin.Run(ctx, runtime) }()

	route := routeObject("apps", "api", nil, serviceRule("api"))
	policy := kgw(kindTrafficPolicy, "apps", "auth", map[string]any{"targetRefs": []any{targetRef("HTTPRoute", "api")}, "basicAuth": map[string]any{"users": []any{"u:h"}}})
	runtime.sendObject(t, route, discovery.OperationUpsert, time.Unix(10, 0))
	runtime.sendObject(t, policy, discovery.OperationUpsert, time.Unix(11, 0))
	runtime.syncResources(1, time.Unix(12, 0))
	assertNoOutput(t, runtime.outputs)

	covered := []kubernetesplugin.ResourceCoverage{
		{Capability: "kgateway-core-v1", GVR: "/v1, Resource=services", Required: true, Advertised: true, Status: kubernetesplugin.CoverageCovered},
		{Capability: "gateway-api-v1", GVR: "gateway.networking.k8s.io/v1, Resource=httproutes", Advertised: true, Status: kubernetesplugin.CoverageCovered},
		{Capability: "kgateway-trafficpolicies-v1alpha1", GVR: "gateway.kgateway.dev/v1alpha1, Resource=trafficpolicies", Advertised: true, Status: kubernetesplugin.CoverageCovered},
	}
	runtime.sendCoverage(t, covered, 1, time.Unix(13, 0))
	first := receiveOutput(t, runtime.outputs)
	if first.Generation != 12 || first.Name != "semantics" || first.SourceHealth != "healthy" || !first.Ready {
		t.Fatalf("first output metadata = %#v", first)
	}
	if len(relationshipsBetween(first.Input, route, graph.PredicateGovernedBy, claimOf(policy))) != 1 {
		t.Fatalf("first output relationships = %#v", first.Input.Relationships)
	}

	runtime.sendObject(t, policy, discovery.OperationDelete, time.Unix(15, 0))
	runtime.syncResources(2, time.Unix(16, 0))
	runtime.sendCoverage(t, nil, 2, time.Unix(16, 0))
	second := receiveOutput(t, runtime.outputs)
	if second.Generation != 13 || len(second.Input.Relationships) != 0 || len(second.Input.Resources) != 0 {
		t.Fatalf("delete output = generation %d relationships %d resources %d", second.Generation, len(second.Input.Relationships), len(second.Input.Resources))
	}

	close(runtime.objects[collectionForKind(kindTrafficPolicy)])
	degraded := receiveOutput(t, runtime.outputs)
	if degraded.Generation != 14 || degraded.SourceHealth != "degraded" {
		t.Fatalf("closure output = generation %d health %q", degraded.Generation, degraded.SourceHealth)
	}
	select {
	case runErr := <-errorsChannel:
		if runErr == nil || !strings.Contains(runErr.Error(), "closed unexpectedly") {
			t.Fatalf("run error = %v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("plugin did not return after subscription closure")
	}
}

func TestCoverageHealthAndCapabilityState(t *testing.T) {
	record := func(capability string, status kubernetesplugin.CoverageStatus, required bool) kubernetesplugin.ResourceCoverage {
		return kubernetesplugin.ResourceCoverage{Capability: capability, Status: status, Required: required}
	}
	tests := []struct {
		name    string
		records map[string]kubernetesplugin.ResourceCoverage
		want    string
	}{
		{name: "missing", records: nil, want: "degraded"},
		{name: "covered", records: map[string]kubernetesplugin.ResourceCoverage{"a": record("gateway-api-v1", kubernetesplugin.CoverageCovered, false)}, want: "healthy"},
		{name: "crd not installed", records: map[string]kubernetesplugin.ResourceCoverage{
			"a": record("gateway-api-v1", kubernetesplugin.CoverageCovered, false),
			"b": record("kgateway-trafficpolicies-v1alpha1", kubernetesplugin.CoverageUnsupported, false),
		}, want: "healthy"},
		{name: "crd degraded", records: map[string]kubernetesplugin.ResourceCoverage{
			"a": record("gateway-api-v1", kubernetesplugin.CoverageCovered, false),
			"b": record("kgateway-backends-v1alpha1", kubernetesplugin.CoverageDegraded, false),
		}, want: "degraded"},
		{name: "foreign capability ignored", records: map[string]kubernetesplugin.ResourceCoverage{
			"a": record("gateway-api-v1", kubernetesplugin.CoverageCovered, false),
			"b": record("istio-security-v1", kubernetesplugin.CoverageDegraded, false),
		}, want: "healthy"},
		{name: "required failed", records: map[string]kubernetesplugin.ResourceCoverage{
			"a": record("gateway-api-v1", kubernetesplugin.CoverageCovered, false),
			"b": record("kgateway-core-v1", kubernetesplugin.CoverageFailed, true),
		}, want: "degraded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := coverageHealth(test.records); got != test.want {
				t.Fatalf("coverageHealth() = %q, want %q", got, test.want)
			}
		})
	}
	states := capabilityCoverage(map[string]kubernetesplugin.ResourceCoverage{
		"a": record("gateway-api-v1", kubernetesplugin.CoverageCovered, false),
		"b": record("gateway-api-v1", kubernetesplugin.CoverageUnsupported, false),
		"c": record("kgateway-backends-v1alpha1", kubernetesplugin.CoverageDegraded, false),
	})
	if states["gateway-api-v1"] != CoverageStateNotInstalled || states["kgateway-backends-v1alpha1"] != CoverageStateDegraded {
		t.Fatalf("capability states = %#v", states)
	}
}

func TestDescriptorAndRequirements(t *testing.T) {
	descriptor := Descriptor()
	if descriptor.ID != PluginID || len(descriptor.Consumes) != len(resourceRequirements)+1 || len(descriptor.IdentitySchemes) != 0 {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	for _, requirement := range resourceRequirements {
		if requirement.GVR.Group == kgatewayGroup && requirement.Required {
			t.Fatalf("kgateway CRD %s must be optional", requirement.GVR.Resource)
		}
	}
	if _, err := New(Config{ClusterID: "cluster"}); err == nil {
		t.Fatal("missing source ID accepted")
	}
	if got := SplitList(" a.dev/x, ,b.dev/y "); len(got) != 2 || got[0] != "a.dev/x" || got[1] != "b.dev/y" {
		t.Fatalf("SplitList = %#v", got)
	}
}

func receiveOutput(t *testing.T, outputs <-chan discovery.ContributionOutput) discovery.ContributionOutput {
	t.Helper()
	select {
	case output := <-outputs:
		return output
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for contribution output")
		return discovery.ContributionOutput{}
	}
}

func assertNoOutput(t *testing.T, outputs <-chan discovery.ContributionOutput) {
	t.Helper()
	select {
	case output := <-outputs:
		t.Fatalf("unexpected output before readiness: %#v", output)
	case <-time.After(20 * time.Millisecond):
	}
}
