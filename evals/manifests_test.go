package evals

import (
	"errors"
	"io"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestGovernedCampaignRendersDescriptiveResourcesAndPolicyContracts(t *testing.T) {
	campaign := Campaign{ID: "declared-benign-control", SourceComponent: "client", BaselineTarget: "api", ObservedTarget: "secrets-store", Governed: true}
	workload := RenderCampaign(campaign)
	for _, required := range []string{"app.kubernetes.io/name: secrets-store", "kind: ServiceAccount", "serviceAccountName: client", "automountServiceAccountToken: false", "kind: NetworkPolicy", "gateway.networking.k8s.io/gateway-name: waypoint", "port: 15008"} {
		if !strings.Contains(workload.Manifest, required) {
			t.Fatalf("manifest omitted %q", required)
		}
	}
	for _, pluginSpecific := range []string{"istio.io/", "istio-waypoint", "kind: Telemetry"} {
		if strings.Contains(workload.Manifest, pluginSpecific) {
			t.Fatalf("provider-neutral manifest contains %q", pluginSpecific)
		}
	}
	if strings.Contains(workload.Namespace, campaign.ID) || strings.Contains(workload.Manifest, campaign.ID) {
		t.Fatal("rendered workload exposed the scorer-facing campaign ID")
	}
	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(workload.Manifest), 4096)
	for {
		var document map[string]any
		if err := decoder.Decode(&document); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode rendered manifest: %v", err)
		}
	}
}

func TestIstioOTLPObservationAdapterOwnsItsPluginResources(t *testing.T) {
	campaign := Campaign{ID: "control", SourceComponent: "client", BaselineTarget: "api", ObservedTarget: "secrets-store"}
	workload := RenderCampaign(campaign)
	manifest := istioOTLPObservationAdapter{}.Manifest(campaign, workload)
	for _, required := range []string{"istio.io/dataplane-mode: ambient", "istio.io/waypoint-for: all", "gatewayClassName: istio-waypoint", "kind: Telemetry", "name: waypoint-access-logs", "group: gateway.networking.k8s.io", "kind: Gateway"} {
		if !strings.Contains(manifest, required) {
			t.Fatalf("observation adapter manifest omitted %q", required)
		}
	}
}

func TestObservationAdapterRejectsUnknownPlugin(t *testing.T) {
	if _, err := observationAdapter("unknown"); err == nil {
		t.Fatal("expected unknown observation adapter to be rejected")
	}
}

func TestObservationAdapterPreparesNamespaceBeforeWorkloads(t *testing.T) {
	campaign := Campaign{ID: "control", SourceComponent: "client", BaselineTarget: "api", ObservedTarget: "secrets-store"}
	workload := RenderCampaign(campaign)
	stages := campaignApplyStages(istioOTLPObservationAdapter{}, campaign, workload)
	if len(stages) != 2 || stages[0].FieldManager != "agentshield-mission-evals-observation" || !strings.Contains(stages[0].Manifest, "istio.io/dataplane-mode: ambient") {
		t.Fatalf("apply stages did not prepare observation enrollment before workloads: %#v", stages)
	}
}
