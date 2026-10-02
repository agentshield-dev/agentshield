package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
	agentgatewayplugin "github.com/agentshield-dev/agentshield/plugins/agentgateway"
	awsplugin "github.com/agentshield-dev/agentshield/plugins/aws"
	ciliumplugin "github.com/agentshield-dev/agentshield/plugins/cilium"
	falcoplugin "github.com/agentshield-dev/agentshield/plugins/falco"
	istioplugin "github.com/agentshield-dev/agentshield/plugins/istio"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/rest"
)

func TestInitialSnapshot(t *testing.T) {
	existing := graph.Snapshot{Resources: []graph.Resource{{ID: "resource"}}}
	got, err := initialSnapshot(state.GraphView{Snapshot: existing}, nil)
	if err != nil || len(got.Resources) != 1 {
		t.Fatalf("persisted snapshot = %+v, err = %v", got, err)
	}
	got, err = initialSnapshot(state.GraphView{}, state.ErrNotMaterialized)
	if err != nil || len(got.Resources) != 0 {
		t.Fatalf("empty snapshot = %+v, err = %v", got, err)
	}
	wantErr := errors.New("read failed")
	if _, err := initialSnapshot(state.GraphView{}, wantErr); !errors.Is(err, wantErr) {
		t.Fatalf("read error = %v, want %v", err, wantErr)
	}
}

func TestLoopbackListenAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8088", "[::1]:8088", "localhost:8088"} {
		if !loopbackListenAddress(address) {
			t.Fatalf("loopback address %q was rejected", address)
		}
	}
	for _, address := range []string{"0.0.0.0:8088", ":8088", "example.com:8088", "invalid"} {
		if loopbackListenAddress(address) {
			t.Fatalf("non-loopback address %q was accepted", address)
		}
	}
}

func TestNewInvestigationAnalyzerRequiresExplicitOptIn(t *testing.T) {
	analyzer, err := newInvestigationAnalyzer(options{modelEndpoint: "http://model.invalid"})
	if err != nil || analyzer != nil {
		t.Fatalf("analyzer without --agentic-investigation = %T, err = %v", analyzer, err)
	}
	analyzer, err = newInvestigationAnalyzer(options{agenticInvestigation: true, modelEndpoint: "http://model.invalid", investigationRetrieval: reasoning.RetrievalDeterministic})
	if err != nil || analyzer == nil {
		t.Fatalf("enabled analyzer = %T, err = %v", analyzer, err)
	}
}

func TestValidateDetectionFeatures(t *testing.T) {
	valid := options{
		detectionInterval: time.Second, detectorReloadInterval: time.Second, detectionSignalRetention: 24 * time.Hour,
		modelEndpoint: "http://model.invalid", investigationRetrieval: reasoning.RetrievalModelSelected,
		deploymentRulePollInterval: time.Second, deploymentRuleAuthorTimeout: time.Minute, deploymentRuleBaseline: 6 * time.Hour,
		investigationBatchWindow: 30 * time.Second, investigationSampleRate: 1, investigationDedupWindow: time.Hour,
		investigationMaxAttempts: 5, investigationPollInterval: time.Second,
	}
	for _, test := range []struct {
		name   string
		modify func(*options)
		valid  bool
	}{
		{name: "everything disabled", modify: func(config *options) { config.modelEndpoint = "" }, valid: true},
		{name: "agentic investigation", modify: func(config *options) { config.agenticInvestigation = true }, valid: true},
		{name: "authoring only", modify: func(config *options) { config.deploymentRuleAuthoring = true }, valid: true},
		{name: "both model features", modify: func(config *options) { config.agenticInvestigation, config.deploymentRuleAuthoring = true, true }, valid: true},
		{name: "authoring with Anthropic", modify: func(config *options) {
			config.deploymentRuleAuthoring, config.modelProvider = true, reasoning.ProviderAnthropic
		}, valid: true},
		{name: "investigation without endpoint", modify: func(config *options) { config.agenticInvestigation, config.modelEndpoint = true, "" }},
		{name: "investigation with Anthropic", modify: func(config *options) {
			config.agenticInvestigation, config.modelProvider = true, reasoning.ProviderAnthropic
		}},
		{name: "investigation retrieval", modify: func(config *options) {
			config.agenticInvestigation, config.investigationRetrieval = true, "everything"
		}},
		{name: "authoring without endpoint", modify: func(config *options) { config.deploymentRuleAuthoring, config.modelEndpoint = true, "" }},
		{name: "authoring timeout", modify: func(config *options) {
			config.deploymentRuleAuthoring, config.deploymentRuleAuthorTimeout = true, time.Second
		}},
		{name: "authoring without a baseline", modify: func(config *options) { config.deploymentRuleAuthoring, config.deploymentRuleBaseline = true, 0 }, valid: true},
		{name: "baseline window longer than telemetry retention", modify: func(config *options) {
			config.deploymentRuleAuthoring, config.deploymentRuleBaseline = true, 25*time.Hour
		}},
		{name: "negative baseline window", modify: func(config *options) {
			config.deploymentRuleAuthoring, config.deploymentRuleBaseline = true, -time.Minute
		}},
		{name: "signal retention", modify: func(config *options) { config.detectionSignalRetention = time.Minute }},
		{name: "sampled investigation", modify: func(config *options) {
			config.agenticInvestigation, config.investigationSampleRate, config.investigationMaxPerHour = true, 0.1, 60
		}, valid: true},
		{name: "sample rate above one", modify: func(config *options) { config.agenticInvestigation, config.investigationSampleRate = true, 1.5 }},
		{name: "negative budget", modify: func(config *options) { config.agenticInvestigation, config.investigationMaxPerHour = true, -1 }},
		{name: "batch window too long", modify: func(config *options) {
			config.agenticInvestigation, config.investigationBatchWindow = true, time.Hour
		}},
		{name: "zero attempts", modify: func(config *options) { config.agenticInvestigation, config.investigationMaxAttempts = true, 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.modify(&config)
			if err := config.validateDetectionFeatures(); (err == nil) != test.valid {
				t.Fatalf("validateDetectionFeatures() = %v, want valid=%t", err, test.valid)
			}
		})
	}
}

func TestDetectionRunsOnlyForModelFeatures(t *testing.T) {
	for _, test := range []struct {
		config options
		want   bool
	}{
		{config: options{}, want: false},
		{config: options{agenticInvestigation: true}, want: true},
		{config: options{deploymentRuleAuthoring: true}, want: true},
		{config: options{agenticInvestigation: true, deploymentRuleAuthoring: true}, want: true},
	} {
		if got := test.config.detectionEnabled(); got != test.want {
			t.Fatalf("detectionEnabled(%+v) = %t, want %t", test.config, got, test.want)
		}
	}
}

func TestResolveModelAPIKeyPrecedence(t *testing.T) {
	t.Setenv("AGENTSHIELD_MODEL_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "openai")
	t.Setenv("ANTHROPIC_API_KEY", "anthropic")
	if got := resolveModelAPIKey("", reasoning.ProviderOpenAI); got != "openai" {
		t.Fatalf("OpenAI fallback = %q", got)
	}
	if got := resolveModelAPIKey("", reasoning.ProviderAnthropic); got != "anthropic" {
		t.Fatalf("Anthropic fallback = %q", got)
	}
	t.Setenv("AGENTSHIELD_MODEL_API_KEY", " shared ")
	if got := resolveModelAPIKey("", reasoning.ProviderAnthropic); got != "shared" {
		t.Fatalf("AGENTSHIELD_MODEL_API_KEY = %q", got)
	}
	if got := resolveModelAPIKey(" flag ", reasoning.ProviderOpenAI); got != "flag" {
		t.Fatalf("flag value = %q", got)
	}
}

func TestCompiledInDescriptorsCoverEveryPlugin(t *testing.T) {
	descriptors := map[string]discovery.Descriptor{}
	for _, descriptor := range compiledInDescriptors() {
		if _, found := descriptors[descriptor.ID]; found {
			t.Fatalf("duplicate compiled-in plugin %q", descriptor.ID)
		}
		descriptors[descriptor.ID] = descriptor
	}
	config := options{
		kubernetes:   kubernetesplugin.CLIConfig{ClusterID: "cluster", SourceID: "kubernetes/cluster"},
		istio:        istioplugin.CLIConfig{ClusterID: "cluster", SourceID: "kubernetes/cluster"},
		agentgateway: agentgatewayplugin.CLIConfig{ClusterID: "cluster", SourceID: "kubernetes/cluster"},
		cilium:       ciliumplugin.CLIConfig{ClusterID: "cluster", SourceID: "kubernetes/cluster"},
		falco:        falcoplugin.CLIConfig{ClusterID: "cluster", SourceID: "kubernetes/cluster"},
	}
	consumers, err := kubernetesConsumerPlugins(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{kubernetesplugin.PluginID, awsplugin.PluginID}
	for _, plugin := range consumers {
		ids = append(ids, plugin.Descriptor().ID)
	}
	if len(ids) != len(descriptors) {
		t.Fatalf("constructed plugins %v, compiled-in descriptors %d", ids, len(descriptors))
	}
	for _, id := range ids {
		if _, found := descriptors[id]; !found {
			t.Fatalf("plugin %q is constructed but its identity schemes are not registered", id)
		}
	}
	for _, plugin := range consumers {
		if got, want := len(plugin.Descriptor().IdentitySchemes), len(descriptors[plugin.Descriptor().ID].IdentitySchemes); got != want {
			t.Fatalf("plugin %q instance declares %d identity schemes, static descriptor %d", plugin.Descriptor().ID, got, want)
		}
	}
	registry := graph.NewRegistry()
	if err := discovery.RegisterIdentitySchemes(registry, compiledInDescriptors()...); err != nil {
		t.Fatal(err)
	}
	for _, definition := range []graph.SchemeDefinition{kubernetesplugin.IdentitySchemeDefinition(), awsplugin.IdentitySchemeDefinition()} {
		if err := registry.Register(definition); err == nil {
			t.Fatalf("identity scheme %q was not registered", definition.Scheme)
		}
	}
}

func TestPluginCLIFlagsAreNamespacedAndCollisionFree(t *testing.T) {
	flags := pflag.NewFlagSet("agentshield", pflag.ContinueOnError)
	configs := []interface{ RegisterFlags(*pflag.FlagSet) error }{
		&kubernetesplugin.CLIConfig{}, &istioplugin.CLIConfig{}, &agentgatewayplugin.CLIConfig{},
		&ciliumplugin.CLIConfig{}, &falcoplugin.CLIConfig{}, &awsplugin.CLIConfig{},
	}
	for _, config := range configs {
		if err := config.RegisterFlags(flags); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		"kubernetes-cluster-id", "istio-cluster-id", "agentgateway-cluster-id", "cilium-cluster-id",
		"falco-cluster-id", "falco-source-id", "aws-region", "aws-firehose-stream-arn",
	} {
		if flags.Lookup(name) == nil {
			t.Errorf("expected plugin-owned flag --%s", name)
		}
	}
	for _, oldName := range []string{"cluster-id", "source-id", "kubeconfig", "disable-kubernetes"} {
		if flags.Lookup(oldName) != nil {
			t.Errorf("legacy unprefixed flag --%s was registered", oldName)
		}
	}
}

func TestParseOptionsUsesIndependentPluginClusterIDs(t *testing.T) {
	config, err := parseOptions([]string{
		"--kubernetes-cluster-id=k8s-a", "--istio-cluster-id=istio-b",
		"--agentgateway-cluster-id=gateway-c", "--cilium-cluster-id=cilium-d", "--falco-cluster-id=falco-e",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.kubernetes.ClusterID != "k8s-a" || config.istio.ClusterID != "istio-b" ||
		config.agentgateway.ClusterID != "gateway-c" || config.cilium.ClusterID != "cilium-d" ||
		config.falco.ClusterID != "falco-e" {
		t.Fatalf("plugin cluster IDs were not independent: %+v", config)
	}
}

func TestParseOptionsRequiresAWSRegionForAWSReceivers(t *testing.T) {
	for _, flag := range []string{
		"--aws-events-queue-url=https://sqs.example.test/queue",
		"--aws-firehose-stream-arn=arn:aws:firehose:us-east-1:111111111111:deliverystream/test",
	} {
		if _, err := parseOptions([]string{flag}); err == nil || !strings.Contains(err.Error(), "--aws-region") {
			t.Errorf("parseOptions(%q) error = %v, want an --aws-region requirement", flag, err)
		}
	}
}

func TestRulesSubcommandRunsFromMainBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"id":"test","rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := runWithArgsOutput([]string{"rules", "validate", "--file", path}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "valid ruleset=test rules=0") {
		t.Fatalf("main rules subcommand output = %q", output.String())
	}
}

func TestGoRecoverTurnsPanicIntoErrorWithStack(t *testing.T) {
	var group errgroup.Group
	goRecover(&group, "test component", func() error {
		var values map[string]*int
		return fmt.Errorf("unreachable %d", *values["missing"])
	})
	err := group.Wait()
	if err == nil || !strings.Contains(err.Error(), "test component panicked") || !strings.Contains(err.Error(), "goroutine ") {
		t.Fatalf("panic error = %v, want component name and stack", err)
	}
	wantErr := errors.New("component failed")
	var failing errgroup.Group
	goRecover(&failing, "failing component", func() error { return wantErr })
	if err := failing.Wait(); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

func TestKubernetesClientConfigsKeepWatchesUnbounded(t *testing.T) {
	base := &rest.Config{Host: "https://kubernetes.example"}
	watch, request := kubernetesClientConfigs(base)
	if watch.Timeout != 0 {
		t.Fatalf("informer client timeout = %s, want none; it would end watch streams", watch.Timeout)
	}
	if request.Timeout != kubernetesRequestTimeout {
		t.Fatalf("request client timeout = %s, want %s", request.Timeout, kubernetesRequestTimeout)
	}
	for _, config := range []*rest.Config{watch, request} {
		if config.QPS != kubernetesQPS || config.Burst != kubernetesBurst || config.Host != base.Host {
			t.Fatalf("client config = %+v", config)
		}
	}
	if base.QPS != 0 || base.Timeout != 0 {
		t.Fatalf("base config modified: %+v", base)
	}
}
