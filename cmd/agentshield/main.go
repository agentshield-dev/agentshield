// Command agentshield runs the AgentShield service: discovery plugins, the
// graph store, telemetry ingestion and rollups, detection with optional
// agentic investigation and Deployment rule authoring, and the HTTP API and UI.
//
// One process observes at most one Kubernetes cluster and one AWS region and
// persists to PostgreSQL. With --disable-discovery it serves persisted state
// only. The HTTP API is unauthenticated; the default listener is loopback, and
// the remediation endpoints act only with live discovery on a loopback
// listener. Elsewhere they return 503. Flags and environment variables are
// documented at https://agent-shield.dev/docs/operations/configuration/.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agentshield-dev/agentshield/internal/version"
	"github.com/agentshield-dev/agentshield/pkg/api"
	"github.com/agentshield-dev/agentshield/pkg/deploymentauthoring"
	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/reasoning/modelanalyzer"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/rulescli"
	"github.com/agentshield-dev/agentshield/pkg/state"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
	agentgatewayplugin "github.com/agentshield-dev/agentshield/plugins/agentgateway"
	awsplugin "github.com/agentshield-dev/agentshield/plugins/aws"
	ciliumplugin "github.com/agentshield-dev/agentshield/plugins/cilium"
	falcoplugin "github.com/agentshield-dev/agentshield/plugins/falco"
	istioplugin "github.com/agentshield-dev/agentshield/plugins/istio"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
	k8sdiscovery "k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// storeOpenTimeout bounds opening PostgreSQL and applying pending migrations.
	// The Helm chart's startup probe allows longer than this plus the 30-second
	// startup budget; keep them in step.
	storeOpenTimeout = 5 * time.Minute

	startupOpenTimeout = 30 * time.Second
)

type options struct {
	listen                      string
	databaseURL                 string
	databaseMaxConns            int
	databaseMinConns            int
	telemetryPath               string
	clickHouseURL               string
	clickHouseDatabase          string
	clickHouseTable             string
	clickHouseUsername          string
	disableDiscovery            bool
	kubernetes                  kubernetesplugin.CLIConfig
	istio                       istioplugin.CLIConfig
	agentgateway                agentgatewayplugin.CLIConfig
	cilium                      ciliumplugin.CLIConfig
	falco                       falcoplugin.CLIConfig
	aws                         awsplugin.CLIConfig
	modelEndpoint               string
	modelAPIKey                 string
	modelProviderName           string
	model                       string
	modelReasoningEffort        string
	detectionConsumer           string
	detectionInterval           time.Duration
	detectionSignalRetention    time.Duration
	detectorReloadInterval      time.Duration
	agenticInvestigation        bool
	investigationRetrieval      string
	investigationBatchWindow    time.Duration
	investigationSampleRate     float64
	investigationMaxPerHour     int
	investigationDedupWindow    time.Duration
	investigationMaxAttempts    int
	investigationPollInterval   time.Duration
	deploymentRuleAuthoring     bool
	deploymentRulePollInterval  time.Duration
	deploymentRuleAuthorTimeout time.Duration
	deploymentRuleBaseline      time.Duration
	ruleReviewAPI               bool
	modelProvider               reasoning.Provider
}

func main() {
	if err := runWithArgs(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func runWithArgs(args []string) error {
	return runWithArgsOutput(args, os.Stdout)
}

func runWithArgsOutput(args []string, output io.Writer) error {
	if len(args) > 0 && args[0] == "rules" {
		return rulescli.Run(context.Background(), args[1:], output)
	}
	for _, arg := range args {
		if arg == "--version" || arg == "-version" {
			_, err := fmt.Fprintln(output, "agentshield "+version.String())
			return err
		}
	}
	config, err := parseOptions(args)
	if err != nil {
		return err
	}
	log.Printf("AgentShield %s starting", version.String())
	// Opening the store applies pending migrations, which can take much longer
	// than a connection check, so it has its own budget.
	storeContext, cancelStore := context.WithTimeout(context.Background(), storeOpenTimeout)
	store, err := openStore(storeContext, config)
	cancelStore()
	if err != nil {
		return err
	}
	defer store.Close()
	// Provider identity lookups and detector bootstrap share one startup
	// budget so an unreachable dependency fails fast.
	startupContext, cancelStartup := context.WithTimeout(context.Background(), startupOpenTimeout)
	defer cancelStartup()
	runtime, err := discovery.NewRuntime(store)
	if err != nil {
		return err
	}
	plugins, manager, err := newDiscovery(startupContext, config, runtime)
	if err != nil {
		return err
	}

	sink, closeSink, err := telemetrySink(config)
	if err != nil {
		return err
	}
	defer closeSink()
	pipeline, err := newTelemetryPipeline(store, runtime, sink)
	if err != nil {
		return err
	}
	handler, apiServer, err := newHTTPHandler(config, store, manager, plugins, pipeline)
	if err != nil {
		return err
	}
	detection, err := newDetectionServices(startupContext, config, store)
	if err != nil {
		return err
	}
	return serve(config, newHTTPServer(config.listen, handler, apiServer.CloseStreams), store, pipeline, manager, detection)
}

// parseOptions registers every command-line flag, resolves model provider
// defaults, and validates intervals. Flag names, defaults, and environment
// fallbacks are part of the operator contract in
// https://agent-shield.dev/docs/operations/configuration/.
func parseOptions(args []string) (options, error) {
	var config options
	flags := pflag.NewFlagSet("agentshield", pflag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&config.listen, "listen", "127.0.0.1:8088", "HTTP listen address")
	flags.StringVar(&config.databaseURL, "database-url", os.Getenv("AGENTSHIELD_DATABASE_URL"), "PostgreSQL connection URL; defaults to AGENTSHIELD_DATABASE_URL")
	flags.IntVar(&config.databaseMaxConns, "database-max-conns", envInt("AGENTSHIELD_DATABASE_MAX_CONNS", 20), "maximum PostgreSQL pool connections")
	flags.IntVar(&config.databaseMinConns, "database-min-conns", envInt("AGENTSHIELD_DATABASE_MIN_CONNS", 2), "minimum PostgreSQL pool connections")
	flags.StringVar(&config.telemetryPath, "telemetry-jsonl", ".agentshield/telemetry.jsonl", "local durable telemetry path")
	flags.StringVar(&config.clickHouseURL, "clickhouse-url", "", "ClickHouse HTTP endpoint; uses JSONL when empty")
	flags.StringVar(&config.clickHouseDatabase, "clickhouse-database", "agentshield", "ClickHouse database")
	flags.StringVar(&config.clickHouseTable, "clickhouse-table", "telemetry_events", "ClickHouse raw telemetry table")
	flags.StringVar(&config.clickHouseUsername, "clickhouse-username", "default", "ClickHouse user")
	flags.BoolVar(&config.disableDiscovery, "disable-discovery", false, "serve persisted/replayed state without live discovery")
	flags.StringVar(&config.modelEndpoint, "model-endpoint", os.Getenv("AGENTSHIELD_MODEL_ENDPOINT"), "model API base endpoint for the model-calling features --agentic-investigation and --deployment-rule-authoring")
	flags.StringVar(&config.modelAPIKey, "model-api-key", "", "model API key; defaults to AGENTSHIELD_MODEL_API_KEY or the selected provider's API key")
	flags.StringVar(&config.modelProviderName, "model-provider", "openai", "model API provider: openai or anthropic. --agentic-investigation requires openai (the Responses API)")
	flags.StringVar(&config.model, "model", envString("AGENTSHIELD_MODEL", reasoning.Model), "model name")
	flags.StringVar(&config.modelReasoningEffort, "model-reasoning-effort", os.Getenv("AGENTSHIELD_MODEL_REASONING_EFFORT"), "reasoning effort for model calls, for compatible providers")
	flags.StringVar(&config.detectionConsumer, "detection-consumer", "reasoning/default", "stable durable detection cursor ID; detection runs when --agentic-investigation or --deployment-rule-authoring is enabled")
	flags.DurationVar(&config.detectionInterval, "detection-interval", time.Second, "detection graph polling interval")
	flags.DurationVar(&config.detectionSignalRetention, "detection-signal-retention", 7*24*time.Hour, "how long recorded detection signals and finished investigation jobs are kept")
	flags.DurationVar(&config.detectorReloadInterval, "detector-reload-interval", 10*time.Second, "detector ruleset and Deployment rule polling interval")
	flags.BoolVar(&config.agenticInvestigation, "agentic-investigation", envBool("AGENTSHIELD_AGENTIC_INVESTIGATION", false), "investigate built-in novelty signals with a model agent that may promote findings; calls --model-endpoint (OpenAI Responses API) at most once per admitted investigation job")
	flags.StringVar(&config.investigationRetrieval, "agentic-investigation-retrieval", envString("AGENTSHIELD_AGENTIC_INVESTIGATION_RETRIEVAL", reasoning.RetrievalModelSelected), "agentic investigation context retrieval: model_selected or deterministic")
	flags.DurationVar(&config.investigationBatchWindow, "agentic-investigation-batch-window", 30*time.Second, "how long a queued investigation waits so later change windows that share a resource join it")
	flags.Float64Var(&config.investigationSampleRate, "agentic-investigation-sample-rate", 1, "fraction of medium-risk investigations run (0-1); high and critical always run")
	flags.IntVar(&config.investigationMaxPerHour, "agentic-investigation-max-per-hour", 0, "maximum investigations started in any trailing hour; 0 is unlimited. Over budget, medium-risk work is skipped and high-risk work waits")
	flags.DurationVar(&config.investigationDedupWindow, "agentic-investigation-dedup-window", time.Hour, "skip an investigation whose signal pattern was already investigated within this window; 0 disables")
	flags.IntVar(&config.investigationMaxAttempts, "agentic-investigation-max-attempts", 5, "failed investigation attempts before a queued investigation fails permanently")
	flags.DurationVar(&config.investigationPollInterval, "agentic-investigation-poll-interval", time.Second, "investigation queue polling interval")
	flags.BoolVar(&config.deploymentRuleAuthoring, "deployment-rule-authoring", envBool("AGENTSHIELD_DEPLOYMENT_RULE_AUTHORING", false), "draft a detector rule for each Kubernetes Deployment Pod template revision with a model agent, from the Deployment's observed behavior, and run approved rules; calls --model-endpoint once per revision")
	flags.BoolVar(&config.ruleReviewAPI, "rule-review-api", envBool("AGENTSHIELD_RULE_REVIEW_API", false), "serve the unauthenticated rule review and regenerate API routes on a non-loopback listener; they are always served on a loopback listener. Expose only behind an authenticating proxy or for disposable environments")
	flags.DurationVar(&config.deploymentRuleBaseline, "deployment-rule-baseline-window", 6*time.Hour, "how long a new Deployment or Pod template revision is observed before its rule is drafted (0 to 24h, bounded by telemetry retention)")
	flags.DurationVar(&config.deploymentRulePollInterval, "deployment-rule-authoring-poll-interval", time.Second, "Deployment rule authoring queue polling interval")
	flags.DurationVar(&config.deploymentRuleAuthorTimeout, "deployment-rule-authoring-timeout", 5*time.Minute, "maximum duration for one Deployment rule authoring model call")
	for _, register := range []func(*pflag.FlagSet) error{
		config.kubernetes.RegisterFlags, config.istio.RegisterFlags, config.agentgateway.RegisterFlags,
		config.cilium.RegisterFlags, config.falco.RegisterFlags, config.aws.RegisterFlags,
	} {
		if err := register(flags); err != nil {
			return options{}, err
		}
	}
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if strings.TrimSpace(config.aws.Region) == "" &&
		(strings.TrimSpace(config.aws.EventsQueueURL) != "" || strings.TrimSpace(config.aws.FirehoseStreamARN) != "") {
		return options{}, errors.New("AWS events queue and Firehose options require --aws-region")
	}
	switch strings.ToLower(strings.TrimSpace(config.modelProviderName)) {
	case "openai":
		config.modelProvider = reasoning.ProviderOpenAI
	case "anthropic":
		config.modelProvider = reasoning.ProviderAnthropic
		if strings.TrimSpace(config.modelEndpoint) == "" {
			config.modelEndpoint = "https://api.anthropic.com"
		}
	default:
		return options{}, fmt.Errorf("unsupported --model-provider %q (expected openai or anthropic)", config.modelProviderName)
	}
	config.modelAPIKey = resolveModelAPIKey(config.modelAPIKey, config.modelProvider)
	if err := config.validateDetectionFeatures(); err != nil {
		return options{}, err
	}
	return config, nil
}

// detectionEnabled reports whether the detection service runs. Detection serves
// the model-calling features: it gates agentic investigation and runs the rules
// that authoring produces, so it has no standalone mode.
func (config options) detectionEnabled() bool {
	return config.agenticInvestigation || config.deploymentRuleAuthoring
}

// validateDetectionFeatures checks that each model-calling feature is explicitly
// enabled and has what it needs; nothing calls a model implicitly.
func (config options) validateDetectionFeatures() error {
	if config.detectorReloadInterval <= 0 || config.detectionInterval <= 0 {
		return errors.New("detection and detector reload intervals must be positive")
	}
	if config.detectionSignalRetention < time.Hour {
		return errors.New("--detection-signal-retention must be at least one hour")
	}
	if config.agenticInvestigation {
		switch {
		case config.modelProvider == reasoning.ProviderAnthropic:
			return errors.New("--agentic-investigation requires an OpenAI Responses-compatible endpoint and cannot be combined with --model-provider anthropic")
		case strings.TrimSpace(config.modelEndpoint) == "":
			return errors.New("--agentic-investigation requires --model-endpoint or AGENTSHIELD_MODEL_ENDPOINT")
		}
		if config.investigationRetrieval != reasoning.RetrievalModelSelected && config.investigationRetrieval != reasoning.RetrievalDeterministic {
			return fmt.Errorf("unsupported --agentic-investigation-retrieval %q", config.investigationRetrieval)
		}
		switch {
		case config.investigationBatchWindow < 0 || config.investigationBatchWindow > 10*time.Minute:
			return errors.New("--agentic-investigation-batch-window must be between 0 and 10 minutes")
		case config.investigationSampleRate < 0 || config.investigationSampleRate > 1:
			return errors.New("--agentic-investigation-sample-rate must be between 0 and 1")
		case config.investigationMaxPerHour < 0 || config.investigationDedupWindow < 0:
			return errors.New("--agentic-investigation-max-per-hour and --agentic-investigation-dedup-window must not be negative")
		case config.investigationMaxAttempts < 1 || config.investigationPollInterval <= 0:
			return errors.New("--agentic-investigation-max-attempts and --agentic-investigation-poll-interval must be positive")
		}
	}
	if config.deploymentRuleAuthoring {
		if strings.TrimSpace(config.modelEndpoint) == "" {
			return errors.New("--deployment-rule-authoring requires --model-endpoint, AGENTSHIELD_MODEL_ENDPOINT, or --model-provider anthropic")
		}
		if config.deploymentRulePollInterval <= 0 || config.deploymentRuleAuthorTimeout < 30*time.Second {
			return errors.New("Deployment rule authoring poll interval must be positive and timeout must be at least 30 seconds")
		}
		if config.deploymentRuleBaseline < 0 || config.deploymentRuleBaseline > deploymentauthoring.MaxBaselineWindow {
			return fmt.Errorf("--deployment-rule-baseline-window must be between 0 and %s", deploymentauthoring.MaxBaselineWindow)
		}
	}
	return nil
}

// resolveModelAPIKey prefers the flag, then AGENTSHIELD_MODEL_API_KEY, then the
// provider's conventional variable.
func resolveModelAPIKey(flagValue string, provider reasoning.Provider) string {
	if key := strings.TrimSpace(flagValue); key != "" {
		return key
	}
	if key := strings.TrimSpace(os.Getenv("AGENTSHIELD_MODEL_API_KEY")); key != "" {
		return key
	}
	if provider == reasoning.ProviderAnthropic {
		return strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	}
	return strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
}

func openStore(ctx context.Context, config options) (*state.Store, error) {
	registry := graph.NewRegistry()
	// Register schemes for every compiled-in plugin, enabled or not. The
	// compiler must normalize claims in contributions persisted by earlier
	// runs, including when this process runs with --disable-discovery or with
	// a different set of sources.
	if err := discovery.RegisterIdentitySchemes(registry, compiledInDescriptors()...); err != nil {
		return nil, err
	}
	return state.Open(ctx, state.Config{
		DatabaseURL: config.databaseURL, MaxConnections: int32(config.databaseMaxConns), MinConnections: int32(config.databaseMinConns),
		// Migration detaches from ctx, so bound it here to stay inside the
		// Helm startup probe.
		MigrationTimeout:         storeOpenTimeout,
		InvestigationMaxAttempts: config.investigationMaxAttempts,
	}, graph.NewCompiler(registry))
}

// compiledInDescriptors returns the static descriptor of every plugin built
// into this binary. Plugins are compiled in; there is no dynamic plugin
// registration. Today only Kubernetes and AWS declare identity schemes;
// Kubernetes-backed plugins reuse the Kubernetes and built-in graph schemes.
func compiledInDescriptors() []discovery.Descriptor {
	return []discovery.Descriptor{
		kubernetesplugin.Descriptor(), istioplugin.Descriptor(), agentgatewayplugin.Descriptor(),
		ciliumplugin.Descriptor(), falcoplugin.Descriptor(), awsplugin.Descriptor(),
	}
}

// newDiscovery builds the enabled discovery plugins and their manager. Both
// are nil with --disable-discovery, which serves only persisted state.
func newDiscovery(ctx context.Context, config options, runtime *discovery.RuntimeService) ([]discovery.Plugin, *discovery.Manager, error) {
	if config.disableDiscovery {
		return nil, nil, nil
	}
	plugins, err := discoveryPlugins(ctx, config)
	if err != nil {
		return nil, nil, err
	}
	manager, err := discovery.NewManager(runtime, plugins...)
	if err != nil {
		return nil, nil, err
	}
	return plugins, manager, nil
}

// newTelemetryPipeline restores bounded rollups from the latest graph and
// returns a pipeline that hands each sink-acknowledged batch to a
// telemetry.RollupPublisher, which owns rollup generations and retraction.
func newTelemetryPipeline(store *state.Store, runtime *discovery.RuntimeService, sink telemetry.Sink) (*telemetry.Pipeline, error) {
	// Retention also bounds the Deployment rule baseline window, which reads telemetry from the graph.
	rollup := telemetry.NewRollup(telemetry.RollupConfig{Window: time.Minute, Retention: deploymentauthoring.MaxBaselineWindow, MaxSeries: 100_000})
	currentGraph, err := store.Latest(context.Background())
	initialGraph, err := initialSnapshot(currentGraph, err)
	if err != nil {
		return nil, err
	}
	if err := rollup.Restore(initialGraph); err != nil {
		return nil, fmt.Errorf("restore telemetry rollup: %w", err)
	}
	publisher, err := telemetry.NewRollupPublisher(telemetry.RollupPublisherConfig{
		Rollup: rollup, Snapshot: func(ctx context.Context) (graph.Snapshot, error) { return latestSnapshot(ctx, store) },
		Target: runtime.RollupTarget(), PublishInterval: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return telemetry.NewPipeline(telemetry.PipelineConfig{LifecycleInterval: 30 * time.Second}, sink, publisher.Commit)
}

// newHTTPHandler assembles the API, the OTLP receiver for plugin telemetry
// mappings, and plugin-owned native telemetry receivers. The remediation routes are
// always registered, but the live executor is wired only with live discovery
// on a loopback listener because the API is unauthenticated; otherwise they
// return 503. The API server is returned so shutdown can close its event
// streams.
func newHTTPHandler(config options, store *state.Store, manager *discovery.Manager, plugins []discovery.Plugin, pipeline *telemetry.Pipeline) (http.Handler, *api.Server, error) {
	var mappings []telemetry.Mapping
	for _, plugin := range plugins {
		if provider, ok := plugin.(discovery.TelemetryMappingProvider); ok {
			mappings = append(mappings, provider.TelemetryMappings()...)
		}
	}
	mappingRegistry, err := telemetry.NewMappingRegistry(mappings...)
	if err != nil {
		return nil, nil, err
	}
	otlpReceiver, err := telemetry.NewOTLPReceiver(telemetry.OTLPReceiverConfig{}, mappingRegistry, pipeline)
	if err != nil {
		return nil, nil, err
	}
	apiServer, err := newAPIServer(config, store, manager, otlpReceiver)
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	for _, plugin := range plugins {
		provider, ok := plugin.(discovery.TelemetryReceiverProvider)
		if !ok {
			continue
		}
		receivers, err := provider.TelemetryReceivers(pipeline)
		if err != nil {
			return nil, nil, fmt.Errorf("register telemetry receivers for plugin %q: %w", plugin.Descriptor().ID, err)
		}
		for _, receiver := range receivers {
			if receiver.Method == "" || receiver.Path == "" || receiver.Handler == nil {
				return nil, nil, fmt.Errorf("plugin %q returned an incomplete telemetry receiver", plugin.Descriptor().ID)
			}
			mux.Handle(receiver.Method+" "+receiver.Path, receiver.Handler)
		}
	}
	mux.Handle("/", apiServer.Handler())
	return mux, apiServer, nil
}

func newAPIServer(config options, store *state.Store, manager *discovery.Manager, otlpReceiver *telemetry.OTLPReceiver) (*api.Server, error) {
	loopback := loopbackListenAddress(config.listen)
	if config.ruleReviewAPI && !loopback {
		log.Printf("rule review API enabled on non-loopback listener %q without authentication", config.listen)
	}
	rules := api.WithRules(store, loopback || config.ruleReviewAPI)
	if manager == nil || !loopback {
		apiServer, err := api.NewServer(store, otlpReceiver, api.WithLoopbackHostCheck(loopback), rules)
		if manager != nil {
			log.Printf("live remediation API disabled on non-loopback listener %q", config.listen)
		}
		return apiServer, err
	}
	executor, err := remediation.NewExecutor(manager.Remediations(), func(ctx context.Context) (remediation.GraphView, error) {
		view, latestErr := store.Latest(ctx)
		return remediation.GraphView{SHA256: view.SHA256, Snapshot: view.Snapshot}, latestErr
	})
	if err != nil {
		return nil, err
	}
	return api.NewServerWithRemediations(store, otlpReceiver, executor, rules)
}

// detectionServices are the detection components. All are nil unless
// --agentic-investigation or --deployment-rule-authoring is enabled.
type detectionServices struct {
	engine           *detector.Engine
	detection        *reasoning.Service
	investigation    *reasoning.InvestigationWorker
	deploymentAuthor *deploymentauthoring.Worker
}

// newDetectionServices builds deterministic detection, which never calls a
// model, and each enabled model-calling feature as its own worker.
func newDetectionServices(ctx context.Context, config options, store *state.Store) (detectionServices, error) {
	var services detectionServices
	if !config.detectionEnabled() {
		log.Printf("detection is disabled; pass --agentic-investigation and/or --deployment-rule-authoring to enable it")
		return services, nil
	}
	if err := store.EnsureDefaultDetectorRuleset(ctx); err != nil {
		return services, fmt.Errorf("bootstrap detector rules: %w", err)
	}
	engine, err := detector.Load(ctx, store, detector.DefaultConfig())
	if err != nil {
		return services, fmt.Errorf("load detector rules: %w", err)
	}
	services.engine = engine
	serviceConfig := reasoning.DefaultServiceConfig()
	serviceConfig.ConsumerID = config.detectionConsumer
	serviceConfig.PollInterval = config.detectionInterval
	serviceConfig.Detection = engine
	serviceConfig.QueueInvestigations = config.agenticInvestigation
	signalSink, err := reasoning.NewSignalSink(store, config.detectionSignalRetention, nil)
	if err != nil {
		return services, err
	}
	// The finding sink records rule findings and invalidates stale agentic
	// findings, so it runs even without agentic investigation.
	findingSink, err := reasoning.NewFindingSink(store, nil)
	if err != nil {
		return services, err
	}
	sinks := []reasoning.ResultSink{findingSink, signalSink}
	if config.agenticInvestigation {
		queue, err := reasoning.NewInvestigationQueue(store, config.investigationBatchWindow)
		if err != nil {
			return services, err
		}
		sinks = append(sinks, queue)
		if services.investigation, err = newInvestigationWorker(config, store); err != nil {
			return services, err
		}
	}
	if services.detection, err = reasoning.NewService(store, nil, reasoning.ResultSinks(sinks...), serviceConfig); err != nil {
		return services, err
	}
	if config.deploymentRuleAuthoring {
		authorModel := config.model
		// The default model name is an OpenAI model; let the Anthropic client
		// choose its own default unless the operator named a model.
		if config.modelProvider == reasoning.ProviderAnthropic && authorModel == reasoning.Model {
			authorModel = ""
		}
		services.deploymentAuthor, err = deploymentauthoring.NewWorker(store, deploymentauthoring.WorkerConfig{
			ID: fmt.Sprintf("deployment-author/%d", os.Getpid()), PollInterval: config.deploymentRulePollInterval,
			LeaseDuration: 30 * time.Second, BaselineWindow: config.deploymentRuleBaseline,
			Author: deploymentauthoring.ModelAuthor{Client: reasoning.Client{
				Endpoint: config.modelEndpoint, APIKey: config.modelAPIKey, Model: authorModel, Provider: config.modelProvider,
				ReasoningEffort: config.modelReasoningEffort, HTTPClient: &http.Client{Timeout: config.deploymentRuleAuthorTimeout},
			}},
			ReportError: func(err error) { log.Printf("Deployment rule authoring: %v", err) },
		})
		if err != nil {
			return services, err
		}
	}
	status := engine.Status()
	log.Printf("detection enabled (ruleset=%s, Deployment rules active=%d shadow=%d); agentic investigation=%t, Deployment rule authoring=%t",
		status.RulesetID, status.ActiveWorkloadRules, status.ShadowWorkloadRules, config.agenticInvestigation, config.deploymentRuleAuthoring)
	return services, nil
}

func newInvestigationWorker(config options, store *state.Store) (*reasoning.InvestigationWorker, error) {
	analyzer, err := newInvestigationAnalyzer(config)
	if err != nil {
		return nil, err
	}
	investigator, err := reasoning.NewInvestigator(analyzer, reasoning.DefaultLimits(), reasoning.DefaultContextLimits())
	if err != nil {
		return nil, err
	}
	sampling := reasoning.DefaultSamplingPolicy()
	sampling.SampleRate, sampling.MaxPerHour, sampling.DedupWindow = config.investigationSampleRate, config.investigationMaxPerHour, config.investigationDedupWindow
	return reasoning.NewInvestigationWorker(store, investigator, reasoning.InvestigationWorkerConfig{
		ID: fmt.Sprintf("investigation/%d", os.Getpid()), PollInterval: config.investigationPollInterval, LeaseDuration: 30 * time.Second,
		MaxAttempts: config.investigationMaxAttempts, Sampling: sampling, Retention: config.detectionSignalRetention,
		ReportError: func(err error) { log.Printf("agentic investigation: %v", err) },
	})
}

// newHTTPServer runs each onShutdown hook when Shutdown starts; the API uses
// one to end its long-lived event streams, which Shutdown would otherwise wait
// for until its deadline.
func newHTTPServer(listen string, handler http.Handler, onShutdown ...func()) *http.Server {
	// The graph event stream sets its own per-write deadline; WriteTimeout
	// would otherwise end it after 30 seconds.
	server := &http.Server{
		Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
	}
	for _, hook := range onShutdown {
		server.RegisterOnShutdown(hook)
	}
	return server
}

// serve runs every long-lived component until SIGINT, SIGTERM, or the first
// component failure or panic, then shuts the HTTP server down and waits for
// all components to return. The telemetry pipeline is stopped only after the
// HTTP server, so no ingest handler is still queueing events when it drains
// its final batch, and waiting lets that drain finish before run closes the
// sink and store.
func serve(config options, httpServer *http.Server, store *state.Store, pipeline *telemetry.Pipeline, manager *discovery.Manager, detection detectionServices) error {
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	group, ctx := errgroup.WithContext(signalContext)
	pipelineContext, stopPipeline := context.WithCancel(context.Background())
	defer stopPipeline()
	goRecover(group, "telemetry pipeline", func() error {
		if err := pipeline.Run(pipelineContext); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("telemetry pipeline: %w", err)
		}
		return nil
	})
	if manager != nil {
		goRecover(group, "discovery manager", func() error {
			if err := manager.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		})
	}
	if detection.deploymentAuthor != nil {
		goRecover(group, "Deployment rule author", func() error {
			detection.deploymentAuthor.Run(ctx)
			return nil
		})
	}
	if detection.investigation != nil {
		goRecover(group, "investigation worker", func() error {
			detection.investigation.Run(ctx)
			return nil
		})
	}
	if detection.detection != nil {
		goRecover(group, "detector reload", func() error {
			if err := detection.engine.RunReloads(ctx, store, config.detectorReloadInterval, func(err error) {
				log.Printf("detector reload failed; retaining last known-good rules: %v", err)
			}); err != nil {
				return fmt.Errorf("detector reload: %w", err)
			}
			return nil
		})
		goRecover(group, "detection service", func() error {
			if err := detection.detection.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("detection service: %w", err)
			}
			return nil
		})
	}
	goRecover(group, "HTTP server", func() error {
		log.Printf("AgentShield listening on http://%s", config.listen)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server: %w", err)
		}
		return nil
	})
	goRecover(group, "HTTP shutdown", func() error {
		// Stop the pipeline however this returns, so group.Wait cannot hang.
		defer stopPipeline()
		<-ctx.Done()
		// Restore default signal handling so a second interrupt terminates a
		// slow drain.
		stop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownContext)
	})
	return group.Wait()
}

// goRecover runs fn on group and turns a panic into an error that carries the
// stack, so a panicking component stops the process through the normal
// shutdown path, including the telemetry drain, instead of crashing it. It
// does not cover goroutines that fn starts itself.
func goRecover(group *errgroup.Group, component string, fn func() error) {
	group.Go(func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("%s panicked: %v\n%s", component, recovered, debug.Stack())
			}
		}()
		return fn()
	})
}

func newInvestigationAnalyzer(config options) (reasoning.Analyzer, error) {
	if !config.agenticInvestigation {
		return nil, nil
	}
	return modelanalyzer.New(reasoning.Client{Endpoint: config.modelEndpoint, APIKey: config.modelAPIKey, Model: config.model, ReasoningEffort: config.modelReasoningEffort}, modelanalyzer.Config{
		Analysis: reasoning.AnalysisConfig{Name: "agentshield-runtime", Compact: true, RetrievalMode: config.investigationRetrieval}, MaxAttempts: 3,
	})
}

func initialSnapshot(view state.GraphView, err error) (graph.Snapshot, error) {
	if err == nil {
		return view.Snapshot, nil
	}
	if errors.Is(err, state.ErrNotMaterialized) {
		return graph.Snapshot{}, nil
	}
	return graph.Snapshot{}, err
}

func discoveryPlugins(ctx context.Context, config options) ([]discovery.Plugin, error) {
	var plugins []discovery.Plugin
	if config.aws.Region != "" {
		awsDiscovery, err := awsDiscoveryPlugin(ctx, config.aws)
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, awsDiscovery)
	}
	if !config.kubernetes.Disabled {
		kubernetesPlugins, err := kubernetesDiscoveryPlugins(config, discovery.IdentityReferenceResolvers(plugins...))
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, kubernetesPlugins...)
	}
	if len(plugins) == 0 {
		return nil, errors.New("discovery enabled without a Kubernetes or AWS source")
	}
	return plugins, nil
}

func kubernetesDiscoveryPlugins(config options, identityResolvers []discovery.IdentityReferenceResolver) ([]discovery.Plugin, error) {
	var restConfig *rest.Config
	var err error
	if config.kubernetes.Kubeconfig == "" && os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		restConfig, err = rest.InClusterConfig()
	} else {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		loadingRules.ExplicitPath = config.kubernetes.Kubeconfig
		restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes client config: %w", err)
	}
	watchConfig, requestConfig := kubernetesClientConfigs(restConfig)
	dynamicClient, err := dynamic.NewForConfig(watchConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes dynamic client: %w", err)
	}
	actionClient, err := dynamic.NewForConfig(requestConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes action client: %w", err)
	}
	actionTransport, err := kubernetesplugin.NewDynamicTransport(actionClient)
	if err != nil {
		return nil, err
	}
	discoveryClient, err := k8sdiscovery.NewDiscoveryClientForConfig(requestConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes discovery client: %w", err)
	}
	consumerPlugins, err := kubernetesConsumerPlugins(config, actionTransport)
	if err != nil {
		return nil, err
	}
	// TODO: Add multi-context discovery. Each plugin owns its authority flags,
	// but consumers currently share one Kubernetes watch source and need matching
	// cluster IDs when their claims refer to the same provider objects.
	kubernetes, err := kubernetesplugin.New(kubernetesplugin.Config{
		ClusterID: config.kubernetes.ClusterID, NetworkID: config.kubernetes.NetworkID, SourceID: config.kubernetes.SourceID,
		Dynamic: dynamicClient, Actions: actionTransport, Discovery: discoveryClient, Resources: kubernetesplugin.ResourceRequirements(consumerPlugins...),
		IdentityResolvers: identityResolvers,
	})
	if err != nil {
		return nil, err
	}
	return append([]discovery.Plugin{kubernetes}, consumerPlugins...), nil
}

// Kubernetes client limits. client-go's defaults (5 QPS, burst 10) throttle
// the startup list of every watched resource type on a large cluster.
const (
	kubernetesQPS            = 50
	kubernetesBurst          = 100
	kubernetesRequestTimeout = 30 * time.Second
)

// kubernetesClientConfigs returns copies of config with higher client rate
// limits: one for the informer client and one for single requests (API
// discovery and remediation actions) that also has a request timeout.
// rest.Config.Timeout becomes the http.Client timeout, which also ends watch
// streams, so the informer client must not have one.
func kubernetesClientConfigs(config *rest.Config) (watch, request *rest.Config) {
	watch = rest.CopyConfig(config)
	watch.QPS, watch.Burst = kubernetesQPS, kubernetesBurst
	request = rest.CopyConfig(watch)
	request.Timeout = kubernetesRequestTimeout
	return watch, request
}

// kubernetesConsumerPlugins builds the plugins that consume the Kubernetes
// plugin's shared collections instead of opening their own watches.
func kubernetesConsumerPlugins(config options, actions kubernetesplugin.WriteTransport) ([]discovery.Plugin, error) {
	istio, err := istioplugin.New(istioplugin.Config{
		ClusterID: config.istio.ClusterID, NetworkID: config.istio.NetworkID, SourceID: config.istio.SourceID,
		RootNamespace: config.istio.RootNamespace, Actions: actions,
	})
	if err != nil {
		return nil, err
	}
	agentgateway, err := agentgatewayplugin.New(agentgatewayplugin.Config{ClusterID: config.agentgateway.ClusterID, SourceID: config.agentgateway.SourceID})
	if err != nil {
		return nil, err
	}
	cilium, err := ciliumplugin.New(ciliumplugin.Config{ClusterID: config.cilium.ClusterID, SourceID: config.cilium.SourceID, Actions: actions})
	if err != nil {
		return nil, err
	}
	falco, err := falcoplugin.New(falcoplugin.Config{ClusterID: config.falco.ClusterID, SourceID: config.falco.SourceID})
	if err != nil {
		return nil, err
	}
	return []discovery.Plugin{istio, agentgateway, cilium, falco}, nil
}

func awsDiscoveryPlugin(ctx context.Context, pluginConfig awsplugin.CLIConfig) (discovery.Plugin, error) {
	config, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(pluginConfig.Region))
	if err != nil {
		return nil, fmt.Errorf("load AWS SDK config: %w", err)
	}
	identity, err := sts.NewFromConfig(config).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("get AWS caller identity: %w", err)
	}
	parsed, err := arn.Parse(strings.TrimSpace(aws.ToString(identity.Arn)))
	if err != nil {
		return nil, fmt.Errorf("parse AWS caller ARN: %w", err)
	}
	sourceID, err := awsplugin.SourceID(parsed.Partition, aws.ToString(identity.Account), pluginConfig.Region)
	if err != nil {
		return nil, err
	}
	var subscriber awsplugin.EventSubscriber
	if strings.TrimSpace(pluginConfig.EventsQueueURL) != "" {
		subscriber, err = awsplugin.NewSQSSubscriber(sqs.NewFromConfig(config), awsplugin.SQSSubscriberConfig{
			QueueURL: pluginConfig.EventsQueueURL, AccountID: aws.ToString(identity.Account), Region: pluginConfig.Region,
			Subscriptions: awsplugin.InventoryEventSubscriptions(),
		})
		if err != nil {
			return nil, err
		}
	}
	plugin, err := awsplugin.New(awsplugin.Config{
		Partition: parsed.Partition, Region: pluginConfig.Region, SourceID: sourceID, EC2: ec2.NewFromConfig(config), Subscriber: subscriber,
		FirehoseStreamARN: pluginConfig.FirehoseStreamARN, FirehoseAccessKey: pluginConfig.FirehoseAccessKey,
	})
	if err != nil {
		return nil, err
	}
	return plugin, nil
}

func telemetrySink(config options) (telemetry.Sink, func() error, error) {
	if config.clickHouseURL != "" {
		sink, err := telemetry.NewClickHouseSink(telemetry.ClickHouseConfig{
			Endpoint: config.clickHouseURL, Database: config.clickHouseDatabase, Table: config.clickHouseTable,
			Username: config.clickHouseUsername, Password: os.Getenv("AGENTSHIELD_CLICKHOUSE_PASSWORD"),
		})
		return sink, func() error { return nil }, err
	}
	sink, err := telemetry.OpenJSONLSink(filepath.Clean(config.telemetryPath))
	if err != nil {
		return nil, nil, err
	}
	return sink, sink.Close, nil
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(name string, fallback bool) bool {
	parsed, err := strconv.ParseBool(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return parsed
}

func envString(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func loopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func latestSnapshot(ctx context.Context, store *state.Store) (graph.Snapshot, error) {
	record, err := store.Latest(ctx)
	if err != nil {
		if errors.Is(err, state.ErrNotMaterialized) {
			return graph.Snapshot{}, nil
		}
		return graph.Snapshot{}, err
	}
	return record.Snapshot, nil
}
