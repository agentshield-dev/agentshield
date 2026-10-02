package evals

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/reasoning/modelanalyzer"
	"github.com/agentshield-dev/agentshield/pkg/state"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

type RunConfig struct {
	// Suite is SuiteMission (the default) or SuiteRules.
	Suite              string
	CatalogPath        string
	DatabaseURL        string
	ModelEndpoint      string
	Model              string
	ReasoningEffort    string
	RetrievalMode      string
	Variant            string
	Kubeconfig         string
	OutputDir          string
	CampaignIDs        []string
	ObservationAdapter string
	ValidateOnly       bool
	DetectorOnly       bool
	// AuthorSelectors, when set, restricts the selectors the rule suite's
	// Deployment rule author may use; empty offers every selector.
	AuthorSelectors []string
	Timeout         time.Duration
}

type PhaseReport struct {
	Name                string                    `json:"name"`
	StartedAt           time.Time                 `json:"startedAt"`
	CheckpointSequence  uint64                    `json:"checkpointSequence"`
	ObservationContract string                    `json:"observationContract"`
	Observation         ObservationEvidence       `json:"observation"`
	Incident            reasoning.IncidentContext `json:"incident,omitempty"`
}

// PhaseDetection records deterministic detection for one graph change window without model calls.
type PhaseDetection struct {
	Phase           string                         `json:"phase"`
	Signals         []detector.InvestigationSignal `json:"signals"`
	SignalCount     int                            `json:"signalCount"`
	EligibleSignals int                            `json:"eligibleSignals"`
	// InvokesAgent reports whether agentic investigation would run for this window.
	InvokesAgent bool `json:"invokesAgent"`
	// PathSignal reports an investigation-eligible signal anchored to both observed endpoints.
	PathSignal bool `json:"pathSignal,omitempty"`
	// Unsettled reports a setup window measured before the graph stopped changing.
	Unsettled bool `json:"unsettled,omitempty"`
}

type CampaignReport struct {
	SchemaVersion      string                         `json:"schemaVersion"`
	Campaign           Campaign                       `json:"campaign"`
	StartedAt          time.Time                      `json:"startedAt"`
	FinishedAt         time.Time                      `json:"finishedAt"`
	Phases             []PhaseReport                  `json:"phases"`
	Detection          []PhaseDetection               `json:"detection"`
	Signals            []detector.InvestigationSignal `json:"signals"`
	Retrievals         []reasoning.ContextResult      `json:"retrievals,omitempty"`
	Assessment         reasoning.Assessment           `json:"assessment"`
	Promotion          reasoning.Promotion            `json:"promotion"`
	Usage              reasoning.Usage                `json:"usage"`
	ModelLatencyMillis int64                          `json:"modelLatencyMillis"`
	Variant            string                         `json:"variant"`
	Model              string                         `json:"model,omitempty"`
	RetrievalMode      string                         `json:"retrievalMode,omitempty"`
	DetectorOnly       bool                           `json:"detectorOnly,omitempty"`
	MatchesExpectation bool                           `json:"matchesExpectation"`
	Error              string                         `json:"error,omitempty"`
}

// DetectionSummary aggregates deterministic detection across campaign phases.
type DetectionSummary struct {
	// SecurityPathRecall is the share of security campaigns whose observed window has an
	// investigation-eligible signal anchored to the observed path; promotion is impossible without one.
	SecurityPathRecall float64                       `json:"securityPathRecall"`
	Phases             map[string]PhaseDetectionStat `json:"phases"`
}

type PhaseDetectionStat struct {
	Windows             int `json:"windows"`
	WindowsWithSignals  int `json:"windowsWithSignals"`
	AgentInvocations    int `json:"agentInvocations"`
	Signals             int `json:"signals"`
	EligibleSignals     int `json:"eligibleSignals"`
	SecurityPathSignals int `json:"securityPathSignals,omitempty"`
}

type Summary struct {
	SchemaVersion       string           `json:"schemaVersion"`
	CompletedAt         time.Time        `json:"completedAt"`
	Campaigns           int              `json:"campaigns"`
	DetectorOnly        bool             `json:"detectorOnly,omitempty"`
	Detection           DetectionSummary `json:"detection"`
	TruePositive        int              `json:"truePositive"`
	FalseNegative       int              `json:"falseNegative"`
	TrueNegative        int              `json:"trueNegative"`
	FalsePositive       int              `json:"falsePositive"`
	ObservationFailures int              `json:"observationFailures"`
	SecurityRecall      float64          `json:"securityRecall"`
	BenignSpecificity   float64          `json:"benignSpecificity"`
	Usage               reasoning.Usage  `json:"usage"`
	ModelLatencyMillis  int64            `json:"modelLatencyMillis"`
	Variant             string           `json:"variant"`
	Model               string           `json:"model"`
	RetrievalMode       string           `json:"retrievalMode"`
}

func Run(ctx context.Context, config RunConfig) error {
	if config.ObservationAdapter == "" {
		config.ObservationAdapter = defaultObservationAdapterID
	}
	if config.Model == "" {
		config.Model = reasoning.Model
	}
	switch config.Suite {
	case "", SuiteMission:
	case SuiteRules:
		if config.Variant == "" {
			config.Variant = SuiteRules
		}
		return runRuleSuite(ctx, config)
	default:
		return fmt.Errorf("unsupported eval suite %q", config.Suite)
	}
	if config.RetrievalMode == "" {
		config.RetrievalMode = reasoning.RetrievalModelSelected
	}
	if config.Variant == "" {
		config.Variant = config.RetrievalMode
	}
	if config.RetrievalMode != reasoning.RetrievalModelSelected && config.RetrievalMode != reasoning.RetrievalDeterministic {
		return fmt.Errorf("unsupported retrieval mode %q", config.RetrievalMode)
	}
	adapter, err := observationAdapter(config.ObservationAdapter)
	if err != nil {
		return err
	}
	catalog, err := LoadCatalog(config.CatalogPath)
	if err != nil {
		return err
	}
	campaigns, err := selectCampaigns(catalog.Campaigns, config.CampaignIDs)
	if err != nil {
		return err
	}
	for _, campaign := range campaigns {
		workload := RenderCampaign(campaign)
		if strings.TrimSpace(workload.Manifest) == "" {
			return fmt.Errorf("campaign %s rendered an empty manifest", campaign.ID)
		}
	}
	if config.ValidateOnly {
		return nil
	}
	if config.DatabaseURL == "" || config.OutputDir == "" || (!config.DetectorOnly && config.ModelEndpoint == "") {
		return errors.New("database URL and output directory are required, and a model endpoint is required unless detector-only")
	}
	if config.DetectorOnly {
		config.Model, config.RetrievalMode = "", ""
		if config.Variant == reasoning.RetrievalModelSelected || config.Variant == "" {
			config.Variant = "detector-only"
		}
	}
	registry := graph.NewRegistry()
	if err := discovery.RegisterIdentitySchemes(registry, kubernetesplugin.Descriptor()); err != nil {
		return err
	}
	store, err := state.Open(ctx, state.Config{DatabaseURL: config.DatabaseURL}, graph.NewCompiler(registry))
	if err != nil {
		return err
	}
	defer store.Close()
	engine, err := detector.New(detector.DefaultConfig(), detector.DefaultRuleset())
	if err != nil {
		return err
	}
	var service *reasoning.Service
	if !config.DetectorOnly {
		analyzer, err := modelanalyzer.New(reasoning.Client{Endpoint: config.ModelEndpoint, Model: config.Model, ReasoningEffort: config.ReasoningEffort}, modelanalyzer.Config{Analysis: reasoning.AnalysisConfig{Name: "mission-evals", Compact: true, RetrievalMode: config.RetrievalMode}, MaxAttempts: 3})
		if err != nil {
			return err
		}
		serviceConfig := reasoning.DefaultServiceConfig()
		serviceConfig.Detection = engine
		service, err = reasoning.NewService(store, analyzer, nil, serviceConfig)
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(config.OutputDir, "campaigns"), 0o755); err != nil {
		return err
	}
	for _, campaign := range campaigns {
		if err := runCampaign(ctx, store, engine, service, config, adapter, campaign); err != nil {
			return err
		}
	}
	return writeSummary(config.OutputDir, config, campaigns)
}

func runCampaign(ctx context.Context, store *state.Store, engine *detector.Engine, service *reasoning.Service, config RunConfig, adapter ObservationAdapter, campaign Campaign) (runErr error) {
	report := CampaignReport{SchemaVersion: "agentshield.mission-eval-report/v1alpha1", Campaign: campaign, StartedAt: time.Now().UTC(), Variant: config.Variant, Model: config.Model, RetrievalMode: config.RetrievalMode, DetectorOnly: config.DetectorOnly}
	workload := RenderCampaign(campaign)
	defer func() {
		_ = kubectl(ctx, config.Kubeconfig, nil, "delete", "namespace", workload.Namespace, "--ignore-not-found", "--wait=true")
		report.FinishedAt = time.Now().UTC()
		if runErr != nil {
			report.Error = runErr.Error()
		}
		if err := writeJSON(filepath.Join(config.OutputDir, "campaigns", campaign.ID+".json"), report); err != nil && runErr == nil {
			runErr = err
		}
	}()
	if err := kubectl(ctx, config.Kubeconfig, nil, "delete", "namespace", workload.Namespace, "--ignore-not-found", "--wait=true"); err != nil {
		return err
	}
	before, err := store.ReadGraphCheckpoint(ctx)
	if err != nil {
		return err
	}
	for _, stage := range campaignApplyStages(adapter, campaign, workload) {
		if err := kubectl(ctx, config.Kubeconfig, []byte(stage.Manifest), "apply", "--server-side", "--field-manager="+stage.FieldManager, "-f", "-"); err != nil {
			return err
		}
		if stage.WaitForObservation {
			if err := adapter.WaitReady(ctx, config.Kubeconfig, workload); err != nil {
				return fmt.Errorf("observation adapter readiness: %w", err)
			}
		}
	}
	for _, deployment := range []string{workload.Source, workload.BaselineTarget, workload.ObservedTarget} {
		if err := kubectl(ctx, config.Kubeconfig, nil, "-n", workload.Namespace, "rollout", "status", "deployment/"+deployment, "--timeout=180s"); err != nil {
			return err
		}
	}
	if _, err := awaitSequence(ctx, store, before.ThroughSequence, config.Timeout); err != nil {
		return fmt.Errorf("topology convergence: %w", err)
	}
	settled, quiet, err := awaitQuiescence(ctx, store, 5*time.Second, time.Minute)
	if err != nil {
		return fmt.Errorf("topology quiescence: %w", err)
	}
	setup, err := detectPhase(ctx, engine, "setup", before.View.Snapshot, settled.View.Snapshot, nil)
	if err != nil {
		return err
	}
	setup.Unsettled = !quiet
	report.Detection = append(report.Detection, setup)
	history, err := reasoning.NewIncidentHistory(workload.RuntimeID)
	if err != nil {
		return err
	}
	baselineStarted := time.Now().UTC()
	if err := probe(ctx, config.Kubeconfig, workload, workload.BaselineTarget, campaign.BaselineRequest, workload.RuntimeID+"-baseline"); err != nil {
		return fmt.Errorf("baseline probe: %w", err)
	}
	baseline, evidence, err := awaitObservation(ctx, store, workload.Namespace, workload.Source, workload.BaselineTarget, baselineStarted, config.Timeout)
	if err != nil {
		return fmt.Errorf("baseline observation contract: %w", err)
	}
	baselineIncidentSnapshot := namespaceTelemetry(baseline.View.Snapshot, workload.Namespace)
	history.ObserveBaseline(baselineIncidentSnapshot)
	history.ObservePhase("baseline", baselineIncidentSnapshot)
	report.Phases = append(report.Phases, PhaseReport{Name: "baseline", StartedAt: baselineStarted, CheckpointSequence: baseline.ThroughSequence, ObservationContract: "verified", Observation: evidence})
	baselineDetection, err := detectPhase(ctx, engine, "baseline", settled.View.Snapshot, baseline.View.Snapshot, nil)
	if err != nil {
		return err
	}
	report.Detection = append(report.Detection, baselineDetection)
	observedStarted := time.Now().UTC()
	if err := probe(ctx, config.Kubeconfig, workload, workload.ObservedTarget, campaign.ObservedRequest, workload.RuntimeID+"-observed"); err != nil {
		return fmt.Errorf("observed probe: %w", err)
	}
	observed, evidence, err := awaitObservation(ctx, store, workload.Namespace, workload.Source, workload.ObservedTarget, observedStarted, config.Timeout)
	if err != nil {
		return fmt.Errorf("observed observation contract: %w", err)
	}
	history.ObservePhase("observed", namespaceTelemetry(observed.View.Snapshot, workload.Namespace))
	incident, err := history.Context(time.Now().UTC())
	if err != nil {
		return err
	}
	report.Phases = append(report.Phases, PhaseReport{Name: "observed", StartedAt: observedStarted, CheckpointSequence: observed.ThroughSequence, ObservationContract: "verified", Observation: evidence, Incident: incident})
	observedDetection, err := detectPhase(ctx, engine, "observed", baseline.View.Snapshot, observed.View.Snapshot, &evidence)
	if err != nil {
		return err
	}
	report.Detection = append(report.Detection, observedDetection)
	if config.DetectorOnly {
		report.Signals = observedDetection.Signals
		report.MatchesExpectation = campaign.Class != "security" || observedDetection.PathSignal
		return nil
	}
	evaluation, err := service.EvaluateWindowWithIncident(ctx, &baseline.View.Snapshot, baseline.ThroughSequence, incident)
	if err != nil {
		return err
	}
	if evaluation.Rebased || len(evaluation.Window.Events) == 0 {
		return errors.New("observed phase did not produce a coherent graph change window")
	}
	report.Signals = evaluation.Signals
	outcome := evaluation.Analysis.Outcome
	report.Retrievals = outcome.Retrievals
	report.Assessment = outcome.Response.Assessment
	report.Promotion = outcome.Promotion
	report.Usage = outcome.Usage()
	report.ModelLatencyMillis = outcome.Latency()
	detected := outcome.Promotion.Status == "promoted"
	report.MatchesExpectation = (campaign.Expected.Decision == "candidate_finding" && detected && slices.Contains(campaign.Expected.Categories, outcome.Response.Assessment.Category)) || (campaign.Expected.Decision == "no_finding" && !detected)
	return nil
}

func probe(ctx context.Context, kubeconfig string, workload WorkloadContract, target string, request Request, requestID string) error {
	url := fmt.Sprintf("http://%s.%s.svc.cluster.local:8080%s", target, workload.Namespace, request.Path)
	return kubectl(ctx, kubeconfig, nil, "-n", workload.Namespace, "exec", "deployment/"+workload.Source, "--", "curl", "-fsS", "--max-time", "10", "-X", request.Method, "-H", "X-Request-ID: "+requestID, url)
}

func awaitSequence(ctx context.Context, store *state.Store, after uint64, timeout time.Duration) (state.GraphCheckpoint, error) {
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return state.GraphCheckpoint{}, ctx.Err()
		case <-deadline.C:
			return state.GraphCheckpoint{}, fmt.Errorf("graph sequence did not advance beyond %d", after)
		case <-ticker.C:
			checkpoint, err := store.ReadGraphCheckpoint(ctx)
			if err != nil {
				return state.GraphCheckpoint{}, err
			}
			if checkpoint.ThroughSequence > after {
				return checkpoint, nil
			}
		}
	}
}

type ObservationEvidence struct {
	PluginID    string   `json:"pluginId"`
	SourceID    string   `json:"sourceId"`
	Kind        string   `json:"kind"`
	SubjectID   string   `json:"subjectId"`
	ObjectID    string   `json:"objectId"`
	EvidenceIDs []string `json:"evidenceIds"`
}

type campaignApplyStage struct {
	FieldManager       string
	Manifest           string
	WaitForObservation bool
}

func campaignApplyStages(adapter ObservationAdapter, campaign Campaign, workload WorkloadContract) []campaignApplyStage {
	var stages []campaignApplyStage
	if observationManifest := strings.TrimSpace(adapter.Manifest(campaign, workload)); observationManifest != "" {
		stages = append(stages, campaignApplyStage{FieldManager: "agentshield-mission-evals-observation", Manifest: observationManifest, WaitForObservation: true})
	}
	stages = append(stages, campaignApplyStage{FieldManager: "agentshield-mission-evals", Manifest: workload.Manifest})
	return stages
}

func awaitObservation(ctx context.Context, store *state.Store, namespace, source, target string, after time.Time, timeout time.Duration) (state.GraphCheckpoint, ObservationEvidence, error) {
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return state.GraphCheckpoint{}, ObservationEvidence{}, ctx.Err()
		case <-deadline.C:
			return state.GraphCheckpoint{}, ObservationEvidence{}, fmt.Errorf("no provider-produced %s/%s to %s observation after %s", namespace, source, target, after.Format(time.RFC3339))
		case <-ticker.C:
			checkpoint, err := store.ReadGraphCheckpoint(ctx)
			if err != nil {
				return state.GraphCheckpoint{}, ObservationEvidence{}, err
			}
			resources := resourceNames(checkpoint.View.Snapshot)
			for _, event := range checkpoint.View.Snapshot.Telemetry {
				observedAt, ok := event.Properties["telemetry/last-seen"]
				parsed, parseErr := time.Parse(time.RFC3339Nano, observedAt)
				if !ok || parseErr != nil || parsed.Before(after) {
					continue
				}
				if resources[event.SubjectID] == namespace+"/"+source && resources[event.ObjectID] == namespace+"/"+target {
					return checkpoint, ObservationEvidence{PluginID: event.PluginID, SourceID: event.SourceID, Kind: event.Kind, SubjectID: event.SubjectID, ObjectID: event.ObjectID, EvidenceIDs: append([]string(nil), event.EvidenceIDs...)}, nil
				}
			}
		}
	}
}

// awaitQuiescence returns the graph checkpoint once its sequence has not advanced
// for quiet. After limit it returns the latest checkpoint with settled=false, so
// unrelated cluster churn cannot fail a campaign.
func awaitQuiescence(ctx context.Context, store *state.Store, quiet, limit time.Duration) (state.GraphCheckpoint, bool, error) {
	deadline := time.Now().Add(limit)
	checkpoint, err := store.ReadGraphCheckpoint(ctx)
	if err != nil {
		return state.GraphCheckpoint{}, false, err
	}
	stableSince := time.Now()
	for time.Since(stableSince) < quiet {
		if time.Now().After(deadline) {
			return checkpoint, false, nil
		}
		select {
		case <-ctx.Done():
			return state.GraphCheckpoint{}, false, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		next, err := store.ReadGraphCheckpoint(ctx)
		if err != nil {
			return state.GraphCheckpoint{}, false, err
		}
		if next.ThroughSequence != checkpoint.ThroughSequence {
			checkpoint, stableSince = next, time.Now()
		}
	}
	return checkpoint, true, nil
}

func detectPhase(ctx context.Context, engine *detector.Engine, phase string, previous, current graph.Snapshot, observation *ObservationEvidence) (PhaseDetection, error) {
	result, err := engine.Detect(ctx, previous, current, time.Now().UTC())
	if err != nil {
		return PhaseDetection{}, fmt.Errorf("%s detection: %w", phase, err)
	}
	detection := PhaseDetection{Phase: phase, Signals: result.Signals, SignalCount: len(result.Signals)}
	if detection.Signals == nil {
		detection.Signals = []detector.InvestigationSignal{}
	}
	for _, signal := range result.Signals {
		if signal.RuleID != "" || !reasoning.InvestigationEligible(signal) {
			continue
		}
		detection.EligibleSignals++
		if observation != nil && slices.Contains(signal.AnchorIDs, observation.SubjectID) && slices.Contains(signal.AnchorIDs, observation.ObjectID) {
			detection.PathSignal = true
		}
	}
	detection.InvokesAgent = detection.EligibleSignals > 0
	return detection, nil
}

func resourceNames(snapshot graph.Snapshot) map[string]string {
	result := make(map[string]string)
	for _, resource := range snapshot.Resources {
		for _, assertion := range resource.Assertions {
			name := assertion.Attributes["kubernetes/name"]
			namespace := assertion.Attributes["kubernetes/namespace"]
			if name != "" && namespace != "" {
				result[resource.ID] = namespace + "/" + name
			}
		}
	}
	return result
}

func namespaceTelemetry(snapshot graph.Snapshot, namespace string) graph.Snapshot {
	names := resourceNames(snapshot)
	result := graph.Snapshot{}
	for _, event := range snapshot.Telemetry {
		if strings.HasPrefix(names[event.SubjectID], namespace+"/") && strings.HasPrefix(names[event.ObjectID], namespace+"/") && len(event.EvidenceIDs) > 0 {
			result.Telemetry = append(result.Telemetry, event)
		}
	}
	return result
}

func kubectl(ctx context.Context, kubeconfig string, input []byte, args ...string) error {
	if kubeconfig != "" {
		args = append([]string{"--kubeconfig", kubeconfig}, args...)
	}
	command := exec.CommandContext(ctx, "kubectl", args...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func selectCampaigns(campaigns []Campaign, ids []string) ([]Campaign, error) {
	if len(ids) == 0 {
		return slices.Clone(campaigns), nil
	}
	wanted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	var selected []Campaign
	for _, campaign := range campaigns {
		if _, ok := wanted[campaign.ID]; ok {
			selected = append(selected, campaign)
			delete(wanted, campaign.ID)
		}
	}
	if len(wanted) != 0 {
		return nil, fmt.Errorf("unknown campaign IDs: %v", ids)
	}
	return selected, nil
}

func writeJSON(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(payload, '\n'), 0o644)
}

func writeSummary(outputDir string, config RunConfig, campaigns []Campaign) error {
	summary := Summary{SchemaVersion: "agentshield.mission-eval-summary/v1alpha1", CompletedAt: time.Now().UTC(), Campaigns: len(campaigns), DetectorOnly: config.DetectorOnly, Variant: config.Variant, Model: config.Model, RetrievalMode: config.RetrievalMode}
	summary.Detection.Phases = make(map[string]PhaseDetectionStat)
	securityCampaigns, securityPaths := 0, 0
	for _, campaign := range campaigns {
		payload, err := os.ReadFile(filepath.Join(outputDir, "campaigns", campaign.ID+".json"))
		if err != nil {
			return err
		}
		var report CampaignReport
		if err := json.Unmarshal(payload, &report); err != nil {
			return err
		}
		if report.Error != "" {
			if strings.Contains(report.Error, "observation contract") {
				summary.ObservationFailures++
			}
			return fmt.Errorf("campaign %s is incomplete: %s", campaign.ID, report.Error)
		}
		if campaign.Class == "security" {
			securityCampaigns++
		}
		for _, phase := range report.Detection {
			stat := summary.Detection.Phases[phase.Phase]
			stat.Windows++
			stat.Signals += phase.SignalCount
			stat.EligibleSignals += phase.EligibleSignals
			if phase.SignalCount > 0 {
				stat.WindowsWithSignals++
			}
			if phase.InvokesAgent {
				stat.AgentInvocations++
			}
			if phase.PathSignal && campaign.Class == "security" {
				stat.SecurityPathSignals++
				securityPaths++
			}
			summary.Detection.Phases[phase.Phase] = stat
		}
		if config.DetectorOnly {
			continue
		}
		detected := report.Promotion.Status == "promoted"
		switch {
		case campaign.Class == "security" && detected:
			summary.TruePositive++
		case campaign.Class == "security":
			summary.FalseNegative++
		case detected:
			summary.FalsePositive++
		default:
			summary.TrueNegative++
		}
		summary.Usage.PromptTokens += report.Usage.PromptTokens
		summary.Usage.CompletionTokens += report.Usage.CompletionTokens
		summary.Usage.ReasoningTokens += report.Usage.ReasoningTokens
		summary.Usage.TotalTokens += report.Usage.TotalTokens
		summary.ModelLatencyMillis += report.ModelLatencyMillis
	}
	if securityCampaigns > 0 {
		summary.Detection.SecurityPathRecall = float64(securityPaths) / float64(securityCampaigns)
	}
	if total := summary.TruePositive + summary.FalseNegative; total > 0 {
		summary.SecurityRecall = float64(summary.TruePositive) / float64(total)
	}
	if total := summary.TrueNegative + summary.FalsePositive; total > 0 {
		summary.BenignSpecificity = float64(summary.TrueNegative) / float64(total)
	}
	return writeJSON(filepath.Join(outputDir, "summary.json"), summary)
}
