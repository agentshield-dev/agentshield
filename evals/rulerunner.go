package evals

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/deploymentauthoring"
	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

// Eval suites selected by RunConfig.Suite.
const (
	SuiteMission = "mission"
	SuiteRules   = "rules"
)

// RuleCampaignReport is the result of one rule campaign.
type RuleCampaignReport struct {
	SchemaVersion string           `json:"schemaVersion"`
	Campaign      RuleCampaign     `json:"campaign"`
	StartedAt     time.Time        `json:"startedAt"`
	FinishedAt    time.Time        `json:"finishedAt"`
	Phases        []PhaseReport    `json:"phases"`
	Rules         []RuleEvaluation `json:"rules"`
	Model         string           `json:"model,omitempty"`
	DetectorOnly  bool             `json:"detectorOnly,omitempty"`
	Error         string           `json:"error,omitempty"`
}

// RuleSuiteSummary aggregates the rule suite by rule source.
type RuleSuiteSummary struct {
	SchemaVersion string                  `json:"schemaVersion"`
	CompletedAt   time.Time               `json:"completedAt"`
	Campaigns     int                     `json:"campaigns"`
	Rules         map[string]*RuleSummary `json:"rules"`
	Model         string                  `json:"model,omitempty"`
	DetectorOnly  bool                    `json:"detectorOnly,omitempty"`
	Variant       string                  `json:"variant"`
	// AuthorSelectors are the selectors offered to the author; empty means every selector.
	AuthorSelectors []string `json:"authorSelectors,omitempty"`
}

// runRuleSuite scores operator policies and, unless detector-only, rules drafted
// by the production Deployment rule author, against live rule campaigns.
func runRuleSuite(ctx context.Context, config RunConfig) error {
	adapter, err := observationAdapter(config.ObservationAdapter)
	if err != nil {
		return err
	}
	catalog, err := LoadRuleCatalog(config.CatalogPath)
	if err != nil {
		return err
	}
	campaigns, err := selectRuleCampaigns(catalog.Campaigns, config.CampaignIDs)
	if err != nil {
		return err
	}
	for _, campaign := range campaigns {
		if strings.TrimSpace(RenderRuleCampaign(campaign).Manifest) == "" {
			return fmt.Errorf("rule campaign %s rendered an empty manifest", campaign.ID)
		}
	}
	if strings.TrimSpace(RenderRuleBackground().Manifest) == "" {
		return errors.New("rule background traffic rendered an empty manifest")
	}
	if config.ValidateOnly {
		return nil
	}
	if config.DatabaseURL == "" || config.OutputDir == "" || (!config.DetectorOnly && config.ModelEndpoint == "") {
		return errors.New("database URL and output directory are required, and a model endpoint is required unless detector-only")
	}
	if config.DetectorOnly {
		config.Model = ""
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
	var author deploymentauthoring.Author
	if !config.DetectorOnly {
		author = deploymentauthoring.ModelAuthor{Client: reasoning.Client{
			Endpoint: config.ModelEndpoint, Model: config.Model, ReasoningEffort: config.ReasoningEffort,
			HTTPClient: &http.Client{Timeout: 5 * time.Minute},
		}, Selectors: config.AuthorSelectors}
	}
	if err := os.MkdirAll(filepath.Join(config.OutputDir, "campaigns"), 0o755); err != nil {
		return err
	}
	background := RenderRuleBackground()
	defer func() {
		_ = kubectl(context.WithoutCancel(ctx), config.Kubeconfig, nil, "delete", "namespace", background.Namespace, "--ignore-not-found", "--wait=false")
	}()
	if err := startRuleBackground(ctx, store, config, adapter, background); err != nil {
		return fmt.Errorf("background traffic: %w", err)
	}
	for _, campaign := range campaigns {
		if err := runRuleCampaign(ctx, store, author, config, adapter, campaign); err != nil {
			return err
		}
	}
	return writeRuleSummary(config, campaigns)
}

func runRuleCampaign(ctx context.Context, store *state.Store, author deploymentauthoring.Author, config RunConfig, adapter ObservationAdapter, campaign RuleCampaign) (runErr error) {
	report := RuleCampaignReport{SchemaVersion: "agentshield.rule-eval-report/v1alpha1", Campaign: campaign, StartedAt: time.Now().UTC(), Model: config.Model, DetectorOnly: config.DetectorOnly}
	workload := RenderRuleCampaign(campaign)
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
	if err := applyWorkload(ctx, config, adapter, workload, "agentshield-rule-evals"); err != nil {
		return err
	}
	deployments := []string{campaign.Source}
	for _, target := range campaign.Targets {
		deployments = append(deployments, target.Name)
	}
	for _, deployment := range deployments {
		if err := kubectl(ctx, config.Kubeconfig, nil, "-n", workload.Namespace, "rollout", "status", "deployment/"+deployment, "--timeout=180s"); err != nil {
			return err
		}
	}
	if _, err := awaitSequence(ctx, store, before.ThroughSequence, config.Timeout); err != nil {
		return fmt.Errorf("topology convergence: %w", err)
	}
	settled, _, err := awaitQuiescence(ctx, store, 5*time.Second, time.Minute)
	if err != nil {
		return fmt.Errorf("topology quiescence: %w", err)
	}
	baseline, _, err := runRuleActions(ctx, store, config, workload, "baseline", campaign.Baseline, settled, &report)
	if err != nil {
		return err
	}
	// Draft at the end of the baseline phase, as the authoring worker would once
	// the baseline window has passed, from the same graph-backed context.
	var drafted authoredDraft
	if author != nil {
		deployment, found := findDeployment(baseline.View.Snapshot, workload.Namespace, campaign.Source)
		if !found {
			return fmt.Errorf("source Deployment %s/%s is not in the graph", workload.Namespace, campaign.Source)
		}
		drafted = draftRules(ctx, store, author, deployment)
	}
	observed, evidence, err := runRuleActions(ctx, store, config, workload, "observed", campaign.Observed, baseline, &report)
	if err != nil {
		return err
	}
	windows := []ruleWindow{
		{phase: "setup", previous: before, current: settled},
		{phase: "baseline", previous: settled, current: baseline},
		{phase: "observed", previous: baseline, current: observed, scored: true, observation: evidence},
	}
	deployment, found := findDeployment(observed.View.Snapshot, workload.Namespace, campaign.Source)
	if !found {
		return fmt.Errorf("source Deployment %s/%s is not in the graph", workload.Namespace, campaign.Source)
	}
	now := time.Now().UTC()
	rules, err := policyRules(campaign.Policies, deployment.ID)
	if err != nil {
		return err
	}
	policy, err := evaluateRules(ctx, RuleSourcePolicy, campaign.Class, rules, false, windows, now)
	if err != nil {
		return err
	}
	report.Rules = []RuleEvaluation{policy}
	if author == nil {
		return nil
	}
	evaluation, err := evaluateRules(ctx, RuleSourceAuthored, campaign.Class, drafted.rules, true, windows, now)
	if err != nil {
		return err
	}
	evaluation.Rationale, evaluation.ObservedBehavior = drafted.rationale, drafted.behavior
	if drafted.err != nil {
		evaluation.Error = drafted.err.Error()
	}
	report.Rules = append(report.Rules, evaluation)
	return nil
}

type authoredDraft struct {
	rules     []detector.Rule
	rationale string
	behavior  *state.DeploymentBehavior
	err       error
}

// draftRules authors rules for the source Deployment from the authoring
// worker's context: identity plus the current graph's observed behavior.
func draftRules(ctx context.Context, store *state.Store, author deploymentauthoring.Author, deployment graph.Resource) authoredDraft {
	workload, err := deploymentauthoring.WithBaseline(ctx, store, state.DeploymentAuthoringContextFor(deployment))
	if err != nil {
		return authoredDraft{err: fmt.Errorf("read Deployment baseline: %w", err)}
	}
	rules, rationale, err := authorRules(ctx, author, workload)
	return authoredDraft{rules: rules, rationale: rationale, behavior: workload.ObservedBehavior, err: err}
}

// startRuleBackground deploys the background namespace and waits until its
// mesh telemetry is in the graph, so every campaign baseline is taken in a
// cluster where telemetry is visibly collected.
func startRuleBackground(ctx context.Context, store *state.Store, config RunConfig, adapter ObservationAdapter, background WorkloadContract) error {
	if err := kubectl(ctx, config.Kubeconfig, nil, "delete", "namespace", background.Namespace, "--ignore-not-found", "--wait=true"); err != nil {
		return err
	}
	if err := applyWorkload(ctx, config, adapter, background, "agentshield-rule-evals-background"); err != nil {
		return err
	}
	for _, client := range ruleBackgroundClients {
		if err := kubectl(ctx, config.Kubeconfig, nil, "-n", background.Namespace, "rollout", "status", "deployment/"+client.name, "--timeout=180s"); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(config.Timeout)
	for {
		view, err := store.Latest(ctx)
		if err == nil && len(namespaceTelemetry(view.Snapshot, background.Namespace).Telemetry) > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no telemetry from %s reached the graph within %s", background.Namespace, config.Timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// applyWorkload applies the observation adapter's namespace setup, waits for
// it, then applies the workload. The two use separate field managers so the
// workload apply does not drop the adapter's namespace labels.
func applyWorkload(ctx context.Context, config RunConfig, adapter ObservationAdapter, workload WorkloadContract, fieldManager string) error {
	stages := []campaignApplyStage{{FieldManager: fieldManager, Manifest: workload.Manifest}}
	if manifest := strings.TrimSpace(adapter.Manifest(Campaign{}, workload)); manifest != "" {
		stages = append([]campaignApplyStage{{FieldManager: fieldManager + "-observation", Manifest: manifest, WaitForObservation: true}}, stages...)
	}
	for _, stage := range stages {
		if err := kubectl(ctx, config.Kubeconfig, []byte(stage.Manifest), "apply", "--server-side", "--field-manager="+stage.FieldManager, "-f", "-"); err != nil {
			return err
		}
		if stage.WaitForObservation {
			if err := adapter.WaitReady(ctx, config.Kubeconfig, workload); err != nil {
				return fmt.Errorf("observation adapter readiness: %w", err)
			}
		}
	}
	return nil
}

// runRuleActions runs one phase's actions in order and returns the checkpoint
// after the last one, plus the observation of the last request, if any.
func runRuleActions(ctx context.Context, store *state.Store, config RunConfig, workload WorkloadContract, phase string, actions []RuleAction, current state.GraphCheckpoint, report *RuleCampaignReport) (state.GraphCheckpoint, *ObservationEvidence, error) {
	var last *ObservationEvidence
	for index, action := range actions {
		started := time.Now().UTC()
		switch action.Kind {
		case RuleActionRequest:
			requestID := fmt.Sprintf("%s-%s-%d", workload.RuntimeID, phase, index)
			if err := probeStatus(ctx, config.Kubeconfig, workload, action, requestID); err != nil {
				return state.GraphCheckpoint{}, nil, fmt.Errorf("%s request %d: %w", phase, index, err)
			}
			checkpoint, evidence, err := awaitObservation(ctx, store, workload.Namespace, workload.Source, action.Target, started, config.Timeout)
			if err != nil {
				return state.GraphCheckpoint{}, nil, fmt.Errorf("%s observation contract: %w", phase, err)
			}
			current, last = checkpoint, &evidence
			report.Phases = append(report.Phases, PhaseReport{Name: phase, StartedAt: started, CheckpointSequence: checkpoint.ThroughSequence, ObservationContract: "verified", Observation: evidence})
		case RuleActionRestart:
			if err := kubectl(ctx, config.Kubeconfig, nil, "-n", workload.Namespace, "rollout", "restart", "deployment/"+workload.Source); err != nil {
				return state.GraphCheckpoint{}, nil, err
			}
			if err := kubectl(ctx, config.Kubeconfig, nil, "-n", workload.Namespace, "rollout", "status", "deployment/"+workload.Source, "--timeout=180s"); err != nil {
				return state.GraphCheckpoint{}, nil, err
			}
			if _, err := awaitSequence(ctx, store, current.ThroughSequence, config.Timeout); err != nil {
				return state.GraphCheckpoint{}, nil, fmt.Errorf("%s restart convergence: %w", phase, err)
			}
			checkpoint, _, err := awaitQuiescence(ctx, store, 5*time.Second, time.Minute)
			if err != nil {
				return state.GraphCheckpoint{}, nil, fmt.Errorf("%s restart quiescence: %w", phase, err)
			}
			current = checkpoint
			report.Phases = append(report.Phases, PhaseReport{Name: phase, StartedAt: started, CheckpointSequence: checkpoint.ThroughSequence, ObservationContract: "restart"})
		}
	}
	return current, last, nil
}

// probeStatus sends a request from the source and checks the response status,
// so a request the mesh denies is a valid observation.
func probeStatus(ctx context.Context, kubeconfig string, workload WorkloadContract, action RuleAction, requestID string) error {
	url := fmt.Sprintf("http://%s.%s.svc.cluster.local:8080%s", action.Target, workload.Namespace, action.Path)
	output, err := kubectlOutput(ctx, kubeconfig, "-n", workload.Namespace, "exec", "deployment/"+workload.Source, "--",
		"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "-X", action.Method, "-H", "X-Request-ID: "+requestID, url)
	if err != nil {
		return err
	}
	status, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil {
		return fmt.Errorf("unexpected curl output %q", output)
	}
	if status != action.Status() {
		return fmt.Errorf("%s %s returned %d, want %d", action.Method, action.Path, status, action.Status())
	}
	return nil
}

func kubectlOutput(ctx context.Context, kubeconfig string, args ...string) (string, error) {
	if kubeconfig != "" {
		args = append([]string{"--kubeconfig", kubeconfig}, args...)
	}
	command := exec.CommandContext(ctx, "kubectl", args...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func selectRuleCampaigns(campaigns []RuleCampaign, ids []string) ([]RuleCampaign, error) {
	if len(ids) == 0 {
		return campaigns, nil
	}
	byID := make(map[string]RuleCampaign, len(campaigns))
	for _, campaign := range campaigns {
		byID[campaign.ID] = campaign
	}
	selected := make([]RuleCampaign, 0, len(ids))
	for _, id := range ids {
		campaign, found := byID[id]
		if !found {
			return nil, fmt.Errorf("unknown rule campaign %q", id)
		}
		selected = append(selected, campaign)
	}
	return selected, nil
}

func writeRuleSummary(config RunConfig, campaigns []RuleCampaign) error {
	summary := RuleSuiteSummary{
		SchemaVersion: "agentshield.rule-eval-summary/v1alpha1", CompletedAt: time.Now().UTC(), Campaigns: len(campaigns),
		Rules: make(map[string]*RuleSummary), Model: config.Model, DetectorOnly: config.DetectorOnly, Variant: config.Variant,
		AuthorSelectors: config.AuthorSelectors,
	}
	for _, campaign := range campaigns {
		payload, err := os.ReadFile(filepath.Join(config.OutputDir, "campaigns", campaign.ID+".json"))
		if err != nil {
			return err
		}
		var report RuleCampaignReport
		if err := json.Unmarshal(payload, &report); err != nil {
			return err
		}
		if report.Error != "" {
			return fmt.Errorf("rule campaign %s is incomplete: %s", campaign.ID, report.Error)
		}
		for _, evaluation := range report.Rules {
			if summary.Rules[evaluation.Source] == nil {
				summary.Rules[evaluation.Source] = &RuleSummary{}
			}
			summary.Rules[evaluation.Source].add(evaluation)
		}
	}
	for _, rules := range summary.Rules {
		rules.finish()
	}
	return writeJSON(filepath.Join(config.OutputDir, "summary.json"), summary)
}
