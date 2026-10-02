package evals

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/deploymentauthoring"
	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

// Rule sources scored by the rule evals.
const (
	// RuleSourcePolicy is the campaign's operator-written policy, run as an active CEL ruleset.
	RuleSourcePolicy = "policy"
	// RuleSourceAuthored is the production Deployment rule author's draft for the
	// source workload, written from its observed behavior at the end of the
	// baseline phase and run as an approved (active) Deployment rule.
	RuleSourceAuthored = "authored"
)

// Rule eval outcomes.
const (
	RuleTruePositive  = "true_positive"
	RuleFalseNegative = "false_negative"
	RuleTrueNegative  = "true_negative"
	RuleFalsePositive = "false_positive"
)

// RuleEvaluation scores one rule source for one campaign across its windows.
type RuleEvaluation struct {
	Source    string          `json:"source"`
	Rules     []detector.Rule `json:"rules"`
	Rationale string          `json:"rationale,omitempty"`
	// ObservedBehavior is the baseline profile the author was given, if any.
	ObservedBehavior *state.DeploymentBehavior `json:"observedBehavior,omitempty"`
	// Error records a rule that could not be produced, such as a failed authoring call.
	Error  string      `json:"error,omitempty"`
	Phases []RulePhase `json:"phases"`
	// ObservedPathMatch reports a rule finding in the observed window whose signals
	// anchor both observed endpoints.
	ObservedPathMatch bool `json:"observedPathMatch"`
	// NormalPhaseFindings counts rule findings in the setup and baseline windows,
	// which contain only expected activity.
	NormalPhaseFindings int    `json:"normalPhaseFindings"`
	Outcome             string `json:"outcome"`
	MatchesExpectation  bool   `json:"matchesExpectation"`
}

// RulePhase is the rule output for one window.
type RulePhase struct {
	Phase    string                         `json:"phase"`
	Signals  []detector.InvestigationSignal `json:"signals"`
	Findings []state.Finding                `json:"findings"`
}

// ruleWindow is one evaluated change window: previous and current checkpoints.
// The scored window is the one under test; observation, when set, is the path a
// security finding must anchor to. Every other window is expected activity.
type ruleWindow struct {
	phase       string
	previous    state.GraphCheckpoint
	current     state.GraphCheckpoint
	scored      bool
	observation *ObservationEvidence
}

// evaluateRules runs rules through the production detector and rule-finding path
// over every window and scores them for the campaign class. Workload rules are
// loaded as approved Deployment rules; other rules form the active ruleset.
func evaluateRules(ctx context.Context, source, class string, rules []detector.Rule, workloadRules bool, windows []ruleWindow, now time.Time) (RuleEvaluation, error) {
	evaluation := RuleEvaluation{Source: source, Rules: rules, Phases: []RulePhase{}}
	if evaluation.Rules == nil {
		evaluation.Rules = []detector.Rule{}
	}
	engine, err := ruleEngine(source, rules, workloadRules)
	if err != nil {
		return RuleEvaluation{}, err
	}
	fired := false
	for _, window := range windows {
		result, err := engine.Detect(ctx, window.previous.View.Snapshot, window.current.View.Snapshot, now)
		if err != nil {
			return RuleEvaluation{}, fmt.Errorf("%s rules in %s window: %w", source, window.phase, err)
		}
		phase := RulePhase{Phase: window.phase, Signals: []detector.InvestigationSignal{}, Findings: []state.Finding{}}
		for _, signal := range result.Signals {
			if signal.RuleID != "" && signal.RuleMode != detector.RuleModeShadow {
				phase.Signals = append(phase.Signals, signal)
			}
		}
		for _, finding := range reasoning.RuleFindings(reasoning.Evaluation{
			Window: reasoning.ChangeWindow{Checkpoint: window.current}, RuleSignals: phase.Signals,
		}, now) {
			if err := finding.Validate(); err != nil {
				return RuleEvaluation{}, fmt.Errorf("%s rule finding in %s window: %w", source, window.phase, err)
			}
			phase.Findings = append(phase.Findings, finding)
		}
		fired = fired || len(phase.Findings) > 0
		if window.scored {
			evaluation.ObservedPathMatch = window.observation != nil && slices.ContainsFunc(phase.Signals, func(signal detector.InvestigationSignal) bool {
				return slices.Contains(signal.AnchorIDs, window.observation.SubjectID) && slices.Contains(signal.AnchorIDs, window.observation.ObjectID)
			})
		} else {
			evaluation.NormalPhaseFindings += len(phase.Findings)
		}
		evaluation.Phases = append(evaluation.Phases, phase)
	}
	switch {
	case class == "security" && evaluation.ObservedPathMatch:
		evaluation.Outcome = RuleTruePositive
	case class == "security":
		evaluation.Outcome = RuleFalseNegative
	case fired:
		evaluation.Outcome = RuleFalsePositive
	default:
		evaluation.Outcome = RuleTrueNegative
	}
	evaluation.MatchesExpectation = (evaluation.Outcome == RuleTruePositive || evaluation.Outcome == RuleTrueNegative) && evaluation.NormalPhaseFindings == 0
	return evaluation, nil
}

func ruleEngine(source string, rules []detector.Rule, workloadRules bool) (*detector.Engine, error) {
	if !workloadRules {
		return detector.New(detector.DefaultConfig(), detector.Ruleset{ID: "evals/" + source, Rules: rules})
	}
	engine, err := detector.New(detector.DefaultConfig(), detector.DefaultRuleset())
	if err != nil {
		return nil, err
	}
	overlay := make([]detector.WorkloadRule, 0, len(rules))
	for _, rule := range rules {
		overlay = append(overlay, detector.WorkloadRule{Rule: rule, Mode: detector.RuleModeActive})
	}
	return engine, engine.SetWorkloadRules(overlay)
}

// policyRules scopes rule policies to the source workload.
func policyRules(policies []RulePolicy, workloadResourceID string) ([]detector.Rule, error) {
	rules := make([]detector.Rule, 0, len(policies))
	for _, policy := range policies {
		rule, err := policy.Rule(workloadResourceID)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// authorRules drafts rules for the source Deployment with the production author.
func authorRules(ctx context.Context, author deploymentauthoring.Author, workload state.DeploymentAuthoringContext) ([]detector.Rule, string, error) {
	if author == nil {
		return nil, "", errors.New("Deployment rule author is required")
	}
	proposal, err := author.Author(ctx, workload)
	if err != nil {
		return nil, "", err
	}
	rules := make([]detector.Rule, 0, len(proposal.Rules))
	for _, candidate := range proposal.Rules {
		rules = append(rules, candidate.Rule)
	}
	return rules, proposal.Rationale, nil
}

// findDeployment returns the Kubernetes Deployment resource namespace/name.
func findDeployment(snapshot graph.Snapshot, namespace, name string) (graph.Resource, bool) {
	names := resourceNames(snapshot)
	for _, resource := range snapshot.Resources {
		if resource.Kind == "kubernetes/deployment" && names[resource.ID] == namespace+"/"+name {
			return resource, true
		}
	}
	return graph.Resource{}, false
}

// RuleSummary aggregates one rule source across campaigns.
type RuleSummary struct {
	Campaigns           int     `json:"campaigns"`
	TruePositive        int     `json:"truePositive"`
	FalseNegative       int     `json:"falseNegative"`
	TrueNegative        int     `json:"trueNegative"`
	FalsePositive       int     `json:"falsePositive"`
	SecurityRecall      float64 `json:"securityRecall"`
	BenignSpecificity   float64 `json:"benignSpecificity"`
	NormalPhaseFindings int     `json:"normalPhaseFindings"`
	// Abstentions counts campaigns where the source produced no rule.
	Abstentions int `json:"abstentions"`
	Errors      int `json:"errors"`
}

func (summary *RuleSummary) add(evaluation RuleEvaluation) {
	summary.Campaigns++
	switch evaluation.Outcome {
	case RuleTruePositive:
		summary.TruePositive++
	case RuleFalseNegative:
		summary.FalseNegative++
	case RuleTrueNegative:
		summary.TrueNegative++
	case RuleFalsePositive:
		summary.FalsePositive++
	}
	summary.NormalPhaseFindings += evaluation.NormalPhaseFindings
	if evaluation.Error != "" {
		summary.Errors++
	} else if len(evaluation.Rules) == 0 {
		summary.Abstentions++
	}
}

func (summary *RuleSummary) finish() {
	if total := summary.TruePositive + summary.FalseNegative; total > 0 {
		summary.SecurityRecall = float64(summary.TruePositive) / float64(total)
	}
	if total := summary.TrueNegative + summary.FalsePositive; total > 0 {
		summary.BenignSpecificity = float64(summary.TrueNegative) / float64(total)
	}
}
