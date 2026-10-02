package evals

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/detector"
)

const RuleCatalogSchemaVersion = "agentshield.rule-evals/v1alpha1"

// Rule action kinds.
const (
	// RuleActionRequest sends one HTTP request from the source to a target.
	RuleActionRequest = "request"
	// RuleActionRestart restarts the source Deployment, a routine rollout.
	RuleActionRestart = "restart"
)

// RuleCatalog is the rule-engine eval suite. Unlike the mission campaigns, each
// campaign is built around inputs detection rules evaluate.
type RuleCatalog struct {
	SchemaVersion string         `json:"schemaVersion"`
	Purpose       string         `json:"purpose"`
	Campaigns     []RuleCampaign `json:"campaigns"`
}

// RuleCampaign deploys one source workload and its targets, runs baseline
// actions, then observed actions. A security campaign expects a rule finding in
// the observed window anchored to the source and its last observed target; a
// benign campaign expects no rule to fire. No rule may fire during setup or the
// baseline.
type RuleCampaign struct {
	ID          string       `json:"id"`
	Class       string       `json:"class"`
	Description string       `json:"description"`
	Source      string       `json:"source"`
	Targets     []RuleTarget `json:"targets"`
	Baseline    []RuleAction `json:"baseline"`
	Observed    []RuleAction `json:"observed"`
	Policies    []RulePolicy `json:"policies"`
}

// RuleTarget is an HTTP service the source can call.
type RuleTarget struct {
	Name string `json:"name"`
	// DenyPaths are Istio path patterns an AuthorizationPolicy denies at the waypoint with 403.
	DenyPaths []string `json:"denyPaths,omitempty"`
}

// RuleAction is one step of a campaign phase.
type RuleAction struct {
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	// ExpectStatus is the HTTP status the request must receive; zero means 200.
	ExpectStatus int `json:"expectStatus,omitempty"`
}

// Status returns the expected HTTP status of a request action.
func (action RuleAction) Status() int {
	if action.ExpectStatus == 0 {
		return 200
	}
	return action.ExpectStatus
}

// RulePolicy is an operator-written CEL detection rule, scoped to the
// campaign's source workload when the campaign runs.
type RulePolicy struct {
	ID         string `json:"id"`
	Selector   string `json:"selector"`
	Expression string `json:"expression"`
	Rationale  string `json:"rationale"`
}

// Rule returns the policy as an active detector rule scoped to workloadResourceID.
func (policy RulePolicy) Rule(workloadResourceID string) (detector.Rule, error) {
	inputType, kind, ok := detector.ParseCELSelector(policy.Selector)
	if !ok {
		return detector.Rule{}, fmt.Errorf("rule policy %s has unsupported selector %q", policy.ID, policy.Selector)
	}
	return detector.Rule{
		ID: "evals/policy/" + policy.ID, Revision: 1, InputVersion: detector.InputVersion, PluginID: "*",
		WorkloadResourceID: workloadResourceID, Type: inputType, Kind: kind, Expression: policy.Expression,
		Risk: detector.RiskHigh, Reasons: []string{"workload_policy_violation"},
	}, nil
}

func LoadRuleCatalog(path string) (RuleCatalog, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return RuleCatalog{}, err
	}
	var catalog RuleCatalog
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return RuleCatalog{}, fmt.Errorf("decode rule eval catalog: %w", err)
	}
	if err := catalog.Validate(); err != nil {
		return RuleCatalog{}, err
	}
	return catalog, nil
}

var dnsLabel = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)

func (catalog RuleCatalog) Validate() error {
	if catalog.SchemaVersion != RuleCatalogSchemaVersion || strings.TrimSpace(catalog.Purpose) == "" {
		return fmt.Errorf("unsupported rule eval catalog %q", catalog.SchemaVersion)
	}
	seen := make(map[string]struct{}, len(catalog.Campaigns))
	classes := make(map[string]int)
	for _, campaign := range catalog.Campaigns {
		if _, duplicate := seen[campaign.ID]; duplicate || campaign.ID == "" {
			return fmt.Errorf("rule campaign ID %q is empty or duplicated", campaign.ID)
		}
		seen[campaign.ID] = struct{}{}
		if err := campaign.validate(); err != nil {
			return fmt.Errorf("rule campaign %s: %w", campaign.ID, err)
		}
		classes[campaign.Class]++
	}
	if classes["security"] == 0 || classes["benign"] == 0 {
		return errors.New("rule eval catalog requires security and benign campaigns")
	}
	return nil
}

func (campaign RuleCampaign) validate() error {
	if !slices.Contains([]string{"security", "benign"}, campaign.Class) || strings.TrimSpace(campaign.Description) == "" {
		return errors.New("requires class security or benign and a description")
	}
	if !dnsLabel.MatchString(campaign.Source) {
		return fmt.Errorf("source %q is not a DNS label", campaign.Source)
	}
	targets := make(map[string]struct{}, len(campaign.Targets))
	for _, target := range campaign.Targets {
		if !dnsLabel.MatchString(target.Name) || target.Name == campaign.Source {
			return fmt.Errorf("target %q is not a DNS label distinct from the source", target.Name)
		}
		if _, duplicate := targets[target.Name]; duplicate {
			return fmt.Errorf("duplicate target %q", target.Name)
		}
		targets[target.Name] = struct{}{}
		for _, path := range target.DenyPaths {
			if !strings.HasPrefix(path, "/") {
				return fmt.Errorf("target %s deny path %q must start with /", target.Name, path)
			}
		}
	}
	if len(campaign.Observed) == 0 {
		return errors.New("requires observed actions")
	}
	for phase, actions := range map[string][]RuleAction{"baseline": campaign.Baseline, "observed": campaign.Observed} {
		for _, action := range actions {
			if err := action.validate(targets); err != nil {
				return fmt.Errorf("%s action: %w", phase, err)
			}
		}
	}
	if campaign.Class == "security" && campaign.lastObservedRequest() == nil {
		return errors.New("a security campaign requires an observed request to anchor the expected finding")
	}
	return validateRulePolicies(campaign.Policies)
}

func (action RuleAction) validate(targets map[string]struct{}) error {
	switch action.Kind {
	case RuleActionRequest:
		if _, found := targets[action.Target]; !found {
			return fmt.Errorf("request target %q is not a campaign target", action.Target)
		}
		if action.Method == "" || action.Method != strings.ToUpper(action.Method) || !strings.HasPrefix(action.Path, "/") {
			return fmt.Errorf("request to %s requires an uppercase method and a path starting with /", action.Target)
		}
		if action.ExpectStatus != 0 && (action.ExpectStatus < 100 || action.ExpectStatus > 599) {
			return fmt.Errorf("request to %s has invalid expected status %d", action.Target, action.ExpectStatus)
		}
	case RuleActionRestart:
		if action.Target != "" || action.Method != "" || action.Path != "" || action.ExpectStatus != 0 {
			return errors.New("restart takes no target or request fields")
		}
	default:
		return fmt.Errorf("unsupported action kind %q", action.Kind)
	}
	return nil
}

// lastObservedRequest returns the request whose path a security finding must anchor to.
func (campaign RuleCampaign) lastObservedRequest() *RuleAction {
	for index := len(campaign.Observed) - 1; index >= 0; index-- {
		if campaign.Observed[index].Kind == RuleActionRequest {
			return &campaign.Observed[index]
		}
	}
	return nil
}

func validateRulePolicies(policies []RulePolicy) error {
	if len(policies) == 0 {
		return errors.New("requires at least one rule policy")
	}
	ruleset := detector.Ruleset{ID: "evals/policies"}
	for _, policy := range policies {
		if policy.ID == "" || strings.TrimSpace(policy.Rationale) == "" {
			return errors.New("every rule policy requires an ID and a rationale")
		}
		rule, err := policy.Rule("campaign-source-workload")
		if err != nil {
			return err
		}
		ruleset.Rules = append(ruleset.Rules, rule)
	}
	if err := detector.ValidateRuleset(ruleset); err != nil {
		return fmt.Errorf("rule policies: %w", err)
	}
	return nil
}
