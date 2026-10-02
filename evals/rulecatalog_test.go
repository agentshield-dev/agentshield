package evals

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
)

func TestRuleCatalogIsValidAndBalanced(t *testing.T) {
	catalog, err := LoadRuleCatalog("rule-campaigns.json")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]map[string]bool{}
	for _, campaign := range catalog.Campaigns {
		if sources[campaign.Source] == nil {
			sources[campaign.Source] = map[string]bool{}
		}
		sources[campaign.Source][campaign.Class] = true
	}
	for source, classes := range sources {
		if !classes["benign"] {
			t.Fatalf("source %s has no benign control", source)
		}
	}
}

// TestRulePoliciesMatchTheirCampaignIntent replays each campaign's request
// actions through the detector the way live detection sees them: a request
// yields a telemetry input only for a new target, operation, and outcome, and a
// communicates-with input only for a new target. No policy may match a baseline
// input, and a policy must match an observed input exactly for security campaigns.
func TestRulePoliciesMatchTheirCampaignIntent(t *testing.T) {
	catalog, err := LoadRuleCatalog("rule-campaigns.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, campaign := range catalog.Campaigns {
		t.Run(campaign.ID, func(t *testing.T) {
			rules, err := policyRules(campaign.Policies, "source")
			if err != nil {
				t.Fatal(err)
			}
			engine, err := detector.New(detector.DefaultConfig(), detector.Ruleset{ID: "policies", Rules: rules})
			if err != nil {
				t.Fatal(err)
			}
			seenTelemetry, seenTargets := map[string]bool{}, map[string]bool{}
			inputs := func(actions []RuleAction) []detector.Event {
				var events []detector.Event
				for index, action := range actions {
					if action.Kind != RuleActionRequest {
						continue
					}
					outcome := "allowed"
					if action.Status() == 403 {
						outcome = "denied"
					}
					operation := action.Method + " " + action.Path
					anchors := []string{"source", action.Target}
					if key := action.Target + "\x00" + operation + "\x00" + outcome; !seenTelemetry[key] {
						seenTelemetry[key] = true
						events = append(events, detector.Event{
							ID: "telemetry/" + key, PluginID: "istio", SourceID: "cluster", Type: "telemetry", Kind: "active-probe",
							AnchorIDs: anchors, ObservedAt: time.Unix(int64(index), 0).UTC(),
							Input: detector.Input{Operation: operation, Outcome: outcome, DestinationRole: "service"},
						})
					}
					if !seenTargets[action.Target] {
						seenTargets[action.Target] = true
						events = append(events, detector.Event{
							ID: "edge/" + action.Target, PluginID: "telemetry", SourceID: "runtime", Type: "relationship", Kind: "communicates-with",
							AnchorIDs: anchors, ObservedAt: time.Unix(int64(index), 0).UTC(),
							Input: detector.Input{DestinationIPClass: "unknown", DestinationRole: "service"},
						})
					}
				}
				return events
			}
			matches := func(events []detector.Event) []string {
				t.Helper()
				result, err := engine.Evaluate(context.Background(), events)
				if err != nil {
					t.Fatal(err)
				}
				var matched []string
				for _, signal := range result.Signals {
					matched = append(matched, signal.RuleID)
				}
				return matched
			}
			if matched := matches(inputs(campaign.Baseline)); len(matched) != 0 {
				t.Fatalf("policies %v match baseline activity", matched)
			}
			if matched, want := matches(inputs(campaign.Observed)), campaign.Class == "security"; (len(matched) > 0) != want {
				t.Fatalf("policies matched observed activity: %v, want match=%t", matched, want)
			}
		})
	}
}

func TestRenderRuleCampaignDeploysSourceTargetsAndDenyPolicies(t *testing.T) {
	campaign := RuleCampaign{
		ID: "denied", Source: "report-batch-job",
		Targets: []RuleTarget{{Name: "reports-api", DenyPaths: []string{"/admin/*"}}, {Name: "archive-api"}},
	}
	workload := RenderRuleCampaign(campaign)
	for _, required := range []string{
		"name: report-batch-job", "name: reports-api", "name: archive-api", "kind: AuthorizationPolicy",
		"name: reports-api-deny-paths", "action: DENY", `paths: ["/admin/*"]`, "kind: Gateway, name: waypoint",
		`hosts: ["reports-api.` + workload.Namespace + `.svc.cluster.local"`,
	} {
		if !strings.Contains(workload.Manifest, required) {
			t.Fatalf("manifest missing %q:\n%s", required, workload.Manifest)
		}
	}
	if strings.Count(workload.Manifest, "kind: AuthorizationPolicy") != 1 {
		t.Fatal("only targets with deny paths get an AuthorizationPolicy")
	}
	if other := RenderRuleCampaign(RuleCampaign{ID: "other", Source: "report-batch-job"}); other.Namespace == workload.Namespace {
		t.Fatal("rule campaigns must get distinct namespaces")
	}
	if RenderRuleCampaign(RuleCampaign{ID: campaign.ID}).Namespace == RenderCampaign(Campaign{ID: campaign.ID}).Namespace {
		t.Fatal("rule and mission campaigns with one ID must get distinct namespaces")
	}
}

func TestRuleCatalogRejectsInvalidCampaigns(t *testing.T) {
	valid := func() RuleCampaign {
		return RuleCampaign{
			ID: "c", Class: "security", Description: "d", Source: "source-app", Targets: []RuleTarget{{Name: "target-api"}},
			Observed: []RuleAction{{Kind: RuleActionRequest, Target: "target-api", Method: "GET", Path: "/"}},
			Policies: []RulePolicy{{ID: "p", Selector: "telemetry:active-probe", Expression: "true", Rationale: "r"}},
		}
	}
	for name, modify := range map[string]func(*RuleCampaign){
		"unknown target":       func(c *RuleCampaign) { c.Observed[0].Target = "missing" },
		"lowercase method":     func(c *RuleCampaign) { c.Observed[0].Method = "get" },
		"restart with target":  func(c *RuleCampaign) { c.Observed = []RuleAction{{Kind: RuleActionRestart, Target: "target-api"}} },
		"security without req": func(c *RuleCampaign) { c.Observed = []RuleAction{{Kind: RuleActionRestart}} },
		"bad selector":         func(c *RuleCampaign) { c.Policies[0].Selector = "telemetry:unknown" },
		"bad expression":       func(c *RuleCampaign) { c.Policies[0].Expression = "unknown_variable" },
		"no policies":          func(c *RuleCampaign) { c.Policies = nil },
		"bad status":           func(c *RuleCampaign) { c.Observed[0].ExpectStatus = 42 },
		"source not a label":   func(c *RuleCampaign) { c.Source = "Source_App" },
		"unknown action":       func(c *RuleCampaign) { c.Observed[0].Kind = "scale" },
	} {
		t.Run(name, func(t *testing.T) {
			campaign := valid()
			modify(&campaign)
			if err := campaign.validate(); err == nil {
				t.Fatal("invalid campaign accepted")
			}
		})
	}
	if err := valid().validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRenderRuleBackgroundRunsSteadyClientsAgainstItsServices(t *testing.T) {
	background := RenderRuleBackground()
	if background.Namespace != RenderRuleBackground().Namespace || !strings.HasPrefix(background.Namespace, "aseval-") {
		t.Fatalf("background namespace %q is not stable", background.Namespace)
	}
	for _, service := range ruleBackgroundServices {
		if !strings.Contains(background.Manifest, "name: "+service+"\n") {
			t.Errorf("service %s is not rendered", service)
		}
	}
	for _, client := range ruleBackgroundClients {
		if !strings.Contains(background.Manifest, "name: "+client.name+"\n") || !strings.Contains(client.script, "while true; do") {
			t.Errorf("client %s is not rendered as a loop", client.name)
		}
		if !slices.ContainsFunc(ruleBackgroundServices, func(service string) bool {
			return strings.Contains(client.script, "http://"+service+".$NAMESPACE.svc.cluster.local:")
		}) {
			t.Errorf("client %s calls no background service", client.name)
		}
	}
}
