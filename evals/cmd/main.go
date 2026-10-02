package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/evals"
)

func main() {
	config := evals.RunConfig{}
	var campaigns string
	flag.StringVar(&config.Suite, "suite", envOr("AGENTSHIELD_EVAL_SUITE", evals.SuiteMission), "eval suite: mission (model investigation) or rules (detection rules)")
	flag.StringVar(&config.CatalogPath, "catalog", "", "eval catalog; defaults to evals/campaigns.json for mission and evals/rule-campaigns.json for rules")
	flag.StringVar(&config.DatabaseURL, "database-url", os.Getenv("AGENTSHIELD_DATABASE_URL"), "AgentShield PostgreSQL URL")
	flag.StringVar(&config.ModelEndpoint, "model-endpoint", os.Getenv("AGENTSHIELD_MODEL_ENDPOINT"), "OpenAI-compatible model endpoint")
	flag.StringVar(&config.Model, "model", os.Getenv("AGENTSHIELD_MODEL"), "model name")
	flag.StringVar(&config.ReasoningEffort, "model-reasoning-effort", os.Getenv("AGENTSHIELD_MODEL_REASONING_EFFORT"), "OpenAI Responses reasoning effort for agentic investigation")
	flag.StringVar(&config.RetrievalMode, "agentic-investigation-retrieval", os.Getenv("AGENTSHIELD_AGENTIC_INVESTIGATION_RETRIEVAL"), "agentic investigation context retrieval: model_selected or deterministic")
	flag.StringVar(&config.Variant, "variant", os.Getenv("AGENTSHIELD_EVAL_VARIANT"), "evaluation variant label")
	flag.StringVar(&config.Kubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "eval cluster kubeconfig")
	flag.StringVar(&config.OutputDir, "output", "evals/output/live", "artifact directory")
	flag.StringVar(&config.ObservationAdapter, "observation-adapter", os.Getenv("AGENTSHIELD_EVAL_OBSERVATION_ADAPTER"), "plugin observation adapter")
	flag.StringVar(&campaigns, "campaigns", "", "comma-separated campaign IDs")
	flag.BoolVar(&config.ValidateOnly, "validate-only", false, "validate contracts without cluster changes or model calls")
	flag.BoolVar(&config.DetectorOnly, "detector-only", os.Getenv("AGENTSHIELD_EVAL_DETECTOR_ONLY") == "1", "measure deterministic detection without agentic investigation or model calls")
	flag.DurationVar(&config.Timeout, "timeout", 3*time.Minute, "per-phase convergence timeout")
	var authorSelectors string
	flag.StringVar(&authorSelectors, "author-selectors", os.Getenv("AGENTSHIELD_EVAL_AUTHOR_SELECTORS"), "comma-separated selectors the rule suite's Deployment rule author may use; empty offers every selector")
	flag.Parse()
	if config.CatalogPath == "" {
		config.CatalogPath = "evals/campaigns.json"
		if config.Suite == evals.SuiteRules {
			config.CatalogPath = "evals/rule-campaigns.json"
		}
	}
	if authorSelectors != "" {
		config.AuthorSelectors = strings.Split(authorSelectors, ",")
	}
	if campaigns != "" {
		config.CampaignIDs = strings.Split(campaigns, ",")
	}
	if err := evals.Run(context.Background(), config); err != nil {
		fmt.Fprintf(os.Stderr, "%s evals: %v\n", config.Suite, err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
