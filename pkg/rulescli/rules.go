// Package rulescli implements the detector-rules commands shared by the
// agentshield rules subcommand and the compatibility binary.
package rulescli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/agentshield-dev/agentshield/internal/version"
	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
	"github.com/spf13/pflag"
)

// Run executes a detector-rules action. Its own flag set lets the command be
// mounted under another CLI without consuming that process's flags.
func Run(parent context.Context, args []string, output io.Writer) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if len(args) == 0 {
		return errors.New("usage: agentshield rules <validate|save|activate|show|jobs|job|review|workload-rules|signals|investigations> [flags] | --version")
	}
	action := args[0]
	if action == "--version" || action == "-version" {
		_, err := fmt.Fprintln(output, "agentshield rules "+version.String())
		return err
	}
	switch action {
	case "validate", "save", "activate", "show", "jobs", "job", "review", "workload-rules", "signals", "investigations":
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	flags := pflag.NewFlagSet("agentshield rules", pflag.ContinueOnError)
	flags.SetOutput(io.Discard)
	file := flags.String("file", "", "JSON ruleset file (validate/save)")
	id := flags.String("id", "", "ruleset ID (activate, or show a saved ruleset)")
	actor := flags.String("actor", "", "audit actor (save/activate)")
	expected := flags.Uint64("expected-revision", 0, "expected current activation revision; zero means no active ruleset")
	jobID := flags.Int64("job-id", 0, "Deployment rule authoring job ID (job, review)")
	decision := flags.String("decision", "", "review decision: approved runs the rule in active mode; rejected stops loading it (review)")
	ruleID := flags.String("rule-id", "", "only signals from this rule (signals)")
	investigation := flags.String("investigation", "", "only signals with this investigation state: investigated, below_threshold, disabled, or shadow (signals)")
	limit := flags.Int("limit", 100, "maximum signals or investigation jobs to list (signals, investigations)")
	databaseURL := flags.String("database-url", "", "PostgreSQL URL; defaults to AGENTSHIELD_DATABASE_URL")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	dbURL := *databaseURL
	if dbURL == "" {
		dbURL = os.Getenv("AGENTSHIELD_DATABASE_URL")
	}
	var ruleset detector.Ruleset
	if action == "validate" || action == "save" {
		if *file == "" {
			return errors.New("--file is required")
		}
		input, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer func() { _ = input.Close() }()
		ruleset, err = DecodeRuleset(input)
		if err != nil {
			return err
		}
		if err := detector.ValidateRuleset(ruleset); err != nil {
			return err
		}
		if action == "validate" {
			digest, err := detector.RulesetDigest(ruleset)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(output, "valid ruleset=%s rules=%d digest=%s\n", ruleset.ID, len(ruleset.Rules), digest)
			return err
		}
	}
	if (action == "save" || action == "activate" || action == "review") && *actor == "" {
		return errors.New("--actor is required")
	}
	if action == "activate" && *id == "" {
		return errors.New("--id is required")
	}
	if action == "review" && (*jobID < 1 || (*decision != state.DeploymentRuleReviewApproved && *decision != state.DeploymentRuleReviewRejected)) {
		return errors.New("review requires a positive --job-id and --decision approved or rejected")
	}
	store, err := state.Open(ctx, state.Config{DatabaseURL: dbURL}, graph.NewCompiler(graph.NewRegistry()))
	if err != nil {
		return err
	}
	defer store.Close()
	switch action {
	case "save":
		if err := store.SaveDetectorRuleset(ctx, ruleset, *actor); err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "saved ruleset=%s; not activated\n", ruleset.ID)
		return err
	case "activate":
		revision, err := store.ActivateDetectorRuleset(ctx, *id, *expected, *actor)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "activated ruleset=%s revision=%d\n", *id, revision)
		return err
	case "review":
		if err := store.ReviewDeploymentRuleJob(ctx, *jobID, *decision, *actor); err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "reviewed job=%d decision=%s; the runtime loads the change within its detector reload interval\n", *jobID, *decision)
		return err
	case "workload-rules":
		rules, err := store.ReadWorkloadRules(ctx)
		if err != nil {
			return err
		}
		if rules == nil {
			rules = []detector.WorkloadRule{}
		}
		return encodeJSON(output, rules)
	case "signals":
		signals, err := store.ListDetectionSignals(ctx, state.DetectionSignalQuery{RuleID: *ruleID, Investigation: *investigation, Limit: *limit})
		if err != nil {
			return err
		}
		if signals == nil {
			signals = []state.DetectionSignal{}
		}
		return encodeJSON(output, signals)
	case "investigations":
		jobs, err := store.ListInvestigationJobs(ctx, *limit)
		if err != nil {
			return err
		}
		if jobs == nil {
			jobs = []state.InvestigationJobSummary{}
		}
		return encodeJSON(output, jobs)
	case "jobs":
		jobs, err := store.ListDeploymentRuleJobs(ctx, 100)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(jobs)
	case "job":
		if *jobID < 1 {
			return errors.New("--job-id must be positive")
		}
		status, found, err := store.DeploymentRuleJobStatus(ctx, *jobID)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("Deployment authoring job %d not found", *jobID)
		}
		result := struct {
			Job      state.DeploymentRuleJobSummary `json:"job"`
			Proposal json.RawMessage                `json:"proposal,omitempty"`
		}{Job: status}
		if proposal, found, err := store.DeploymentRuleProposal(ctx, *jobID); err != nil {
			return err
		} else if found {
			result.Proposal = proposal
		}
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case "show":
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		if *id != "" {
			ruleset, err := store.ReadDetectorRuleset(ctx, *id)
			if err != nil {
				return err
			}
			return encoder.Encode(ruleset)
		}
		activation, err := store.ReadActiveDetectorRuleset(ctx)
		if err != nil {
			return err
		}
		return encoder.Encode(activation)
	}
	return nil
}

func encodeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// DecodeRuleset strictly decodes one bounded ruleset JSON document.
func DecodeRuleset(input io.Reader) (detector.Ruleset, error) {
	const limit = 8 * 1024 * 1024
	encoded, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil {
		return detector.Ruleset{}, err
	}
	if len(encoded) > limit {
		return detector.Ruleset{}, errors.New("ruleset JSON exceeds 8 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var ruleset detector.Ruleset
	if err := decoder.Decode(&ruleset); err != nil {
		return detector.Ruleset{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return detector.Ruleset{}, errors.New("ruleset file must contain exactly one JSON document")
	}
	return ruleset, nil
}
