// Command agentshield-deployment-author runs one Deployment rule authoring
// model call outside the service. It reads a normalized Deployment authoring
// context and prints the proposed detector rules. With --dry-run it prints the
// exact first request body that would be sent to the selected provider, without
// sending any request. It uses the same author as the service's Deployment
// authoring worker and never writes to the database.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/internal/version"
	"github.com/agentshield-dev/agentshield/pkg/deploymentauthoring"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/state"
	"github.com/spf13/pflag"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := pflag.NewFlagSet("agentshield-deployment-author", pflag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.String("input", "", "JSON file containing normalized Deployment authoring context")
	flags.String("model-endpoint", os.Getenv("AGENTSHIELD_MODEL_ENDPOINT"), "model API base endpoint; defaults to AGENTSHIELD_MODEL_ENDPOINT")
	flags.String("model-api-key", "", "model API key; defaults to AGENTSHIELD_MODEL_API_KEY or the selected provider's API key")
	flags.Duration("timeout", 5*time.Minute, "maximum model request duration")
	flags.String("model", "", "model override; defaults to the selected provider's default model")
	flags.String("model-provider", "openai", "model API provider: openai or anthropic")
	flags.Bool("dry-run", false, "print the exact first request body that would be sent, without calling the model")
	flags.Bool("version", false, "print the version and exit")
	flags.Bool("verbose", false, "log add_rule calls and the run outcome to stderr at debug level")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if showVersion, _ := flags.GetBool("version"); showVersion {
		_, err := fmt.Fprintln(output, "agentshield-deployment-author "+version.String())
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	inputPath, _ := flags.GetString("input")
	endpoint, _ := flags.GetString("model-endpoint")
	modelAPIKey, _ := flags.GetString("model-api-key")
	timeout, _ := flags.GetDuration("timeout")
	model, _ := flags.GetString("model")
	providerName, _ := flags.GetString("model-provider")
	dryRun, _ := flags.GetBool("dry-run")
	verbose, _ := flags.GetBool("verbose")
	if inputPath == "" {
		return errors.New("--input is required")
	}
	var provider reasoning.Provider
	switch strings.ToLower(strings.TrimSpace(providerName)) {
	case "openai":
		provider = reasoning.ProviderOpenAI
	case "anthropic":
		provider = reasoning.ProviderAnthropic
		if strings.TrimSpace(endpoint) == "" {
			endpoint = "https://api.anthropic.com"
		}
	default:
		return fmt.Errorf("unsupported --model-provider %q (expected openai or anthropic)", providerName)
	}
	if strings.TrimSpace(endpoint) == "" && !dryRun {
		return errors.New("--model-endpoint or AGENTSHIELD_MODEL_ENDPOINT is required")
	}
	apiKey := ""
	if !dryRun {
		apiKey = strings.TrimSpace(modelAPIKey)
		if apiKey == "" {
			apiKey = strings.TrimSpace(os.Getenv("AGENTSHIELD_MODEL_API_KEY"))
		}
		if apiKey == "" {
			if provider == reasoning.ProviderAnthropic {
				apiKey = strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
			} else {
				apiKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
			}
		}
	}
	if timeout < 30*time.Second {
		return errors.New("--timeout must be at least 30 seconds")
	}
	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open Deployment context: %w", err)
	}
	defer func() { _ = input.Close() }()
	deploymentContext, err := decodeContext(input)
	if err != nil {
		return err
	}
	author := deploymentauthoring.ModelAuthor{Client: reasoning.Client{
		Endpoint: endpoint, APIKey: apiKey, HTTPClient: &http.Client{Timeout: timeout},
		Model: model, Provider: provider, DryRun: dryRun,
	}}
	if verbose {
		// Logs go to stderr so the proposal on stdout stays machine-readable.
		author.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	proposal, err := author.Author(context.Background(), deploymentContext)
	if err != nil {
		var preview *reasoning.RequestPreviewError
		if dryRun && errors.As(err, &preview) {
			if _, writeErr := output.Write(preview.Body); writeErr != nil {
				return fmt.Errorf("write model request preview: %w", writeErr)
			}
			if _, writeErr := io.WriteString(output, "\n"); writeErr != nil {
				return fmt.Errorf("write model request preview: %w", writeErr)
			}
			return nil
		}
		return fmt.Errorf("author Deployment rules: %w", err)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(proposal)
}

func decodeContext(input io.Reader) (state.DeploymentAuthoringContext, error) {
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	var deploymentContext state.DeploymentAuthoringContext
	if err := decoder.Decode(&deploymentContext); err != nil {
		return state.DeploymentAuthoringContext{}, fmt.Errorf("decode Deployment context: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return state.DeploymentAuthoringContext{}, errors.New("Deployment context must contain exactly one JSON document")
	}
	if err := deploymentauthoring.ValidateContext(deploymentContext); err != nil {
		return state.DeploymentAuthoringContext{}, err
	}
	return deploymentContext, nil
}
