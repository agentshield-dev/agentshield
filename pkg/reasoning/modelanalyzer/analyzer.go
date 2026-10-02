package modelanalyzer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/reasoning/mcpserver"
)

// Config configures an [Analyzer]. MaxAttempts defaults to 3.
type Config struct {
	Analysis    reasoning.AnalysisConfig
	MaxAttempts int
}

// Analyzer runs model investigations with bounded retry.
type Analyzer struct {
	client reasoning.Client
	config Config
}

// New returns an analyzer for client. The client must have an endpoint.
func New(client reasoning.Client, config Config) (*Analyzer, error) {
	if strings.TrimSpace(client.Endpoint) == "" {
		return nil, errors.New("model endpoint is required")
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 3
	}
	if config.MaxAttempts < 1 {
		return nil, errors.New("analysis max attempts must be positive")
	}
	if config.Analysis.Name == "" {
		config.Analysis.Name = "agentshield-reasoning"
	}
	return &Analyzer{client: client, config: config}, nil
}

// Analyze implements [reasoning.Analyzer]. The returned run records every
// failed attempt's error, including when a later attempt succeeds.
func (analyzer *Analyzer) Analyze(ctx context.Context, packet reasoning.Packet, provider *reasoning.ContextProvider) (reasoning.AnalysisRun, error) {
	var attemptErrors []string
	for attempt := 1; attempt <= analyzer.config.MaxAttempts; attempt++ {
		session, closeSession, err := mcpserver.ConnectInMemory(ctx, provider)
		if err != nil {
			return reasoning.AnalysisRun{Attempts: attempt, Errors: attemptErrors}, err
		}
		outcome, analyzeErr := reasoning.AnalyzeCandidateWithTools(ctx, analyzer.client, packet, analyzer.config.Analysis, session)
		closeErr := closeSession()
		if analyzeErr == nil && closeErr == nil {
			return reasoning.AnalysisRun{Outcome: outcome, Attempts: attempt, Errors: attemptErrors}, nil
		}
		cause := analyzeErr
		if cause == nil {
			cause = closeErr
		}
		attemptErrors = append(attemptErrors, cause.Error())
		// Repeating a request the endpoint rejected as invalid, or after the
		// caller gave up, cannot succeed.
		if reasoning.IsPermanentModelError(cause) || ctx.Err() != nil {
			return reasoning.AnalysisRun{Attempts: attempt, Errors: attemptErrors}, fmt.Errorf("analysis failed after %d attempts: %w", attempt, cause)
		}
	}
	return reasoning.AnalysisRun{Attempts: analyzer.config.MaxAttempts, Errors: attemptErrors}, fmt.Errorf("analysis failed after %d attempts: %s", analyzer.config.MaxAttempts, strings.Join(attemptErrors, "; "))
}
