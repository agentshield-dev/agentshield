package remediation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// IneligibleTargetError lets a provider report that a proposal's target
// cannot take its action, as distinct from a transient failure.
type IneligibleTargetError struct {
	ProviderID string
	Reason     string
}

// Error implements error.
func (err *IneligibleTargetError) Error() string {
	return fmt.Sprintf("remediation target is ineligible for provider %q: %s", err.ProviderID, err.Reason)
}

// Action is one remediation a provider can perform: an intent for targets of
// one kind, identity scheme, and authority. ID has the form "mechanism/vN".
type Action struct {
	ID          string
	Intent      Intent
	TargetKind  string
	Scheme      graph.IdentityScheme
	AuthorityID string
	Mode        Mode
}

// Descriptor lists a provider's actions.
type Descriptor struct {
	Actions []Action
}

// Provider implements remediation actions for one configured source.
//
// Plan must be deterministic for the same proposal and provider state.
// Prepare must validate every intended write without persisting it. Execute
// must re-read the prepared observations, refuse to write when they changed,
// and roll back partial writes where it can. Verify re-reads the declared
// configuration. Every returned value must be built with this package's
// constructors so its content-derived ID matches.
type Provider interface {
	RemediationDescriptor() Descriptor
	Plan(context.Context, Proposal, string) (Plan, error)
	Prepare(context.Context, Proposal, Plan) (Preparation, error)
	Execute(context.Context, Proposal, Plan, Preparation) (ExecutionResult, error)
	Verify(context.Context, Proposal, Plan, ExecutionResult) (Verification, error)
}

// Registration binds a provider to host-attested provider and source IDs.
// The host, not the provider, decides these IDs.
type Registration struct {
	ProviderID string
	SourceID   string
	Provider   Provider
}

// Registry indexes provider actions by what they can act on. It is immutable
// after construction.
type Registry struct {
	providers map[actionKey][]registeredAction
	byID      map[providerActionKey]registeredAction
}

type actionKey struct {
	intent      Intent
	targetKind  string
	scheme      graph.IdentityScheme
	authorityID string
}

type providerActionKey struct {
	providerID string
	sourceID   string
	actionID   string
}

type registeredAction struct {
	providerID string
	sourceID   string
	action     Action
	provider   Provider
}

// Candidate is one eligible provider action for a proposal.
type Candidate struct {
	ProviderID string `json:"providerId"`
	SourceID   string `json:"sourceId"`
	ActionID   string `json:"actionId"`
	Mode       Mode   `json:"mode"`
}

// AdvisoryOnlyError is returned when an advisory-only plan is prepared,
// executed, or verified.
type AdvisoryOnlyError struct {
	ProviderID string
	Operation  string
}

// Error implements error.
func (err *AdvisoryOnlyError) Error() string {
	return fmt.Sprintf("remediation provider %q is advisory-only and cannot %s", err.ProviderID, err.Operation)
}

// NewRegistry validates and indexes every registration's actions. A
// (provider, source, action) triple must be unique.
func NewRegistry(registrations ...Registration) (*Registry, error) {
	registry := &Registry{providers: make(map[actionKey][]registeredAction), byID: make(map[providerActionKey]registeredAction)}
	seenProviders := make(map[providerActionKey]Provider, len(registrations))
	for _, registration := range registrations {
		provider := registration.Provider
		if provider == nil {
			return nil, errors.New("nil remediation provider")
		}
		if registration.ProviderID == "" || registration.SourceID == "" {
			return nil, errors.New("remediation registration requires host-attested provider and source IDs")
		}
		providerKey := providerActionKey{providerID: registration.ProviderID, sourceID: registration.SourceID}
		if existing, found := seenProviders[providerKey]; found && existing != provider {
			return nil, fmt.Errorf("remediation provider instance %q/%q registered more than once", registration.ProviderID, registration.SourceID)
		}
		seenProviders[providerKey] = provider
		descriptor := provider.RemediationDescriptor()
		if len(descriptor.Actions) == 0 {
			continue
		}
		for _, action := range descriptor.Actions {
			if !validActionID(action.ID) || !action.Intent.Valid() || action.TargetKind == "" || action.Scheme.Group == "" || action.Scheme.Version == "" || action.Scheme.Kind == "" || action.AuthorityID == "" || !action.Mode.Valid() {
				return nil, fmt.Errorf("remediation provider %q has an invalid action", registration.ProviderID)
			}
			key := actionKey{intent: action.Intent, targetKind: action.TargetKind, scheme: action.Scheme, authorityID: action.AuthorityID}
			selection := providerActionKey{providerID: registration.ProviderID, sourceID: registration.SourceID, actionID: action.ID}
			if _, found := registry.byID[selection]; found {
				return nil, fmt.Errorf("duplicate remediation provider, source, and action ID %q/%q/%q", registration.ProviderID, registration.SourceID, action.ID)
			}
			registered := registeredAction{providerID: registration.ProviderID, sourceID: registration.SourceID, action: action, provider: provider}
			registry.providers[key] = append(registry.providers[key], registered)
			registry.byID[selection] = registered
		}
	}
	return registry, nil
}

func validActionID(actionID string) bool {
	mechanism, version, found := strings.Cut(actionID, "/v")
	if !found || mechanism == "" || version == "" || strings.Contains(version, "/") || version[0] == '0' {
		return false
	}
	for _, character := range mechanism {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	for _, character := range version {
		if character < '0' || character > '9' {
			return false
		}
	}
	parsed, err := strconv.ParseUint(version, 10, 64)
	return err == nil && parsed > 0
}

// Candidates returns every action matching the proposal's intent and target
// kind, identity scheme, and authority, sorted by provider, source, and action.
// Alternatives from different plugins or clusters are all returned; the user
// chooses.
func (registry *Registry) Candidates(proposal Proposal) ([]Candidate, error) {
	if registry == nil {
		return nil, errors.New("remediation registry is required")
	}
	if err := proposal.Validate(); err != nil {
		return nil, err
	}
	key := actionKey{
		intent: proposal.Intent, targetKind: proposal.Target.Kind, scheme: proposal.Target.Identity.Scheme, authorityID: proposal.Target.Identity.AuthorityID,
	}
	actions := registry.providers[key]
	candidates := make([]Candidate, 0, len(actions))
	for _, action := range actions {
		candidates = append(candidates, Candidate{ProviderID: action.providerID, SourceID: action.sourceID, ActionID: action.action.ID, Mode: action.action.Mode})
	}
	slices.SortFunc(candidates, func(left, right Candidate) int {
		if result := stringsCompare(left.ProviderID, right.ProviderID); result != 0 {
			return result
		}
		if result := stringsCompare(left.SourceID, right.SourceID); result != 0 {
			return result
		}
		return stringsCompare(left.ActionID, right.ActionID)
	})
	return candidates, nil
}

// Provider resolves a selection to an eligible provider and action. selection
// is either (actionID) or (sourceID, actionID). With no selection at all, it
// succeeds only when exactly one candidate exists; with a provider and action
// but no source, only when the source is unambiguous.
func (registry *Registry) Provider(proposal Proposal, providerID string, selection ...string) (Provider, Action, error) {
	sourceID, actionID, err := selectionParts(selection)
	if err != nil {
		return nil, Action{}, err
	}
	if err := proposal.Validate(); err != nil {
		return nil, Action{}, err
	}
	candidates, err := registry.Candidates(proposal)
	if err != nil {
		return nil, Action{}, err
	}
	if len(candidates) == 0 {
		return nil, Action{}, fmt.Errorf("no remediation provider for intent %q and target kind, scheme, and authority", proposal.Intent)
	}
	if providerID == "" && sourceID == "" && actionID == "" {
		if len(candidates) != 1 {
			return nil, Action{}, errors.New("multiple remediation actions match; explicit provider, source, and action selection is required")
		}
		providerID = candidates[0].ProviderID
		sourceID = candidates[0].SourceID
		actionID = candidates[0].ActionID
	} else if providerID != "" && sourceID == "" && actionID != "" {
		matches := make([]Candidate, 0, 1)
		for _, candidate := range candidates {
			if candidate.ProviderID == providerID && candidate.ActionID == actionID {
				matches = append(matches, candidate)
			}
		}
		if len(matches) != 1 {
			return nil, Action{}, errors.New("remediation selection requires an explicit source ID")
		}
		sourceID = matches[0].SourceID
	} else if providerID == "" || sourceID == "" || actionID == "" {
		return nil, Action{}, errors.New("remediation selection requires provider, source, and action IDs")
	}
	for _, candidate := range candidates {
		if candidate.ProviderID == providerID && candidate.SourceID == sourceID && candidate.ActionID == actionID {
			registered := registry.byID[providerActionKey{providerID: providerID, sourceID: sourceID, actionID: actionID}]
			return registered.provider, registered.action, nil
		}
	}
	return nil, Action{}, fmt.Errorf("remediation provider, source, and action %q/%q/%q are not eligible for this proposal", providerID, sourceID, actionID)
}

func selectionParts(selection []string) (string, string, error) {
	switch len(selection) {
	case 1:
		return "", selection[0], nil
	case 2:
		return selection[0], selection[1], nil
	default:
		return "", "", errors.New("remediation selection requires action or source and action IDs")
	}
}

func stringsCompare(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

// GraphView is a current graph snapshot and its digest.
type GraphView struct {
	SHA256   string
	Snapshot graph.Snapshot
}

// GraphSourceFunc reads the current graph for target applicability checks.
type GraphSourceFunc func(context.Context) (GraphView, error)

// Executor enforces the remediation lifecycle around registered providers.
// Successful preparations and execution results are kept in memory, keyed by
// plan ID, and are lost on restart.
type Executor struct {
	registry     *Registry
	graphSource  GraphSourceFunc
	mu           sync.Mutex
	preparations map[string]Preparation
	executions   map[string]*executionState
}

type executionState struct {
	executing bool
	executed  bool
	done      chan struct{}
	result    ExecutionResult
}

// NewExecutor returns an executor over registry that checks targets against
// graphSource.
func NewExecutor(registry *Registry, graphSource GraphSourceFunc) (*Executor, error) {
	if registry == nil || graphSource == nil {
		return nil, errors.New("remediation executor requires registry and graph source")
	}
	return &Executor{
		registry: registry, graphSource: graphSource,
		preparations: make(map[string]Preparation), executions: make(map[string]*executionState),
	}, nil
}

// Candidates returns the registry's candidates for proposal.
func (executor *Executor) Candidates(proposal Proposal) ([]Candidate, error) {
	return executor.registry.Candidates(proposal)
}

// Plan selects a provider action (see [Registry.Provider]), checks the target
// against the current graph, and returns the provider's plan after verifying it
// matches the proposal and selection. Planning never writes.
func (executor *Executor) Plan(ctx context.Context, proposal Proposal, providerID string, selection ...string) (Plan, error) {
	if err := proposal.Validate(); err != nil {
		return Plan{}, err
	}
	sourceID, actionID, err := selectionParts(selection)
	if err != nil {
		return Plan{}, err
	}
	selectedProviderID := providerID
	selectedSourceID := sourceID
	if providerID == "" && sourceID == "" && actionID == "" {
		candidates, err := executor.registry.Candidates(proposal)
		if err != nil {
			return Plan{}, err
		}
		if len(candidates) == 1 {
			selectedProviderID = candidates[0].ProviderID
			selectedSourceID = candidates[0].SourceID
		}
	} else if providerID != "" && sourceID == "" && actionID != "" {
		candidates, err := executor.registry.Candidates(proposal)
		if err != nil {
			return Plan{}, err
		}
		for _, candidate := range candidates {
			if candidate.ProviderID == providerID && candidate.ActionID == actionID {
				if selectedSourceID != "" {
					return Plan{}, errors.New("remediation selection requires an explicit source ID")
				}
				selectedSourceID = candidate.SourceID
			}
		}
	}
	provider, action, err := executor.registry.Provider(proposal, providerID, sourceID, actionID)
	if err != nil {
		return Plan{}, err
	}
	if err := executor.requireCurrentTarget(ctx, proposal); err != nil {
		return Plan{}, err
	}
	plan, err := provider.Plan(ctx, proposal, action.ID)
	if err != nil {
		return Plan{}, err
	}
	if err := validatePlan(proposal, action, selectedProviderID, selectedSourceID, plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// Prepare rechecks the plan and target, asks the provider to prepare it, and
// records a successful preparation as the only one [Executor.Execute] will
// accept for that plan. Preparing again replaces it.
func (executor *Executor) Prepare(ctx context.Context, proposal Proposal, plan Plan) (Preparation, error) {
	provider, action, err := executor.registry.Provider(proposal, plan.ProviderID, plan.SourceID, plan.ActionID)
	if err != nil {
		return Preparation{}, err
	}
	if err := validatePlan(proposal, action, plan.ProviderID, plan.SourceID, plan); err != nil {
		return Preparation{}, err
	}
	if plan.Mode == ModeAdvisoryOnly {
		return Preparation{}, &AdvisoryOnlyError{ProviderID: plan.ProviderID, Operation: "prepare"}
	}
	if err := executor.requireCurrentTarget(ctx, proposal); err != nil {
		return Preparation{}, err
	}
	preparation, err := provider.Prepare(ctx, proposal, plan)
	if err != nil {
		return Preparation{}, err
	}
	if err := validatePreparation(plan, preparation); err != nil {
		return Preparation{}, err
	}
	if preparation.Successful {
		executor.mu.Lock()
		executor.preparations[plan.ID] = preparation
		executor.mu.Unlock()
	}
	return preparation, nil
}

// Execute runs a prepared plan. approval must equal plan.ID: approving a
// proposal or a finding is not enough, the user must approve the exact plan
// they were shown. preparation must be the one recorded by [Executor.Prepare].
//
// Execution is single-flight per plan. A concurrent call waits for the
// in-flight one, then returns its successful result or, if it failed, tries
// again. A successful execution consumes the recorded preparation. The target
// is checked against the current graph immediately before the provider is
// called.
func (executor *Executor) Execute(ctx context.Context, proposal Proposal, plan Plan, preparation Preparation, approval string) (ExecutionResult, error) {
	provider, action, err := executor.registry.Provider(proposal, plan.ProviderID, plan.SourceID, plan.ActionID)
	if err != nil {
		return ExecutionResult{}, err
	}
	if err := validatePlan(proposal, action, plan.ProviderID, plan.SourceID, plan); err != nil {
		return ExecutionResult{}, err
	}
	if approval == "" || approval != plan.ID {
		return ExecutionResult{}, errors.New("remediation execution requires explicit approval matching the exact plan ID")
	}
	if plan.Mode == ModeAdvisoryOnly {
		return ExecutionResult{}, &AdvisoryOnlyError{ProviderID: plan.ProviderID, Operation: "execute"}
	}
	if err := validatePreparation(plan, preparation); err != nil || !preparation.Successful {
		return ExecutionResult{}, errors.New("remediation execution requires a successful matching preparation")
	}
	for {
		executor.mu.Lock()
		state := executor.executions[plan.ID]
		if state != nil && state.executed {
			result := state.result
			executor.mu.Unlock()
			return result, nil
		}
		if state != nil && state.executing {
			done := state.done
			executor.mu.Unlock()
			select {
			case <-ctx.Done():
				return ExecutionResult{}, ctx.Err()
			case <-done:
				continue
			}
		}
		recorded, found := executor.preparations[plan.ID]
		if !found || recorded.ID != preparation.ID {
			executor.mu.Unlock()
			return ExecutionResult{}, errors.New("remediation execution requires a recorded matching preparation")
		}
		if state == nil {
			state = &executionState{}
			executor.executions[plan.ID] = state
		}
		state.executing = true
		state.done = make(chan struct{})
		executor.mu.Unlock()
		break
	}
	if err := executor.requireCurrentTarget(ctx, proposal); err != nil {
		executor.finishExecution(plan.ID, ExecutionResult{}, false)
		return ExecutionResult{}, err
	}
	result, err := provider.Execute(ctx, proposal, plan, preparation)
	if err != nil {
		executor.finishExecution(plan.ID, ExecutionResult{}, false)
		return ExecutionResult{}, err
	}
	if err := validateExecutionResult(plan, preparation, result); err != nil {
		executor.finishExecution(plan.ID, ExecutionResult{}, false)
		return ExecutionResult{}, err
	}
	executor.finishExecution(plan.ID, result, result.Successful)
	return result, nil
}

func (executor *Executor) finishExecution(planID string, result ExecutionResult, executed bool) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	state := executor.executions[planID]
	state.executing = false
	state.executed = executed
	state.result = result
	close(state.done)
	if executed {
		delete(executor.preparations, planID)
	}
}

// Verify asks the provider to re-check a plan this executor successfully
// executed, and rejects a verification that does not match the plan and
// execution result.
func (executor *Executor) Verify(ctx context.Context, proposal Proposal, plan Plan) (Verification, error) {
	provider, action, err := executor.registry.Provider(proposal, plan.ProviderID, plan.SourceID, plan.ActionID)
	if err != nil {
		return Verification{}, err
	}
	if err := validatePlan(proposal, action, plan.ProviderID, plan.SourceID, plan); err != nil {
		return Verification{}, err
	}
	if plan.Mode == ModeAdvisoryOnly {
		return Verification{}, &AdvisoryOnlyError{ProviderID: plan.ProviderID, Operation: "verify"}
	}
	executor.mu.Lock()
	state := executor.executions[plan.ID]
	executed := state != nil && state.executed && state.result.Successful
	result := ExecutionResult{}
	if executed {
		result = state.result
	}
	executor.mu.Unlock()
	if !executed {
		return Verification{}, errors.New("remediation verification requires a successful execution recorded by this executor")
	}
	verification, err := provider.Verify(ctx, proposal, plan, result)
	if err != nil {
		return Verification{}, err
	}
	if verification.PlanID != plan.ID || verification.ProviderID != plan.ProviderID || verification.SourceID != plan.SourceID || verification.ActionID != plan.ActionID || verification.ExecutionResultID != result.ID {
		return Verification{}, errors.New("remediation verification does not match plan")
	}
	return verification, nil
}

// requireCurrentTarget checks the target against current graph state rather
// than the finding's digest, so unrelated churn does not block remediation
// while a removed or reclassified target does.
func (executor *Executor) requireCurrentTarget(ctx context.Context, proposal Proposal) error {
	view, err := executor.graphSource(ctx)
	if err != nil {
		return fmt.Errorf("read current graph: %w", err)
	}
	for _, conflict := range view.Snapshot.Conflicts {
		if conflict.ResourceID == proposal.Target.EntityID {
			return fmt.Errorf("remediation target %q has conflicting kinds", proposal.Target.EntityID)
		}
	}
	for _, resource := range view.Snapshot.Resources {
		if resource.ID != proposal.Target.EntityID {
			continue
		}
		if resource.Kind != proposal.Target.Kind {
			return fmt.Errorf("remediation target %q changed kind from %q to %q", proposal.Target.EntityID, proposal.Target.Kind, resource.Kind)
		}
		return nil
	}
	return fmt.Errorf("remediation target %q is absent from the current graph", proposal.Target.EntityID)
}

func validatePlan(proposal Proposal, action Action, providerID, sourceID string, plan Plan) error {
	if err := proposal.validateID(); err != nil {
		return err
	}
	if err := plan.validateID(); err != nil {
		return err
	}
	if plan.ProposalID != proposal.ID || plan.GraphSHA256 != proposal.GraphSHA256 || plan.ProviderID != providerID || plan.SourceID != sourceID || plan.ActionID != action.ID || plan.Mode != action.Mode || plan.ID == "" || plan.DesiredSHA256 == "" {
		return errors.New("remediation plan does not match proposal and provider")
	}
	return nil
}

func validatePreparation(plan Plan, preparation Preparation) error {
	if err := preparation.validateID(); err != nil {
		return err
	}
	if preparation.PlanID != plan.ID || preparation.ProposalID != plan.ProposalID || preparation.ProviderID != plan.ProviderID || preparation.SourceID != plan.SourceID || preparation.ActionID != plan.ActionID || preparation.GraphSHA256 != plan.GraphSHA256 || preparation.ID == "" {
		return errors.New("remediation preparation does not match plan")
	}
	return nil
}

func validateExecutionResult(plan Plan, preparation Preparation, result ExecutionResult) error {
	if err := result.validateID(); err != nil {
		return err
	}
	if result.PlanID != plan.ID || result.ProposalID != plan.ProposalID || result.ProviderID != plan.ProviderID || result.SourceID != plan.SourceID || result.ActionID != plan.ActionID || result.PreparationID != preparation.ID || result.ID == "" {
		return errors.New("remediation execution result does not match plan and preparation")
	}
	return nil
}
