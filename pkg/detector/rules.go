package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// ErrNoActiveRuleset is returned by a [Repository] when no ruleset has been
// activated. An activated empty ruleset is different: it disables detection.
var ErrNoActiveRuleset = errors.New("no active detector ruleset")

// ErrActivationConflict is returned when an activation's expected revision is
// not the current one, meaning another activation won the race.
var ErrActivationConflict = errors.New("detector ruleset activation revision conflict")

// Rule matches its CEL Expression against inputs selected by PluginID ("*" for
// any), Type, Kind, and, when set, WorkloadResourceID. (ID, Revision) is
// immutable once stored. WindowSeconds is the signal half-width; zero uses
// [Config.Window].
type Rule struct {
	ID                 string   `json:"id"`
	Revision           uint64   `json:"revision"`
	InputVersion       string   `json:"inputVersion"`
	PluginID           string   `json:"pluginId"`
	WorkloadResourceID string   `json:"workloadResourceId,omitempty"`
	Type               string   `json:"type"`
	Kind               string   `json:"kind"`
	Expression         string   `json:"expression"`
	Risk               Risk     `json:"risk"`
	Reasons            []string `json:"reasons"`
	WindowSeconds      int64    `json:"windowSeconds"`
}

// Ruleset is a complete set of rules. Activating one replaces the entire
// active set; it does not merge with the previous one.
type Ruleset struct {
	ID    string `json:"id"`
	Rules []Rule `json:"rules"`
}

// Activation is the active ruleset and its monotonically increasing
// activation revision.
type Activation struct {
	Revision uint64  `json:"revision"`
	Ruleset  Ruleset `json:"ruleset"`
}

// Repository reads the active ruleset. *state.Store implements it and
// verifies the stored content checksum before returning.
type Repository interface {
	ReadActiveDetectorRuleset(context.Context) (Activation, error)
}

// Result is the signals from one detection, with the identity of the exact
// ruleset that produced them, recorded even when there are no signals.
type Result struct {
	Signals             []InvestigationSignal
	RulesetID           string
	RulesetDigest       string
	ActivationRevision  uint64
	WorkloadRulesDigest string
	// Omitted counts what an evaluation left out to stay within its bounds:
	// "events" beyond [MaxEvaluationEvents], "oversizedEvents" over 64 KiB, and
	// rule "signals" beyond [MaxEvaluationSignals]. It is nil when nothing was left out.
	Omitted map[string]int
}

// Evaluation bounds. Inputs and signals beyond them are left out and counted
// in [Result.Omitted] rather than failing the evaluation, so one oversized
// window, such as a large rollout, cannot stop detection.
const (
	MaxEvaluationEvents  = 100_000
	MaxEvaluationSignals = 1000
)

// Detector compares two snapshots. observedAt centers signal windows; zero
// uses the latest telemetry first-seen time in the current snapshot.
type Detector interface {
	Detect(context.Context, graph.Snapshot, graph.Snapshot, time.Time) (Result, error)
}

// Status reports the active ruleset and the error from the most recent
// reload attempt, empty if it succeeded.
type Status struct {
	RulesetID           string
	RulesetDigest       string
	ActivationRevision  uint64
	WorkloadRulesDigest string
	ActiveWorkloadRules int
	ShadowWorkloadRules int
	// SkippedWorkloadRules counts invalid workload rules, and groups of rules
	// over [MaxWorkloadRules], that the loaded overlay left out.
	SkippedWorkloadRules int
	LastReloadError      string
}

type compiledRule struct {
	rule  Rule
	match cel.Program
}

type compiledRuleset struct {
	id       string
	digest   string
	revision uint64
	rules    map[string][]compiledRule
}

type inputActivation struct {
	input Input
}

func (activation inputActivation) ResolveName(name string) (any, bool) {
	typ := reflect.TypeOf(activation.input)
	value := reflect.ValueOf(activation.input)
	for index := 0; index < typ.NumField(); index++ {
		if strings.Split(typ.Field(index).Tag.Get("json"), ",")[0] == name {
			return value.Field(index).Interface(), true
		}
	}
	return nil, false
}

func (activation inputActivation) Parent() interpreter.Activation { return nil }

// Engine evaluates built-in novelty and the active CEL ruleset. It is safe for
// concurrent use: evaluations load the active ruleset once through an atomic
// pointer, so a concurrent reload never changes the rules mid-evaluation.
type Engine struct {
	config          Config
	active          atomic.Pointer[compiledRuleset]
	workload        atomic.Pointer[compiledWorkloadRules]
	reload          sync.Mutex
	lastReloadError string
}

// New compiles ruleset and returns an engine. The activation revision is zero;
// use [Load] for a stored activation.
func New(config Config, ruleset Ruleset) (*Engine, error) {
	compiled, err := compileRuleset(ruleset)
	if err != nil {
		return nil, err
	}
	engine := &Engine{config: normalizedConfig(config)}
	engine.active.Store(compiled)
	empty, err := compileWorkloadRules(nil)
	if err != nil {
		return nil, err
	}
	engine.workload.Store(empty)
	return engine, nil
}

// Load compiles the active ruleset from repository. Unlike [Engine.Reload],
// a ruleset failure is returned: there is no known-good ruleset to fall back
// to, so invalid operator rules fail startup. The workload rule overlay never
// fails startup: invalid workload rules are skipped, and if the overlay cannot
// be read the engine starts without it. Either is recorded for
// [Engine.Status], and the next reload retries.
func Load(ctx context.Context, repository Repository, config Config) (*Engine, error) {
	activation, err := repository.ReadActiveDetectorRuleset(ctx)
	if err != nil {
		return nil, err
	}
	engine, err := New(config, activation.Ruleset)
	if err != nil {
		return nil, err
	}
	// Safe to set in place: the engine has not been shared yet.
	engine.active.Load().revision = activation.Revision
	if workloadRepository, ok := repository.(WorkloadRuleRepository); ok {
		if err := engine.ReloadWorkloadRules(ctx, workloadRepository); err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			engine.lastReloadError = err.Error()
			slog.WarnContext(ctx, "workload rules not fully loaded at startup; the next reload retries", "error", err)
		}
	}
	return engine, nil
}

// Reload reads the active activation and swaps in its ruleset if it is new.
// When repository also implements WorkloadRuleRepository, it then refreshes
// the workload-scoped rules the same way.
//
// The candidate is compiled completely before the atomic swap, so an
// evaluation sees either the old ruleset or the new one, never a mix, and
// in-flight evaluations finish on the ruleset they loaded. An unchanged
// revision is only checksum-compared, not recompiled. A revision that moves
// backward, or content that changed without a new revision, is an error.
//
// On any error the current rules stay active (last known good) and the
// error is recorded for [Engine.Status]. Reloads are serialized.
func (engine *Engine) Reload(ctx context.Context, repository Repository) (err error) {
	engine.reload.Lock()
	defer engine.reload.Unlock()
	defer func() {
		engine.lastReloadError = ""
		if err != nil {
			engine.lastReloadError = err.Error()
		}
	}()
	if err := engine.reloadRuleset(ctx, repository); err != nil {
		return err
	}
	if workloadRepository, ok := repository.(WorkloadRuleRepository); ok {
		return engine.reloadWorkloadRules(ctx, workloadRepository)
	}
	return nil
}

func (engine *Engine) reloadRuleset(ctx context.Context, repository Repository) error {
	activation, err := repository.ReadActiveDetectorRuleset(ctx)
	if err != nil {
		return err
	}
	current := engine.active.Load()
	if activation.Revision < current.revision {
		return errors.New("detector activation revision regressed")
	}
	if activation.Revision == current.revision {
		digest, err := RulesetDigest(activation.Ruleset)
		if err != nil {
			return err
		}
		if digest != current.digest {
			return errors.New("detector ruleset changed without advancing activation revision")
		}
		return nil
	}
	compiled, err := compileRuleset(activation.Ruleset)
	if err != nil {
		return err
	}
	compiled.revision = activation.Revision
	engine.active.Store(compiled)
	return nil
}

// Status returns the active ruleset identity and the last reload error.
func (engine *Engine) Status() Status {
	engine.reload.Lock()
	defer engine.reload.Unlock()
	current := engine.active.Load()
	workload := engine.workload.Load()
	return Status{
		RulesetID: current.id, RulesetDigest: current.digest, ActivationRevision: current.revision,
		WorkloadRulesDigest: workload.digest, ActiveWorkloadRules: workload.active, ShadowWorkloadRules: workload.shadow,
		SkippedWorkloadRules: len(workload.skipped), LastReloadError: engine.lastReloadError,
	}
}

// RunReloads calls [Engine.Reload] every interval until ctx is cancelled.
// Reload errors go to report and do not stop the loop. Polling is independent
// of graph changes, and a reload affects only future evaluations; it never
// replays history.
func (engine *Engine) RunReloads(ctx context.Context, repository Repository, interval time.Duration, report func(error)) error {
	if interval <= 0 {
		return errors.New("detector reload interval must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	loaded := engine.Status()
	logLoaded(ctx, "detector rules loaded", loaded)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := engine.Reload(ctx, repository); err != nil && report != nil {
				report(err)
			}
			// Log only when the loaded rules change; an unchanged reload is silent.
			if current := engine.Status(); current.RulesetDigest != loaded.RulesetDigest ||
				current.ActivationRevision != loaded.ActivationRevision || current.WorkloadRulesDigest != loaded.WorkloadRulesDigest {
				loaded = current
				logLoaded(ctx, "detector rules reloaded", current)
			}
		}
	}
}

func logLoaded(ctx context.Context, message string, status Status) {
	slog.InfoContext(ctx, message, "ruleset", status.RulesetID, "activation_revision", status.ActivationRevision,
		"active_workload_rules", status.ActiveWorkloadRules, "shadow_workload_rules", status.ShadowWorkloadRules,
		"skipped_workload_rules", status.SkippedWorkloadRules)
}

// Detect returns built-in novelty signals plus signals from the active CEL ruleset and workload rules.
func (engine *Engine) Detect(ctx context.Context, previous, current graph.Snapshot, observedAt time.Time) (Result, error) {
	result, err := engine.Evaluate(ctx, Events(previous, current, observedAt))
	if err != nil {
		return Result{}, err
	}
	result.Signals = append(result.Signals, DetectNovelChanges(previous, current, observedAt, engine.config)...)
	slices.SortFunc(result.Signals, func(left, right InvestigationSignal) int { return strings.Compare(left.ID, right.ID) })
	result.Signals = slices.CompactFunc(result.Signals, func(left, right InvestigationSignal) bool { return left.ID == right.ID })
	return result, nil
}

// Evaluate matches events against the ruleset active when it starts. It
// returns an error, rather than a partial result, on cancellation or a CEL
// runtime error, so callers never mistake a failed evaluation for "no match".
// Events beyond [MaxEvaluationEvents], events over 64 KiB, and rule signals
// beyond [MaxEvaluationSignals] are left out deterministically, in the order
// given, and counted in [Result.Omitted].
func (engine *Engine) Evaluate(ctx context.Context, events []Event) (Result, error) {
	compiled := engine.active.Load()
	workload := engine.workload.Load()
	result := Result{RulesetID: compiled.id, RulesetDigest: compiled.digest, ActivationRevision: compiled.revision, WorkloadRulesDigest: workload.digest}
	omitted := make(map[string]int)
	if len(events) > MaxEvaluationEvents {
		omitted["events"] = len(events) - MaxEvaluationEvents
		events = events[:MaxEvaluationEvents]
	}
	add := func(signals ...InvestigationSignal) {
		for _, signal := range signals {
			if len(result.Signals) >= MaxEvaluationSignals {
				omitted["signals"]++
				continue
			}
			result.Signals = append(result.Signals, signal)
		}
	}
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if event.validate() != nil {
			omitted["oversizedEvents"]++
			continue
		}
		for _, candidate := range compiled.rules[event.Type] {
			rule := candidate.rule
			if rule.PluginID != "*" && rule.PluginID != event.PluginID || rule.Kind != event.Kind {
				continue
			}
			if rule.WorkloadResourceID != "" && !slices.Contains(event.AnchorIDs, rule.WorkloadResourceID) {
				continue
			}
			matched, _, err := candidate.match.ContextEval(ctx, inputActivation{input: event.Input})
			if err != nil {
				return Result{}, fmt.Errorf("rule %s match: %w", rule.ID, err)
			}
			if matched.Value() != true {
				continue
			}
			window := time.Duration(rule.WindowSeconds) * time.Second
			if rule.WindowSeconds == 0 {
				window = engine.config.Window
			}
			add(newSignal(event, rule, compiled.digest, window))
		}
		matched, err := workload.evaluate(ctx, event, engine.config.Window)
		if err != nil {
			return Result{}, err
		}
		add(matched...)
	}
	slices.SortFunc(result.Signals, func(left, right InvestigationSignal) int { return strings.Compare(left.ID, right.ID) })
	result.Signals = slices.CompactFunc(result.Signals, func(left, right InvestigationSignal) bool { return left.ID == right.ID })
	if len(omitted) > 0 {
		result.Omitted = omitted
	}
	return result, nil
}

func newSignal(event Event, rule Rule, rulesetDigest string, window time.Duration) InvestigationSignal {
	return newModeSignal(event, rule, rulesetDigest, window, "")
}

func newModeSignal(event Event, rule Rule, rulesetDigest string, window time.Duration, mode RuleMode) InvestigationSignal {
	anchors := slices.Clone(event.AnchorIDs)
	slices.Sort(anchors)
	reasons := slices.Clone(rule.Reasons)
	slices.Sort(reasons)
	observedAt := event.ObservedAt.UTC()
	signal := InvestigationSignal{
		Risk: rule.Risk, Reasons: slices.Compact(reasons), AnchorIDs: slices.Compact(anchors),
		Window: TimeWindow{Start: observedAt.Add(-window), End: observedAt.Add(window)},
		RuleID: rule.ID, RuleRevision: rule.Revision, RulesetDigest: rulesetDigest, RuleMode: mode,
	}
	encoded, _ := json.Marshal([]any{event.ID, signal})
	digest := sha256.Sum256(encoded)
	signal.ID = "signal:sha256:" + hex.EncodeToString(digest[:])
	return signal
}

// CanonicalRuleset encodes ruleset with rules sorted by ID, so the encoding
// and [RulesetDigest] do not depend on rule order.
func CanonicalRuleset(ruleset Ruleset) ([]byte, error) {
	if ruleset.ID == "" || len(ruleset.ID) > 128 {
		return nil, errors.New("ruleset ID must contain 1-128 bytes")
	}
	if len(ruleset.Rules) > 256 {
		return nil, errors.New("ruleset exceeds 256 rules")
	}
	ruleset.Rules = slices.Clone(ruleset.Rules)
	if ruleset.Rules == nil {
		ruleset.Rules = []Rule{}
	}
	slices.SortFunc(ruleset.Rules, func(left, right Rule) int { return strings.Compare(left.ID, right.ID) })
	return json.Marshal(ruleset)
}

// RulesetDigest returns the hex SHA-256 of the canonical ruleset. Signal IDs
// include it, so the same input matched under different rulesets yields
// different signals.
func RulesetDigest(ruleset Ruleset) (string, error) {
	encoded, err := CanonicalRuleset(ruleset)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// ValidateRuleset compiles ruleset exactly as activation would, without
// activating it.
func ValidateRuleset(ruleset Ruleset) error {
	_, err := compileRuleset(ruleset)
	return err
}

func compileRuleset(ruleset Ruleset) (*compiledRuleset, error) {
	digest, err := RulesetDigest(ruleset)
	if err != nil {
		return nil, err
	}
	ruleset.Rules = slices.Clone(ruleset.Rules)
	slices.SortFunc(ruleset.Rules, func(left, right Rule) int { return strings.Compare(left.ID, right.ID) })
	cache := newCELCache()
	compiled := &compiledRuleset{id: ruleset.ID, digest: digest, rules: map[string][]compiledRule{}}
	seen := map[string]bool{}
	for _, rule := range ruleset.Rules {
		if seen[rule.ID] {
			return nil, fmt.Errorf("invalid or duplicate rule identity %q", rule.ID)
		}
		seen[rule.ID] = true
		candidate, err := compileRule(rule, cache)
		if err != nil {
			return nil, err
		}
		compiled.rules[rule.Type] = append(compiled.rules[rule.Type], candidate)
	}
	return compiled, nil
}

// celCache shares CEL environments per selector, and compiled programs per
// selector and expression, across the rules of one compilation. A program is
// stateless and safe for concurrent use, so rules with the same expression,
// common among model-authored Deployment rules, compile it once.
type celCache struct {
	environments map[string]*cel.Env
	programs     map[string]cel.Program
}

func newCELCache() *celCache {
	return &celCache{environments: map[string]*cel.Env{}, programs: map[string]cel.Program{}}
}

// compileRule validates one rule and compiles its expression in the selector's CEL environment.
func compileRule(rule Rule, cache *celCache) (compiledRule, error) {
	if rule.ID == "" || len(rule.ID) > 128 || rule.Revision == 0 || rule.Revision > 1<<63-1 {
		return compiledRule{}, fmt.Errorf("invalid or duplicate rule identity %q", rule.ID)
	}
	if rule.InputVersion != InputVersion {
		return compiledRule{}, fmt.Errorf("rule %s uses unsupported input version %q", rule.ID, rule.InputVersion)
	}
	if rule.PluginID == "" || len(rule.PluginID) > 128 || rule.Kind == "" || len(rule.Kind) > 128 {
		return compiledRule{}, fmt.Errorf("rule %s requires bounded plugin and kind selectors", rule.ID)
	}
	if len(rule.WorkloadResourceID) > 128 {
		return compiledRule{}, fmt.Errorf("rule %s workload resource ID exceeds 128 bytes", rule.ID)
	}
	if !ValidCELRuleKind(rule.Type, rule.Kind) {
		return compiledRule{}, fmt.Errorf("rule %s uses unsupported input type or kind %q/%q", rule.ID, rule.Type, rule.Kind)
	}
	switch rule.Risk {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
	default:
		return compiledRule{}, fmt.Errorf("rule %s uses unknown risk %q", rule.ID, rule.Risk)
	}
	if rule.WindowSeconds < 0 || rule.WindowSeconds > 86400 {
		return compiledRule{}, fmt.Errorf("rule %s window must be between 0 and 86400 seconds", rule.ID)
	}
	if err := validateReasons(rule.Reasons); err != nil {
		return compiledRule{}, fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	if len(rule.Expression) == 0 || len(rule.Expression) > 8192 {
		return compiledRule{}, fmt.Errorf("compile rule %s: CEL expression must contain 1-8192 bytes", rule.ID)
	}
	rule.Reasons = slices.Clone(rule.Reasons)
	selector := rule.Type + ":" + rule.Kind
	if match, cached := cache.programs[selector+"\x00"+rule.Expression]; cached {
		return compiledRule{rule: rule, match: match}, nil
	}
	environment := cache.environments[selector]
	if environment == nil {
		var err error
		if environment, err = CELEnvironment(rule.Type, rule.Kind); err != nil {
			return compiledRule{}, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		cache.environments[selector] = environment
	}
	ast, issues := environment.Compile(rule.Expression)
	if issues.Err() != nil {
		return compiledRule{}, fmt.Errorf("compile rule %s: %w", rule.ID, issues.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return compiledRule{}, fmt.Errorf("compile rule %s: CEL expression must return %s, got %s", rule.ID, cel.BoolType, ast.OutputType())
	}
	match, err := environment.Program(ast, cel.CostLimit(10_000), cel.InterruptCheckFrequency(100))
	if err != nil {
		return compiledRule{}, fmt.Errorf("compile rule %s: %w", rule.ID, err)
	}
	cache.programs[selector+"\x00"+rule.Expression] = match
	return compiledRule{rule: rule, match: match}, nil
}

func validateReasons(reasons []string) error {
	if len(reasons) == 0 || len(reasons) > 16 {
		return errors.New("rule must emit 1-16 reasons")
	}
	for _, reason := range reasons {
		if reason == "" || len(reason) > 128 {
			return errors.New("reason must contain 1-128 bytes")
		}
	}
	return nil
}

// DefaultRuleset is builtin/v1, the ruleset bootstrapped when none is active.
// It has no CEL rules; built-in novelty detection still runs.
func DefaultRuleset() Ruleset {
	return Ruleset{ID: "builtin/v1", Rules: []Rule{}}
}
