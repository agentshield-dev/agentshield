package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// RuleMode controls what a workload rule match does.
type RuleMode string

const (
	// RuleModeActive signals are eligible for agentic investigation like any other rule signal.
	RuleModeActive RuleMode = "active"
	// RuleModeShadow signals are recorded for review but never investigated.
	RuleModeShadow RuleMode = "shadow"
)

// MaxWorkloadRules bounds the workload rule overlay. A workload loads at most
// two rule sets (its approved and its current draft) of up to three rules each,
// so the bound keeps room for about 5,000 workloads. Rules over the bound are
// not loaded; see [Engine.SetWorkloadRules].
const MaxWorkloadRules = 30_000

// WorkloadRule is a rule scoped to one workload resource, such as a model-authored
// Deployment rule. Approved rules run in RuleModeActive; unreviewed drafts in RuleModeShadow.
type WorkloadRule struct {
	Rule Rule     `json:"rule"`
	Mode RuleMode `json:"mode"`
}

// WorkloadRuleRepository supplies workload rules. Engine.Load and Engine.Reload
// read them when their Repository also implements this interface.
type WorkloadRuleRepository interface {
	ReadWorkloadRules(context.Context) ([]WorkloadRule, error)
}

type compiledWorkloadRule struct {
	compiledRule
	mode RuleMode
}

// compiledWorkloadRules indexes rules by workload so evaluation cost scales with
// an input's anchors rather than with the number of workloads. digest
// identifies the loaded rules; source identifies the rules as read, so an
// unchanged read is not recompiled. skipped describes rules that were not loaded.
type compiledWorkloadRules struct {
	digest     string
	source     string
	active     int
	shadow     int
	skipped    []string
	byWorkload map[string][]compiledWorkloadRule
}

// WorkloadRulesDigest returns the canonical digest of a workload rule set.
func WorkloadRulesDigest(rules []WorkloadRule) (string, error) {
	rules = slices.Clone(rules)
	if rules == nil {
		rules = []WorkloadRule{}
	}
	slices.SortFunc(rules, func(left, right WorkloadRule) int { return strings.Compare(left.Rule.ID, right.Rule.ID) })
	encoded, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// ValidateWorkloadRules compiles workload rules without loading them. Unlike
// [Engine.SetWorkloadRules], any rule that would be skipped is an error.
func ValidateWorkloadRules(rules []WorkloadRule) error {
	compiled, err := compileWorkloadRules(rules)
	if err != nil {
		return err
	}
	if len(compiled.skipped) > 0 {
		return errors.New(strings.Join(compiled.skipped, "; "))
	}
	return nil
}

// compileWorkloadRules compiles every valid rule and skips the rest, so one bad
// proposal cannot unload every other workload's rules. Rules are considered in
// a fixed order, active before shadow and then by ID, so the rules kept under
// [MaxWorkloadRules] and the first of any duplicate ID do not depend on read order.
func compileWorkloadRules(rules []WorkloadRule) (*compiledWorkloadRules, error) {
	source, err := WorkloadRulesDigest(rules)
	if err != nil {
		return nil, err
	}
	ordered := slices.Clone(rules)
	slices.SortStableFunc(ordered, func(left, right WorkloadRule) int {
		if (left.Mode == RuleModeActive) != (right.Mode == RuleModeActive) {
			if left.Mode == RuleModeActive {
				return -1
			}
			return 1
		}
		return strings.Compare(left.Rule.ID, right.Rule.ID)
	})
	compiled := &compiledWorkloadRules{source: source, byWorkload: make(map[string][]compiledWorkloadRule)}
	cache := newCELCache()
	seen := make(map[string]struct{}, len(ordered))
	loaded := make([]WorkloadRule, 0, min(len(ordered), MaxWorkloadRules))
	for index, workloadRule := range ordered {
		if len(loaded) == MaxWorkloadRules {
			compiled.skipped = append(compiled.skipped, fmt.Sprintf("%d workload rules exceed %d and were not loaded", len(ordered)-index, MaxWorkloadRules))
			break
		}
		if err := compiled.add(workloadRule, seen, cache); err != nil {
			compiled.skipped = append(compiled.skipped, err.Error())
			continue
		}
		loaded = append(loaded, workloadRule)
	}
	if compiled.digest, err = WorkloadRulesDigest(loaded); err != nil {
		return nil, err
	}
	for workload := range compiled.byWorkload {
		slices.SortFunc(compiled.byWorkload[workload], func(left, right compiledWorkloadRule) int {
			return strings.Compare(left.rule.ID, right.rule.ID)
		})
	}
	return compiled, nil
}

// add validates and compiles one workload rule into the index.
func (compiled *compiledWorkloadRules) add(workloadRule WorkloadRule, seen map[string]struct{}, cache *celCache) error {
	rule := workloadRule.Rule
	if _, duplicate := seen[rule.ID]; duplicate {
		return fmt.Errorf("duplicate workload rule %q", rule.ID)
	}
	if rule.WorkloadResourceID == "" {
		return fmt.Errorf("workload rule %s requires a workload resource ID", rule.ID)
	}
	if workloadRule.Mode != RuleModeActive && workloadRule.Mode != RuleModeShadow {
		return fmt.Errorf("workload rule %s uses unknown mode %q", rule.ID, workloadRule.Mode)
	}
	candidate, err := compileRule(rule, cache)
	if err != nil {
		return err
	}
	seen[rule.ID] = struct{}{}
	if workloadRule.Mode == RuleModeActive {
		compiled.active++
	} else {
		compiled.shadow++
	}
	compiled.byWorkload[rule.WorkloadResourceID] = append(compiled.byWorkload[rule.WorkloadResourceID], compiledWorkloadRule{compiledRule: candidate, mode: workloadRule.Mode})
	return nil
}

// SetWorkloadRules compiles rules and then swaps them in atomically. Invalid
// rules and rules over [MaxWorkloadRules] are skipped rather than failing the
// whole overlay: the valid rules are loaded, [Engine.Status] counts the
// skipped ones, and the returned error describes them.
func (engine *Engine) SetWorkloadRules(rules []WorkloadRule) error {
	compiled, err := compileWorkloadRules(rules)
	if err != nil {
		return err
	}
	engine.workload.Store(compiled)
	if len(compiled.skipped) > 0 {
		return fmt.Errorf("skipped %d workload rule problem(s): %s", len(compiled.skipped), strings.Join(compiled.skipped, "; "))
	}
	return nil
}

// ReloadWorkloadRules reads and swaps in workload rules. A read failure retains
// the current rules; invalid rules are skipped as in [Engine.SetWorkloadRules].
func (engine *Engine) ReloadWorkloadRules(ctx context.Context, repository WorkloadRuleRepository) error {
	engine.reload.Lock()
	defer engine.reload.Unlock()
	return engine.reloadWorkloadRules(ctx, repository)
}

func (engine *Engine) reloadWorkloadRules(ctx context.Context, repository WorkloadRuleRepository) error {
	if repository == nil {
		return errors.New("workload rule repository is required")
	}
	rules, err := repository.ReadWorkloadRules(ctx)
	if err != nil {
		return fmt.Errorf("read workload rules: %w", err)
	}
	source, err := WorkloadRulesDigest(rules)
	if err != nil {
		return err
	}
	if source == engine.workload.Load().source {
		return nil
	}
	return engine.SetWorkloadRules(rules)
}

func (rules *compiledWorkloadRules) evaluate(ctx context.Context, event Event, defaultWindow time.Duration) ([]InvestigationSignal, error) {
	if len(rules.byWorkload) == 0 {
		return nil, nil
	}
	var signals []InvestigationSignal
	// A workload rule describes what the workload itself does, so it matches
	// only inputs whose subject is the workload or one of its Pods, never
	// inputs where the workload is the object, such as a new client calling it.
	for _, subject := range event.SubjectIDs {
		for _, candidate := range rules.byWorkload[subject] {
			rule := candidate.rule
			if rule.Type != event.Type || rule.Kind != event.Kind || (rule.PluginID != "*" && rule.PluginID != event.PluginID) {
				continue
			}
			matched, _, err := candidate.match.ContextEval(ctx, inputActivation{input: event.Input})
			if err != nil {
				return nil, fmt.Errorf("workload rule %s match: %w", rule.ID, err)
			}
			if matched.Value() != true {
				continue
			}
			window := time.Duration(rule.WindowSeconds) * time.Second
			if rule.WindowSeconds == 0 {
				window = defaultWindow
			}
			mode := RuleMode("")
			if candidate.mode == RuleModeShadow {
				mode = RuleModeShadow
			}
			signals = append(signals, newModeSignal(event, rule, rules.digest, window, mode))
		}
	}
	return signals, nil
}
