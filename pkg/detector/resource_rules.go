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

// RuleMode controls what a resource rule match does.
type RuleMode string

const (
	// RuleModeActive signals are eligible for agentic investigation like any other rule signal.
	RuleModeActive RuleMode = "active"
	// RuleModeShadow signals are recorded for review but never investigated.
	RuleModeShadow RuleMode = "shadow"
)

// MaxResourceRules bounds the resource rule overlay. A resource loads at most
// two rule sets (its approved and its current draft) of up to three rules each,
// so the bound keeps room for about 5,000 resources. Rules over the bound are
// not loaded; see [Engine.SetResourceRules].
const MaxResourceRules = 30_000

// ResourceRule is a rule scoped to one resource. Approved rules run in
// RuleModeActive; unreviewed drafts in RuleModeShadow.
type ResourceRule struct {
	Rule Rule     `json:"rule"`
	Mode RuleMode `json:"mode"`
}

// ResourceRuleRepository supplies resource rules. Engine.Load and Engine.Reload
// read them when their Repository also implements this interface.
type ResourceRuleRepository interface {
	ReadResourceRules(context.Context) ([]ResourceRule, error)
}

type compiledResourceRule struct {
	compiledRule
	mode RuleMode
}

// compiledResourceRules indexes rules by resource so evaluation cost scales with
// an input's anchors rather than with the number of resources. digest
// identifies the loaded rules; inputDigest identifies the rules as read, so an
// unchanged read is not recompiled. skipped describes rules that were not loaded.
type compiledResourceRules struct {
	digest      string
	inputDigest string
	active      int
	shadow      int
	skipped     []string
	byResource  map[string][]compiledResourceRule
}

// ResourceRulesDigest returns the canonical digest of a resource rule set.
func ResourceRulesDigest(rules []ResourceRule) (string, error) {
	rules = slices.Clone(rules)
	if rules == nil {
		rules = []ResourceRule{}
	}
	slices.SortFunc(rules, func(left, right ResourceRule) int { return strings.Compare(left.Rule.ID, right.Rule.ID) })
	encoded, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// ValidateResourceRules compiles resource rules without loading them. Unlike
// [Engine.SetResourceRules], any rule that would be skipped is an error.
func ValidateResourceRules(rules []ResourceRule) error {
	compiled, err := compileResourceRules(rules)
	if err != nil {
		return err
	}
	if len(compiled.skipped) > 0 {
		return errors.New(strings.Join(compiled.skipped, "; "))
	}
	return nil
}

// compileResourceRules compiles every valid rule and skips the rest, so one bad
// proposal cannot unload every other resource's rules. Rules are considered in
// a fixed order, active before shadow and then by ID, so the rules kept under
// [MaxResourceRules] and the first of any duplicate ID do not depend on read order.
func compileResourceRules(rules []ResourceRule) (*compiledResourceRules, error) {
	inputDigest, err := ResourceRulesDigest(rules)
	if err != nil {
		return nil, err
	}
	ordered := slices.Clone(rules)
	slices.SortStableFunc(ordered, func(left, right ResourceRule) int {
		if (left.Mode == RuleModeActive) != (right.Mode == RuleModeActive) {
			if left.Mode == RuleModeActive {
				return -1
			}
			return 1
		}
		return strings.Compare(left.Rule.ID, right.Rule.ID)
	})
	compiled := &compiledResourceRules{inputDigest: inputDigest, byResource: make(map[string][]compiledResourceRule)}
	cache := newCELCache()
	seen := make(map[string]struct{}, len(ordered))
	loaded := make([]ResourceRule, 0, min(len(ordered), MaxResourceRules))
	for index, resourceRule := range ordered {
		if len(loaded) == MaxResourceRules {
			compiled.skipped = append(compiled.skipped, fmt.Sprintf("%d resource rules exceed %d and were not loaded", len(ordered)-index, MaxResourceRules))
			break
		}
		if err := compiled.add(resourceRule, seen, cache); err != nil {
			compiled.skipped = append(compiled.skipped, err.Error())
			continue
		}
		loaded = append(loaded, resourceRule)
	}
	if compiled.digest, err = ResourceRulesDigest(loaded); err != nil {
		return nil, err
	}
	for resource := range compiled.byResource {
		slices.SortFunc(compiled.byResource[resource], func(left, right compiledResourceRule) int {
			return strings.Compare(left.rule.ID, right.rule.ID)
		})
	}
	return compiled, nil
}

// add validates and compiles one resource rule into the index.
func (compiled *compiledResourceRules) add(resourceRule ResourceRule, seen map[string]struct{}, cache *celCache) error {
	rule := resourceRule.Rule
	if _, duplicate := seen[rule.ID]; duplicate {
		return fmt.Errorf("duplicate resource rule %q", rule.ID)
	}
	if rule.ScopeResourceID == "" {
		return fmt.Errorf("resource rule %s requires a resource ID", rule.ID)
	}
	if resourceRule.Mode != RuleModeActive && resourceRule.Mode != RuleModeShadow {
		return fmt.Errorf("resource rule %s uses unknown mode %q", rule.ID, resourceRule.Mode)
	}
	candidate, err := compileRule(rule, cache)
	if err != nil {
		return err
	}
	seen[rule.ID] = struct{}{}
	if resourceRule.Mode == RuleModeActive {
		compiled.active++
	} else {
		compiled.shadow++
	}
	compiled.byResource[rule.ScopeResourceID] = append(compiled.byResource[rule.ScopeResourceID], compiledResourceRule{compiledRule: candidate, mode: resourceRule.Mode})
	return nil
}

// SetResourceRules compiles rules and then swaps them in atomically. Invalid
// rules and rules over [MaxResourceRules] are skipped rather than failing the
// whole overlay: the valid rules are loaded, [Engine.Status] counts the
// skipped ones, and the returned error describes them.
func (engine *Engine) SetResourceRules(rules []ResourceRule) error {
	compiled, err := compileResourceRules(rules)
	if err != nil {
		return err
	}
	engine.resource.Store(compiled)
	if len(compiled.skipped) > 0 {
		return fmt.Errorf("skipped %d resource rule problem(s): %s", len(compiled.skipped), strings.Join(compiled.skipped, "; "))
	}
	return nil
}

// ReloadResourceRules reads and swaps in resource rules. A read failure retains
// the current rules; invalid rules are skipped as in [Engine.SetResourceRules].
func (engine *Engine) ReloadResourceRules(ctx context.Context, repository ResourceRuleRepository) error {
	engine.reload.Lock()
	defer engine.reload.Unlock()
	return engine.reloadResourceRules(ctx, repository)
}

func (engine *Engine) reloadResourceRules(ctx context.Context, repository ResourceRuleRepository) error {
	if repository == nil {
		return errors.New("resource rule repository is required")
	}
	rules, err := repository.ReadResourceRules(ctx)
	if err != nil {
		return fmt.Errorf("read resource rules: %w", err)
	}
	inputDigest, err := ResourceRulesDigest(rules)
	if err != nil {
		return err
	}
	if inputDigest == engine.resource.Load().inputDigest {
		return nil
	}
	return engine.SetResourceRules(rules)
}

func (rules *compiledResourceRules) evaluate(ctx context.Context, event Event, defaultWindow time.Duration) ([]InvestigationSignal, error) {
	if len(rules.byResource) == 0 {
		return nil, nil
	}
	var signals []InvestigationSignal
	// A resource rule describes what the resource itself does, so it matches
	// only inputs whose subject is the resource or one of its Pods, never
	// inputs where the resource is the object, such as a new client calling it.
	for _, subject := range event.SubjectIDs {
		for _, candidate := range rules.byResource[subject] {
			rule := candidate.rule
			if rule.Type != event.Type || rule.Kind != event.Kind || (rule.PluginID != "*" && rule.PluginID != event.PluginID) {
				continue
			}
			matched, _, err := candidate.match.ContextEval(ctx, inputActivation{input: event.Input})
			if err != nil {
				return nil, fmt.Errorf("resource rule %s match: %w", rule.ID, err)
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
