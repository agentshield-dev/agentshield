package reasoning

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

const (
	ruleFindingIDDomain   = "detector.rule-match"
	ruleFindingCategory   = "detection_rule_match"
	ruleFindingAnalysisID = "detection-window:sha256:"
)

// RuleFindings turns the active rule signals of an evaluated window into findings,
// one per rule revision. An active rule is operator-approved or operator-activated,
// so its match is a finding without agentic investigation. Shadow and built-in
// novelty signals never produce rule findings.
func RuleFindings(evaluation Evaluation, createdAt time.Time) []state.Finding {
	if evaluation.Rebased || len(evaluation.RuleSignals) == 0 {
		return nil
	}
	type ruleKey struct {
		id       string
		revision uint64
	}
	groups := make(map[ruleKey][]detector.InvestigationSignal)
	for _, signal := range evaluation.RuleSignals {
		if signal.RuleID == "" || signal.RuleMode == detector.RuleModeShadow {
			continue
		}
		key := ruleKey{id: signal.RuleID, revision: signal.RuleRevision}
		groups[key] = append(groups[key], signal)
	}
	checkpoint := evaluation.Window.Checkpoint
	windowDigest := sha256.Sum256([]byte(checkpoint.View.SHA256 + "\x00" + strconv.FormatUint(checkpoint.ThroughSequence, 10)))
	findings := make([]state.Finding, 0, len(groups))
	for key, signals := range groups {
		signalIDs := make([]string, 0, len(signals))
		reasons := make(map[string]struct{})
		affected := make(map[string]struct{})
		risk := detector.RiskLow
		for _, signal := range signals {
			signalIDs = append(signalIDs, signal.ID)
			for _, reason := range signal.Reasons {
				reasons[reason] = struct{}{}
			}
			for _, anchor := range signal.AnchorIDs {
				affected[anchor] = struct{}{}
			}
			if signal.Risk.Rank() > risk.Rank() {
				risk = signal.Risk
			}
		}
		slices.Sort(signalIDs)
		signalIDs = slices.Compact(signalIDs)
		reasonList := sortedKeys(reasons)
		digest := sha256.Sum256([]byte(strings.Join(append([]string{ruleFindingIDDomain, key.id, strconv.FormatUint(key.revision, 10), checkpoint.View.SHA256}, signalIDs...), "\x00")))
		findings = append(findings, state.Finding{
			ID: "finding:sha256:" + hex.EncodeToString(digest[:]), Origin: state.FindingOriginDetectionRule,
			AnalysisID: ruleFindingAnalysisID + hex.EncodeToString(windowDigest[:]), GraphSHA256: checkpoint.View.SHA256,
			Category: ruleFindingCategory, Severity: string(risk),
			Summary:         fmt.Sprintf("Detection rule %s (revision %d) matched %d new input(s): %s", key.id, key.revision, len(signalIDs), strings.Join(reasonList, ", ")),
			DetectionRuleID: key.id, DetectionRuleRevision: key.revision,
			SignalIDs: signalIDs, AffectedEntityIDs: sortedKeys(affected), Remediations: []remediation.Proposal{},
			Status: state.FindingStatusActive, CreatedAt: createdAt,
		})
	}
	slices.SortFunc(findings, func(left, right state.Finding) int { return strings.Compare(left.ID, right.ID) })
	return findings
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}
