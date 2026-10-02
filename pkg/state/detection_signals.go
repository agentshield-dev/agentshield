package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/agentshield-dev/agentshield/pkg/detector"
)

// Detection signal investigation states.
const (
	// InvestigationInvestigated means agentic investigation analyzed the signal inline.
	InvestigationInvestigated = "investigated"
	// InvestigationQueued means the signal was handed to the agentic investigation queue,
	// whose job records whether it was investigated, batched, or sampled out.
	InvestigationQueued = "queued"
	// InvestigationBelowThreshold means no signal in the window was eligible, so no agent ran.
	InvestigationBelowThreshold = "below_threshold"
	// InvestigationDisabled means the window had an eligible signal but agentic investigation is disabled.
	InvestigationDisabled = "disabled"
	// InvestigationShadow means the signal came from an unreviewed workload rule and is never investigated.
	InvestigationShadow = "shadow"
	// InvestigationRuleFinding means the signal came from an active detection rule and became a finding directly.
	InvestigationRuleFinding = "rule_finding"
)

const maxDetectionSignalBatch = 1000

// DetectionSignal is one recorded detector signal and what happened to it.
type DetectionSignal struct {
	Signal          detector.InvestigationSignal `json:"signal"`
	ThroughSequence uint64                       `json:"throughSequence"`
	GraphSHA256     string                       `json:"graphSha256"`
	Investigation   string                       `json:"investigation"`
	RecordedAt      time.Time                    `json:"recordedAt"`
}

type DetectionSignalQuery struct {
	RuleID        string
	Investigation string
	Limit         int
}

func validInvestigation(value string) bool {
	switch value {
	case InvestigationInvestigated, InvestigationQueued, InvestigationBelowThreshold, InvestigationDisabled, InvestigationShadow, InvestigationRuleFinding:
		return true
	}
	return false
}

// RecordDetectionSignals stores signals idempotently; a retried window does not duplicate rows.
func (s *Store) RecordDetectionSignals(ctx context.Context, signals []DetectionSignal) error {
	if len(signals) == 0 {
		return nil
	}
	if len(signals) > maxDetectionSignalBatch {
		return fmt.Errorf("detection signal batch exceeds %d", maxDetectionSignalBatch)
	}
	batch := &pgx.Batch{}
	for _, record := range signals {
		signal := record.Signal
		if signal.ID == "" || !validInvestigation(record.Investigation) || record.ThroughSequence > 1<<63-1 {
			return errors.New("detection signal requires an ID, investigation state, and bounded sequence")
		}
		if record.Investigation == InvestigationShadow && signal.RuleMode != detector.RuleModeShadow {
			return errors.New("only shadow rule signals can be recorded as shadow")
		}
		if record.Investigation == InvestigationRuleFinding && (signal.RuleID == "" || signal.RuleMode == detector.RuleModeShadow) {
			return errors.New("only active rule signals can be recorded as rule findings")
		}
		reasons, err := json.Marshal(nonNilStrings(signal.Reasons))
		if err != nil {
			return err
		}
		anchors, err := json.Marshal(nonNilStrings(signal.AnchorIDs))
		if err != nil {
			return err
		}
		var ruleID, rulesetDigest any
		var ruleRevision any
		if signal.RuleID != "" {
			ruleID, ruleRevision, rulesetDigest = signal.RuleID, int64(signal.RuleRevision), nullIfEmpty(signal.RulesetDigest)
		}
		batch.Queue(`
			INSERT INTO detection_signals (
				signal_id, through_sequence, graph_sha256, risk, reasons, anchor_ids,
				window_start, window_end, rule_id, rule_revision, ruleset_digest, investigation
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (signal_id) DO NOTHING`,
			signal.ID, int64(record.ThroughSequence), record.GraphSHA256, string(signal.Risk), reasons, anchors,
			signal.Window.Start, signal.Window.End, ruleID, ruleRevision, rulesetDigest, record.Investigation)
	}
	if err := s.pool.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("record detection signals: %w", err)
	}
	return nil
}

// PruneDetectionSignals deletes signals recorded before the cutoff.
func (s *Store) PruneDetectionSignals(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.pool.Exec(ctx, `DELETE FROM detection_signals WHERE recorded_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("prune detection signals: %w", err)
	}
	return result.RowsAffected(), nil
}

// ListDetectionSignals returns the most recently recorded signals first.
func (s *Store) ListDetectionSignals(ctx context.Context, query DetectionSignalQuery) ([]DetectionSignal, error) {
	if query.Limit < 1 || query.Limit > 1000 {
		return nil, errors.New("detection signal limit must be between 1 and 1000")
	}
	if query.Investigation != "" && !validInvestigation(query.Investigation) {
		return nil, errors.New("detection signal investigation filter is invalid")
	}
	rows, err := s.pool.Query(ctx, `
		SELECT signal_id, through_sequence, graph_sha256, risk, reasons, anchor_ids, window_start, window_end,
		       COALESCE(rule_id, ''), COALESCE(rule_revision, 0), COALESCE(ruleset_digest, ''), investigation, recorded_at
		FROM detection_signals
		WHERE ($1 = '' OR rule_id = $1) AND ($2 = '' OR investigation = $2)
		ORDER BY recorded_at DESC, signal_id
		LIMIT $3`, strings.TrimSpace(query.RuleID), query.Investigation, query.Limit)
	if err != nil {
		return nil, fmt.Errorf("list detection signals: %w", err)
	}
	defer rows.Close()
	var result []DetectionSignal
	for rows.Next() {
		var record DetectionSignal
		var sequence, revision int64
		var risk string
		var reasons, anchors []byte
		signal := &record.Signal
		if err := rows.Scan(&signal.ID, &sequence, &record.GraphSHA256, &risk, &reasons, &anchors, &signal.Window.Start, &signal.Window.End,
			&signal.RuleID, &revision, &signal.RulesetDigest, &record.Investigation, &record.RecordedAt); err != nil {
			return nil, fmt.Errorf("scan detection signal: %w", err)
		}
		if err := json.Unmarshal(reasons, &signal.Reasons); err != nil {
			return nil, fmt.Errorf("decode detection signal reasons: %w", err)
		}
		if err := json.Unmarshal(anchors, &signal.AnchorIDs); err != nil {
			return nil, fmt.Errorf("decode detection signal anchors: %w", err)
		}
		record.ThroughSequence, signal.RuleRevision, signal.Risk = uint64(sequence), uint64(revision), detector.Risk(risk)
		if record.Investigation == InvestigationShadow {
			signal.RuleMode = detector.RuleModeShadow
		}
		record.Signal.Window.Start, record.Signal.Window.End = signal.Window.Start.UTC(), signal.Window.End.UTC()
		record.RecordedAt = record.RecordedAt.UTC()
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate detection signals: %w", err)
	}
	return result, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
