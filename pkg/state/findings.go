package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
)

// ErrFindingNotFound is returned by GetFinding for an unknown ID.
var ErrFindingNotFound = errors.New("finding not found")

// Finding statuses. Invalidated findings are retained for audit but cannot
// launch remediation.
const (
	FindingStatusActive      = "active"
	FindingStatusInvalidated = "invalidated"
)

// Finding origins. Agentic investigation findings are promoted from a model
// assessment; detection rule findings are created directly from an active rule match.
const (
	FindingOriginAgenticInvestigation = "agentic_investigation"
	FindingOriginDetectionRule        = "detection_rule"
)

// Finding is a promoted reasoning result grounded in one graph digest.
// AffectedEntityIDs drive invalidation when later publications touch those
// entities.
type Finding struct {
	ID                     string                 `json:"id"`
	Origin                 string                 `json:"origin"`
	AnalysisID             string                 `json:"analysisId"`
	GraphSHA256            string                 `json:"graphSha256"`
	Category               string                 `json:"category"`
	Severity               string                 `json:"severity"`
	ModelUncertainty       string                 `json:"modelUncertainty,omitempty"`
	DetectionRuleID        string                 `json:"detectionRuleId,omitempty"`
	DetectionRuleRevision  uint64                 `json:"detectionRuleRevision,omitempty"`
	Summary                string                 `json:"summary"`
	SignalIDs              []string               `json:"signalIds"`
	AffectedEntityIDs      []string               `json:"affectedEntityIds"`
	Remediations           []remediation.Proposal `json:"remediations"`
	Status                 string                 `json:"status"`
	CreatedAt              time.Time              `json:"createdAt"`
	InvalidatedAt          *time.Time             `json:"invalidatedAt,omitempty"`
	InvalidatedBySequence  *uint64                `json:"invalidatedBySequence,omitempty"`
	InvalidatedGraphSHA256 string                 `json:"invalidatedGraphSha256,omitempty"`
}

// FindingQuery filters and pages findings. BeforeCreatedAt and
// BeforeFindingID together form the keyset cursor for the next page.
type FindingQuery struct {
	Status           string
	Severity         string
	Category         string
	AffectedEntityID string
	Limit            int
	BeforeCreatedAt  *time.Time
	BeforeFindingID  string
}

// FindingPage is one page of findings. Total counts every finding matching the
// filters, ignoring the cursor.
type FindingPage struct {
	Findings []Finding
	HasMore  bool
	Total    int
}

// Validate checks status, limit (1-100), and cursor completeness.
func (query FindingQuery) Validate() error {
	if query.Status != "" && query.Status != FindingStatusActive && query.Status != FindingStatusInvalidated {
		return errors.New("finding status is invalid")
	}
	if query.Limit < 1 || query.Limit > 100 {
		return errors.New("finding limit must be between 1 and 100")
	}
	if (query.BeforeCreatedAt == nil) != (strings.TrimSpace(query.BeforeFindingID) == "") {
		return errors.New("finding cursor requires creation time and finding ID")
	}
	return nil
}

// Validate checks required fields, that invalidation metadata matches the
// status, and that every remediation proposal belongs to this finding.
func (finding Finding) Validate() error {
	values := []string{finding.ID, finding.AnalysisID, finding.GraphSHA256, finding.Category, finding.Severity, finding.Summary}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return errors.New("finding requires identity, classification, and summary fields")
		}
	}
	switch finding.Origin {
	case FindingOriginAgenticInvestigation:
		if strings.TrimSpace(finding.ModelUncertainty) == "" || finding.DetectionRuleID != "" || finding.DetectionRuleRevision != 0 {
			return errors.New("agentic investigation finding requires model uncertainty and no detection rule")
		}
	case FindingOriginDetectionRule:
		if finding.DetectionRuleID == "" || len(finding.DetectionRuleID) > 128 || finding.DetectionRuleRevision == 0 || finding.DetectionRuleRevision > 1<<63-1 {
			return errors.New("detection rule finding requires a bounded rule ID and positive revision")
		}
	default:
		return fmt.Errorf("finding origin %q is invalid", finding.Origin)
	}
	if len(finding.SignalIDs) == 0 {
		return errors.New("finding requires signal IDs")
	}
	if finding.Status != FindingStatusActive && finding.Status != FindingStatusInvalidated {
		return errors.New("finding status is invalid")
	}
	if finding.Status == FindingStatusActive && (finding.InvalidatedAt != nil || finding.InvalidatedBySequence != nil || finding.InvalidatedGraphSHA256 != "") {
		return errors.New("active finding contains invalidation metadata")
	}
	if finding.Status == FindingStatusInvalidated && (finding.InvalidatedAt == nil || finding.InvalidatedBySequence == nil || finding.InvalidatedGraphSHA256 == "") {
		return errors.New("invalidated finding requires invalidation metadata")
	}
	if len(finding.Remediations) > remediation.MaxSuggestions {
		return fmt.Errorf("finding exceeds %d remediations", remediation.MaxSuggestions)
	}
	seen := make(map[string]struct{}, len(finding.Remediations))
	for _, proposal := range finding.Remediations {
		if err := proposal.Validate(); err != nil {
			return fmt.Errorf("validate finding remediation: %w", err)
		}
		if proposal.FindingID != finding.ID || proposal.AnalysisID != finding.AnalysisID || proposal.GraphSHA256 != finding.GraphSHA256 {
			return errors.New("finding remediation does not match its finding")
		}
		if _, found := seen[proposal.ID]; found {
			return fmt.Errorf("finding contains duplicate remediation %q", proposal.ID)
		}
		seen[proposal.ID] = struct{}{}
	}
	return nil
}

// PutFinding inserts a finding keyed by its deterministic ID. Re-putting the
// same content is a no-op, so a reasoning evaluation repeated after a crash
// is harmless; different content under an existing ID is an error.
// CreatedAt is ignored when comparing.
func (s *Store) PutFinding(ctx context.Context, finding Finding) error {
	if finding.Status == "" {
		finding.Status = FindingStatusActive
	}
	if finding.Origin == "" {
		finding.Origin = FindingOriginAgenticInvestigation
	}
	if finding.AffectedEntityIDs == nil {
		finding.AffectedEntityIDs = []string{}
	}
	if finding.Remediations == nil {
		finding.Remediations = []remediation.Proposal{}
	}
	if err := finding.Validate(); err != nil {
		return err
	}
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = time.Now().UTC()
	}
	signalIDs, err := json.Marshal(finding.SignalIDs)
	if err != nil {
		return fmt.Errorf("encode finding signal IDs: %w", err)
	}
	remediations, err := json.Marshal(finding.Remediations)
	if err != nil {
		return fmt.Errorf("encode finding remediations: %w", err)
	}
	affectedEntityIDs, err := json.Marshal(finding.AffectedEntityIDs)
	if err != nil {
		return fmt.Errorf("encode finding affected entity IDs: %w", err)
	}
	command, err := s.pool.Exec(ctx, `
		INSERT INTO findings (
			finding_id, analysis_id, graph_sha256, category,
			severity, model_uncertainty, summary, signal_ids, affected_entity_ids, remediations,
			status, created_at, invalidated_at, invalidated_by_sequence, invalidated_graph_sha256,
			origin, detection_rule_id, detection_rule_revision
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (finding_id) DO NOTHING`,
		finding.ID, finding.AnalysisID, finding.GraphSHA256, finding.Category, finding.Severity, finding.ModelUncertainty, finding.Summary,
		signalIDs, affectedEntityIDs, remediations, finding.Status, finding.CreatedAt,
		finding.InvalidatedAt, finding.InvalidatedBySequence, nullIfEmpty(finding.InvalidatedGraphSHA256),
		finding.Origin, nullIfEmpty(finding.DetectionRuleID), nullIfZero(finding.DetectionRuleRevision),
	)
	if err != nil {
		return fmt.Errorf("record finding %q: %w", finding.ID, err)
	}
	if command.RowsAffected() == 1 {
		return nil
	}
	existing, err := s.GetFinding(ctx, finding.ID)
	if err != nil {
		return err
	}
	existing.CreatedAt = finding.CreatedAt
	if !reflect.DeepEqual(existing, finding) {
		return fmt.Errorf("finding %q already exists with different content", finding.ID)
	}
	return nil
}

// GetFinding returns one finding or ErrFindingNotFound.
func (s *Store) GetFinding(ctx context.Context, findingID string) (Finding, error) {
	findingID = strings.TrimSpace(findingID)
	if findingID == "" {
		return Finding{}, errors.New("finding ID is required")
	}
	finding, err := scanFinding(s.pool.QueryRow(ctx, `
		SELECT finding_id, analysis_id, graph_sha256, category,
			severity, model_uncertainty, summary, signal_ids, affected_entity_ids, remediations,
			status, created_at, invalidated_at, invalidated_by_sequence, invalidated_graph_sha256,
			origin, COALESCE(detection_rule_id, ''), COALESCE(detection_rule_revision, 0)
		FROM findings WHERE finding_id=$1`, findingID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Finding{}, ErrFindingNotFound
	}
	if err != nil {
		return Finding{}, fmt.Errorf("read finding %q: %w", findingID, err)
	}
	return finding, nil
}

// QueryFindings returns findings newest first.
func (s *Store) QueryFindings(ctx context.Context, query FindingQuery) (FindingPage, error) {
	query.Status = strings.TrimSpace(query.Status)
	query.Severity = strings.TrimSpace(query.Severity)
	query.Category = strings.TrimSpace(query.Category)
	query.AffectedEntityID = strings.TrimSpace(query.AffectedEntityID)
	query.BeforeFindingID = strings.TrimSpace(query.BeforeFindingID)
	if err := query.Validate(); err != nil {
		return FindingPage{}, err
	}
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM findings
		WHERE ($1 = '' OR status = $1)
			AND ($2 = '' OR severity = $2)
			AND ($3 = '' OR category = $3)
			AND ($4 = '' OR affected_entity_ids ? $4)`,
		query.Status, query.Severity, query.Category, query.AffectedEntityID,
	).Scan(&total); err != nil {
		return FindingPage{}, fmt.Errorf("count findings: %w", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT finding_id, analysis_id, graph_sha256, category,
			severity, model_uncertainty, summary, signal_ids, affected_entity_ids, remediations,
			status, created_at, invalidated_at, invalidated_by_sequence, invalidated_graph_sha256,
			origin, COALESCE(detection_rule_id, ''), COALESCE(detection_rule_revision, 0)
		FROM findings
		WHERE ($1 = '' OR status = $1)
			AND ($2 = '' OR severity = $2)
			AND ($3 = '' OR category = $3)
			AND ($4 = '' OR affected_entity_ids ? $4)
			AND ($5::timestamptz IS NULL OR (created_at, finding_id) < ($5, $6))
		ORDER BY created_at DESC, finding_id DESC
		LIMIT $7`,
		query.Status, query.Severity, query.Category, query.AffectedEntityID,
		query.BeforeCreatedAt, query.BeforeFindingID, query.Limit+1,
	)
	if err != nil {
		return FindingPage{}, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	findings := make([]Finding, 0, query.Limit+1)
	for rows.Next() {
		finding, err := scanFinding(rows)
		if err != nil {
			return FindingPage{}, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return FindingPage{}, fmt.Errorf("iterate findings: %w", err)
	}
	page := FindingPage{Findings: findings, HasMore: len(findings) > query.Limit, Total: total}
	if page.HasMore {
		page.Findings = page.Findings[:query.Limit]
	}
	return page, nil
}

type findingRow interface {
	Scan(...any) error
}

func scanFinding(row findingRow) (Finding, error) {
	var finding Finding
	var signalIDs, affectedEntityIDs, remediations []byte
	var invalidatedBySequence *int64
	var invalidatedGraphSHA256 *string
	var ruleRevision int64
	err := row.Scan(
		&finding.ID, &finding.AnalysisID, &finding.GraphSHA256, &finding.Category, &finding.Severity, &finding.ModelUncertainty, &finding.Summary,
		&signalIDs, &affectedEntityIDs, &remediations, &finding.Status, &finding.CreatedAt,
		&finding.InvalidatedAt, &invalidatedBySequence, &invalidatedGraphSHA256,
		&finding.Origin, &finding.DetectionRuleID, &ruleRevision,
	)
	if err != nil {
		return Finding{}, err
	}
	finding.DetectionRuleRevision = uint64(ruleRevision)
	if err := json.Unmarshal(signalIDs, &finding.SignalIDs); err != nil {
		return Finding{}, fmt.Errorf("decode finding signal IDs: %w", err)
	}
	if err := json.Unmarshal(affectedEntityIDs, &finding.AffectedEntityIDs); err != nil {
		return Finding{}, fmt.Errorf("decode finding affected entity IDs: %w", err)
	}
	if err := json.Unmarshal(remediations, &finding.Remediations); err != nil {
		return Finding{}, fmt.Errorf("decode finding remediations: %w", err)
	}
	if invalidatedBySequence != nil {
		sequence := uint64(*invalidatedBySequence)
		finding.InvalidatedBySequence = &sequence
	}
	if invalidatedGraphSHA256 != nil {
		finding.InvalidatedGraphSHA256 = *invalidatedGraphSHA256
	}
	if err := finding.Validate(); err != nil {
		return Finding{}, fmt.Errorf("validate stored finding: %w", err)
	}
	return finding, nil
}

// InvalidateFindings marks active agentic investigation findings grounded in a
// digest other than graphSHA256 as invalidated by throughSequence. A nil
// affectedEntityIDs invalidates all of them (used on a rebase where change
// history is unavailable); a non-nil empty slice invalidates none; otherwise
// only findings touching one of the IDs, or recording no affected entities, are
// invalidated. Findings already grounded in graphSHA256 are left alone, which
// keeps repeated evaluation idempotent. Detection rule findings record that a
// rule matched and are never invalidated.
func (s *Store) InvalidateFindings(ctx context.Context, graphSHA256 string, throughSequence uint64, affectedEntityIDs []string, invalidatedAt time.Time) error {
	if graphSHA256 = strings.TrimSpace(graphSHA256); len(graphSHA256) != 64 {
		return errors.New("invalidation graph digest is required")
	}
	if throughSequence == 0 {
		return errors.New("invalidation sequence must be positive")
	}
	if affectedEntityIDs != nil && len(affectedEntityIDs) == 0 {
		return nil
	}
	if invalidatedAt.IsZero() {
		invalidatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE findings
		SET status='invalidated', invalidated_at=$1, invalidated_by_sequence=$2, invalidated_graph_sha256=$3
		WHERE status='active' AND graph_sha256 <> $3 AND origin <> 'detection_rule'
			AND ($4::text[] IS NULL OR affected_entity_ids = '[]'::jsonb OR affected_entity_ids ?| $4::text[])`,
		invalidatedAt.UTC(), int64(throughSequence), graphSHA256, affectedEntityIDs,
	)
	if err != nil {
		return fmt.Errorf("invalidate findings: %w", err)
	}
	return nil
}

func nullIfZero(value uint64) any {
	if value == 0 {
		return nil
	}
	return int64(value)
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}
