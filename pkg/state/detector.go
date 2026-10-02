package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/agentshield-dev/agentshield/pkg/detector"
)

const detectorRulesetQuery = `
    SELECT s.id, s.sha256,
           COALESCE(jsonb_agg(r.definition ORDER BY m.rule_id) FILTER (WHERE m.rule_id IS NOT NULL), '[]'::jsonb)
    FROM detector_rulesets s
    LEFT JOIN detector_ruleset_members m ON m.ruleset_id = s.id
    LEFT JOIN detector_rule_revisions r ON r.rule_id = m.rule_id AND r.revision = m.rule_revision
    WHERE s.id = $1
    GROUP BY s.id, s.sha256`

// ReadDetectorRuleset loads a stored ruleset and verifies its checksum.
func (s *Store) ReadDetectorRuleset(ctx context.Context, id string) (detector.Ruleset, error) {
	return decodeDetectorRuleset(s.pool.QueryRow(ctx, detectorRulesetQuery, id))
}

// ReadActiveDetectorRuleset loads the currently activated ruleset and its
// activation revision, or detector.ErrNoActiveRuleset.
func (s *Store) ReadActiveDetectorRuleset(ctx context.Context) (detector.Activation, error) {
	row := s.pool.QueryRow(ctx, `
        SELECT a.revision, s.id, s.sha256,
               COALESCE(jsonb_agg(r.definition ORDER BY m.rule_id) FILTER (WHERE m.rule_id IS NOT NULL), '[]'::jsonb)
        FROM detector_active_ruleset active
        JOIN detector_activations a ON a.revision = active.activation_revision
        JOIN detector_rulesets s ON s.id = a.ruleset_id
        LEFT JOIN detector_ruleset_members m ON m.ruleset_id = s.id
        LEFT JOIN detector_rule_revisions r ON r.rule_id = m.rule_id AND r.revision = m.rule_revision
        GROUP BY a.revision, s.id, s.sha256`)
	var revision int64
	var ruleset detector.Ruleset
	var digest string
	var definitions []byte
	if err := row.Scan(&revision, &ruleset.ID, &digest, &definitions); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return detector.Activation{}, detector.ErrNoActiveRuleset
		}
		return detector.Activation{}, fmt.Errorf("read active detector ruleset: %w", err)
	}
	if revision < 1 {
		return detector.Activation{}, errors.New("active detector revision must be positive")
	}
	if err := decodeDetectorRules(&ruleset, definitions, digest); err != nil {
		return detector.Activation{}, err
	}
	return detector.Activation{Revision: uint64(revision), Ruleset: ruleset}, nil
}

func decodeDetectorRuleset(row pgx.Row) (detector.Ruleset, error) {
	var ruleset detector.Ruleset
	var digest string
	var definitions []byte
	if err := row.Scan(&ruleset.ID, &digest, &definitions); err != nil {
		return detector.Ruleset{}, fmt.Errorf("read detector ruleset: %w", err)
	}
	if err := decodeDetectorRules(&ruleset, definitions, digest); err != nil {
		return detector.Ruleset{}, err
	}
	return ruleset, nil
}

func decodeDetectorRules(ruleset *detector.Ruleset, definitions []byte, expected string) error {
	if err := json.Unmarshal(definitions, &ruleset.Rules); err != nil {
		return fmt.Errorf("decode detector rules: %w", err)
	}
	digest, err := detector.RulesetDigest(*ruleset)
	if err != nil {
		return err
	}
	if digest != expected {
		return fmt.Errorf("detector ruleset %q checksum mismatch", ruleset.ID)
	}
	return nil
}

// SaveDetectorRuleset stores a validated ruleset and its rule revisions.
// Rulesets and rule revisions are immutable: saving identical content again
// is a no-op and different content under an existing ID or revision fails.
// Saving does not activate.
func (s *Store) SaveDetectorRuleset(ctx context.Context, ruleset detector.Ruleset, actor string) error {
	ruleset.Rules = slices.Clone(ruleset.Rules)
	slices.SortFunc(ruleset.Rules, func(left, right detector.Rule) int { return strings.Compare(left.ID, right.ID) })
	if err := validateDetectorActor(actor); err != nil {
		return err
	}
	if err := detector.ValidateRuleset(ruleset); err != nil {
		return err
	}
	digest, err := detector.RulesetDigest(ruleset)
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin detector ruleset save: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO detector_rulesets (id, sha256, created_by) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, ruleset.ID, digest, actor); err != nil {
		return err
	}
	var existing string
	if err := tx.QueryRow(ctx, `SELECT sha256 FROM detector_rulesets WHERE id=$1`, ruleset.ID).Scan(&existing); err != nil {
		return err
	}
	if existing != digest {
		return fmt.Errorf("detector ruleset %q is immutable", ruleset.ID)
	}
	for _, rule := range ruleset.Rules {
		definition, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(definition)
		ruleDigest := hex.EncodeToString(hash[:])
		if _, err := tx.Exec(ctx, `INSERT INTO detector_rule_revisions (rule_id, revision, definition, sha256, created_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, rule.ID, int64(rule.Revision), definition, ruleDigest, actor); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT sha256 FROM detector_rule_revisions WHERE rule_id=$1 AND revision=$2`, rule.ID, int64(rule.Revision)).Scan(&existing); err != nil {
			return err
		}
		if existing != ruleDigest {
			return fmt.Errorf("detector rule %q revision %d is immutable", rule.ID, rule.Revision)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO detector_ruleset_members (ruleset_id, rule_id, rule_revision) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, ruleset.ID, rule.ID, int64(rule.Revision)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ActivateDetectorRuleset makes ruleset id active as revision
// expectedRevision+1. It is a compare-and-set: if the current activation
// revision is not expectedRevision it returns detector.ErrActivationConflict.
// Every activation is kept as an audit row, so rollback is activating an
// older ruleset again.
func (s *Store) ActivateDetectorRuleset(ctx context.Context, id string, expectedRevision uint64, actor string) (uint64, error) {
	if err := validateDetectorActor(actor); err != nil {
		return 0, err
	}
	if expectedRevision >= math.MaxInt64 {
		return 0, errors.New("detector activation revision exceeds PostgreSQL bigint range")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin detector activation: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('agentshield/detector-activation', 0))`); err != nil {
		return 0, err
	}
	var current int64
	err = tx.QueryRow(ctx, `SELECT activation_revision FROM detector_active_ruleset WHERE singleton`).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	if uint64(current) != expectedRevision {
		return 0, detector.ErrActivationConflict
	}
	ruleset, err := decodeDetectorRuleset(tx.QueryRow(ctx, detectorRulesetQuery, id))
	if err != nil {
		return 0, err
	}
	if err := detector.ValidateRuleset(ruleset); err != nil {
		return 0, err
	}
	revision := current + 1
	if _, err := tx.Exec(ctx, `INSERT INTO detector_activations (revision, ruleset_id, activated_by) VALUES ($1,$2,$3)`, revision, id, actor); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO detector_active_ruleset (singleton, activation_revision) VALUES (true,$1) ON CONFLICT (singleton) DO UPDATE SET activation_revision=EXCLUDED.activation_revision`, revision); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return uint64(revision), nil
}

// EnsureDefaultDetectorRuleset saves and activates the built-in ruleset when
// nothing is active. Losing the activation race to another process is not an
// error.
func (s *Store) EnsureDefaultDetectorRuleset(ctx context.Context) error {
	if _, err := s.ReadActiveDetectorRuleset(ctx); err == nil {
		return nil
	} else if !errors.Is(err, detector.ErrNoActiveRuleset) {
		return err
	}
	ruleset := detector.DefaultRuleset()
	if err := s.SaveDetectorRuleset(ctx, ruleset, "agentshield/bootstrap"); err != nil {
		return err
	}
	_, err := s.ActivateDetectorRuleset(ctx, ruleset.ID, 0, "agentshield/bootstrap")
	if errors.Is(err, detector.ErrActivationConflict) {
		return nil
	}
	return err
}

func validateDetectorActor(actor string) error {
	if strings.TrimSpace(actor) == "" || len(actor) > 128 {
		return errors.New("detector actor must contain 1-128 bytes")
	}
	return nil
}
