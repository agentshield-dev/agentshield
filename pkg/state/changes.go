package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ContributionEventOwner identifies the contribution version that produced a
// change event, with its readiness and health at that version.
type ContributionEventOwner struct {
	VersionID        int64     `json:"versionId"`
	PluginID         string    `json:"pluginId"`
	SourceID         string    `json:"sourceId"`
	Name             string    `json:"name"`
	Generation       uint64    `json:"generation"`
	Ready            bool      `json:"ready"`
	SourceHealth     string    `json:"sourceHealth"`
	SourceObservedAt time.Time `json:"sourceObservedAt"`
	Status           string    `json:"status"`
}

// EntityLocator identifies the compiled graph entity an assertion belongs to.
// For relationships it carries both endpoints and the predicate so a consumer
// can act on a retraction without reading the retracted row.
type EntityLocator struct {
	EntityType string `json:"entityType"`
	ID         string `json:"id"`
	ResourceID string `json:"resourceId,omitempty"`
	SubjectID  string `json:"subjectId,omitempty"`
	Predicate  string `json:"predicate,omitempty"`
	ObjectID   string `json:"objectId,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Qualifier  string `json:"qualifier,omitempty"`
}

// AssertionChange is one assertion added to or retracted from a contribution.
type AssertionChange struct {
	AssertionType string        `json:"assertionType"`
	AssertionID   string        `json:"assertionId"`
	Entity        EntityLocator `json:"entity"`
}

// ContributionChangeEvent is one outbox entry: the non-telemetry membership
// delta of one contribution version. Several events may touch the same graph
// entity; consumers should batch and resolve current truth from a checkpoint.
type ContributionChangeEvent struct {
	Sequence     uint64                 `json:"sequence"`
	Contribution ContributionEventOwner `json:"contribution"`
	Added        []AssertionChange      `json:"added,omitempty"`
	Retracted    []AssertionChange      `json:"retracted,omitempty"`
}

// GraphCheckpoint pairs an outbox position with the graph compiled from the
// same database snapshot.
type GraphCheckpoint struct {
	ThroughSequence uint64    `json:"throughSequence"`
	View            GraphView `json:"view"`
}

// ReasoningCursor is a consumer's durable outbox position and the graph digest
// it evaluated at that position.
type ReasoningCursor struct {
	ConsumerID      string    `json:"consumerId"`
	ThroughSequence uint64    `json:"throughSequence"`
	GraphSHA256     string    `json:"graphSha256"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// ReadContributionChanges returns up to limit (1-1000) outbox events with a
// sequence greater than afterSequence, in sequence order.
func (s *Store) ReadContributionChanges(ctx context.Context, afterSequence uint64, limit int) ([]ContributionChangeEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("contribution change limit must be between 1 and 1000")
	}
	if afterSequence > math.MaxInt64 {
		return nil, errors.New("contribution change sequence exceeds PostgreSQL bigint range")
	}
	rows, err := s.pool.Query(ctx, `SELECT sequence, payload FROM graph_change_outbox WHERE sequence > $1 ORDER BY sequence LIMIT $2`, int64(afterSequence), limit)
	if err != nil {
		return nil, fmt.Errorf("read contribution changes: %w", err)
	}
	defer rows.Close()
	var events []ContributionChangeEvent
	for rows.Next() {
		var sequence int64
		var payload []byte
		if err := rows.Scan(&sequence, &payload); err != nil {
			return nil, fmt.Errorf("scan contribution change: %w", err)
		}
		var event ContributionChangeEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode contribution change %d: %w", sequence, err)
		}
		if sequence < 1 || event.Sequence != uint64(sequence) {
			return nil, fmt.Errorf("contribution change sequence mismatch: row=%d payload=%d", sequence, event.Sequence)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate contribution changes: %w", err)
	}
	return events, nil
}

// ReadReasoningCursor returns the stored cursor for consumerID and whether one
// exists.
func (s *Store) ReadReasoningCursor(ctx context.Context, consumerID string) (ReasoningCursor, bool, error) {
	consumerID = strings.TrimSpace(consumerID)
	if consumerID == "" {
		return ReasoningCursor{}, false, errors.New("reasoning consumer ID is required")
	}
	var sequence int64
	var cursor ReasoningCursor
	err := s.pool.QueryRow(ctx, `SELECT through_sequence, graph_sha256, updated_at FROM reasoning_cursors WHERE consumer_id=$1`, consumerID).Scan(&sequence, &cursor.GraphSHA256, &cursor.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReasoningCursor{}, false, nil
	}
	if err != nil {
		return ReasoningCursor{}, false, fmt.Errorf("read reasoning cursor %q: %w", consumerID, err)
	}
	if sequence < 0 {
		return ReasoningCursor{}, false, fmt.Errorf("reasoning cursor %q has negative sequence %d", consumerID, sequence)
	}
	cursor.ConsumerID = consumerID
	cursor.ThroughSequence = uint64(sequence)
	return cursor, true, nil
}

// AdvanceReasoningCursor moves a consumer's cursor forward. Writing the same
// sequence and digest again is a no-op; moving backwards, or reusing a
// sequence with a different digest, is an error. A per-consumer advisory lock
// makes concurrent first writes for one consumer safe. Callers should advance
// only after durably recording what they did with the range.
func (s *Store) AdvanceReasoningCursor(ctx context.Context, cursor ReasoningCursor) error {
	cursor.ConsumerID = strings.TrimSpace(cursor.ConsumerID)
	cursor.GraphSHA256 = strings.TrimSpace(cursor.GraphSHA256)
	if cursor.ConsumerID == "" {
		return errors.New("reasoning consumer ID is required")
	}
	if cursor.GraphSHA256 == "" {
		return errors.New("reasoning cursor graph digest is required")
	}
	if cursor.ThroughSequence > math.MaxInt64 {
		return errors.New("reasoning cursor sequence exceeds PostgreSQL bigint range")
	}
	if cursor.UpdatedAt.IsZero() {
		cursor.UpdatedAt = time.Now().UTC()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin reasoning cursor advance: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, cursor.ConsumerID); err != nil {
		return fmt.Errorf("lock reasoning cursor %q: %w", cursor.ConsumerID, err)
	}
	var currentSequence int64
	var currentDigest string
	err = tx.QueryRow(ctx, `SELECT through_sequence, graph_sha256 FROM reasoning_cursors WHERE consumer_id=$1 FOR UPDATE`, cursor.ConsumerID).Scan(&currentSequence, &currentDigest)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		_, err = tx.Exec(ctx, `INSERT INTO reasoning_cursors (consumer_id, through_sequence, graph_sha256, updated_at) VALUES ($1,$2,$3,$4)`, cursor.ConsumerID, int64(cursor.ThroughSequence), cursor.GraphSHA256, cursor.UpdatedAt)
	case err != nil:
		return fmt.Errorf("lock reasoning cursor %q: %w", cursor.ConsumerID, err)
	case cursor.ThroughSequence < uint64(currentSequence):
		return fmt.Errorf("reasoning cursor %q cannot regress from %d to %d", cursor.ConsumerID, currentSequence, cursor.ThroughSequence)
	case cursor.ThroughSequence == uint64(currentSequence) && cursor.GraphSHA256 != currentDigest:
		return fmt.Errorf("reasoning cursor %q sequence %d has graph digest %q, not %q", cursor.ConsumerID, cursor.ThroughSequence, currentDigest, cursor.GraphSHA256)
	case cursor.ThroughSequence == uint64(currentSequence):
		return tx.Commit(ctx)
	default:
		_, err = tx.Exec(ctx, `UPDATE reasoning_cursors SET through_sequence=$2, graph_sha256=$3, updated_at=$4 WHERE consumer_id=$1`, cursor.ConsumerID, int64(cursor.ThroughSequence), cursor.GraphSHA256, cursor.UpdatedAt)
	}
	if err != nil {
		return fmt.Errorf("advance reasoning cursor %q: %w", cursor.ConsumerID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit reasoning cursor %q: %w", cursor.ConsumerID, err)
	}
	return nil
}
