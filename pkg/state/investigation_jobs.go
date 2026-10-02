package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Investigation job states. Terminal states are completed, sampled_out, and failed.
const (
	InvestigationJobQueued     = "queued"
	InvestigationJobRunning    = "running"
	InvestigationJobRetryable  = "retryable"
	InvestigationJobCompleted  = "completed"
	InvestigationJobSampledOut = "sampled_out"
	InvestigationJobFailed     = "failed"
)

// Admission decisions for a claimed investigation job.
const (
	InvestigationAdmitted   = "admitted"
	InvestigationDuplicate  = "duplicate"
	InvestigationOverBudget = "budget"
	InvestigationDeferred   = "deferred"
)

const maxInvestigationRequestBytes = 1024 * 1024

// InvestigationJobRecord is the indexed form of an investigation request. Request
// is opaque to storage; the caller owns its schema and merge semantics.
type InvestigationJobRecord struct {
	RiskRank      int             `json:"riskRank"`
	AnchorIDs     []string        `json:"anchorIds"`
	Fingerprint   string          `json:"fingerprint"`
	SampleKey     string          `json:"sampleKey"`
	FirstSequence uint64          `json:"firstSequence"`
	LastSequence  uint64          `json:"lastSequence"`
	Request       json.RawMessage `json:"request"`
}

func (record InvestigationJobRecord) validate() error {
	if record.RiskRank < 1 || record.RiskRank > 4 {
		return errors.New("investigation risk rank must be between 1 and 4")
	}
	if len(record.AnchorIDs) == 0 || len(record.AnchorIDs) > 1024 {
		return errors.New("investigation job requires 1-1024 anchors")
	}
	if len(record.Fingerprint) != 64 || len(record.SampleKey) != 64 {
		return errors.New("investigation fingerprint and sample key must be SHA-256 hex digests")
	}
	if record.FirstSequence == 0 || record.LastSequence < record.FirstSequence || record.LastSequence > 1<<63-1 {
		return errors.New("investigation job requires a positive, ordered sequence range")
	}
	if !json.Valid(record.Request) || len(record.Request) > maxInvestigationRequestBytes {
		return errors.New("investigation request must be valid JSON no larger than 1 MiB")
	}
	return nil
}

// InvestigationJob is a claimed job.
type InvestigationJob struct {
	ID int64 `json:"id"`
	InvestigationJobRecord
	AttemptCount int  `json:"attemptCount"`
	Admitted     bool `json:"admitted"`
}

// InvestigationAdmission bounds model spend for claimed jobs.
type InvestigationAdmission struct {
	// DedupWindow skips a job whose fingerprint was admitted within the window; zero disables it.
	DedupWindow time.Duration
	// MaxPerHour caps admissions in any trailing hour; zero is unlimited.
	MaxPerHour int
	// DeferRiskRank defers, rather than skips, over-budget jobs at or above this rank.
	DeferRiskRank int
	// DeferFor is how long an over-budget job at or above DeferRiskRank waits before retrying admission.
	DeferFor time.Duration
}

// MaxInvestigationJobSpan is the largest change range one job may cover, matching
// the change reader's batch limit.
const MaxInvestigationJobSpan = 1000

// EnqueueInvestigationJob coalesces record into the oldest queued, unclaimed job
// that shares an anchor and whose combined change range stays within
// MaxInvestigationJobSpan, when merge accepts it. Otherwise it inserts a new job
// available after batchWindow.
func (s *Store) EnqueueInvestigationJob(ctx context.Context, record InvestigationJobRecord, batchWindow time.Duration, merge func(existing InvestigationJobRecord) (InvestigationJobRecord, bool, error)) (int64, bool, error) {
	if err := record.validate(); err != nil {
		return 0, false, err
	}
	if batchWindow < 0 || batchWindow > time.Hour {
		return 0, false, errors.New("investigation batch window must be between zero and one hour")
	}
	anchors, err := json.Marshal(record.AnchorIDs)
	if err != nil {
		return 0, false, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, false, fmt.Errorf("begin investigation enqueue: %w", err)
	}
	defer tx.Rollback(ctx)
	if merge != nil {
		var existing InvestigationJobRecord
		var jobID, first, last int64
		var existingAnchors []byte
		err := tx.QueryRow(ctx, `
			SELECT job_id, risk_rank, anchor_ids, fingerprint, sample_key, first_sequence, last_sequence, request
			FROM investigation_jobs
			WHERE status = 'queued' AND admitted_at IS NULL AND anchor_ids ?| $1::text[]
			  AND GREATEST(last_sequence, $3) - LEAST(first_sequence, $2) < $4
			ORDER BY job_id
			LIMIT 1
			FOR UPDATE SKIP LOCKED`, record.AnchorIDs, int64(record.FirstSequence), int64(record.LastSequence), int64(MaxInvestigationJobSpan)).
			Scan(&jobID, &existing.RiskRank, &existingAnchors, &existing.Fingerprint, &existing.SampleKey, &first, &last, &existing.Request)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return 0, false, fmt.Errorf("find coalescable investigation job: %w", err)
		}
		if err == nil {
			existing.FirstSequence, existing.LastSequence = uint64(first), uint64(last)
			if err := json.Unmarshal(existingAnchors, &existing.AnchorIDs); err != nil {
				return 0, false, fmt.Errorf("decode investigation anchors: %w", err)
			}
			merged, accepted, err := merge(existing)
			if err != nil {
				return 0, false, err
			}
			if accepted {
				if err := merged.validate(); err != nil {
					return 0, false, err
				}
				mergedAnchors, err := json.Marshal(merged.AnchorIDs)
				if err != nil {
					return 0, false, err
				}
				if _, err := tx.Exec(ctx, `
					UPDATE investigation_jobs
					SET risk_rank=$2, anchor_ids=$3, fingerprint=$4, sample_key=$5, first_sequence=$6, last_sequence=$7,
					    request=$8, updated_at=now()
					WHERE job_id=$1`,
					jobID, merged.RiskRank, mergedAnchors, merged.Fingerprint, merged.SampleKey,
					int64(merged.FirstSequence), int64(merged.LastSequence), merged.Request); err != nil {
					return 0, false, fmt.Errorf("coalesce investigation job %d: %w", jobID, err)
				}
				if err := tx.Commit(ctx); err != nil {
					return 0, false, fmt.Errorf("commit investigation coalesce: %w", err)
				}
				return jobID, true, nil
			}
		}
	}
	var jobID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO investigation_jobs (risk_rank, anchor_ids, fingerprint, sample_key, first_sequence, last_sequence, request, available_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, now()+($8::bigint * interval '1 microsecond'))
		RETURNING job_id`,
		record.RiskRank, anchors, record.Fingerprint, record.SampleKey, int64(record.FirstSequence), int64(record.LastSequence),
		record.Request, batchWindow.Microseconds()).Scan(&jobID); err != nil {
		return 0, false, fmt.Errorf("enqueue investigation job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, false, fmt.Errorf("commit investigation enqueue: %w", err)
	}
	return jobID, false, nil
}

// ClaimInvestigationJob leases the highest-risk available job, oldest first, or a
// running job whose lease expired.
//
// AttemptCount counts failed attempts, and an expired lease is one: the
// previous worker is presumed to have crashed. Reclaiming an expired job
// increments it, and an expired job that would reach the store's maximum
// attempts is failed instead, so a job that crashes every worker cannot stay
// at the head of the queue forever.
func (s *Store) ClaimInvestigationJob(ctx context.Context, workerID string, lease time.Duration) (InvestigationJob, bool, error) {
	leaseMicros, err := investigationLease(workerID, lease)
	if err != nil {
		return InvestigationJob{}, false, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return InvestigationJob{}, false, fmt.Errorf("begin investigation claim: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		UPDATE investigation_jobs j
		SET status='failed', attempt_count=j.attempt_count+1, last_error='investigation lease expired; maximum attempts reached',
		    lease_owner=NULL, lease_expires_at=NULL, completed_at=now(), updated_at=now()
		FROM (
			SELECT job_id FROM investigation_jobs
			WHERE status = 'running' AND lease_expires_at <= now() AND attempt_count+1 >= $1
			FOR UPDATE SKIP LOCKED
		) exhausted
		WHERE j.job_id=exhausted.job_id`, s.investigationMaxAttempts); err != nil {
		return InvestigationJob{}, false, fmt.Errorf("fail exhausted investigation jobs: %w", err)
	}
	var job InvestigationJob
	var first, last int64
	var anchors []byte
	var admittedAt *time.Time
	err = tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT job_id FROM investigation_jobs
			WHERE (status IN ('queued', 'retryable') AND available_at <= now())
			   OR (status = 'running' AND lease_expires_at <= now() AND attempt_count+1 < $3)
			ORDER BY risk_rank DESC, available_at, job_id
			FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE investigation_jobs j
		SET status='running', lease_owner=$1, lease_expires_at=now()+($2::bigint * interval '1 microsecond'), updated_at=now(),
		    attempt_count=j.attempt_count + CASE WHEN j.status='running' THEN 1 ELSE 0 END,
		    last_error=CASE WHEN j.status='running' THEN 'investigation lease expired' ELSE j.last_error END
		FROM candidate WHERE j.job_id=candidate.job_id
		RETURNING j.job_id, j.risk_rank, j.anchor_ids, j.fingerprint, j.sample_key, j.first_sequence, j.last_sequence,
		          j.request, j.attempt_count, j.admitted_at`,
		strings.TrimSpace(workerID), leaseMicros, s.investigationMaxAttempts).
		Scan(&job.ID, &job.RiskRank, &anchors, &job.Fingerprint, &job.SampleKey, &first, &last, &job.Request, &job.AttemptCount, &admittedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return InvestigationJob{}, false, fmt.Errorf("claim investigation job: %w", err)
	}
	found := err == nil
	if found {
		if err := json.Unmarshal(anchors, &job.AnchorIDs); err != nil {
			return InvestigationJob{}, false, fmt.Errorf("decode investigation anchors: %w", err)
		}
		job.FirstSequence, job.LastSequence, job.Admitted = uint64(first), uint64(last), admittedAt != nil
	}
	// Commit even when nothing was claimed, to keep any exhausted-job failures.
	if err := tx.Commit(ctx); err != nil {
		return InvestigationJob{}, false, fmt.Errorf("commit investigation claim: %w", err)
	}
	if !found {
		return InvestigationJob{}, false, nil
	}
	return job, true, nil
}

// AdmitInvestigationJob atomically applies deduplication and the hourly budget to a
// claimed job. Admitted jobs keep their admission across retries.
func (s *Store) AdmitInvestigationJob(ctx context.Context, jobID int64, workerID string, admission InvestigationAdmission) (string, error) {
	if admission.DedupWindow < 0 || admission.MaxPerHour < 0 || admission.DeferFor < 0 {
		return "", errors.New("investigation admission bounds must not be negative")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("begin investigation admission: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('agentshield/investigation-admission', 0))`); err != nil {
		return "", err
	}
	var fingerprint string
	var riskRank int
	var admittedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT fingerprint, risk_rank, admitted_at FROM investigation_jobs WHERE job_id=$1 AND status='running' AND lease_owner=$2 FOR UPDATE`, jobID, workerID).
		Scan(&fingerprint, &riskRank, &admittedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("investigation job lease is no longer owned by this worker")
	}
	if err != nil {
		return "", fmt.Errorf("read investigation job for admission: %w", err)
	}
	if admittedAt != nil {
		return InvestigationAdmitted, tx.Commit(ctx)
	}
	decision := InvestigationAdmitted
	if admission.DedupWindow > 0 {
		var duplicate bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM investigation_jobs
				WHERE job_id <> $1 AND fingerprint = $2 AND status <> 'failed'
				  AND admitted_at > now()-($3::bigint * interval '1 microsecond')
			)`, jobID, fingerprint, admission.DedupWindow.Microseconds()).Scan(&duplicate); err != nil {
			return "", fmt.Errorf("check investigation duplicate: %w", err)
		}
		if duplicate {
			decision = InvestigationDuplicate
		}
	}
	if decision == InvestigationAdmitted && admission.MaxPerHour > 0 {
		var admitted int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM investigation_jobs WHERE admitted_at > now() - interval '1 hour'`).Scan(&admitted); err != nil {
			return "", fmt.Errorf("count investigation admissions: %w", err)
		}
		if admitted >= admission.MaxPerHour {
			decision = InvestigationOverBudget
			if admission.DeferRiskRank > 0 && riskRank >= admission.DeferRiskRank {
				decision = InvestigationDeferred
			}
		}
	}
	switch decision {
	case InvestigationAdmitted:
		_, err = tx.Exec(ctx, `UPDATE investigation_jobs SET admitted_at=now(), updated_at=now() WHERE job_id=$1`, jobID)
	case InvestigationDeferred:
		_, err = tx.Exec(ctx, `
			UPDATE investigation_jobs
			SET status='queued', available_at=now()+($2::bigint * interval '1 microsecond'), lease_owner=NULL, lease_expires_at=NULL, updated_at=now()
			WHERE job_id=$1`, jobID, admission.DeferFor.Microseconds())
	default:
		_, err = tx.Exec(ctx, `
			UPDATE investigation_jobs
			SET status='sampled_out', skip_reason=$2, lease_owner=NULL, lease_expires_at=NULL, completed_at=now(), updated_at=now()
			WHERE job_id=$1`, jobID, decision)
	}
	if err != nil {
		return "", fmt.Errorf("record investigation admission: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit investigation admission: %w", err)
	}
	return decision, nil
}

// SkipInvestigationJob ends a claimed job without investigating it.
func (s *Store) SkipInvestigationJob(ctx context.Context, jobID int64, workerID, reason string) error {
	if reason == "" || len(reason) > 64 {
		return errors.New("investigation skip reason must contain 1-64 bytes")
	}
	return s.finishInvestigationJob(ctx, `
		UPDATE investigation_jobs
		SET status='sampled_out', skip_reason=$3, lease_owner=NULL, lease_expires_at=NULL, completed_at=now(), updated_at=now()
		WHERE job_id=$1 AND status='running' AND lease_owner=$2`, jobID, workerID, reason)
}

func (s *Store) RenewInvestigationJob(ctx context.Context, jobID int64, workerID string, lease time.Duration) (bool, error) {
	leaseMicros, err := investigationLease(workerID, lease)
	if err != nil {
		return false, err
	}
	result, err := s.pool.Exec(ctx, `UPDATE investigation_jobs SET lease_expires_at=now()+($3::bigint * interval '1 microsecond'), updated_at=now() WHERE job_id=$1 AND status='running' AND lease_owner=$2`, jobID, workerID, leaseMicros)
	if err != nil {
		return false, fmt.Errorf("renew investigation lease: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// CompleteInvestigationJob records the outcome of an investigated job.
func (s *Store) CompleteInvestigationJob(ctx context.Context, jobID int64, workerID string, outcome json.RawMessage) error {
	if !json.Valid(outcome) || len(outcome) > 64*1024 {
		return errors.New("investigation outcome must be valid JSON no larger than 64 KiB")
	}
	return s.finishInvestigationJob(ctx, `
		UPDATE investigation_jobs
		SET status='completed', outcome=$3, lease_owner=NULL, lease_expires_at=NULL, last_error=NULL, completed_at=now(), updated_at=now()
		WHERE job_id=$1 AND status='running' AND lease_owner=$2`, jobID, workerID, outcome)
}

// RetryInvestigationJob records a failed attempt. A terminal failure ends the job.
func (s *Store) RetryInvestigationJob(ctx context.Context, jobID int64, workerID, failure string, retryAfter time.Duration, terminal bool) error {
	if len(failure) > 2048 {
		failure = failure[:2048]
	}
	retryAfter = min(max(retryAfter, time.Second), 24*time.Hour)
	if terminal {
		return s.finishInvestigationJob(ctx, `
			UPDATE investigation_jobs
			SET status='failed', attempt_count=attempt_count+1, last_error=$3, lease_owner=NULL, lease_expires_at=NULL, completed_at=now(), updated_at=now()
			WHERE job_id=$1 AND status='running' AND lease_owner=$2`, jobID, workerID, failure)
	}
	return s.finishInvestigationJob(ctx, `
		UPDATE investigation_jobs
		SET status='retryable', attempt_count=attempt_count+1, last_error=$3, available_at=now()+($4::bigint * interval '1 microsecond'),
		    lease_owner=NULL, lease_expires_at=NULL, updated_at=now()
		WHERE job_id=$1 AND status='running' AND lease_owner=$2`, jobID, workerID, failure, retryAfter.Microseconds())
}

func (s *Store) finishInvestigationJob(ctx context.Context, query string, arguments ...any) error {
	result, err := s.pool.Exec(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("update investigation job: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("investigation job lease is no longer owned by this worker")
	}
	return nil
}

// PruneInvestigationJobs deletes terminal jobs that finished before the cutoff.
func (s *Store) PruneInvestigationJobs(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.pool.Exec(ctx, `DELETE FROM investigation_jobs WHERE completed_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("prune investigation jobs: %w", err)
	}
	return result.RowsAffected(), nil
}

type InvestigationJobSummary struct {
	ID            int64           `json:"id"`
	Status        string          `json:"status"`
	RiskRank      int             `json:"riskRank"`
	AnchorIDs     []string        `json:"anchorIds"`
	FirstSequence uint64          `json:"firstSequence"`
	LastSequence  uint64          `json:"lastSequence"`
	AttemptCount  int             `json:"attemptCount"`
	SkipReason    string          `json:"skipReason,omitempty"`
	LastError     string          `json:"lastError,omitempty"`
	Outcome       json.RawMessage `json:"outcome,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
	AvailableAt   time.Time       `json:"availableAt"`
	AdmittedAt    *time.Time      `json:"admittedAt,omitempty"`
	CompletedAt   *time.Time      `json:"completedAt,omitempty"`
}

// ListInvestigationJobs returns the newest jobs first.
func (s *Store) ListInvestigationJobs(ctx context.Context, limit int) ([]InvestigationJobSummary, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("investigation job list limit must be between 1 and 1000")
	}
	rows, err := s.pool.Query(ctx, `
		SELECT job_id, status, risk_rank, anchor_ids, first_sequence, last_sequence, attempt_count,
		       COALESCE(skip_reason, ''), COALESCE(last_error, ''), outcome, created_at, available_at, admitted_at, completed_at
		FROM investigation_jobs ORDER BY job_id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list investigation jobs: %w", err)
	}
	defer rows.Close()
	var jobs []InvestigationJobSummary
	for rows.Next() {
		var job InvestigationJobSummary
		var anchors, outcome []byte
		var first, last int64
		if err := rows.Scan(&job.ID, &job.Status, &job.RiskRank, &anchors, &first, &last, &job.AttemptCount,
			&job.SkipReason, &job.LastError, &outcome, &job.CreatedAt, &job.AvailableAt, &job.AdmittedAt, &job.CompletedAt); err != nil {
			return nil, fmt.Errorf("scan investigation job: %w", err)
		}
		if err := json.Unmarshal(anchors, &job.AnchorIDs); err != nil {
			return nil, fmt.Errorf("decode investigation anchors: %w", err)
		}
		job.FirstSequence, job.LastSequence = uint64(first), uint64(last)
		if outcome != nil {
			job.Outcome = json.RawMessage(outcome)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate investigation jobs: %w", err)
	}
	return jobs, nil
}

func investigationLease(workerID string, lease time.Duration) (int64, error) {
	if workerID = strings.TrimSpace(workerID); workerID == "" || len(workerID) > 128 {
		return 0, errors.New("investigation worker ID must contain 1-128 bytes")
	}
	micros := lease.Microseconds()
	if micros < 1 || micros > int64((24*time.Hour).Microseconds()) {
		return 0, errors.New("investigation lease must be between one microsecond and 24 hours")
	}
	return micros, nil
}
