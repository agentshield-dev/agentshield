package state

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// DeploymentAuthoringContextMaxBytes bounds the compact JSON persisted for a
// Deployment authoring job, which holds identity only. ValidateContext limits
// the resource ID to 128 bytes, the three names to 253 bytes each, and the
// template digest to 64 hex characters; even when JSON escaping expands every
// permitted character, a valid identity context remains below this 8 KiB
// bound. Observed behavior is added by the worker and never persisted here.
const DeploymentAuthoringContextMaxBytes = 8 << 10

// DeploymentAuthoringContext is the bounded workload description given to the
// rule author for one Kubernetes Deployment.
type DeploymentAuthoringContext struct {
	ResourceID         string `json:"resourceId"`
	Kind               string `json:"kind"`
	Name               string `json:"name,omitempty"`
	Namespace          string `json:"namespace,omitempty"`
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// TemplateSHA256 is the Deployment's kubernetes/pod-template-sha256: the
	// revision a job authors for. It scopes rule IDs and is not sent to the model.
	TemplateSHA256 string `json:"templateSha256,omitempty"`
	// ObservedBehavior is the Deployment's baseline of outbound requests. Nil
	// means no baseline was taken; an empty request list means one was taken
	// and the Deployment made no outbound requests. The authoring worker sets
	// it when it claims a job; the queue stores only identity.
	ObservedBehavior *DeploymentBehavior `json:"observedBehavior,omitempty"`
}

// Limits on [DeploymentBehavior], which is sent to a model.
const (
	MaxObservedRequests        = 32
	MaxCollectedTelemetry      = 16
	maxObservedOperationLength = 256
)

// DeploymentBehavior summarizes the telemetry whose subject is one Deployment.
// Operations are normalized by [NormalizeObservedOperation].
type DeploymentBehavior struct {
	// CollectedTelemetry lists the telemetry kinds observed anywhere in the
	// graph, so an empty Requests list can be told apart from telemetry that is
	// not collected at all.
	CollectedTelemetry []string          `json:"collectedTelemetry"`
	Requests           []ObservedRequest `json:"requests"`
	// Truncated reports that more distinct requests were observed than
	// MaxObservedRequests; the most frequent are kept.
	Truncated bool `json:"truncated,omitempty"`
}

// ObservedRequest is one distinct (telemetry kind, destination, operation,
// outcome) combination and how often it was observed. Destinations outside
// Kubernetes are described by kind and role only, never by raw address.
type ObservedRequest struct {
	Telemetry       string `json:"telemetry"`
	Destination     string `json:"destination,omitempty"`
	DestinationKind string `json:"destinationKind"`
	DestinationRole string `json:"destinationRole,omitempty"`
	Operation       string `json:"operation,omitempty"`
	Outcome         string `json:"outcome,omitempty"`
	Count           uint64 `json:"count"`
}

// DeploymentObservedBehavior summarizes the current graph's telemetry for a
// Deployment; see [DeploymentBehaviorFor].
func (s *Store) DeploymentObservedBehavior(ctx context.Context, resourceID string) (DeploymentBehavior, error) {
	view, err := s.Latest(ctx)
	if err != nil {
		return DeploymentBehavior{}, fmt.Errorf("read graph for Deployment baseline: %w", err)
	}
	return DeploymentBehaviorFor(view.Snapshot, resourceID), nil
}

// DeploymentBehaviorFor summarizes the telemetry in snapshot whose subject is
// the resource. The result is deterministic for a given snapshot.
func DeploymentBehaviorFor(snapshot graph.Snapshot, resourceID string) DeploymentBehavior {
	kinds := make(map[string]string, len(snapshot.Resources))
	names := make(map[string]string, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		kinds[resource.ID] = resource.Kind
		for _, assertion := range resource.Assertions {
			name, namespace := assertion.Attributes["kubernetes/name"], assertion.Attributes["kubernetes/namespace"]
			if name != "" && namespace != "" {
				names[resource.ID] = boundedString(namespace+"/"+name, 507)
				break
			}
		}
	}
	roles := graph.ResourceNetworkRoles(snapshot)
	counts := make(map[ObservedRequest]uint64)
	collected := make(map[string]struct{})
	for _, event := range snapshot.Telemetry {
		collected[boundedString(event.Kind, 128)] = struct{}{}
		if event.SubjectID != resourceID {
			continue
		}
		key := ObservedRequest{
			Telemetry: event.Kind, Destination: names[event.ObjectID], DestinationKind: kinds[event.ObjectID],
			DestinationRole: roles[event.ObjectID], Operation: NormalizeObservedOperation(event.Operation), Outcome: boundedString(event.Outcome, 64),
		}
		counts[key] += event.Count
	}
	behavior := DeploymentBehavior{CollectedTelemetry: append([]string{}, slices.Sorted(maps.Keys(collected))...), Requests: make([]ObservedRequest, 0, len(counts))}
	if len(behavior.CollectedTelemetry) > MaxCollectedTelemetry {
		behavior.CollectedTelemetry = behavior.CollectedTelemetry[:MaxCollectedTelemetry]
	}
	for request, count := range counts {
		request.Count = count
		behavior.Requests = append(behavior.Requests, request)
	}
	slices.SortFunc(behavior.Requests, func(left, right ObservedRequest) int {
		return cmp.Or(cmp.Compare(right.Count, left.Count), compareObservedRequests(left, right))
	})
	if len(behavior.Requests) > MaxObservedRequests {
		behavior.Requests, behavior.Truncated = behavior.Requests[:MaxObservedRequests], true
	}
	slices.SortFunc(behavior.Requests, compareObservedRequests)
	return behavior
}

func compareObservedRequests(left, right ObservedRequest) int {
	return cmp.Or(
		cmp.Compare(left.Destination, right.Destination), cmp.Compare(left.DestinationKind, right.DestinationKind),
		cmp.Compare(left.DestinationRole, right.DestinationRole), cmp.Compare(left.Telemetry, right.Telemetry),
		cmp.Compare(left.Operation, right.Operation), cmp.Compare(left.Outcome, right.Outcome),
	)
}

// NormalizeObservedOperation drops the query string and fragment from an
// operation of the form "METHOD path" and replaces identifier-like path
// segments (all digits, or 16 or more hex characters and dashes, such as a
// UUID) with {id}, so
// a baseline describes API shape rather than individual records.
func NormalizeObservedOperation(operation string) string {
	if index := strings.IndexAny(operation, "?#"); index >= 0 {
		operation = operation[:index]
	}
	segments := strings.Split(operation, "/")
	for index, segment := range segments {
		if index > 0 && identifierSegment(segment) {
			segments[index] = "{id}"
		}
	}
	return boundedString(strings.Join(segments, "/"), maxObservedOperationLength)
}

func identifierSegment(segment string) bool {
	if segment == "" {
		return false
	}
	digits, hex, anyDigit := true, len(segment) >= 16, false
	for _, character := range segment {
		isDigit := character >= '0' && character <= '9'
		isHex := isDigit || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F') || character == '-'
		digits = digits && isDigit
		hex = hex && isHex
		anyDigit = anyDigit || isDigit
	}
	return digits || (hex && anyDigit)
}

// DeploymentRuleJob is a claimed rule-authoring job.
type DeploymentRuleJob struct {
	ID           int64                      `json:"id"`
	Context      DeploymentAuthoringContext `json:"context"`
	AttemptCount int                        `json:"attemptCount"`
}

// enqueueChangedDeploymentRuleJobs queues authoring only for changed workload
// resources. The kind filter is the extension point for future CEL targets.
func enqueueChangedDeploymentRuleJobs(ctx context.Context, tx pgx.Tx, changed []graph.Resource) error {
	var deployments []DeploymentAuthoringContext
	var ids []string
	for _, resource := range changed {
		if resource.Kind == "kubernetes/deployment" {
			deployments = append(deployments, DeploymentAuthoringContextFor(resource))
			ids = append(ids, resource.ID)
		}
	}
	if len(deployments) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT resource_id::text, template_sha256, status IN ('queued', 'retryable'), current_revision FROM deployment_rule_jobs WHERE resource_id = ANY($1::uuid[])`, ids)
	if err != nil {
		return fmt.Errorf("read Deployment rule authoring revisions: %w", err)
	}
	authored := make(map[[2]string]struct{})
	waiting := make(map[string][]string)
	marked := make(map[string][]string)
	for rows.Next() {
		var revision [2]string
		var queued, current bool
		if err := rows.Scan(&revision[0], &revision[1], &queued, &current); err != nil {
			rows.Close()
			return fmt.Errorf("scan Deployment rule authoring revision: %w", err)
		}
		authored[revision] = struct{}{}
		if queued {
			waiting[revision[0]] = append(waiting[revision[0]], revision[1])
		}
		if current {
			marked[revision[0]] = append(marked[revision[0]], revision[1])
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Deployment rule authoring revisions: %w", err)
	}
	rows.Close()
	for _, workload := range deployments {
		if slices.ContainsFunc(waiting[workload.ResourceID], func(template string) bool { return template != workload.TemplateSHA256 }) {
			if _, err := tx.Exec(ctx, `
				DELETE FROM deployment_rule_jobs
				WHERE resource_id=$1 AND template_sha256<>$2 AND status IN ('queued', 'retryable')`, workload.ResourceID, workload.TemplateSHA256); err != nil {
				return fmt.Errorf("drop superseded Deployment rule authoring jobs %s: %w", workload.ResourceID, err)
			}
		}
		if _, found := authored[[2]string{workload.ResourceID, workload.TemplateSHA256}]; found {
			if !slices.Equal(marked[workload.ResourceID], []string{workload.TemplateSHA256}) {
				if _, err := tx.Exec(ctx, `
					UPDATE deployment_rule_jobs SET current_revision = (template_sha256=$2)
					WHERE resource_id=$1 AND current_revision <> (template_sha256=$2)`, workload.ResourceID, workload.TemplateSHA256); err != nil {
					return fmt.Errorf("mark current Deployment revision %s: %w", workload.ResourceID, err)
				}
			}
			continue
		}
		if len(marked[workload.ResourceID]) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE deployment_rule_jobs SET current_revision=false WHERE resource_id=$1 AND current_revision`, workload.ResourceID); err != nil {
				return fmt.Errorf("unmark previous Deployment revision %s: %w", workload.ResourceID, err)
			}
		}
		encoded, err := json.Marshal(workload)
		if err != nil {
			return fmt.Errorf("encode Deployment authoring context %s: %w", workload.ResourceID, err)
		}
		if len(encoded) > DeploymentAuthoringContextMaxBytes {
			return fmt.Errorf("Deployment authoring context %s exceeds %d bytes", workload.ResourceID, DeploymentAuthoringContextMaxBytes)
		}
		digest := sha256.Sum256(encoded)
		if _, err := tx.Exec(ctx, `
			INSERT INTO deployment_rule_jobs (resource_id, template_sha256, current_revision, workload_context, context_sha256)
			VALUES ($1,$2,true,$3,$4)
			ON CONFLICT (resource_id, template_sha256) DO NOTHING`, workload.ResourceID, workload.TemplateSHA256, encoded, hex.EncodeToString(digest[:])); err != nil {
			return fmt.Errorf("enqueue Deployment rule authoring job %s: %w", workload.ResourceID, err)
		}
	}
	return nil
}

// DeploymentAuthoringContextFor returns the minimal authoring context for a
// Deployment resource, taken only from the Kubernetes plugin's authoring-context
// assertion. It is what the authoring queue stores and sends to the model.
func DeploymentAuthoringContextFor(resource graph.Resource) DeploymentAuthoringContext {
	result := DeploymentAuthoringContext{ResourceID: resource.ID, Kind: resource.Kind}
	for _, assertion := range resource.Assertions {
		if assertion.PluginID != "kubernetes" || assertion.RuleID != "kubernetes.deployment.authoring-context" {
			continue
		}
		result.Name = boundedString(assertion.Attributes["kubernetes/name"], 253)
		result.Namespace = boundedString(assertion.Attributes["kubernetes/namespace"], 253)
		result.ServiceAccountName = boundedString(assertion.Attributes["kubernetes/service-account-name"], 253)
		if digest := assertion.Attributes["kubernetes/pod-template-sha256"]; validTemplateDigest(digest) {
			result.TemplateSHA256 = digest
		}
		break
	}
	return result
}

func validTemplateDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func boundedString(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// ClaimDeploymentRuleJob leases the oldest available job to workerID. Queued
// and retryable jobs past available_at are eligible once they are minAge old
// (the baseline window) or were requested by an operator, as are running jobs
// whose lease expired (the previous worker is presumed dead). Eligible jobs
// that went stale (see [staleDeploymentRuleJob]) are deleted first, so no
// model call is spent on them. SKIP LOCKED lets concurrent workers claim
// different jobs. It returns false when nothing is available.
func (s *Store) ClaimDeploymentRuleJob(ctx context.Context, workerID string, leaseInterval, minAge time.Duration) (DeploymentRuleJob, bool, error) {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" || len(workerID) > 128 {
		return DeploymentRuleJob{}, false, errors.New("Deployment job worker ID must contain 1-128 bytes")
	}
	if leaseInterval <= 0 {
		return DeploymentRuleJob{}, false, errors.New("Deployment job lease interval must be positive")
	}
	leaseMicros := leaseInterval.Microseconds()
	if leaseMicros < 1 || leaseMicros > int64((24*time.Hour).Microseconds()) {
		return DeploymentRuleJob{}, false, errors.New("Deployment job lease interval must be at most 24 hours")
	}
	if minAge < 0 || minAge > 7*24*time.Hour {
		return DeploymentRuleJob{}, false, errors.New("Deployment job minimum age must be between 0 and 7 days")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DeploymentRuleJob{}, false, fmt.Errorf("begin Deployment job claim: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		DELETE FROM deployment_rule_jobs j
		WHERE ((j.status IN ('queued', 'retryable') AND j.available_at <= now())
		       OR (j.status='running' AND j.lease_expires_at <= now()))
		  AND `+staleDeploymentRuleJob); err != nil {
		return DeploymentRuleJob{}, false, fmt.Errorf("drop stale Deployment rule authoring jobs: %w", err)
	}
	var job DeploymentRuleJob
	var contextJSON []byte
	err = tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT job_id FROM deployment_rule_jobs
			WHERE (status IN ('queued', 'retryable') AND available_at <= now()
			       AND (requested_at IS NOT NULL OR created_at <= now()-($3::bigint * interval '1 microsecond')))
			   OR (status='running' AND lease_expires_at <= now())
			ORDER BY available_at, job_id
			FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE deployment_rule_jobs j
		SET status='running', attempt_count=j.attempt_count+1, lease_owner=$1,
		    lease_expires_at=now()+($2::bigint * interval '1 microsecond'), updated_at=now(), last_error=NULL
		FROM candidate WHERE j.job_id=candidate.job_id
		RETURNING j.job_id, j.workload_context, j.attempt_count`,
		workerID, leaseMicros, minAge.Microseconds()).Scan(&job.ID, &contextJSON, &job.AttemptCount)
	if errors.Is(err, pgx.ErrNoRows) {
		// Keep the stale-job cleanup even when nothing is left to claim.
		if err := tx.Commit(ctx); err != nil {
			return DeploymentRuleJob{}, false, fmt.Errorf("commit Deployment job claim: %w", err)
		}
		return DeploymentRuleJob{}, false, nil
	}
	if err != nil {
		return DeploymentRuleJob{}, false, fmt.Errorf("claim Deployment rule authoring job: %w", err)
	}
	if err := json.Unmarshal(contextJSON, &job.Context); err != nil {
		return DeploymentRuleJob{}, false, fmt.Errorf("decode Deployment rule authoring context: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return DeploymentRuleJob{}, false, fmt.Errorf("commit Deployment job claim: %w", err)
	}
	return job, true, nil
}

// RenewDeploymentRuleJob extends a lease still held by workerID and reports
// whether it was.
func (s *Store) RenewDeploymentRuleJob(ctx context.Context, jobID int64, workerID string, leaseInterval time.Duration) (bool, error) {
	leaseMicros := leaseInterval.Microseconds()
	if leaseMicros < 1 || leaseMicros > int64((24*time.Hour).Microseconds()) {
		return false, errors.New("Deployment job lease interval must be between one microsecond and 24 hours")
	}
	result, err := s.pool.Exec(ctx, `UPDATE deployment_rule_jobs SET lease_expires_at=now()+($3::bigint * interval '1 microsecond'), updated_at=now() WHERE job_id=$1 AND status='running' AND lease_owner=$2`, jobID, workerID, leaseMicros)
	if err != nil {
		return false, fmt.Errorf("renew Deployment rule authoring lease: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// CompleteDeploymentRuleJob stores the proposal and completes the job. It
// fails if workerID no longer holds the lease, so a worker whose lease expired
// cannot overwrite the result of the worker that reclaimed it.
func (s *Store) CompleteDeploymentRuleJob(ctx context.Context, jobID int64, workerID string, proposal json.RawMessage) error {
	if !json.Valid(proposal) || len(proposal) > 256*1024 {
		return errors.New("Deployment rule proposal must be valid JSON no larger than 256 KiB")
	}
	result, err := s.pool.Exec(ctx, `
		UPDATE deployment_rule_jobs
		SET status='completed', proposal=$3, lease_owner=NULL, lease_expires_at=NULL,
		    completed_at=now(), updated_at=now(), last_error=NULL
		WHERE job_id=$1 AND status='running' AND lease_owner=$2`, jobID, workerID, proposal)
	if err != nil {
		return fmt.Errorf("complete Deployment rule authoring job: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("Deployment rule authoring lease is no longer owned by this worker")
	}
	return nil
}

// staleDeploymentRuleJob matches a job, aliased j, whose Pod template
// revision is no longer the one its Deployment runs, or whose Deployment left
// the graph. Its draft would describe nothing that runs, and a newer revision
// has its own job.
const staleDeploymentRuleJob = `(NOT j.current_revision OR NOT EXISTS (SELECT 1 FROM current_resources r WHERE r.resource_id = j.resource_id))`

// DeploymentRuleRetry is what [Store.RetryDeploymentRuleJob] did with a job.
type DeploymentRuleRetry int

const (
	// DeploymentRuleRetryScheduled made the job available again after the delay.
	DeploymentRuleRetryScheduled DeploymentRuleRetry = iota
	// DeploymentRuleRetryFailed ended the job as failed; only an operator
	// request queues it again.
	DeploymentRuleRetryFailed
	// DeploymentRuleRetrySuperseded deleted the job because it went stale.
	DeploymentRuleRetrySuperseded
)

// RetryDeploymentRuleJob releases a held lease after a failed attempt. A job
// that went stale is deleted, whatever terminal says. Otherwise a terminal
// failure ends the job as failed, and any other failure makes it available
// again after retryAfter, clamped to 1s-24h. failure is truncated to 2 KiB.
func (s *Store) RetryDeploymentRuleJob(ctx context.Context, jobID int64, workerID, failure string, retryAfter time.Duration, terminal bool) (DeploymentRuleRetry, error) {
	retryAfter = min(max(retryAfter, time.Second), 24*time.Hour)
	if len(failure) > 2048 {
		failure = failure[:2048]
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin Deployment rule authoring retry: %w", err)
	}
	defer tx.Rollback(ctx)
	var stale bool
	err = tx.QueryRow(ctx, `
		SELECT `+staleDeploymentRuleJob+` FROM deployment_rule_jobs j
		WHERE j.job_id=$1 AND j.status='running' AND j.lease_owner=$2
		FOR UPDATE`, jobID, workerID).Scan(&stale)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, errors.New("Deployment rule authoring lease is no longer owned by this worker")
	}
	if err != nil {
		return 0, fmt.Errorf("read Deployment rule authoring job for retry: %w", err)
	}
	outcome := DeploymentRuleRetryScheduled
	switch {
	case stale:
		outcome = DeploymentRuleRetrySuperseded
		_, err = tx.Exec(ctx, `DELETE FROM deployment_rule_jobs WHERE job_id=$1`, jobID)
	case terminal:
		outcome = DeploymentRuleRetryFailed
		_, err = tx.Exec(ctx, `
			UPDATE deployment_rule_jobs
			SET status='failed', last_error=$2, lease_owner=NULL, lease_expires_at=NULL, updated_at=now()
			WHERE job_id=$1`, jobID, failure)
	default:
		_, err = tx.Exec(ctx, `
			UPDATE deployment_rule_jobs
			SET status='retryable', available_at=now()+($3::bigint * interval '1 microsecond'), last_error=$2,
			    lease_owner=NULL, lease_expires_at=NULL, updated_at=now()
			WHERE job_id=$1`, jobID, failure, retryAfter.Microseconds())
	}
	if err != nil {
		return 0, fmt.Errorf("retry Deployment rule authoring job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit Deployment rule authoring retry: %w", err)
	}
	return outcome, nil
}

// DeploymentRuleJobSummary is a job's status without its proposal.
type DeploymentRuleJobSummary struct {
	ID         int64  `json:"id"`
	ResourceID string `json:"resourceId"`
	// TemplateSHA256 is the Pod template revision the job authors for.
	TemplateSHA256 string `json:"templateSha256,omitempty"`
	// Status is queued, running, retryable, completed, or failed.
	Status       string     `json:"status"`
	AttemptCount int        `json:"attemptCount"`
	LastError    string     `json:"lastError,omitempty"`
	ReviewStatus string     `json:"reviewStatus"`
	ReviewedBy   string     `json:"reviewedBy,omitempty"`
	ReviewedAt   *time.Time `json:"reviewedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	CompletedAt  *time.Time `json:"completedAt,omitempty"`
	// RuleCount is the number of rules in a completed proposal.
	RuleCount int `json:"ruleCount"`
	// RequestedBy and RequestedAt record the operator's last regeneration request.
	RequestedBy string     `json:"requestedBy,omitempty"`
	RequestedAt *time.Time `json:"requestedAt,omitempty"`
	// CurrentRevision reports whether the job is for the revision the Deployment runs now.
	CurrentRevision bool `json:"currentRevision"`
}

// Deployment rule job errors.
var (
	ErrDeploymentRuleJobNotFound      = errors.New("Deployment rule authoring job not found")
	ErrDeploymentRuleJobNotReviewable = errors.New("Deployment rule job is not a completed proposal")
	ErrDeploymentRuleJobInProgress    = errors.New("Deployment rule authoring is already in progress")
)

// Deployment rule review decisions. Pending drafts run in shadow mode; approved
// rules run in active mode; rejected rules are not loaded.
const (
	DeploymentRuleReviewPending  = "pending"
	DeploymentRuleReviewApproved = "approved"
	DeploymentRuleReviewRejected = "rejected"
)

const deploymentRuleJobColumns = `job_id, resource_id::text, template_sha256, status, attempt_count, COALESCE(last_error,''), review_status, COALESCE(reviewed_by,''), reviewed_at, created_at, completed_at,
	CASE WHEN jsonb_typeof(proposal->'rules') = 'array' THEN jsonb_array_length(proposal->'rules') ELSE 0 END,
	COALESCE(requested_by,''), requested_at, current_revision`

func scanDeploymentRuleJob(row pgx.Row, job *DeploymentRuleJobSummary) error {
	return row.Scan(&job.ID, &job.ResourceID, &job.TemplateSHA256, &job.Status, &job.AttemptCount, &job.LastError, &job.ReviewStatus, &job.ReviewedBy, &job.ReviewedAt, &job.CreatedAt, &job.CompletedAt,
		&job.RuleCount, &job.RequestedBy, &job.RequestedAt, &job.CurrentRevision)
}

// ListDeploymentRuleJobs returns up to limit (1-1000) jobs, newest first.
func (s *Store) ListDeploymentRuleJobs(ctx context.Context, limit int) ([]DeploymentRuleJobSummary, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("Deployment job list limit must be between 1 and 1000")
	}
	rows, err := s.pool.Query(ctx, `SELECT `+deploymentRuleJobColumns+` FROM deployment_rule_jobs ORDER BY job_id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list Deployment rule authoring jobs: %w", err)
	}
	defer rows.Close()
	var jobs []DeploymentRuleJobSummary
	for rows.Next() {
		var job DeploymentRuleJobSummary
		if err := scanDeploymentRuleJob(rows, &job); err != nil {
			return nil, fmt.Errorf("scan Deployment rule authoring job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Deployment rule authoring jobs: %w", err)
	}
	return jobs, nil
}

// DeploymentRuleProposal returns a completed job's proposal and whether the job
// exists and is completed.
func (s *Store) DeploymentRuleProposal(ctx context.Context, jobID int64) (json.RawMessage, bool, error) {
	var proposal []byte
	err := s.pool.QueryRow(ctx, `SELECT proposal FROM deployment_rule_jobs WHERE job_id=$1 AND status='completed'`, jobID).Scan(&proposal)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read Deployment rule proposal: %w", err)
	}
	return json.RawMessage(proposal), true, nil
}

// DeploymentRuleJobStatus returns one job's summary and whether it exists.
func (s *Store) DeploymentRuleJobStatus(ctx context.Context, jobID int64) (DeploymentRuleJobSummary, bool, error) {
	var job DeploymentRuleJobSummary
	err := scanDeploymentRuleJob(s.pool.QueryRow(ctx, `SELECT `+deploymentRuleJobColumns+` FROM deployment_rule_jobs WHERE job_id=$1`, jobID), &job)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeploymentRuleJobSummary{}, false, nil
	}
	if err != nil {
		return DeploymentRuleJobSummary{}, false, fmt.Errorf("read Deployment rule authoring job status: %w", err)
	}
	return job, true, nil
}

// ReviewDeploymentRuleJob records an operator decision on a completed proposal.
// actor is audit metadata, not authorization.
func (s *Store) ReviewDeploymentRuleJob(ctx context.Context, jobID int64, decision, actor string) error {
	if decision != DeploymentRuleReviewApproved && decision != DeploymentRuleReviewRejected {
		return errors.New("Deployment rule review decision must be approved or rejected")
	}
	if err := validateDetectorActor(actor); err != nil {
		return err
	}
	result, err := s.pool.Exec(ctx, `
		UPDATE deployment_rule_jobs
		SET review_status=$2, reviewed_by=$3, reviewed_at=now(), updated_at=now()
		WHERE job_id=$1 AND status='completed'`, jobID, decision, actor)
	if err != nil {
		return fmt.Errorf("review Deployment rule job: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("%w: job %d", ErrDeploymentRuleJobNotReviewable, jobID)
	}
	return nil
}

// RequestDeploymentRuleJob asks for the Deployment's current Pod template
// revision to be authored now. A queued or retrying job is woken: it skips the
// baseline wait and any retry backoff. A completed job is reset to queued,
// dropping its proposal and review, so the next proposal starts in shadow mode;
// a previously approved draft's rules stop running actively until the new draft
// is approved. It returns [ErrDeploymentRuleJobInProgress] with the job while a
// worker is authoring it, and [ErrDeploymentRuleJobNotFound] when the
// Deployment has no job for its current revision. actor is audit metadata, not
// authorization.
func (s *Store) RequestDeploymentRuleJob(ctx context.Context, resourceID, actor string) (DeploymentRuleJobSummary, error) {
	if err := validateDetectorActor(actor); err != nil {
		return DeploymentRuleJobSummary{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DeploymentRuleJobSummary{}, fmt.Errorf("begin Deployment rule request: %w", err)
	}
	defer tx.Rollback(ctx)
	var jobID int64
	var status string
	err = tx.QueryRow(ctx, `
		SELECT job_id, status FROM deployment_rule_jobs
		WHERE resource_id::text=$1 AND current_revision
		FOR UPDATE`, resourceID).Scan(&jobID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeploymentRuleJobSummary{}, fmt.Errorf("%w for the Deployment's current revision", ErrDeploymentRuleJobNotFound)
	}
	if err != nil {
		return DeploymentRuleJobSummary{}, fmt.Errorf("read Deployment rule job for request: %w", err)
	}
	var job DeploymentRuleJobSummary
	switch status {
	case "running":
		if err := scanDeploymentRuleJob(tx.QueryRow(ctx, `SELECT `+deploymentRuleJobColumns+` FROM deployment_rule_jobs WHERE job_id=$1`, jobID), &job); err != nil {
			return DeploymentRuleJobSummary{}, fmt.Errorf("read running Deployment rule job: %w", err)
		}
		return job, ErrDeploymentRuleJobInProgress
	case "queued", "retryable":
		if err := scanDeploymentRuleJob(tx.QueryRow(ctx, `
			UPDATE deployment_rule_jobs
			SET available_at=now(), requested_by=$2, requested_at=now(), updated_at=now()
			WHERE job_id=$1
			RETURNING `+deploymentRuleJobColumns, jobID, actor), &job); err != nil {
			return DeploymentRuleJobSummary{}, fmt.Errorf("wake Deployment rule job: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return DeploymentRuleJobSummary{}, fmt.Errorf("commit Deployment rule request: %w", err)
		}
		return job, nil
	}
	if err := scanDeploymentRuleJob(tx.QueryRow(ctx, `
		UPDATE deployment_rule_jobs
		SET status='queued', attempt_count=0, available_at=now(), lease_owner=NULL, lease_expires_at=NULL,
		    proposal=NULL, last_error=NULL, completed_at=NULL,
		    review_status='pending', reviewed_by=NULL, reviewed_at=NULL,
		    requested_by=$2, requested_at=now(), updated_at=now()
		WHERE job_id=$1
		RETURNING `+deploymentRuleJobColumns, jobID, actor), &job); err != nil {
		return DeploymentRuleJobSummary{}, fmt.Errorf("request Deployment rule job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return DeploymentRuleJobSummary{}, fmt.Errorf("commit Deployment rule request: %w", err)
	}
	return job, nil
}

// DeploymentRuleQueueStats counts authoring jobs by what they wait for.
type DeploymentRuleQueueStats struct {
	// WaitingForBaseline jobs are queued but younger than the baseline window.
	WaitingForBaseline int
	// Ready jobs can be claimed now.
	Ready    int
	Running  int
	Retrying int
	// Failed jobs exhausted their attempts and wait for an operator request.
	Failed int
	// NextEligibleAt is when the next baseline wait ends, if any job is waiting.
	NextEligibleAt *time.Time
}

// DeploymentRuleQueueStats reports the authoring queue for a worker that waits
// minAge (the baseline window) before claiming unrequested jobs.
func (s *Store) DeploymentRuleQueueStats(ctx context.Context, minAge time.Duration) (DeploymentRuleQueueStats, error) {
	var stats DeploymentRuleQueueStats
	err := s.pool.QueryRow(ctx, `
		WITH jobs AS (
			SELECT status, available_at,
			       requested_at IS NULL AND created_at > now()-($1::bigint * interval '1 microsecond') AS waiting,
			       created_at + ($1::bigint * interval '1 microsecond') AS eligible_at
			FROM deployment_rule_jobs WHERE status <> 'completed'
		)
		SELECT
			count(*) FILTER (WHERE status IN ('queued', 'retryable') AND waiting),
			count(*) FILTER (WHERE status IN ('queued', 'retryable') AND NOT waiting AND available_at <= now()),
			count(*) FILTER (WHERE status = 'running'),
			count(*) FILTER (WHERE status = 'retryable'),
			count(*) FILTER (WHERE status = 'failed'),
			min(eligible_at) FILTER (WHERE status IN ('queued', 'retryable') AND waiting)
		FROM jobs`, minAge.Microseconds()).Scan(&stats.WaitingForBaseline, &stats.Ready, &stats.Running, &stats.Retrying, &stats.Failed, &stats.NextEligibleAt)
	if err != nil {
		return DeploymentRuleQueueStats{}, fmt.Errorf("read Deployment rule authoring queue: %w", err)
	}
	return stats, nil
}

// ReadWorkloadRules returns the rules of completed, non-rejected Deployment
// proposals whose Deployment is still in the graph. Approved rules are active;
// unreviewed drafts run in shadow mode. A proposal that does not decode, or
// that holds a rule scoped to another Deployment, is skipped and logged so one
// bad row cannot block every reload. The result may exceed
// detector.MaxWorkloadRules; the detector caps it deterministically.
func (s *Store) ReadWorkloadRules(ctx context.Context) ([]detector.WorkloadRule, error) {
	// Per Deployment, the current revision's approved rule runs active; until it
	// is approved, the newest approved rule of another revision stays active and
	// the current revision's pending draft runs in shadow.
	rows, err := s.pool.Query(ctx, `
		WITH loadable AS (
			SELECT j.job_id, j.resource_id, j.review_status, j.current_revision, j.proposal
			FROM deployment_rule_jobs j
			JOIN current_resources r ON r.resource_id = j.resource_id
			WHERE j.status = 'completed' AND j.review_status <> 'rejected'
		), active AS (
			SELECT DISTINCT ON (resource_id) job_id
			FROM loadable WHERE review_status = 'approved'
			ORDER BY resource_id, current_revision DESC, job_id DESC
		)
		SELECT resource_id::text, review_status, proposal
		FROM loadable
		WHERE job_id IN (SELECT job_id FROM active) OR (current_revision AND review_status = 'pending')
		ORDER BY job_id
		LIMIT $1`, detector.MaxWorkloadRules+1)
	if err != nil {
		return nil, fmt.Errorf("read workload rules: %w", err)
	}
	defer rows.Close()
	var result []detector.WorkloadRule
	for rows.Next() {
		var resourceID, review string
		var encoded []byte
		if err := rows.Scan(&resourceID, &review, &encoded); err != nil {
			return nil, fmt.Errorf("scan workload rule proposal: %w", err)
		}
		var proposal struct {
			Rules []struct {
				Rule detector.Rule `json:"rule"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(encoded, &proposal); err != nil {
			slog.WarnContext(ctx, "skip undecodable Deployment rule proposal", "resourceID", resourceID)
			continue
		}
		mode := detector.RuleModeShadow
		if review == DeploymentRuleReviewApproved {
			mode = detector.RuleModeActive
		}
		scoped := true
		for _, candidate := range proposal.Rules {
			if candidate.Rule.WorkloadResourceID != resourceID {
				scoped = false
				break
			}
		}
		if !scoped {
			slog.WarnContext(ctx, "skip Deployment rule proposal with a rule scoped to another Deployment", "resourceID", resourceID)
			continue
		}
		for _, candidate := range proposal.Rules {
			result = append(result, detector.WorkloadRule{Rule: candidate.Rule, Mode: mode})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate workload rule proposals: %w", err)
	}
	return result, nil
}
