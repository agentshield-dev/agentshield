package state

import (
	"bytes"
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

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/jackc/pgx/v5"
)

const ResourceAuthoringContextMaxBytes = 48 << 10

// ResourceAuthoringContext is the bounded plugin context given to the rule author.
type ResourceAuthoringContext struct {
	ResourceID    string            `json:"resourceId"`
	Kind          string            `json:"kind"`
	Name          string            `json:"name,omitempty"`
	Namespace     string            `json:"namespace,omitempty"`
	ContextSHA256 string            `json:"contextSha256"`
	Context       json.RawMessage   `json:"context"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	// ObservedBehavior is the workload's baseline of outbound requests. Nil
	// means no baseline was taken; an empty request list means one was taken
	// and the workload made no outbound requests. The authoring worker sets
	// it when it claims a job; the queue stores only identity.
	ObservedBehavior *WorkloadBehavior `json:"observedBehavior,omitempty"`
}

func resourceAuthoringContextSHA256(resource ResourceAuthoringContext, sourceRevisionSHA256 string) (string, error) {
	encoded, err := json.Marshal(struct {
		Kind                 string            `json:"kind"`
		Name                 string            `json:"name,omitempty"`
		Namespace            string            `json:"namespace,omitempty"`
		SourceRevisionSHA256 string            `json:"sourceRevisionSha256,omitempty"`
		Context              json.RawMessage   `json:"context"`
		Attributes           map[string]string `json:"attributes,omitempty"`
	}{
		Kind: resource.Kind, Name: resource.Name, Namespace: resource.Namespace,
		SourceRevisionSHA256: sourceRevisionSHA256, Context: resource.Context, Attributes: resource.Attributes,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Limits on [WorkloadBehavior], which is sent to a model.
const (
	MaxObservedRequests        = 32
	MaxCollectedTelemetry      = 16
	maxObservedOperationLength = 256
)

// WorkloadBehavior summarizes the telemetry whose subject is one workload or
// a Pod instantiated by it.
// Operations are normalized by [NormalizeObservedOperation].
type WorkloadBehavior struct {
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
// outcome) combination and how often it was observed. Destinations include a
// stable graph resource ID but never a raw address.
type ObservedRequest struct {
	Telemetry             string `json:"telemetry"`
	Destination           string `json:"destination,omitempty"`
	DestinationResourceID string `json:"destinationResourceId,omitempty"`
	DestinationKind       string `json:"destinationKind"`
	DestinationRole       string `json:"destinationRole,omitempty"`
	Operation             string `json:"operation,omitempty"`
	Outcome               string `json:"outcome,omitempty"`
	Count                 uint64 `json:"count"`
}

// WorkloadObservedBehavior summarizes the current graph's telemetry for a
// supported workload controller; see [WorkloadBehaviorFor].
func (s *Store) WorkloadObservedBehavior(ctx context.Context, resourceID string) (WorkloadBehavior, error) {
	view, err := s.Latest(ctx)
	if err != nil {
		return WorkloadBehavior{}, fmt.Errorf("read graph for workload baseline: %w", err)
	}
	return WorkloadBehaviorFor(view.Snapshot, resourceID), nil
}

// WorkloadBehaviorFor summarizes the telemetry in snapshot whose subject is
// the resource. The result is deterministic for a given snapshot.
func WorkloadBehaviorFor(snapshot graph.Snapshot, resourceID string) WorkloadBehavior {
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
	instances := make(map[string][]string)
	for _, relationship := range snapshot.Relationships {
		if relationship.Predicate == graph.PredicateInstantiates && relationship.ResolutionStatus != graph.ResolutionUnresolved {
			instances[relationship.SubjectID] = append(instances[relationship.SubjectID], relationship.ObjectID)
		}
	}
	for controller := range instances {
		slices.Sort(instances[controller])
		instances[controller] = slices.Compact(instances[controller])
	}
	subjects := map[string]struct{}{resourceID: {}}
	visited := map[string]struct{}{resourceID: {}}
	queue := slices.Clone(instances[resourceID])
	for len(queue) > 0 {
		instance := queue[0]
		queue = queue[1:]
		if _, found := visited[instance]; found {
			continue
		}
		visited[instance] = struct{}{}
		if kinds[instance] == "kubernetes/pod" {
			subjects[instance] = struct{}{}
			continue
		}
		queue = append(queue, instances[instance]...)
	}
	roles := graph.ResourceNetworkRoles(snapshot)
	counts := make(map[ObservedRequest]uint64)
	collected := make(map[string]struct{})
	for _, event := range snapshot.Telemetry {
		collected[boundedString(event.Kind, 128)] = struct{}{}
		if _, found := subjects[event.SubjectID]; !found {
			continue
		}
		key := ObservedRequest{
			Telemetry: event.Kind, Destination: names[event.ObjectID], DestinationResourceID: event.ObjectID, DestinationKind: kinds[event.ObjectID],
			DestinationRole: roles[event.ObjectID], Operation: NormalizeObservedOperation(event.Operation), Outcome: boundedString(event.Outcome, 64),
		}
		counts[key] += event.Count
	}
	behavior := WorkloadBehavior{CollectedTelemetry: append([]string{}, slices.Sorted(maps.Keys(collected))...), Requests: make([]ObservedRequest, 0, len(counts))}
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
		cmp.Compare(left.Destination, right.Destination), cmp.Compare(left.DestinationResourceID, right.DestinationResourceID), cmp.Compare(left.DestinationKind, right.DestinationKind),
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

// ResourceRuleJob is a claimed rule-authoring job.
type ResourceRuleJob struct {
	ID           int64                    `json:"id"`
	Context      ResourceAuthoringContext `json:"context"`
	AttemptCount int                      `json:"attemptCount"`
}

// enqueueChangedResourceRuleJobs queues authoring for resources with valid authoring context.
func enqueueChangedResourceRuleJobs(ctx context.Context, tx pgx.Tx, changed []graph.Resource) error {
	var resources []ResourceAuthoringContext
	var ids []string
	var optedOut []string
	for _, resource := range changed {
		candidate := ResourceAuthoringContextFor(resource)
		if candidate.ContextSHA256 == "" {
			optedOut = append(optedOut, resource.ID)
			continue
		}
		resources = append(resources, candidate)
		ids = append(ids, resource.ID)
	}
	if len(optedOut) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE resource_rule_jobs SET current_revision=false, updated_at=now() WHERE resource_id = ANY($1::uuid[]) AND current_revision`, optedOut); err != nil {
			return fmt.Errorf("retire resource rule authoring revisions: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM resource_rule_jobs WHERE resource_id = ANY($1::uuid[]) AND status IN ('queued', 'retryable')`, optedOut); err != nil {
			return fmt.Errorf("drop opted-out resource rule authoring jobs: %w", err)
		}
	}
	if len(resources) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT resource_id::text, context_sha256, status IN ('queued', 'retryable'), current_revision FROM resource_rule_jobs WHERE resource_id = ANY($1::uuid[])`, ids)
	if err != nil {
		return fmt.Errorf("read resource rule authoring revisions: %w", err)
	}
	authored := make(map[[2]string]struct{})
	waiting := make(map[string][]string)
	marked := make(map[string][]string)
	for rows.Next() {
		var revision [2]string
		var queued, current bool
		if err := rows.Scan(&revision[0], &revision[1], &queued, &current); err != nil {
			rows.Close()
			return fmt.Errorf("scan resource rule authoring revision: %w", err)
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
		return fmt.Errorf("iterate resource rule authoring revisions: %w", err)
	}
	rows.Close()
	for _, resource := range resources {
		encoded, err := json.Marshal(resource)
		if err != nil {
			return fmt.Errorf("encode resource authoring context %s: %w", resource.ResourceID, err)
		}
		if len(encoded) > ResourceAuthoringContextMaxBytes {
			return fmt.Errorf("resource authoring context %s exceeds %d bytes", resource.ResourceID, ResourceAuthoringContextMaxBytes)
		}
		if slices.ContainsFunc(waiting[resource.ResourceID], func(revision string) bool { return revision != resource.ContextSHA256 }) {
			if _, err := tx.Exec(ctx, `
				DELETE FROM resource_rule_jobs
				WHERE resource_id=$1 AND context_sha256<>$2 AND status IN ('queued', 'retryable')`, resource.ResourceID, resource.ContextSHA256); err != nil {
				return fmt.Errorf("drop superseded resource rule authoring jobs %s: %w", resource.ResourceID, err)
			}
		}
		if _, found := authored[[2]string{resource.ResourceID, resource.ContextSHA256}]; found {
			if !slices.Equal(marked[resource.ResourceID], []string{resource.ContextSHA256}) {
				if _, err := tx.Exec(ctx, `UPDATE resource_rule_jobs SET current_revision=false WHERE resource_id=$1 AND current_revision AND context_sha256<>$2`, resource.ResourceID, resource.ContextSHA256); err != nil {
					return fmt.Errorf("unmark previous resource revision %s: %w", resource.ResourceID, err)
				}
				if _, err := tx.Exec(ctx, `UPDATE resource_rule_jobs SET current_revision=true WHERE resource_id=$1 AND context_sha256=$2 AND NOT current_revision`, resource.ResourceID, resource.ContextSHA256); err != nil {
					return fmt.Errorf("mark current resource revision %s: %w", resource.ResourceID, err)
				}
			}
			continue
		}
		if len(marked[resource.ResourceID]) > 0 {
			if _, err := tx.Exec(ctx, `UPDATE resource_rule_jobs SET current_revision=false WHERE resource_id=$1 AND current_revision`, resource.ResourceID); err != nil {
				return fmt.Errorf("unmark previous resource revision %s: %w", resource.ResourceID, err)
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO resource_rule_jobs (resource_id, context_sha256, current_revision, resource_context)
			VALUES ($1,$2,true,$3)
			ON CONFLICT (resource_id, context_sha256) DO NOTHING`, resource.ResourceID, resource.ContextSHA256, encoded); err != nil {
			return fmt.Errorf("enqueue resource rule authoring job %s: %w", resource.ResourceID, err)
		}
	}
	return nil
}

// ResourceAuthoringContextFor returns a resource's bounded plugin context.
func ResourceAuthoringContextFor(resource graph.Resource) ResourceAuthoringContext {
	empty := ResourceAuthoringContext{ResourceID: resource.ID, Kind: resource.Kind}
	var selected *ResourceAuthoringContext
	var selectedEncoded []byte
	var conflict bool
	for _, assertion := range resource.Assertions {
		encodedContext := assertion.Attributes[graph.ResourceAuthoringContextAttribute]
		if encodedContext == "" {
			continue
		}
		authoringContext, err := graph.DecodeResourceAuthoringContext(encodedContext)
		if err != nil {
			continue
		}
		candidate := empty
		candidate.Name = boundedString(assertion.DisplayName, 253)
		if name := assertion.Attributes["kubernetes/name"]; name != "" {
			candidate.Name = boundedString(name, 253)
		}
		candidate.Namespace = boundedString(assertion.Attributes["kubernetes/namespace"], 253)
		candidate.Context = slices.Clone(authoringContext.Context)
		candidate.Attributes = maps.Clone(authoringContext.Attributes)
		candidate.ContextSHA256, err = resourceAuthoringContextSHA256(candidate, authoringContext.SourceRevisionSHA256)
		if err != nil {
			continue
		}
		encoded, _ := json.Marshal(candidate)
		if selected == nil {
			selected, selectedEncoded = &candidate, encoded
		} else if !bytes.Equal(selectedEncoded, encoded) {
			conflict = true
		}
	}
	if conflict || selected == nil {
		return empty
	}
	return *selected
}

func boundedString(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// ClaimResourceRuleJob leases the oldest available job to workerID. Queued
// and retryable jobs past available_at are eligible once they are minAge old
// (the stabilization window) or were requested by an operator, as are running jobs
// whose lease expired (the previous worker is presumed dead). Eligible jobs
// that went stale (see [staleResourceRuleJob]) are deleted first, so no
// model call is spent on them. SKIP LOCKED lets concurrent workers claim
// different jobs. It returns false when nothing is available.
func (s *Store) ClaimResourceRuleJob(ctx context.Context, workerID string, leaseInterval, minAge time.Duration) (ResourceRuleJob, bool, error) {
	workerID = strings.TrimSpace(workerID)
	if workerID == "" || len(workerID) > 128 {
		return ResourceRuleJob{}, false, errors.New("resource job worker ID must contain 1-128 bytes")
	}
	if leaseInterval <= 0 {
		return ResourceRuleJob{}, false, errors.New("resource job lease interval must be positive")
	}
	leaseMicros := leaseInterval.Microseconds()
	if leaseMicros < 1 || leaseMicros > int64((24*time.Hour).Microseconds()) {
		return ResourceRuleJob{}, false, errors.New("resource job lease interval must be at most 24 hours")
	}
	if minAge < 0 || minAge > 7*24*time.Hour {
		return ResourceRuleJob{}, false, errors.New("resource job minimum age must be between 0 and 7 days")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ResourceRuleJob{}, false, fmt.Errorf("begin resource job claim: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		DELETE FROM resource_rule_jobs j
		WHERE ((j.status IN ('queued', 'retryable') AND j.available_at <= now())
		       OR (j.status='running' AND j.lease_expires_at <= now()))
		  AND `+staleResourceRuleJob); err != nil {
		return ResourceRuleJob{}, false, fmt.Errorf("drop stale Resource rule authoring jobs: %w", err)
	}
	var job ResourceRuleJob
	var contextJSON []byte
	err = tx.QueryRow(ctx, `
		WITH candidate AS (
			SELECT job_id FROM resource_rule_jobs
			WHERE (status IN ('queued', 'retryable') AND available_at <= now()
			       AND (requested_at IS NOT NULL OR created_at <= now()-($3::bigint * interval '1 microsecond')))
			   OR (status='running' AND lease_expires_at <= now())
			ORDER BY available_at, job_id
			FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE resource_rule_jobs j
		SET status='running', attempt_count=j.attempt_count+1, lease_owner=$1,
		    lease_expires_at=now()+($2::bigint * interval '1 microsecond'), updated_at=now(), last_error=NULL
		FROM candidate WHERE j.job_id=candidate.job_id
		RETURNING j.job_id, j.resource_context, j.attempt_count`,
		workerID, leaseMicros, minAge.Microseconds()).Scan(&job.ID, &contextJSON, &job.AttemptCount)
	if errors.Is(err, pgx.ErrNoRows) {
		// Keep the stale-job cleanup even when nothing is left to claim.
		if err := tx.Commit(ctx); err != nil {
			return ResourceRuleJob{}, false, fmt.Errorf("commit resource job claim: %w", err)
		}
		return ResourceRuleJob{}, false, nil
	}
	if err != nil {
		return ResourceRuleJob{}, false, fmt.Errorf("claim Resource rule authoring job: %w", err)
	}
	if err := json.Unmarshal(contextJSON, &job.Context); err != nil {
		return ResourceRuleJob{}, false, fmt.Errorf("decode Resource rule authoring context: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ResourceRuleJob{}, false, fmt.Errorf("commit resource job claim: %w", err)
	}
	return job, true, nil
}

// RenewResourceRuleJob extends a lease still held by workerID and reports
// whether it was.
func (s *Store) RenewResourceRuleJob(ctx context.Context, jobID int64, workerID string, leaseInterval time.Duration) (bool, error) {
	leaseMicros := leaseInterval.Microseconds()
	if leaseMicros < 1 || leaseMicros > int64((24*time.Hour).Microseconds()) {
		return false, errors.New("resource job lease interval must be between one microsecond and 24 hours")
	}
	result, err := s.pool.Exec(ctx, `UPDATE resource_rule_jobs SET lease_expires_at=now()+($3::bigint * interval '1 microsecond'), updated_at=now() WHERE job_id=$1 AND status='running' AND lease_owner=$2 AND current_revision AND EXISTS (SELECT 1 FROM current_resources r WHERE r.resource_id=resource_rule_jobs.resource_id)`, jobID, workerID, leaseMicros)
	if err != nil {
		return false, fmt.Errorf("renew Resource rule authoring lease: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

// MaxResourceRuleProposalRules bounds rules stored in one authoring proposal.
const MaxResourceRuleProposalRules = 3

// CompleteResourceRuleJob stores the proposal and completes the job. It
// fails if workerID no longer holds the lease, so a worker whose lease expired
// cannot overwrite the result of the worker that reclaimed it.
func (s *Store) CompleteResourceRuleJob(ctx context.Context, jobID int64, workerID string, proposal json.RawMessage) error {
	if !json.Valid(proposal) || len(proposal) > 256*1024 {
		return errors.New("resource rule proposal must be valid JSON no larger than 256 KiB")
	}
	var decoded struct {
		Rules []struct {
			Rule detector.Rule `json:"rule"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(proposal, &decoded); err != nil {
		return fmt.Errorf("decode resource rule proposal: %w", err)
	}
	if len(decoded.Rules) > MaxResourceRuleProposalRules {
		return fmt.Errorf("resource rule proposal cannot contain more than %d rules", MaxResourceRuleProposalRules)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin Resource rule authoring completion: %w", err)
	}
	defer tx.Rollback(ctx)
	var resourceID string
	err = tx.QueryRow(ctx, `SELECT resource_id::text FROM resource_rule_jobs WHERE job_id=$1 AND status='running' AND lease_owner=$2 AND current_revision FOR UPDATE`, jobID, workerID).Scan(&resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("resource rule authoring lease is no longer owned by this worker")
	}
	if err != nil {
		return fmt.Errorf("read Resource rule authoring job for completion: %w", err)
	}
	rules := make([]detector.ResourceRule, 0, len(decoded.Rules))
	for _, candidate := range decoded.Rules {
		if candidate.Rule.ScopeResourceID != resourceID {
			return errors.New("resource rule proposal contains a rule scoped to another resource")
		}
		rules = append(rules, detector.ResourceRule{Rule: candidate.Rule, Mode: detector.RuleModeShadow})
	}
	if err := detector.ValidateResourceRules(rules); err != nil {
		return fmt.Errorf("validate resource rule proposal: %w", err)
	}
	result, err := tx.Exec(ctx, `
		UPDATE resource_rule_jobs
		SET status='completed', proposal=$3, lease_owner=NULL, lease_expires_at=NULL,
		    completed_at=now(), updated_at=now(), last_error=NULL
		WHERE job_id=$1 AND status='running' AND lease_owner=$2 AND current_revision`, jobID, workerID, proposal)
	if err != nil {
		return fmt.Errorf("complete Resource rule authoring job: %w", err)
	}
	if result.RowsAffected() != 1 {
		return errors.New("resource rule authoring lease is no longer owned by this worker")
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Resource rule authoring completion: %w", err)
	}
	return nil
}

// staleResourceRuleJob matches a job, aliased j, whose context revision is
// no longer current, or whose resource left the graph. Its draft would describe
// nothing that exists, and a newer revision
// has its own job.
const staleResourceRuleJob = `(NOT j.current_revision OR NOT EXISTS (SELECT 1 FROM current_resources r WHERE r.resource_id = j.resource_id))`

// ResourceRuleRetry is what [Store.RetryResourceRuleJob] did with a job.
type ResourceRuleRetry int

const (
	// ResourceRuleRetryScheduled made the job available again after the delay.
	ResourceRuleRetryScheduled ResourceRuleRetry = iota
	// ResourceRuleRetryFailed ended the job as failed; only an operator
	// request queues it again.
	ResourceRuleRetryFailed
	// ResourceRuleRetrySuperseded deleted the job because it went stale.
	ResourceRuleRetrySuperseded
)

// RetryResourceRuleJob releases a held lease after a failed attempt. A job
// that went stale is deleted, whatever terminal says. Otherwise a terminal
// failure ends the job as failed, and any other failure makes it available
// again after retryAfter, clamped to 1s-24h. failure is truncated to 2 KiB.
func (s *Store) RetryResourceRuleJob(ctx context.Context, jobID int64, workerID, failure string, retryAfter time.Duration, terminal bool) (ResourceRuleRetry, error) {
	retryAfter = min(max(retryAfter, time.Second), 24*time.Hour)
	if len(failure) > 2048 {
		failure = failure[:2048]
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin Resource rule authoring retry: %w", err)
	}
	defer tx.Rollback(ctx)
	var stale bool
	err = tx.QueryRow(ctx, `
		SELECT `+staleResourceRuleJob+` FROM resource_rule_jobs j
		WHERE j.job_id=$1 AND j.status='running' AND j.lease_owner=$2
		FOR UPDATE`, jobID, workerID).Scan(&stale)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, errors.New("resource rule authoring lease is no longer owned by this worker")
	}
	if err != nil {
		return 0, fmt.Errorf("read Resource rule authoring job for retry: %w", err)
	}
	outcome := ResourceRuleRetryScheduled
	switch {
	case stale:
		outcome = ResourceRuleRetrySuperseded
		_, err = tx.Exec(ctx, `DELETE FROM resource_rule_jobs WHERE job_id=$1`, jobID)
	case terminal:
		outcome = ResourceRuleRetryFailed
		_, err = tx.Exec(ctx, `
			UPDATE resource_rule_jobs
			SET status='failed', last_error=$2, lease_owner=NULL, lease_expires_at=NULL, updated_at=now()
			WHERE job_id=$1`, jobID, failure)
	default:
		_, err = tx.Exec(ctx, `
			UPDATE resource_rule_jobs
			SET status='retryable', available_at=now()+($3::bigint * interval '1 microsecond'), last_error=$2,
			    lease_owner=NULL, lease_expires_at=NULL, updated_at=now()
			WHERE job_id=$1`, jobID, failure, retryAfter.Microseconds())
	}
	if err != nil {
		return 0, fmt.Errorf("retry Resource rule authoring job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit Resource rule authoring retry: %w", err)
	}
	return outcome, nil
}

// ResourceRuleJobSummary is a job's status without its proposal.
type ResourceRuleJobSummary struct {
	ID         int64  `json:"id"`
	ResourceID string `json:"resourceId"`
	// ContextSHA256 identifies the bounded authoring context for this job.
	ContextSHA256 string `json:"contextSha256,omitempty"`
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
	// CurrentRevision reports whether the job is for the resource's current authoring context.
	CurrentRevision bool `json:"currentRevision"`
}

// Resource rule job errors.
var (
	ErrResourceRuleJobNotFound      = errors.New("resource rule authoring job not found")
	ErrResourceRuleJobNotReviewable = errors.New("resource rule job is not reviewable")
	ErrResourceRuleJobInProgress    = errors.New("resource rule authoring is already in progress")
	ErrResourceRuleSelectionInvalid = errors.New("resource rule selection is invalid")
)

// Resource rule review decisions. Pending drafts run in shadow mode; approved
// rules run in active mode; rejected rules are not loaded.
const (
	ResourceRuleReviewPending  = "pending"
	ResourceRuleReviewApproved = "approved"
	ResourceRuleReviewRejected = "rejected"
)

const resourceRuleJobColumns = `job_id, resource_id::text, context_sha256, status, attempt_count, COALESCE(last_error,''), review_status, COALESCE(reviewed_by,''), reviewed_at, created_at, completed_at,
	CASE WHEN jsonb_typeof(proposal->'rules') = 'array' THEN jsonb_array_length(proposal->'rules') ELSE 0 END,
	COALESCE(requested_by,''), requested_at, current_revision`

func scanResourceRuleJob(row pgx.Row, job *ResourceRuleJobSummary) error {
	return row.Scan(&job.ID, &job.ResourceID, &job.ContextSHA256, &job.Status, &job.AttemptCount, &job.LastError, &job.ReviewStatus, &job.ReviewedBy, &job.ReviewedAt, &job.CreatedAt, &job.CompletedAt,
		&job.RuleCount, &job.RequestedBy, &job.RequestedAt, &job.CurrentRevision)
}

// ListResourceRuleJobs returns up to limit (1-1000) jobs, newest first. A
// non-empty resourceID restricts the result to that resource.
func (s *Store) ListResourceRuleJobs(ctx context.Context, limit int, resourceID string) ([]ResourceRuleJobSummary, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("resource job list limit must be between 1 and 1000")
	}
	rows, err := s.pool.Query(ctx, `SELECT `+resourceRuleJobColumns+` FROM resource_rule_jobs WHERE $2='' OR resource_id::text=$2 ORDER BY job_id DESC LIMIT $1`, limit, resourceID)
	if err != nil {
		return nil, fmt.Errorf("list Resource rule authoring jobs: %w", err)
	}
	defer rows.Close()
	var jobs []ResourceRuleJobSummary
	for rows.Next() {
		var job ResourceRuleJobSummary
		if err := scanResourceRuleJob(rows, &job); err != nil {
			return nil, fmt.Errorf("scan Resource rule authoring job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Resource rule authoring jobs: %w", err)
	}
	return jobs, nil
}

// ResourceRuleProposal returns a completed job's proposal and whether the job
// exists and is completed.
func (s *Store) ResourceRuleProposal(ctx context.Context, jobID int64) (json.RawMessage, bool, error) {
	var proposal []byte
	err := s.pool.QueryRow(ctx, `SELECT proposal FROM resource_rule_jobs WHERE job_id=$1 AND status='completed'`, jobID).Scan(&proposal)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read Resource rule proposal: %w", err)
	}
	return json.RawMessage(proposal), true, nil
}

// ResourceRuleJobStatus returns one job's summary and whether it exists.
func (s *Store) ResourceRuleJobStatus(ctx context.Context, jobID int64) (ResourceRuleJobSummary, bool, error) {
	var job ResourceRuleJobSummary
	err := scanResourceRuleJob(s.pool.QueryRow(ctx, `SELECT `+resourceRuleJobColumns+` FROM resource_rule_jobs WHERE job_id=$1`, jobID), &job)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResourceRuleJobSummary{}, false, nil
	}
	if err != nil {
		return ResourceRuleJobSummary{}, false, fmt.Errorf("read Resource rule authoring job status: %w", err)
	}
	return job, true, nil
}

func (s *Store) ReviewResourceRuleJobRules(ctx context.Context, jobID int64, decision, actor string, selectedRuleIDs []string) error {
	if decision != ResourceRuleReviewApproved && decision != ResourceRuleReviewRejected {
		return errors.New("resource rule review decision must be approved or rejected")
	}
	if err := validateDetectorActor(actor); err != nil {
		return err
	}
	if decision == ResourceRuleReviewRejected && len(selectedRuleIDs) > 0 {
		return fmt.Errorf("%w: rejected drafts cannot select rules", ErrResourceRuleSelectionInvalid)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin resource rule review: %w", err)
	}
	defer tx.Rollback(ctx)
	var proposal []byte
	var current bool
	if err := tx.QueryRow(ctx, `SELECT proposal, current_revision FROM resource_rule_jobs WHERE job_id=$1 AND status='completed' FOR UPDATE`, jobID).Scan(&proposal, &current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: job %d", ErrResourceRuleJobNotReviewable, jobID)
		}
		return fmt.Errorf("read resource rule proposal for review: %w", err)
	}
	if decision == ResourceRuleReviewApproved && !current {
		return fmt.Errorf("%w: job %d is not the current resource revision", ErrResourceRuleJobNotReviewable, jobID)
	}
	updatedProposal, err := proposalWithApprovedRules(proposal, decision, selectedRuleIDs)
	if err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE resource_rule_jobs
		SET review_status=$2, reviewed_by=$3, reviewed_at=now(), updated_at=now(), proposal=$4
		WHERE job_id=$1 AND status='completed'`, jobID, decision, actor, updatedProposal)
	if err != nil {
		return fmt.Errorf("review Resource rule job: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("%w: job %d", ErrResourceRuleJobNotReviewable, jobID)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit resource rule review: %w", err)
	}
	return nil
}

func proposalWithApprovedRules(encoded []byte, decision string, selectedRuleIDs []string) ([]byte, error) {
	var proposal map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &proposal); err != nil {
		return nil, fmt.Errorf("%w: proposal is not valid JSON", ErrResourceRuleSelectionInvalid)
	}
	delete(proposal, "approvedRuleIds")
	if decision != ResourceRuleReviewApproved {
		return json.Marshal(proposal)
	}
	if len(selectedRuleIDs) == 0 {
		return nil, fmt.Errorf("%w: select at least one rule", ErrResourceRuleSelectionInvalid)
	}
	var rules []struct {
		Rule struct {
			ID string `json:"id"`
		} `json:"rule"`
	}
	if err := json.Unmarshal(proposal["rules"], &rules); err != nil {
		return nil, fmt.Errorf("%w: proposal rules are invalid", ErrResourceRuleSelectionInvalid)
	}
	available := make(map[string]struct{}, len(rules))
	for _, candidate := range rules {
		available[candidate.Rule.ID] = struct{}{}
	}
	selected := slices.Clone(selectedRuleIDs)
	slices.Sort(selected)
	selected = slices.Compact(selected)
	if len(selected) != len(selectedRuleIDs) {
		return nil, fmt.Errorf("%w: rule IDs must be unique", ErrResourceRuleSelectionInvalid)
	}
	for _, id := range selected {
		if _, found := available[id]; !found {
			return nil, fmt.Errorf("%w: unknown rule %q", ErrResourceRuleSelectionInvalid, id)
		}
	}
	approved, err := json.Marshal(selected)
	if err != nil {
		return nil, fmt.Errorf("encode approved resource rule IDs: %w", err)
	}
	proposal["approvedRuleIds"] = approved
	updated, err := json.Marshal(proposal)
	if err != nil {
		return nil, fmt.Errorf("encode reviewed resource rule proposal: %w", err)
	}
	if len(updated) > 256*1024 {
		return nil, fmt.Errorf("%w: reviewed proposal exceeds 256 KiB", ErrResourceRuleSelectionInvalid)
	}
	return updated, nil
}

// RequestResourceRuleJob asks for the resource's current authoring context
// to be authored now. A queued or retrying job is woken: it skips the
// stabilization wait and any retry backoff. A completed job is reset to queued,
// dropping its proposal and review, so the next proposal starts in shadow mode;
// a previously approved draft's rules stop running actively until the new draft
// is approved. It returns [ErrResourceRuleJobInProgress] with the job while a
// worker is authoring it, and [ErrResourceRuleJobNotFound] when the
// resource has no job for its current revision. actor is audit metadata, not
// authorization.
func (s *Store) RequestResourceRuleJob(ctx context.Context, resourceID, actor string) (ResourceRuleJobSummary, error) {
	if err := validateDetectorActor(actor); err != nil {
		return ResourceRuleJobSummary{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ResourceRuleJobSummary{}, fmt.Errorf("begin Resource rule request: %w", err)
	}
	defer tx.Rollback(ctx)
	var jobID int64
	var status string
	err = tx.QueryRow(ctx, `
		SELECT job_id, status FROM resource_rule_jobs
		WHERE resource_id::text=$1 AND current_revision
		FOR UPDATE`, resourceID).Scan(&jobID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResourceRuleJobSummary{}, fmt.Errorf("%w for the resource's current revision", ErrResourceRuleJobNotFound)
	}
	if err != nil {
		return ResourceRuleJobSummary{}, fmt.Errorf("read Resource rule job for request: %w", err)
	}
	var job ResourceRuleJobSummary
	switch status {
	case "running":
		if err := scanResourceRuleJob(tx.QueryRow(ctx, `SELECT `+resourceRuleJobColumns+` FROM resource_rule_jobs WHERE job_id=$1`, jobID), &job); err != nil {
			return ResourceRuleJobSummary{}, fmt.Errorf("read running Resource rule job: %w", err)
		}
		return job, ErrResourceRuleJobInProgress
	case "queued", "retryable":
		if err := scanResourceRuleJob(tx.QueryRow(ctx, `
			UPDATE resource_rule_jobs
			SET available_at=now(), requested_by=$2, requested_at=now(), updated_at=now()
			WHERE job_id=$1
			RETURNING `+resourceRuleJobColumns, jobID, actor), &job); err != nil {
			return ResourceRuleJobSummary{}, fmt.Errorf("wake Resource rule job: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return ResourceRuleJobSummary{}, fmt.Errorf("commit Resource rule request: %w", err)
		}
		return job, nil
	}
	if err := scanResourceRuleJob(tx.QueryRow(ctx, `
		UPDATE resource_rule_jobs
		SET status='queued', attempt_count=0, available_at=now(), lease_owner=NULL, lease_expires_at=NULL,
		    proposal=NULL, last_error=NULL, completed_at=NULL,
		    review_status='pending', reviewed_by=NULL, reviewed_at=NULL,
		    requested_by=$2, requested_at=now(), updated_at=now()
		WHERE job_id=$1
		RETURNING `+resourceRuleJobColumns, jobID, actor), &job); err != nil {
		return ResourceRuleJobSummary{}, fmt.Errorf("request Resource rule job: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ResourceRuleJobSummary{}, fmt.Errorf("commit Resource rule request: %w", err)
	}
	return job, nil
}

// ResourceRuleQueueStats counts authoring jobs by what they wait for.
type ResourceRuleQueueStats struct {
	// WaitingForStabilization jobs are queued but younger than the stabilization window.
	WaitingForStabilization int
	// Ready jobs can be claimed now.
	Ready    int
	Running  int
	Retrying int
	// Failed jobs exhausted their attempts and wait for an operator request.
	Failed int
	// NextEligibleAt is when the next stabilization wait ends, if any job is waiting.
	NextEligibleAt *time.Time
}

// ResourceRuleQueueStats reports the authoring queue for a worker that waits
// minAge (the stabilization window) before claiming unrequested jobs.
func (s *Store) ResourceRuleQueueStats(ctx context.Context, minAge time.Duration) (ResourceRuleQueueStats, error) {
	var stats ResourceRuleQueueStats
	err := s.pool.QueryRow(ctx, `
		WITH jobs AS (
			SELECT status, available_at,
			       requested_at IS NULL AND created_at > now()-($1::bigint * interval '1 microsecond') AS waiting,
			       created_at + ($1::bigint * interval '1 microsecond') AS eligible_at
			FROM resource_rule_jobs WHERE status <> 'completed'
		)
		SELECT
			count(*) FILTER (WHERE status IN ('queued', 'retryable') AND waiting),
			count(*) FILTER (WHERE status IN ('queued', 'retryable') AND NOT waiting AND available_at <= now()),
			count(*) FILTER (WHERE status = 'running'),
			count(*) FILTER (WHERE status = 'retryable'),
			count(*) FILTER (WHERE status = 'failed'),
			min(eligible_at) FILTER (WHERE status IN ('queued', 'retryable') AND waiting)
		FROM jobs`, minAge.Microseconds()).Scan(&stats.WaitingForStabilization, &stats.Ready, &stats.Running, &stats.Retrying, &stats.Failed, &stats.NextEligibleAt)
	if err != nil {
		return ResourceRuleQueueStats{}, fmt.Errorf("read Resource rule authoring queue: %w", err)
	}
	return stats, nil
}

// ReadResourceRules returns every rule from completed, non-rejected resource
// proposals whose resource is still in the graph. Approved rules are active;
// unreviewed drafts run in shadow mode.
func (s *Store) ReadResourceRules(ctx context.Context) ([]detector.ResourceRule, error) {
	return s.readResourceRules(ctx, 0)
}

// ReadResourceRulesForDetector returns active rules before shadow rules and
// stops after the detector's capacity plus one overflow rule.
func (s *Store) ReadResourceRulesForDetector(ctx context.Context) ([]detector.ResourceRule, error) {
	return s.readResourceRules(ctx, detector.MaxResourceRules)
}

func (s *Store) readResourceRules(ctx context.Context, limit int) ([]detector.ResourceRule, error) {
	// Per resource, the current revision's approved rule runs active; until it
	// is approved, the newest approved rule of another revision stays active and
	// the current revision's pending draft runs in shadow.
	rows, err := s.pool.Query(ctx, `
		WITH current AS (
			SELECT j.job_id, j.resource_id
			FROM resource_rule_jobs j
			JOIN current_resources r ON r.resource_id = j.resource_id
			WHERE j.current_revision
		), selected AS (
			SELECT active.*
			FROM current
			CROSS JOIN LATERAL (
				SELECT j.job_id, j.resource_id, j.review_status, j.current_revision, j.proposal
				FROM resource_rule_jobs j
				WHERE j.resource_id = current.resource_id
				  AND j.status = 'completed' AND j.review_status = 'approved'
				ORDER BY j.current_revision DESC, j.job_id DESC
				LIMIT 1
			) active
			UNION ALL
			SELECT pending.job_id, pending.resource_id, pending.review_status, pending.current_revision, pending.proposal
			FROM current
			JOIN resource_rule_jobs pending ON pending.job_id = current.job_id
			WHERE pending.status = 'completed' AND pending.review_status = 'pending'
		), candidates AS (
			SELECT selected.*, expanded.candidate
			FROM selected
			CROSS JOIN LATERAL (
				SELECT candidate
				FROM jsonb_array_elements(
					CASE WHEN jsonb_typeof(proposal->'rules') = 'array' THEN proposal->'rules' ELSE '[]'::jsonb END
				) candidate
				LIMIT $2
			) expanded
			WHERE expanded.candidate->'rule'->>'scopeResourceId' = resource_id::text
			AND (
				review_status <> 'approved'
				OR proposal->'approvedRuleIds' IS NULL
				OR proposal->'approvedRuleIds' ? (expanded.candidate->'rule'->>'id')
			)
		)
		SELECT resource_id::text, review_status, proposal->'approvedRuleIds', candidate
		FROM candidates
		ORDER BY (review_status = 'approved') DESC, candidate->'rule'->>'id', job_id
		LIMIT CASE WHEN $1 > 0 THEN (2 * $1) + 1 END`, limit, MaxResourceRuleProposalRules+1)
	if err != nil {
		return nil, fmt.Errorf("read resource rules: %w", err)
	}
	defer rows.Close()
	var result []detector.ResourceRule
	seen := make(map[string]struct{})
	for rows.Next() {
		var resourceID, review string
		var encodedApproved, encodedCandidate []byte
		if err := rows.Scan(&resourceID, &review, &encodedApproved, &encodedCandidate); err != nil {
			return nil, fmt.Errorf("scan resource rule: %w", err)
		}
		var approvedRuleIDs []string
		if encodedApproved != nil && json.Unmarshal(encodedApproved, &approvedRuleIDs) != nil {
			slog.WarnContext(ctx, "skip resource rule with undecodable approval selection", "resourceID", resourceID)
			continue
		}
		var candidate struct {
			Rule detector.Rule `json:"rule"`
		}
		if err := json.Unmarshal(encodedCandidate, &candidate); err != nil {
			slog.WarnContext(ctx, "skip undecodable resource rule", "resourceID", resourceID)
			continue
		}
		mode := detector.RuleModeShadow
		if review == ResourceRuleReviewApproved {
			mode = detector.RuleModeActive
		}
		approved := make(map[string]struct{}, len(approvedRuleIDs))
		for _, id := range approvedRuleIDs {
			approved[id] = struct{}{}
		}
		if review == ResourceRuleReviewApproved && approvedRuleIDs != nil {
			if _, found := approved[candidate.Rule.ID]; !found {
				continue
			}
		}
		if _, found := seen[candidate.Rule.ID]; found {
			slog.WarnContext(ctx, "skip duplicate resource rule", "resourceID", resourceID, "ruleID", candidate.Rule.ID)
			continue
		}
		resourceRule := detector.ResourceRule{Rule: candidate.Rule, Mode: mode}
		if err := detector.ValidateResourceRules([]detector.ResourceRule{resourceRule}); err != nil {
			slog.WarnContext(ctx, "skip invalid resource rule", "resourceID", resourceID, "ruleID", candidate.Rule.ID)
			continue
		}
		seen[candidate.Rule.ID] = struct{}{}
		result = append(result, resourceRule)
		if limit > 0 && len(result) > limit {
			return result, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resource rule proposals: %w", err)
	}
	return result, nil
}
