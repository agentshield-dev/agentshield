package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func investigationRecord(t *testing.T, risk int, first, last uint64, fingerprint string, anchors ...string) InvestigationJobRecord {
	t.Helper()
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	request, err := json.Marshal(map[string]any{"anchors": anchors, "first": first})
	if err != nil {
		t.Fatal(err)
	}
	return InvestigationJobRecord{
		RiskRank: risk, AnchorIDs: anchors, Fingerprint: digest(fingerprint), SampleKey: digest(strings.Join(anchors, ",")),
		FirstSequence: first, LastSequence: last, Request: request,
	}
}

func makeInvestigationJobsAvailable(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.pool.Exec(context.Background(), `UPDATE investigation_jobs SET available_at = now() - interval '1 second' WHERE status IN ('queued', 'retryable')`); err != nil {
		t.Fatal(err)
	}
}

func TestPostgreSQLInvestigationJobsCoalesceWhileBatching(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	first, merged, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 2, 10, 10, "a", "checkout", "secrets"), time.Minute, nil)
	if err != nil || merged {
		t.Fatalf("first enqueue id=%d merged=%t err=%v", first, merged, err)
	}
	var seen InvestigationJobRecord
	next := investigationRecord(t, 3, 12, 12, "b", "secrets", "orders")
	id, merged, err := store.EnqueueInvestigationJob(ctx, next, time.Minute, func(existing InvestigationJobRecord) (InvestigationJobRecord, bool, error) {
		seen = existing
		combined := next
		combined.FirstSequence = existing.FirstSequence
		combined.AnchorIDs = []string{"checkout", "orders", "secrets"}
		return combined, true, nil
	})
	if err != nil || !merged || id != first {
		t.Fatalf("coalesce id=%d merged=%t err=%v", id, merged, err)
	}
	if seen.FirstSequence != 10 || !slices.Equal(seen.AnchorIDs, []string{"checkout", "secrets"}) {
		t.Fatalf("merge saw %#v", seen)
	}
	declined, merged, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 2, 20, 20, "c", "orders"), time.Minute, func(InvestigationJobRecord) (InvestigationJobRecord, bool, error) {
		return InvestigationJobRecord{}, false, nil
	})
	if err != nil || merged || declined == first {
		t.Fatalf("declined merge id=%d merged=%t err=%v", declined, merged, err)
	}
	unrelated, merged, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 2, 21, 21, "d", "ledger"), time.Minute, func(InvestigationJobRecord) (InvestigationJobRecord, bool, error) {
		t.Fatal("merge called for a job without a shared anchor")
		return InvestigationJobRecord{}, false, nil
	})
	if err != nil || merged || unrelated == first {
		t.Fatalf("unrelated id=%d merged=%t err=%v", unrelated, merged, err)
	}
	if _, found, err := store.ClaimInvestigationJob(ctx, "worker/a", time.Minute); err != nil || found {
		t.Fatalf("claimed a job inside its batch window: found=%t err=%v", found, err)
	}
	makeInvestigationJobsAvailable(t, store)
	job, found, err := store.ClaimInvestigationJob(ctx, "worker/a", time.Minute)
	if err != nil || !found || job.ID != first || job.RiskRank != 3 || job.FirstSequence != 10 || job.LastSequence != 12 || job.Admitted {
		t.Fatalf("highest-risk claim = %#v found=%t err=%v", job, found, err)
	}
	if _, merged, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 2, 30, 30, "e", "checkout"), time.Minute, func(InvestigationJobRecord) (InvestigationJobRecord, bool, error) {
		t.Fatal("merge called for a claimed job")
		return InvestigationJobRecord{}, false, nil
	}); err != nil || merged {
		t.Fatalf("enqueue after claim merged=%t err=%v", merged, err)
	}
}

func TestPostgreSQLInvestigationCoalescingSkipsJobsBeyondSpan(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	old, _, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 2, 1, 900, "a", "checkout"), time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	accept := func(record InvestigationJobRecord) func(InvestigationJobRecord) (InvestigationJobRecord, bool, error) {
		return func(existing InvestigationJobRecord) (InvestigationJobRecord, bool, error) {
			record.FirstSequence = min(record.FirstSequence, existing.FirstSequence)
			record.LastSequence = max(record.LastSequence, existing.LastSequence)
			return record, true, nil
		}
	}
	far := investigationRecord(t, 2, 1500, 1510, "b", "checkout")
	recent, merged, err := store.EnqueueInvestigationJob(ctx, far, time.Minute, accept(far))
	if err != nil || merged || recent == old {
		t.Fatalf("window beyond the oldest job's span id=%d merged=%t err=%v", recent, merged, err)
	}
	later := investigationRecord(t, 2, 1600, 1610, "c", "checkout")
	id, merged, err := store.EnqueueInvestigationJob(ctx, later, time.Minute, accept(later))
	if err != nil || !merged || id != recent {
		t.Fatalf("later window joined id=%d merged=%t err=%v, want job %d", id, merged, err, recent)
	}
}

func TestPostgreSQLInvestigationDedupIgnoresFailedJobs(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	admission := InvestigationAdmission{DedupWindow: time.Hour}
	for index, want := range []string{InvestigationAdmitted, InvestigationAdmitted} {
		if _, _, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 3, uint64(index+1), uint64(index+1), "same", "checkout"), 0, nil); err != nil {
			t.Fatal(err)
		}
		job, found, err := store.ClaimInvestigationJob(ctx, "worker/a", time.Minute)
		if err != nil || !found {
			t.Fatalf("claim found=%t err=%v", found, err)
		}
		if decision, err := store.AdmitInvestigationJob(ctx, job.ID, "worker/a", admission); err != nil || decision != want {
			t.Fatalf("attempt %d decision=%s err=%v, want %s", index, decision, err, want)
		}
		if err := store.RetryInvestigationJob(ctx, job.ID, "worker/a", "model unavailable", time.Second, true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPostgreSQLInvestigationJobsConcurrentClaims(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, _, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 2, 1, 1, "a", "checkout"), 0, nil); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	claims := make(chan bool, 4)
	for index := range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, found, err := store.ClaimInvestigationJob(ctx, "worker/"+string(rune('a'+index)), time.Minute)
			if err != nil {
				t.Error(err)
			}
			claims <- found
		}()
	}
	wait.Wait()
	close(claims)
	count := 0
	for found := range claims {
		if found {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("concurrent claims = %d, want 1", count)
	}
}

func TestPostgreSQLInvestigationAdmissionDedupBudgetAndDeferral(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	admission := InvestigationAdmission{DedupWindow: time.Hour, MaxPerHour: 2, DeferRiskRank: 3, DeferFor: time.Minute}
	claimAndAdmit := func(record InvestigationJobRecord) (int64, string) {
		t.Helper()
		if _, _, err := store.EnqueueInvestigationJob(ctx, record, 0, nil); err != nil {
			t.Fatal(err)
		}
		job, found, err := store.ClaimInvestigationJob(ctx, "worker/a", time.Minute)
		if err != nil || !found {
			t.Fatalf("claim found=%t err=%v", found, err)
		}
		decision, err := store.AdmitInvestigationJob(ctx, job.ID, "worker/a", admission)
		if err != nil {
			t.Fatal(err)
		}
		return job.ID, decision
	}
	firstID, decision := claimAndAdmit(investigationRecord(t, 2, 1, 1, "same", "checkout"))
	if decision != InvestigationAdmitted {
		t.Fatalf("first decision = %s", decision)
	}
	if again, err := store.AdmitInvestigationJob(ctx, firstID, "worker/a", admission); err != nil || again != InvestigationAdmitted {
		t.Fatalf("re-admission = %s err=%v", again, err)
	}
	if err := store.CompleteInvestigationJob(ctx, firstID, "worker/a", json.RawMessage(`{"promotion":"rejected"}`)); err != nil {
		t.Fatal(err)
	}
	if _, decision := claimAndAdmit(investigationRecord(t, 2, 2, 2, "same", "checkout")); decision != InvestigationDuplicate {
		t.Fatalf("duplicate decision = %s", decision)
	}
	secondID, decision := claimAndAdmit(investigationRecord(t, 2, 3, 3, "other", "orders"))
	if decision != InvestigationAdmitted {
		t.Fatalf("second decision = %s", decision)
	}
	if err := store.RetryInvestigationJob(ctx, secondID, "worker/a", "model unavailable", time.Second, false); err != nil {
		t.Fatal(err)
	}
	if _, decision := claimAndAdmit(investigationRecord(t, 2, 4, 4, "medium", "ledger")); decision != InvestigationOverBudget {
		t.Fatalf("over-budget medium decision = %s", decision)
	}
	deferredID, decision := claimAndAdmit(investigationRecord(t, 3, 5, 5, "high", "fraud"))
	if decision != InvestigationDeferred {
		t.Fatalf("over-budget high decision = %s", decision)
	}
	jobs, err := store.ListInvestigationJobs(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[int64]InvestigationJobSummary{}
	for _, job := range jobs {
		statuses[job.ID] = job
	}
	if job := statuses[deferredID]; job.Status != InvestigationJobQueued || job.AdmittedAt != nil || !job.AvailableAt.After(time.Now()) {
		t.Fatalf("deferred job = %#v", job)
	}
	if job := statuses[secondID]; job.Status != InvestigationJobRetryable || job.AttemptCount != 1 || job.LastError != "model unavailable" || job.AdmittedAt == nil {
		t.Fatalf("retryable job = %#v", job)
	}
	skipped := 0
	for _, job := range jobs {
		if job.Status == InvestigationJobSampledOut {
			skipped++
			if job.SkipReason != InvestigationDuplicate && job.SkipReason != InvestigationOverBudget {
				t.Fatalf("skip reason = %q", job.SkipReason)
			}
		}
	}
	if skipped != 2 {
		t.Fatalf("sampled out jobs = %d, want 2", skipped)
	}
	makeInvestigationJobsAvailable(t, store)
	retried, found, err := store.ClaimInvestigationJob(ctx, "worker/b", time.Minute)
	if err != nil || !found || retried.ID != deferredID {
		t.Fatalf("highest-risk reclaim = %#v found=%t err=%v", retried, found, err)
	}
	if err := store.SkipInvestigationJob(ctx, retried.ID, "worker/b", "stale"); err != nil {
		t.Fatal(err)
	}
	retried, found, err = store.ClaimInvestigationJob(ctx, "worker/b", time.Minute)
	if err != nil || !found || retried.ID != secondID || !retried.Admitted || retried.AttemptCount != 1 {
		t.Fatalf("retry claim = %#v found=%t err=%v", retried, found, err)
	}
	if err := store.RetryInvestigationJob(ctx, retried.ID, "worker/a", "wrong owner", time.Second, true); err == nil {
		t.Fatal("non-owner finished a job")
	}
	if err := store.RetryInvestigationJob(ctx, retried.ID, "worker/b", "gave up", time.Second, true); err != nil {
		t.Fatal(err)
	}
	if pruned, err := store.PruneInvestigationJobs(ctx, time.Now().Add(time.Minute)); err != nil || pruned != 5 {
		t.Fatalf("pruned=%d err=%v", pruned, err)
	}
}

func TestPostgreSQLInvestigationJobLeaseReclaim(t *testing.T) {
	store, _ := integrationStore(t)
	ctx := context.Background()
	if _, _, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 2, 1, 1, "a", "checkout"), 0, nil); err != nil {
		t.Fatal(err)
	}
	job, found, err := store.ClaimInvestigationJob(ctx, "worker/crashed", time.Millisecond)
	if err != nil || !found {
		t.Fatalf("claim found=%t err=%v", found, err)
	}
	time.Sleep(10 * time.Millisecond)
	reclaimed, found, err := store.ClaimInvestigationJob(ctx, "worker/b", time.Minute)
	if err != nil || !found || reclaimed.ID != job.ID || reclaimed.AttemptCount != job.AttemptCount+1 {
		t.Fatalf("reclaim = %#v found=%t err=%v", reclaimed, found, err)
	}
	if renewed, err := store.RenewInvestigationJob(ctx, job.ID, "worker/crashed", time.Minute); err != nil || renewed {
		t.Fatalf("stale owner renewed=%t err=%v", renewed, err)
	}
	if err := store.CompleteInvestigationJob(ctx, job.ID, "worker/b", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.EnqueueInvestigationJob(ctx, InvestigationJobRecord{RiskRank: 9}, 0, nil); err == nil {
		t.Fatal("invalid investigation record accepted")
	}
}

func TestPostgreSQLInvestigationJobFailsAfterRepeatedLeaseExpiry(t *testing.T) {
	_, compiler := integrationStore(t)
	config := testConfig(t)
	config.InvestigationMaxAttempts = 3
	store, err := Open(context.Background(), config, compiler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	crashing, _, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 4, 1, 1, "crash", "checkout"), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	healthy, _, err := store.EnqueueInvestigationJob(ctx, investigationRecord(t, 1, 2, 2, "healthy", "orders"), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Two expired leases count as two failed attempts; the third expiry
	// reaches the maximum and fails the job instead of reclaiming it.
	for attempt := 0; attempt < 3; attempt++ {
		job, found, err := store.ClaimInvestigationJob(ctx, "worker/crashing", time.Millisecond)
		if err != nil || !found || job.ID != crashing || job.AttemptCount != attempt {
			t.Fatalf("attempt %d claim = %#v found=%t err=%v", attempt, job, found, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	job, found, err := store.ClaimInvestigationJob(ctx, "worker/b", time.Minute)
	if err != nil || !found || job.ID != healthy {
		t.Fatalf("claim after exhaustion = %#v found=%t err=%v", job, found, err)
	}
	jobs, err := store.ListInvestigationJobs(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, summary := range jobs {
		if summary.ID == crashing && (summary.Status != InvestigationJobFailed || summary.AttemptCount != 3 || summary.CompletedAt == nil) {
			t.Fatalf("exhausted job = %#v", summary)
		}
	}
}
