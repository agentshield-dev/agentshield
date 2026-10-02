package reasoning

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrLeaseLost means a job's lease is now owned by another worker.
var ErrLeaseLost = errors.New("job lease is no longer owned by this worker")

// KeepLease renews a job lease every third of lease until ctx ends, then
// returns nil. renew reports whether this worker still owns the lease. A lost
// lease returns [ErrLeaseLost] at once, because another worker may own the job.
// A failed renewal, such as a brief database outage, is tolerated while the
// lease would still be held at the next attempt; after that the last error is
// returned. The caller cancels its work when KeepLease returns an error.
func KeepLease(ctx context.Context, lease time.Duration, renew func(context.Context) (bool, error)) error {
	interval := lease / 3
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	renewedAt := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			renewed, err := renew(ctx)
			if ctx.Err() != nil {
				return nil
			}
			switch {
			case err == nil && renewed:
				renewedAt = time.Now()
			case err == nil:
				return ErrLeaseLost
			case time.Since(renewedAt)+interval >= lease:
				return fmt.Errorf("lease could not be renewed before it expires: %w", err)
			}
		}
	}
}

// panicError converts a recovered panic into an error carrying its stack.
func panicError(recovered any, stack []byte) error {
	return fmt.Errorf("panic: %v\n%s", recovered, stack)
}
