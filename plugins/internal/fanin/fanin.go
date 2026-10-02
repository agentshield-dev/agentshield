// Package fanin merges per-resource Kubernetes subscriptions into the single
// change and error channels a semantic plugin's Run loop selects on.
package fanin

import "context"

// Forward copies changes to output until both input channels close, an error
// arrives, or ctx ends. It forwards at most one non-nil error and then stops,
// so an output error channel buffered for one error per Forward call never
// blocks. Closing changes alone is not reported here; the producer reports
// unexpected closure on its error channel.
func Forward[T any](ctx context.Context, changes <-chan T, errs <-chan error, output chan<- T, outputErrors chan<- error) {
	for changes != nil || errs != nil {
		select {
		case <-ctx.Done():
			return
		case change, ok := <-changes:
			if !ok {
				changes = nil
				continue
			}
			select {
			case output <- change:
			case <-ctx.Done():
				return
			}
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err != nil {
				select {
				case outputErrors <- err:
				case <-ctx.Done():
				}
				return
			}
		}
	}
}
