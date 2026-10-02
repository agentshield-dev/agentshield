// Package progress logs bounded status lines for long-running loops, such as
// workers and pipelines, so operators can see what each one is doing without
// per-iteration log spam.
//
// A [Reporter] collects counters between lines. [Reporter.Tick] logs at most
// one line per [Interval] while the loop did work, and at most one per
// [IdleInterval] while every counter stayed zero. Lines go to slog's default
// logger at Info level.
package progress

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// Interval and IdleInterval bound how often a loop logs a status line.
const (
	Interval     = 15 * time.Second
	IdleInterval = time.Minute
)

// Reporter accumulates named counters for one loop and logs them periodically.
// It is safe for concurrent use.
type Reporter struct {
	message string
	attrs   []any
	now     func() time.Time

	mu     sync.Mutex
	last   time.Time
	counts map[string]int64
}

// New returns a reporter whose lines carry message and attrs. The first line
// is due one [Interval] after creation.
func New(message string, attrs ...any) *Reporter {
	return &Reporter{message: message, attrs: attrs, now: time.Now, last: time.Now(), counts: make(map[string]int64)}
}

// Add increments a counter for the next line.
func (reporter *Reporter) Add(name string, delta int64) {
	reporter.mu.Lock()
	reporter.counts[name] += delta
	reporter.mu.Unlock()
}

// Tick logs the counters since the previous line, plus the attrs status
// returns, when a line is due, and then resets the counters. status is called
// only when a line is logged, so it may query state; it may be nil. Tick
// reports whether it logged.
func (reporter *Reporter) Tick(ctx context.Context, status func() []any) bool {
	reporter.mu.Lock()
	now := reporter.now()
	idle := true
	for _, count := range reporter.counts {
		if count != 0 {
			idle = false
			break
		}
	}
	due := Interval
	if idle {
		due = IdleInterval
	}
	if now.Sub(reporter.last) < due {
		reporter.mu.Unlock()
		return false
	}
	names := make([]string, 0, len(reporter.counts))
	for name := range reporter.counts {
		names = append(names, name)
	}
	slices.Sort(names)
	attrs := append([]any{}, reporter.attrs...)
	for _, name := range names {
		attrs = append(attrs, name, reporter.counts[name])
	}
	attrs = append(attrs, "since", now.Sub(reporter.last).Round(time.Second).String())
	clear(reporter.counts)
	reporter.last = now
	reporter.mu.Unlock()
	if status != nil {
		attrs = append(attrs, status()...)
	}
	slog.InfoContext(ctx, reporter.message, attrs...)
	return true
}
