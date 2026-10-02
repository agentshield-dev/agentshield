package progress

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestReporterRateLimitsBusyAndIdleLines(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	clock := time.Unix(0, 0)
	reporter := New("worker status", "worker", "test")
	reporter.now = func() time.Time { return clock }
	reporter.last = clock
	ctx := context.Background()
	queried := 0
	status := func() []any { queried++; return []any{"queued", 3} }

	reporter.Add("completed", 2)
	clock = clock.Add(Interval - time.Second)
	if reporter.Tick(ctx, status) || queried != 0 {
		t.Fatal("logged before the interval")
	}
	clock = clock.Add(time.Second)
	if !reporter.Tick(ctx, status) || queried != 1 {
		t.Fatal("did not log a busy line at the interval")
	}
	if line := logs.String(); !strings.Contains(line, "worker=test") || !strings.Contains(line, "completed=2") || !strings.Contains(line, "queued=3") {
		t.Fatalf("line = %q", line)
	}
	// With no work since, the next line waits for the idle interval.
	clock = clock.Add(Interval)
	if reporter.Tick(ctx, status) {
		t.Fatal("logged an idle line at the busy interval")
	}
	clock = clock.Add(IdleInterval - Interval)
	if !reporter.Tick(ctx, status) {
		t.Fatal("did not log an idle line at the idle interval")
	}
	if strings.Count(logs.String(), "worker status") != 2 || strings.Contains(strings.Split(strings.TrimSpace(logs.String()), "\n")[1], "completed=2") {
		t.Fatalf("counters were not reset between lines: %s", logs.String())
	}
}
