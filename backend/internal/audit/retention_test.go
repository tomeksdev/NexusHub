package audit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakePruner struct {
	mu      sync.Mutex
	calls   []time.Time
	retErr  error
	retRows int64
}

func (f *fakePruner) PruneOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cutoff)
	return f.retRows, f.retErr
}

func (f *fakePruner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestRetentionLoopDisabledWhenRetentionZero(t *testing.T) {
	p := &fakePruner{}
	// Retention 0 must return immediately without calling Prune.
	RunRetentionLoop(context.Background(), p, RetentionConfig{}, nil)
	if p.callCount() != 0 {
		t.Fatalf("expected 0 calls, got %d", p.callCount())
	}
}

func TestRetentionLoopRunsOnceOnStart(t *testing.T) {
	p := &fakePruner{}
	// Cancel the context fast so we only see the eager pre-tick pass.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	RunRetentionLoop(ctx, p, RetentionConfig{
		Retention: 24 * time.Hour,
		Interval:  time.Hour,
	}, nil)

	if p.callCount() != 1 {
		t.Fatalf("expected exactly 1 prune call at startup, got %d", p.callCount())
	}
}

func TestRetentionLoopCutoffEqualsNowMinusRetention(t *testing.T) {
	fixedNow := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	p := &fakePruner{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	RunRetentionLoop(ctx, p, RetentionConfig{
		Retention: 90 * 24 * time.Hour,
		Interval:  time.Hour,
		Now:       func() time.Time { return fixedNow },
	}, nil)

	if len(p.calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(p.calls))
	}
	want := fixedNow.Add(-90 * 24 * time.Hour)
	if !p.calls[0].Equal(want) {
		t.Fatalf("cutoff = %v, want %v", p.calls[0], want)
	}
}

func TestRetentionLoopKeepsRunningAfterPruneError(t *testing.T) {
	// A DB hiccup must not take the loop down. We ping the fake on
	// every tick; forcing an error on the first call and checking the
	// second call lands proves the error path doesn't early-return.
	var count atomic.Int32
	stopAfter := 2

	p := &errorThenSuccessPruner{
		first:  errors.New("boom"),
		after:  nil,
		count:  &count,
		target: int32(stopAfter),
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Stop once we've seen the second call.
	go func() {
		for count.Load() < int32(stopAfter) {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()

	// Very short interval so the second tick lands quickly.
	RunRetentionLoop(ctx, p, RetentionConfig{
		Retention: 24 * time.Hour,
		Interval:  10 * time.Millisecond,
	}, nil)

	if got := count.Load(); got < int32(stopAfter) {
		t.Fatalf("expected ≥%d calls, got %d", stopAfter, got)
	}
}

type errorThenSuccessPruner struct {
	first  error
	after  error
	count  *atomic.Int32
	target int32
}

func (e *errorThenSuccessPruner) PruneOlderThan(_ context.Context, _ time.Time) (int64, error) {
	n := e.count.Add(1)
	if n == 1 {
		return 0, e.first
	}
	return 0, e.after
}
