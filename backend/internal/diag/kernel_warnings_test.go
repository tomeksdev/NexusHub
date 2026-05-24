package diag

import (
	"testing"
	"time"
)

func TestKernelWarnings_PushAndList(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	k := New(3, time.Minute)
	k.now = func() time.Time { return now }

	k.Push(KernelWarning{Origin: "wg.create", Iface: "wg0", Message: "first"})
	k.Push(KernelWarning{Origin: "ebpf.attach", Iface: "eth0", Message: "second"})

	got := k.List()
	if len(got) != 2 {
		t.Fatalf("len: want 2, got %d", len(got))
	}
	// Newest-first.
	if got[0].Message != "second" {
		t.Errorf("got[0].Message = %q, want second", got[0].Message)
	}
	if got[1].Message != "first" {
		t.Errorf("got[1].Message = %q, want first", got[1].Message)
	}
}

func TestKernelWarnings_RingEvicts(t *testing.T) {
	t.Parallel()
	k := New(2, time.Minute)
	k.now = func() time.Time { return time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC) }
	k.Push(KernelWarning{Origin: "a", Message: "1"})
	k.Push(KernelWarning{Origin: "a", Message: "2"})
	k.Push(KernelWarning{Origin: "a", Message: "3"})
	got := k.List()
	if len(got) != 2 {
		t.Fatalf("len: want 2, got %d", len(got))
	}
	if got[0].Message != "3" || got[1].Message != "2" {
		t.Errorf("ring did not evict oldest: %+v", got)
	}
}

func TestKernelWarnings_TTLFiltersOld(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	k := New(5, time.Minute)
	k.now = func() time.Time { return now }
	// Two old entries, then a fresh one. List should only return the
	// fresh one because the TTL has lapsed for the others.
	k.Push(KernelWarning{Origin: "a", Message: "old1", OccurredAt: now.Add(-2 * time.Minute)})
	k.Push(KernelWarning{Origin: "a", Message: "old2", OccurredAt: now.Add(-90 * time.Second)})
	k.Push(KernelWarning{Origin: "a", Message: "new", OccurredAt: now.Add(-30 * time.Second)})
	got := k.List()
	if len(got) != 1 || got[0].Message != "new" {
		t.Errorf("TTL filter: got %+v", got)
	}
}

func TestKernelWarnings_NilSafe(t *testing.T) {
	t.Parallel()
	var k *KernelWarnings
	k.Push(KernelWarning{Origin: "x"}) // must not panic
	if got := k.List(); len(got) != 0 {
		t.Errorf("nil List: want empty, got %+v", got)
	}
}

func TestKernelWarnings_DefaultsOriginAndTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
	k := New(2, time.Minute)
	k.now = func() time.Time { return now }
	k.Push(KernelWarning{Message: "missing fields"})
	got := k.List()
	if len(got) != 1 {
		t.Fatalf("len: want 1, got %d", len(got))
	}
	if got[0].Origin != "unknown" {
		t.Errorf("Origin: want unknown, got %q", got[0].Origin)
	}
	if !got[0].OccurredAt.Equal(now) {
		t.Errorf("OccurredAt: want %v, got %v", now, got[0].OccurredAt)
	}
}
