// Package diag exposes operator diagnostics that are too volatile to
// log-and-forget but too transient for the audit table.
//
// KernelWarnings is the round-3 specific solution to "kernel apply
// failed silently" — every wgctrl / netlink / eBPF write that the
// handlers swallowed with slog.Warn now also lands in a small ring
// buffer. The Support page reads it via GET /api/v1/diag/kernel-warnings
// so the operator can see what's broken without ssh-ing into the
// box and tailing journalctl.
package diag

import (
	"sync"
	"time"
)

// KernelWarning is a single row of the ring. Origin is a
// component-scoped tag (e.g. "wg.create", "ebpf.attach") that lets
// the UI group the entries; Iface is the affected device when
// applicable.
type KernelWarning struct {
	OccurredAt time.Time `json:"occurred_at"`
	Origin     string    `json:"origin"`
	Iface      string    `json:"iface,omitempty"`
	Message    string    `json:"message"`
}

// KernelWarnings is a fixed-capacity ring of the most recent kernel-
// apply warnings. Safe for concurrent Push / List from multiple
// goroutines — the handlers run under gin's worker pool so this is a
// hard requirement.
//
// Each entry has a TTL: List filters out anything older than ttl,
// which keeps the operator from chasing a problem that's already
// resolved itself (a transient netlink hiccup during reload, say).
type KernelWarnings struct {
	mu  sync.Mutex
	buf []KernelWarning
	// nextWrite is the index where the next Push lands. Wraps at cap.
	nextWrite int
	// length grows from 0 to cap then stays at cap.
	length int
	cap    int
	ttl    time.Duration
	// now is the clock fn — overridable for tests so we can age
	// entries deterministically.
	now func() time.Time
}

// New returns a KernelWarnings ring sized to capacity, where entries
// older than ttl are filtered out by List. cap=50, ttl=15min are the
// production defaults; tests may pick smaller values.
func New(cap int, ttl time.Duration) *KernelWarnings {
	if cap <= 0 {
		cap = 50
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &KernelWarnings{
		buf: make([]KernelWarning, cap),
		cap: cap,
		ttl: ttl,
		now: time.Now,
	}
}

// Push appends a warning. Oldest entries are evicted when the ring is
// full. Origin is required (the UI groups by it); empty origin gets
// the catch-all "unknown".
func (k *KernelWarnings) Push(w KernelWarning) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if w.OccurredAt.IsZero() {
		w.OccurredAt = k.now()
	}
	if w.Origin == "" {
		w.Origin = "unknown"
	}
	k.buf[k.nextWrite] = w
	k.nextWrite = (k.nextWrite + 1) % k.cap
	if k.length < k.cap {
		k.length++
	}
}

// List returns the live entries in newest-first order, dropping
// anything past the TTL. Returns an empty (non-nil) slice when the
// ring is empty so JSON encoding produces [].
func (k *KernelWarnings) List() []KernelWarning {
	if k == nil {
		return []KernelWarning{}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	cutoff := k.now().Add(-k.ttl)
	out := make([]KernelWarning, 0, k.length)
	// Walk newest-first: start at the last-written slot and step
	// backwards. nextWrite points at the *next* free slot, so the
	// most recent entry lives at (nextWrite-1) mod cap.
	for i := 0; i < k.length; i++ {
		idx := (k.nextWrite - 1 - i + k.cap) % k.cap
		w := k.buf[idx]
		if w.OccurredAt.Before(cutoff) {
			break // older entries follow; stop early.
		}
		out = append(out, w)
	}
	return out
}
