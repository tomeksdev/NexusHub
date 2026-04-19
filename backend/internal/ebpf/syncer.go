// Package ebpf is the backend's seam between the rule repository and
// the kernel-side eBPF loader. It deliberately does NOT import the
// cilium/ebpf module or ebpf/userspace — keeping the backend buildable
// on hosts without BPF headers, and keeping the test surface small.
//
// The Syncer interface is the contract: handlers call Apply after
// every successful DB write and Delete after every DB delete.
// Concrete implementations decide whether that means "write to a
// kernel map" or "no-op".
package ebpf

import (
	"context"
	"net/netip"
	"sync"

	"github.com/google/uuid"
)

// Rule is a snapshot of one ebpf_rules row, flattened to the shape the
// kernel cares about. No DB-only fields (timestamps, created_by) —
// those stay in the repository type. Keeping this struct small and
// map-friendly means the sync layer doesn't need to re-load from the
// DB on every kernel write.
type Rule struct {
	ID          uuid.UUID
	Action      string // allow | deny | rate_limit | log
	Direction   string // ingress | egress | both
	Protocol    string // tcp | udp | icmp | any
	SrcCIDR     *netip.Prefix
	DstCIDR     *netip.Prefix
	SrcPortFrom *uint16
	SrcPortTo   *uint16
	DstPortFrom *uint16
	DstPortTo   *uint16
	RatePPS     *uint32
	RateBurst   *uint32
	Priority    uint16
}

// Syncer is how the handlers push rule changes toward the kernel.
// All methods are safe to call even when no kernel is attached —
// implementations are responsible for degrading gracefully.
//
// Apply writes (INSERT or UPDATE) a rule. The implementation should
// be idempotent: calling Apply with the same rule twice is a no-op
// on the kernel side.
//
// Delete removes a rule by ID. Deleting a non-existent rule is a
// no-op (mirrors the "end state matches intent" approach we already
// use for peer deletes).
//
// Reconcile is called from the background sweep goroutine. It
// receives the full active-rule set from the DB and is expected to
// overwrite any drift between maps and source-of-truth. A naive
// implementation is "delete everything, re-apply the slice"; a
// smarter one computes the diff.
type Syncer interface {
	Apply(ctx context.Context, r Rule) error
	Delete(ctx context.Context, ruleID uuid.UUID) error
	Reconcile(ctx context.Context, active []Rule) error
	Close() error
}

// NoopSyncer is the default for environments where eBPF is unavailable
// (local dev without a kernel runner, CI units that don't exercise
// the kernel path). Every method returns nil.
type NoopSyncer struct{}

func (NoopSyncer) Apply(context.Context, Rule) error             { return nil }
func (NoopSyncer) Delete(context.Context, uuid.UUID) error       { return nil }
func (NoopSyncer) Reconcile(context.Context, []Rule) error       { return nil }
func (NoopSyncer) Close() error                                  { return nil }

// FakeSyncer records calls in memory. Tests inspect the recorded
// slice to assert handlers invoked the syncer in lockstep with DB
// writes. Safe for concurrent use.
type FakeSyncer struct {
	mu            sync.Mutex
	Applied       []Rule
	Deleted       []uuid.UUID
	Reconciled    [][]Rule
	ApplyErr      error
	DeleteErr     error
	ReconcileErr  error
}

func (f *FakeSyncer) Apply(_ context.Context, r Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ApplyErr != nil {
		return f.ApplyErr
	}
	f.Applied = append(f.Applied, r)
	return nil
}

func (f *FakeSyncer) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	f.Deleted = append(f.Deleted, id)
	return nil
}

func (f *FakeSyncer) Reconcile(_ context.Context, rules []Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ReconcileErr != nil {
		return f.ReconcileErr
	}
	cp := make([]Rule, len(rules))
	copy(cp, rules)
	f.Reconciled = append(f.Reconciled, cp)
	return nil
}

func (f *FakeSyncer) Close() error { return nil }

// Snapshot returns defensive copies of the recorded call lists so
// test assertions don't race with an in-flight Apply.
func (f *FakeSyncer) Snapshot() (applied []Rule, deleted []uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	applied = make([]Rule, len(f.Applied))
	copy(applied, f.Applied)
	deleted = make([]uuid.UUID, len(f.Deleted))
	copy(deleted, f.Deleted)
	return
}

// Reset clears the recorded call lists. Call from test setup to
// isolate assertions when the same FakeSyncer is reused.
func (f *FakeSyncer) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Applied = nil
	f.Deleted = nil
	f.Reconciled = nil
}
