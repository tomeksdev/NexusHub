// Package ebpfkernel bridges the backend's in-process rule world
// (internal/ebpf.Rule, identified by uuid.UUID) onto the kernel-side
// map runtime owned by ebpf/userspace.RulesLoader (identified by a
// u32 rule_id).
//
// Placement: this is the only backend package allowed to import
// ebpf/userspace and pull cilium/ebpf into the compile graph. The
// sibling internal/ebpf package stays dependency-free so handlers,
// tests, and stubs can depend on the Syncer interface without paying
// the BPF-toolchain tax.
//
// Identity: rule UUIDs come from PostgreSQL; kernel maps index by a
// u32 rule_id. KernelSyncer holds an in-memory uuid → u32 table
// seeded lazily on first Apply and rebuilt wholesale on Reconcile.
// Restarting the process drops the table — that's fine because
// Reconcile runs on boot and re-populates it from the DB's active
// set before any handler can call Apply.
//
// Ordering: every public method takes a single mutex. Apply and
// Delete are handler-synchronous (p99 < 1ms, pure map writes), so
// coarse locking is both safe and simple. Reconcile is called from
// the background sweep and may hold the lock for longer; the sweep
// cadence is seconds, not per-request, so that's fine too.
package ebpfkernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/google/uuid"

	baseebpf "github.com/tomeksdev/NexusHub/backend/internal/ebpf"
	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

// Compile-time assertion that KernelSyncer satisfies the Syncer
// contract the handlers depend on.
var _ baseebpf.Syncer = (*KernelSyncer)(nil)

// KernelSyncer writes rule updates into the BPF map set owned by a
// RulesLoader. The loader's lifecycle is external: construct it once
// at startup, pass it here, let main.go Close() it at shutdown.
// KernelSyncer.Close is a no-op on the loader for that reason — it
// only clears local state.
type KernelSyncer struct {
	loader *userspace.RulesLoader
	logger *slog.Logger

	mu sync.Mutex

	// ids maps PostgreSQL uuid → kernel u32 rule_id. revIDs is the
	// inverse, used during Reconcile to find stale slots.
	ids    map[uuid.UUID]uint32
	revIDs map[uint32]uuid.UUID

	// nextID is a monotonically-increasing sequence. Gaps left by
	// Delete are intentionally not reused: rule_ids are a debug
	// handle, and stable-over-lifetime ordering helps when reading
	// Prometheus series or raw map dumps.
	nextID uint32

	// srcPrefixes/dstPrefixes remember the last-programmed CIDR for
	// each rule so Apply can evict an old LPM entry when the rule's
	// CIDR changes, and Delete can clean up. Without this map the
	// kernel would leak LPM rows on every CIDR rewrite.
	srcPrefixes map[uuid.UUID]netip.Prefix
	dstPrefixes map[uuid.UUID]netip.Prefix
}

// NewKernelSyncer wires a KernelSyncer around an existing loader.
// The loader must outlive the syncer. A nil logger falls back to
// slog.Default so callers that don't care about logging can pass
// nil and move on.
func NewKernelSyncer(loader *userspace.RulesLoader, logger *slog.Logger) (*KernelSyncer, error) {
	if loader == nil {
		return nil, errors.New("nil loader")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &KernelSyncer{
		loader:      loader,
		logger:      logger,
		ids:         make(map[uuid.UUID]uint32),
		revIDs:      make(map[uint32]uuid.UUID),
		nextID:      1,
		srcPrefixes: make(map[uuid.UUID]netip.Prefix),
		dstPrefixes: make(map[uuid.UUID]netip.Prefix),
	}, nil
}

// Apply programs the rule into the kernel. It is safe to call for a
// rule that was already applied — the write is an upsert, and
// changed CIDRs trigger eviction of the prior LPM entry before the
// new one lands.
//
// Meta write first, then LPM writes: order matters because the XDP
// program consults rule_meta after a successful LPM hit. Installing
// the LPM entry before the meta would give a brief window where a
// packet could hit the prefix with no backing meta row; the
// program's nil-check handles that gracefully (XDP_PASS), but the
// order below keeps the window closed on the happy path too.
func (s *KernelSyncer) Apply(ctx context.Context, r baseebpf.Rule) error {
	meta, err := ruleToMeta(r)
	if err != nil {
		return fmt.Errorf("rule %s: %w", r.ID, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rid, existed := s.ids[r.ID]
	if !existed {
		rid = s.nextID
		s.nextID++
	}

	if err := s.loader.PutRuleMeta(rid, meta); err != nil {
		return fmt.Errorf("put rule_meta for %s: %w", r.ID, err)
	}

	// Commit the id mapping only after the meta write succeeded so a
	// retry after a map-full error re-allocates from the same slot.
	if !existed {
		s.ids[r.ID] = rid
		s.revIDs[rid] = r.ID
	}

	if err := s.reprogramPrefix(ctx, r.ID, rid, r.SrcCIDR, s.srcPrefixes,
		s.loader.PutSrcPrefix, s.loader.DeleteSrcPrefix, "src"); err != nil {
		return err
	}
	if err := s.reprogramPrefix(ctx, r.ID, rid, r.DstCIDR, s.dstPrefixes,
		s.loader.PutDstPrefix, s.loader.DeleteDstPrefix, "dst"); err != nil {
		return err
	}
	return nil
}

// Delete removes every trace of the rule from the kernel. Calling
// Delete for a rule that was never Applied is a no-op — mirrors the
// "end state matches intent" invariant shared by the rest of the
// reconcile path.
func (s *KernelSyncer) Delete(ctx context.Context, ruleID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(ctx, ruleID)
}

// Reconcile converges kernel state to the given active set. Rules
// we know about that aren't in active are removed; rules in active
// are re-Applied so field drift (priority, ports, rate) is fixed.
//
// Errors on individual rules are logged and swallowed: the sweep
// must not abort mid-way because one map write failed, or a single
// bad rule would block every other rule's convergence. The caller
// (reconciler loop) gets nil on partial success.
func (s *KernelSyncer) Reconcile(ctx context.Context, active []baseebpf.Rule) error {
	wanted := make(map[uuid.UUID]struct{}, len(active))
	for _, r := range active {
		wanted[r.ID] = struct{}{}
	}

	s.mu.Lock()
	stale := make([]uuid.UUID, 0)
	for id := range s.ids {
		if _, ok := wanted[id]; !ok {
			stale = append(stale, id)
		}
	}
	for _, id := range stale {
		if err := s.deleteLocked(ctx, id); err != nil {
			s.logger.WarnContext(ctx, "reconcile: delete stale rule", "rule_id", id, "err", err)
		}
	}
	s.mu.Unlock()

	// Apply releases and re-acquires the mutex per rule; that's OK
	// because no one else writes through the syncer concurrently
	// (handlers and reconciler share the same serial loop feeding
	// this type).
	for _, r := range active {
		if err := s.Apply(ctx, r); err != nil {
			s.logger.WarnContext(ctx, "reconcile: apply rule", "rule_id", r.ID, "err", err)
		}
	}
	return nil
}

// Close releases in-memory state. The underlying loader is owned by
// the caller and deliberately not closed here — a caller that built
// the loader once and attached both the XDP and TC programs would
// otherwise lose the kernel attach when one syncer instance exits.
func (s *KernelSyncer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids = nil
	s.revIDs = nil
	s.srcPrefixes = nil
	s.dstPrefixes = nil
	return nil
}

// deleteLocked is the mutex-held core of Delete, reused by Reconcile
// for its stale-slot sweep.
func (s *KernelSyncer) deleteLocked(ctx context.Context, ruleID uuid.UUID) error {
	rid, ok := s.ids[ruleID]
	if !ok {
		return nil
	}

	if err := s.loader.DeleteRuleMeta(rid); err != nil {
		return fmt.Errorf("delete rule_meta for %s: %w", ruleID, err)
	}
	if prev, ok := s.srcPrefixes[ruleID]; ok {
		if err := s.loader.DeleteSrcPrefix(prev); err != nil {
			s.logger.WarnContext(ctx, "delete src prefix", "rule_id", ruleID, "cidr", prev, "err", err)
		}
		delete(s.srcPrefixes, ruleID)
	}
	if prev, ok := s.dstPrefixes[ruleID]; ok {
		if err := s.loader.DeleteDstPrefix(prev); err != nil {
			s.logger.WarnContext(ctx, "delete dst prefix", "rule_id", ruleID, "cidr", prev, "err", err)
		}
		delete(s.dstPrefixes, ruleID)
	}
	delete(s.ids, ruleID)
	delete(s.revIDs, rid)
	return nil
}

// reprogramPrefix is the common body of src+dst prefix lifecycle:
// evict any previously-programmed CIDR for this rule that no longer
// matches (or is no longer present), then insert the new one if the
// rule carries one. Called with the outer mutex held.
func (s *KernelSyncer) reprogramPrefix(
	ctx context.Context,
	ruleID uuid.UUID,
	rid uint32,
	want *netip.Prefix,
	cache map[uuid.UUID]netip.Prefix,
	put func(netip.Prefix, uint32) error,
	del func(netip.Prefix) error,
	side string,
) error {
	prev, had := cache[ruleID]
	switch {
	case had && want == nil:
		// Rule dropped its CIDR.
		if err := del(prev); err != nil {
			s.logger.WarnContext(ctx, "evict prefix", "side", side, "rule_id", ruleID, "cidr", prev, "err", err)
		}
		delete(cache, ruleID)
	case had && want != nil && *want != prev:
		// Rule changed its CIDR — evict old before insert so a brief
		// gap is preferred over a transient double-hit against two
		// rule_ids for the same packet.
		if err := del(prev); err != nil {
			s.logger.WarnContext(ctx, "evict stale prefix", "side", side, "rule_id", ruleID, "cidr", prev, "err", err)
		}
		delete(cache, ruleID)
	}
	if want != nil {
		if err := put(*want, rid); err != nil {
			return fmt.Errorf("put %s prefix for %s: %w", side, ruleID, err)
		}
		cache[ruleID] = *want
	}
	return nil
}

// ruleToMeta lowers the handler-facing Rule into the exact bytes the
// BPF program reads. Enum strings come in straight from the JSON
// validator, so any surprise here means a caller bypassed the
// validator — fail loud.
func ruleToMeta(r baseebpf.Rule) (userspace.RuleMeta, error) {
	action, err := actionByte(r.Action)
	if err != nil {
		return userspace.RuleMeta{}, err
	}
	proto, err := protocolByte(r.Protocol)
	if err != nil {
		return userspace.RuleMeta{}, err
	}
	dir, err := directionByte(r.Direction)
	if err != nil {
		return userspace.RuleMeta{}, err
	}
	return userspace.RuleMeta{
		Action:      action,
		Protocol:    proto,
		Direction:   dir,
		IsActive:    1,
		SrcPortFrom: deref16(r.SrcPortFrom),
		SrcPortTo:   deref16(r.SrcPortTo),
		DstPortFrom: deref16(r.DstPortFrom),
		DstPortTo:   deref16(r.DstPortTo),
		Priority:    r.Priority,
		RatePPS:     deref32(r.RatePPS),
		RateBurst:   deref32(r.RateBurst),
	}, nil
}

// Enum values match ebpf/headers/nexushub.h. Keep in lockstep.
func actionByte(s string) (uint8, error) {
	switch s {
	case "allow":
		return 0, nil
	case "deny":
		return 1, nil
	case "rate_limit":
		return 2, nil
	case "log":
		return 3, nil
	default:
		return 0, fmt.Errorf("unknown action %q", s)
	}
}

func protocolByte(s string) (uint8, error) {
	switch s {
	case "", "any":
		return 0, nil
	case "tcp":
		return 1, nil
	case "udp":
		return 2, nil
	case "icmp":
		return 3, nil
	default:
		return 0, fmt.Errorf("unknown protocol %q", s)
	}
}

func directionByte(s string) (uint8, error) {
	switch s {
	case "", "ingress":
		return 0, nil
	case "egress":
		return 1, nil
	case "both":
		return 2, nil
	default:
		return 0, fmt.Errorf("unknown direction %q", s)
	}
}

func deref16(p *uint16) uint16 {
	if p == nil {
		return 0
	}
	return *p
}

func deref32(p *uint32) uint32 {
	if p == nil {
		return 0
	}
	return *p
}
