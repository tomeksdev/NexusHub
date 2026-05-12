// Package ebpfkernel bridges the backend's in-process rule world
// (internal/ebpf.Rule, identified by uuid.UUID) onto the kernel-side
// map runtime owned by ebpf/userspace.RulesLoader.
//
// Placement: this is the only backend package allowed to import
// ebpf/userspace and pull cilium/ebpf into the compile graph.
//
// v2.1 — per-packet iteration. The kernel now stores active rules in
// two packed BPF arrays (rule_table_v4 / rule_table_v6) and walks them
// per packet via bpf_loop. KernelSyncer maintains the in-memory truth
// of every active rule and, on every change, rewrites the two arrays
// in priority-sorted order then publishes the new count. ADR 0005 has
// the full design.
//
// Identity: rule UUIDs come from PostgreSQL; each gets a stable u32
// kernel_id at first Apply, recorded in the slot's rule_id field and
// used as the rule_hits key. The slot index itself is NOT stable —
// it changes whenever priority order shifts.
//
// Ordering: every public method takes a single mutex. Apply, Delete,
// and Reconcile are handler- or sweep-synchronous and rewrite at most
// 256 v4 + 256 v6 records per call — well under a millisecond even on
// the slow path.
package ebpfkernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"

	"github.com/google/uuid"

	baseebpf "github.com/tomeksdev/NexusHub/backend/internal/ebpf"
	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

// Compile-time assertion that KernelSyncer satisfies the Syncer contract.
var _ baseebpf.Syncer = (*KernelSyncer)(nil)

// family flags the IP family a rule applies to. A rule with no CIDR
// constraints (wildcard) is "both": it goes into both v4 and v6
// tables so it matches every packet on the hook regardless of family.
type family uint8

const (
	familyV4   family = 1
	familyV6   family = 2
	familyBoth family = familyV4 | familyV6
)

// activeRule is the syncer's in-memory copy of a rule. We carry the
// kernel-side record bytes pre-built so rebuilds don't repeat the
// translation work — the kernel_id is the only field that mutates
// across an Apply (slot index changes; rule_id stays).
type activeRule struct {
	id        uuid.UUID
	kernelID  uint32        // stable across Apply cycles
	priority  uint16
	fam       family
	v4Record  userspace.RuleV4Record // valid when fam includes v4
	v6Record  userspace.RuleV6Record // valid when fam includes v6
}

// KernelSyncer writes rule updates into the BPF map set owned by a
// RulesLoader. The loader's lifecycle is external: construct it once
// at startup, pass it here, let main.go Close() it at shutdown.
type KernelSyncer struct {
	loader *userspace.RulesLoader
	logger *slog.Logger

	mu sync.Mutex

	// rules holds the full active set keyed by uuid. Slot index is
	// derived at flush time from priority order — not stored.
	rules map[uuid.UUID]*activeRule

	// kernelIDs maps uuid → stable u32 used as the rule_hits key
	// AND stored in the record's rule_id field. Allocated lazily on
	// first Apply; never reused after Delete so per-rule counters
	// stay meaningful across the rule's lifetime.
	kernelIDs    map[uuid.UUID]uint32
	revKernelIDs map[uint32]uuid.UUID
	nextKernelID uint32

	// lastV4Count / lastV6Count remember how many slots were written
	// on the previous flush so we can clear the now-unused tail when
	// the active set shrinks. Slots past the new count are never read
	// by bpf_loop, but clearing them avoids confusing operators who
	// dump rule_table_v4 with bpftool.
	lastV4Count uint32
	lastV6Count uint32
}

// NewKernelSyncer wires a KernelSyncer around an existing loader.
func NewKernelSyncer(loader *userspace.RulesLoader, logger *slog.Logger) (*KernelSyncer, error) {
	if loader == nil {
		return nil, errors.New("nil loader")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &KernelSyncer{
		loader:       loader,
		logger:       logger,
		rules:        make(map[uuid.UUID]*activeRule),
		kernelIDs:    make(map[uuid.UUID]uint32),
		revKernelIDs: make(map[uint32]uuid.UUID),
		nextKernelID: 1,
	}, nil
}

// Apply programs the rule into the kernel. Idempotent: applying the
// same rule twice converges to the same state. The kernel state
// converges atomically per family — we rewrite each table top-to-
// bottom then publish the count, so packets in flight either see
// the old set or the new set, never a torn intermediate.
func (s *KernelSyncer) Apply(ctx context.Context, r baseebpf.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kid := s.kernelIDFor(r.ID)
	ar, err := buildActiveRule(r, kid)
	if err != nil {
		return fmt.Errorf("rule %s: %w", r.ID, err)
	}
	s.rules[r.ID] = ar
	return s.flushLocked(ctx)
}

// Delete removes the rule from kernel state.
func (s *KernelSyncer) Delete(ctx context.Context, ruleID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(ctx, ruleID)
}

// Reconcile converges kernel state to the given active set.
func (s *KernelSyncer) Reconcile(ctx context.Context, active []baseebpf.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	wanted := make(map[uuid.UUID]struct{}, len(active))
	for _, r := range active {
		wanted[r.ID] = struct{}{}
	}
	for id := range s.rules {
		if _, ok := wanted[id]; !ok {
			delete(s.rules, id)
		}
	}
	for _, r := range active {
		kid := s.kernelIDFor(r.ID)
		ar, err := buildActiveRule(r, kid)
		if err != nil {
			s.logger.WarnContext(ctx, "reconcile: build rule", "rule_id", r.ID, "err", err)
			continue
		}
		s.rules[r.ID] = ar
	}
	return s.flushLocked(ctx)
}

// ResolveRuleID inverts the kernel-side u32 → application-side UUID
// mapping. Used by the log consumer to translate a rule_id stamped
// into a ringbuf event back into a UUID.
func (s *KernelSyncer) ResolveRuleID(rid uint32) (uuid.UUID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.revKernelIDs[rid]
	return id, ok
}

// Has reports whether the rule UUID is currently programmed.
func (s *KernelSyncer) Has(id uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.rules[id]
	return ok
}

// Hits returns the kernel-side packets/bytes counter for the rule.
func (s *KernelSyncer) Hits(id uuid.UUID) (packets, bytes uint64, ok bool) {
	s.mu.Lock()
	kid, exists := s.kernelIDs[id]
	s.mu.Unlock()
	if !exists {
		return 0, 0, false
	}
	hits, present, err := s.loader.PeekRuleHits(kid)
	if err != nil || !present {
		return 0, 0, false
	}
	return hits.Packets, hits.Bytes, true
}

// Close clears in-memory state. Loader is caller-owned.
func (s *KernelSyncer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = nil
	s.kernelIDs = nil
	s.revKernelIDs = nil
	return nil
}

// kernelIDFor returns a stable u32 for the rule UUID, allocating on
// first use. nextKernelID monotonically increases; gaps from Delete
// are deliberately not reused so per-rule counters retain their
// historical identity.
func (s *KernelSyncer) kernelIDFor(id uuid.UUID) uint32 {
	if kid, ok := s.kernelIDs[id]; ok {
		return kid
	}
	kid := s.nextKernelID
	s.nextKernelID++
	s.kernelIDs[id] = kid
	s.revKernelIDs[kid] = id
	return kid
}

func (s *KernelSyncer) deleteLocked(ctx context.Context, ruleID uuid.UUID) error {
	if _, ok := s.rules[ruleID]; !ok {
		return nil
	}
	delete(s.rules, ruleID)
	return s.flushLocked(ctx)
}

// flushLocked rebuilds rule_table_v4 + rule_table_v6 from the current
// in-memory rule set, in descending-priority order (highest first).
// Caller holds s.mu.
//
// Order of map writes matters for the in-flight-packet view:
//  1. Write every populated slot
//  2. Clear the tail (slots past the new count, up to lastCount)
//  3. Publish the new count
//
// Packets that read count before step 3 still iterate slots 0..oldCount-1
// where each slot is either the new value (already written) or a stale
// rule (still valid until step 3 shrinks the count). Either case is
// safe; we never expose a half-written slot.
func (s *KernelSyncer) flushLocked(ctx context.Context) error {
	v4, v6 := s.partitionAndSortLocked()

	if len(v4) > userspace.MaxActiveRulesV4 {
		return fmt.Errorf("active v4 rule count %d exceeds kernel max %d",
			len(v4), userspace.MaxActiveRulesV4)
	}
	if len(v6) > userspace.MaxActiveRulesV6 {
		return fmt.Errorf("active v6 rule count %d exceeds kernel max %d",
			len(v6), userspace.MaxActiveRulesV6)
	}

	// v4: write populated, clear tail, publish count.
	for i, ar := range v4 {
		if err := s.loader.PutRuleV4(uint32(i), ar.v4Record); err != nil {
			return fmt.Errorf("put v4 slot %d: %w", i, err)
		}
	}
	for i := uint32(len(v4)); i < s.lastV4Count; i++ {
		if err := s.loader.ClearRuleV4(i); err != nil {
			s.logger.WarnContext(ctx, "clear v4 tail", "slot", i, "err", err)
		}
	}
	if err := s.loader.SetRuleCountV4(uint32(len(v4))); err != nil {
		return fmt.Errorf("set v4 count: %w", err)
	}
	s.lastV4Count = uint32(len(v4))

	// v6: same shape.
	for i, ar := range v6 {
		if err := s.loader.PutRuleV6(uint32(i), ar.v6Record); err != nil {
			return fmt.Errorf("put v6 slot %d: %w", i, err)
		}
	}
	for i := uint32(len(v6)); i < s.lastV6Count; i++ {
		if err := s.loader.ClearRuleV6(i); err != nil {
			s.logger.WarnContext(ctx, "clear v6 tail", "slot", i, "err", err)
		}
	}
	if err := s.loader.SetRuleCountV6(uint32(len(v6))); err != nil {
		return fmt.Errorf("set v6 count: %w", err)
	}
	s.lastV6Count = uint32(len(v6))

	return nil
}

// partitionAndSortLocked splits the rule set by IP family and sorts
// each partition by descending priority (then UUID for stable tie-break).
// Rules with familyBoth land in both partitions.
func (s *KernelSyncer) partitionAndSortLocked() (v4, v6 []*activeRule) {
	v4 = make([]*activeRule, 0, len(s.rules))
	v6 = make([]*activeRule, 0, len(s.rules))
	for _, ar := range s.rules {
		if ar.fam&familyV4 != 0 {
			v4 = append(v4, ar)
		}
		if ar.fam&familyV6 != 0 {
			v6 = append(v6, ar)
		}
	}
	sortByPriority(v4)
	sortByPriority(v6)
	return v4, v6
}

func sortByPriority(rules []*activeRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].priority != rules[j].priority {
			return rules[i].priority > rules[j].priority
		}
		return rules[i].id.String() < rules[j].id.String()
	})
}

// buildActiveRule lowers a baseebpf.Rule into the per-family records
// the kernel reads. Family is inferred from the CIDRs:
//   - both nil       → wildcard, both families
//   - one v4 only    → v4 family
//   - one v6 only    → v6 family
//   - src/dst mixed  → error (can't program a v4-src + v6-dst rule)
func buildActiveRule(r baseebpf.Rule, kernelID uint32) (*activeRule, error) {
	action, err := actionByte(r.Action)
	if err != nil {
		return nil, err
	}
	proto, err := protocolByte(r.Protocol)
	if err != nil {
		return nil, err
	}
	dir, err := directionByte(r.Direction)
	if err != nil {
		return nil, err
	}

	fam, err := familyFor(r.SrcCIDR, r.DstCIDR)
	if err != nil {
		return nil, err
	}

	ar := &activeRule{
		id:       r.ID,
		kernelID: kernelID,
		priority: r.Priority,
		fam:      fam,
	}

	hasSrc := uint8(0)
	if r.SrcCIDR != nil {
		hasSrc = 1
	}
	hasDst := uint8(0)
	if r.DstCIDR != nil {
		hasDst = 1
	}
	hasProto := uint8(0)
	if proto != 0 {
		hasProto = 1
	}

	if fam&familyV4 != 0 {
		ar.v4Record = userspace.RuleV4Record{
			Action:       action,
			Protocol:     proto,
			Direction:    dir,
			IsActive:     1,
			HasSrc:       hasSrc,
			HasDst:       hasDst,
			HasProtocol:  hasProto,
			SrcPrefixLen: prefixLenV4(r.SrcCIDR),
			DstPrefixLen: prefixLenV4(r.DstCIDR),
			RatePPS:      deref32(r.RatePPS),
			RateBurst:    deref32(r.RateBurst),
			SrcPortFrom:  deref16(r.SrcPortFrom),
			SrcPortTo:    deref16(r.SrcPortTo),
			DstPortFrom:  deref16(r.DstPortFrom),
			DstPortTo:    deref16(r.DstPortTo),
			Priority:     r.Priority,
			SrcAddr:      prefixAddrV4(r.SrcCIDR),
			DstAddr:      prefixAddrV4(r.DstCIDR),
			RuleID:       kernelID,
		}
	}
	if fam&familyV6 != 0 {
		ar.v6Record = userspace.RuleV6Record{
			Action:       action,
			Protocol:     proto,
			Direction:    dir,
			IsActive:     1,
			HasSrc:       hasSrc,
			HasDst:       hasDst,
			HasProtocol:  hasProto,
			SrcPrefixLen: prefixLenV6(r.SrcCIDR),
			DstPrefixLen: prefixLenV6(r.DstCIDR),
			RatePPS:      deref32(r.RatePPS),
			RateBurst:    deref32(r.RateBurst),
			SrcPortFrom:  deref16(r.SrcPortFrom),
			SrcPortTo:    deref16(r.SrcPortTo),
			DstPortFrom:  deref16(r.DstPortFrom),
			DstPortTo:    deref16(r.DstPortTo),
			Priority:     r.Priority,
			SrcAddr:      prefixAddrV6(r.SrcCIDR),
			DstAddr:      prefixAddrV6(r.DstCIDR),
			RuleID:       kernelID,
		}
	}
	return ar, nil
}

// familyFor classifies the rule's IP family from its CIDRs. Returns
// an error when src+dst families disagree (e.g. v4 src + v6 dst);
// a rule with no CIDRs is a wildcard and lands in both families.
func familyFor(src, dst *netip.Prefix) (family, error) {
	srcFam := familyOf(src)
	dstFam := familyOf(dst)
	switch {
	case srcFam == 0 && dstFam == 0:
		return familyBoth, nil
	case srcFam != 0 && dstFam != 0 && srcFam != dstFam:
		return 0, fmt.Errorf("rule src and dst CIDR families differ (src=%s, dst=%s)", src, dst)
	case srcFam != 0:
		return srcFam, nil
	default:
		return dstFam, nil
	}
}

func familyOf(p *netip.Prefix) family {
	if p == nil {
		return 0
	}
	if p.Addr().Is4() {
		return familyV4
	}
	return familyV6
}

func prefixLenV4(p *netip.Prefix) uint8 {
	if p == nil || !p.Addr().Is4() {
		return 0
	}
	return uint8(p.Bits())
}

func prefixLenV6(p *netip.Prefix) uint8 {
	if p == nil || p.Addr().Is4() {
		return 0
	}
	return uint8(p.Bits())
}

func prefixAddrV4(p *netip.Prefix) [4]byte {
	if p == nil || !p.Addr().Is4() {
		return [4]byte{}
	}
	return p.Addr().As4()
}

func prefixAddrV6(p *netip.Prefix) [16]byte {
	if p == nil || p.Addr().Is4() {
		return [16]byte{}
	}
	return p.Addr().As16()
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
