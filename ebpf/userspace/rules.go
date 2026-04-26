// Package userspace provides the Go-side loader and map-manager for
// NexusHub's eBPF programs.
//
// The RulesLoader owns an ebpf.Collection (the rule_meta HASH + four
// LPM_TRIE maps per ADR 0004) and exposes typed CRUD for the kernel's
// rule runtime. Program attach is a separate concern handled by
// callers via the cilium/ebpf link package — keeping it out of this
// type means the Loader is testable against maps only (no netns, no
// kernel interface state).
//
// The Loader is constructed from a *ebpf.CollectionSpec. In
// production, call the bpf2go-generated loader to get a spec embedded
// from the compiled .o; in tests, build a spec in-memory. This
// two-step separates "what the kernel will run" from "how we got
// the bytes".
package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
)

// Map names in the compiled ELF. These match the variable names in
// ebpf/src/rules.c; changing one requires changing the other.
const (
	mapRuleMeta    = "rule_meta"
	mapRuleSrcV4   = "rule_src_v4"
	mapRuleSrcV6   = "rule_src_v6"
	mapRuleDstV4   = "rule_dst_v4"
	mapRuleDstV6   = "rule_dst_v6"
	mapRateStateV4 = "rate_state_v4"
	mapRateStateV6 = "rate_state_v6"
	mapRuleHits    = "rule_hits"
	mapLogEvents   = "log_events"
)

// Program names in the compiled ELF. These match the SEC() function
// names in ebpf/src/rules.c: clang preserves the C symbol and bpf2go
// surfaces them verbatim.
//
// ProgramXDPRules attaches to the WAN interface via link.AttachXDP;
// ProgramTCRulesWg0 attaches to wg0's clsact ingress hook (the caller
// owns tc qdisc setup — cilium/ebpf's tcx helpers or classic tc netlink
// both work).
const (
	ProgramXDPRules   = "xdp_rules"
	ProgramTCRulesWg0 = "tc_rules_wg0"
)

// RuleMeta mirrors struct rule_meta in ebpf/headers/nexushub.h.
// Field order + sizes are load-bearing: the kernel reads raw bytes.
type RuleMeta struct {
	Action      uint8  // ACTION_{ALLOW,DENY,RATE_LIMIT,LOG}
	Protocol    uint8  // PROTO_{ANY,TCP,UDP,ICMP}
	Direction   uint8  // DIR_{INGRESS,EGRESS,BOTH}
	IsActive    uint8  // 0/1
	SrcPortFrom uint16 // 0 when wildcard
	SrcPortTo   uint16
	DstPortFrom uint16
	DstPortTo   uint16
	Priority    uint16
	RatePPS     uint32
	RateBurst   uint32
}

// ruleMetaSize is the on-wire length of struct rule_meta including
// compiler padding. The C struct lays out as:
//
//	u8×4 + u16×5 + u16 _pad + u32×2 + u32 _pad2 = 28 bytes.
const ruleMetaSize = 28

// MarshalBinary serializes RuleMeta into the exact byte layout the
// kernel expects. Little-endian is correct for both bpf2go targets
// (amd64, arm64) — if we ever add a big-endian target this needs
// per-arch handling.
func (m RuleMeta) MarshalBinary() ([]byte, error) {
	b := make([]byte, ruleMetaSize)
	b[0] = m.Action
	b[1] = m.Protocol
	b[2] = m.Direction
	b[3] = m.IsActive
	binary.LittleEndian.PutUint16(b[4:6], m.SrcPortFrom)
	binary.LittleEndian.PutUint16(b[6:8], m.SrcPortTo)
	binary.LittleEndian.PutUint16(b[8:10], m.DstPortFrom)
	binary.LittleEndian.PutUint16(b[10:12], m.DstPortTo)
	binary.LittleEndian.PutUint16(b[12:14], m.Priority)
	// b[14:16] is _pad, left zero.
	binary.LittleEndian.PutUint32(b[16:20], m.RatePPS)
	binary.LittleEndian.PutUint32(b[20:24], m.RateBurst)
	// b[24:28] is _pad2, left zero.
	return b, nil
}

// UnmarshalBinary is the inverse of MarshalBinary. Used by the
// reconciler to read rule_meta entries back for drift detection.
func (m *RuleMeta) UnmarshalBinary(b []byte) error {
	if len(b) != ruleMetaSize {
		return fmt.Errorf("rule_meta: expected %d bytes, got %d", ruleMetaSize, len(b))
	}
	m.Action = b[0]
	m.Protocol = b[1]
	m.Direction = b[2]
	m.IsActive = b[3]
	m.SrcPortFrom = binary.LittleEndian.Uint16(b[4:6])
	m.SrcPortTo = binary.LittleEndian.Uint16(b[6:8])
	m.DstPortFrom = binary.LittleEndian.Uint16(b[8:10])
	m.DstPortTo = binary.LittleEndian.Uint16(b[10:12])
	m.Priority = binary.LittleEndian.Uint16(b[12:14])
	m.RatePPS = binary.LittleEndian.Uint32(b[16:20])
	m.RateBurst = binary.LittleEndian.Uint32(b[20:24])
	return nil
}

// RateTokens mirrors struct rate_tokens in ebpf/headers/nexushub.h.
// PERCPU_HASH stores one copy per CPU; operator-facing code (metrics,
// reconciler) sums across CPUs. The Go shape is a single snapshot —
// callers collect per-CPU slices externally when needed.
type RateTokens struct {
	TokensX1000 uint64
	LastSeenNs  uint64
}

const rateTokensSize = 16

func (r RateTokens) MarshalBinary() ([]byte, error) {
	b := make([]byte, rateTokensSize)
	binary.LittleEndian.PutUint64(b[0:8], r.TokensX1000)
	binary.LittleEndian.PutUint64(b[8:16], r.LastSeenNs)
	return b, nil
}

func (r *RateTokens) UnmarshalBinary(b []byte) error {
	if len(b) != rateTokensSize {
		return fmt.Errorf("rate_tokens: expected %d bytes, got %d", rateTokensSize, len(b))
	}
	r.TokensX1000 = binary.LittleEndian.Uint64(b[0:8])
	r.LastSeenNs = binary.LittleEndian.Uint64(b[8:16])
	return nil
}

// rateKeyV4 mirrors struct rate_key_v4 in ebpf/headers/nexushub.h.
// addr is stored in network byte order to match the packet path.
type rateKeyV4 struct {
	RuleID uint32
	Addr   [4]byte
}

const rateKeyV4Size = 8

func (k rateKeyV4) MarshalBinary() ([]byte, error) {
	b := make([]byte, rateKeyV4Size)
	binary.LittleEndian.PutUint32(b[0:4], k.RuleID)
	copy(b[4:8], k.Addr[:])
	return b, nil
}

// rateKeyV6 mirrors struct rate_key_v6: u32 rule_id + u8[16] addr for
// 20 bytes total. Go struct layout packs u32 at offset 0 + [16]byte at
// offset 4; no tail padding when the struct is used as a map key.
type rateKeyV6 struct {
	RuleID uint32
	Addr   [16]byte
}

const rateKeyV6Size = 20

func (k rateKeyV6) MarshalBinary() ([]byte, error) {
	b := make([]byte, rateKeyV6Size)
	binary.LittleEndian.PutUint32(b[0:4], k.RuleID)
	copy(b[4:20], k.Addr[:])
	return b, nil
}

// RuleHits mirrors struct rule_hits in ebpf/headers/nexushub.h. The
// map is PERCPU_HASH so readers that want an aggregate — a single
// "bytes across the fleet" number — must sum across CPUs. PeekRuleHits
// handles that reduction for callers; direct Lookup on the underlying
// map returns the per-CPU slice if finer granularity is needed.
type RuleHits struct {
	Packets uint64
	Bytes   uint64
}

const ruleHitsSize = 16

func (h RuleHits) MarshalBinary() ([]byte, error) {
	b := make([]byte, ruleHitsSize)
	binary.LittleEndian.PutUint64(b[0:8], h.Packets)
	binary.LittleEndian.PutUint64(b[8:16], h.Bytes)
	return b, nil
}

func (h *RuleHits) UnmarshalBinary(b []byte) error {
	if len(b) != ruleHitsSize {
		return fmt.Errorf("rule_hits: expected %d bytes, got %d", ruleHitsSize, len(b))
	}
	h.Packets = binary.LittleEndian.Uint64(b[0:8])
	h.Bytes = binary.LittleEndian.Uint64(b[8:16])
	return nil
}

// RulesLoader manages the map set of the XDP/TC rule runtime. Every
// rule operation is a single map-write — the eBPF programs pick up
// changes on the next packet without reload. The log_events ringbuf
// is optional: older test specs omit it, and OpenLogReader surfaces
// that as an explicit error rather than panicking.
type RulesLoader struct {
	coll *ebpf.Collection

	meta      *ebpf.Map
	srcV4     *ebpf.Map
	srcV6     *ebpf.Map
	dstV4     *ebpf.Map
	dstV6     *ebpf.Map
	rateV4    *ebpf.Map
	rateV6    *ebpf.Map
	ruleHits  *ebpf.Map // nil if the collection omits the counter map (tests)
	logEvents *ebpf.Map // nil if the collection omits the ringbuf (tests)
}

// NewRulesLoader builds the collection from spec, pulls handles for
// every map the program declares, and returns a ready-to-use loader.
// The caller owns Close() — failing to call it leaks kernel resources.
func NewRulesLoader(spec *ebpf.CollectionSpec) (*RulesLoader, error) {
	if spec == nil {
		return nil, errors.New("nil spec")
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	pick := func(name string) (*ebpf.Map, error) {
		m, ok := coll.Maps[name]
		if !ok {
			return nil, fmt.Errorf("map %q missing from spec", name)
		}
		return m, nil
	}
	meta, err := pick(mapRuleMeta)
	if err != nil {
		coll.Close()
		return nil, err
	}
	srcV4, err := pick(mapRuleSrcV4)
	if err != nil {
		coll.Close()
		return nil, err
	}
	srcV6, err := pick(mapRuleSrcV6)
	if err != nil {
		coll.Close()
		return nil, err
	}
	dstV4, err := pick(mapRuleDstV4)
	if err != nil {
		coll.Close()
		return nil, err
	}
	dstV6, err := pick(mapRuleDstV6)
	if err != nil {
		coll.Close()
		return nil, err
	}
	rateV4, err := pick(mapRateStateV4)
	if err != nil {
		coll.Close()
		return nil, err
	}
	rateV6, err := pick(mapRateStateV6)
	if err != nil {
		coll.Close()
		return nil, err
	}
	// rule_hits and log_events are optional — maps-only test specs
	// may omit them. rule_hits absence surfaces via PeekRuleHits
	// returning ok=false; log_events absence via OpenLogReader.
	ruleHitsMap := coll.Maps[mapRuleHits]
	logEvents := coll.Maps[mapLogEvents]
	return &RulesLoader{
		coll: coll, meta: meta,
		srcV4: srcV4, srcV6: srcV6,
		dstV4: dstV4, dstV6: dstV6,
		rateV4:    rateV4,
		rateV6:    rateV6,
		ruleHits:  ruleHitsMap,
		logEvents: logEvents,
	}, nil
}

// Close releases every map and program in the underlying collection.
// Safe to call on a nil receiver so `defer loader.Close()` works
// around an early-return constructor failure.
func (l *RulesLoader) Close() error {
	if l == nil || l.coll == nil {
		return nil
	}
	l.coll.Close()
	l.coll = nil
	return nil
}

// MapStats is a single-map operational snapshot: how many entries are
// live right now vs. the compile-time ceiling. Prometheus scrapes this
// via the ebpfkernel.MetricsCollector; operator dashboards alert when
// Entries/MaxEntries crosses a capacity threshold.
type MapStats struct {
	Entries    uint32
	MaxEntries uint32
}

// LoaderStats gathers one MapStats per BPF map the loader owns. Read
// lazily (one pass per map) so an empty deploy costs a handful of
// no-op iterations. Scrape cost scales with live entries, not with
// MaxEntries — iteration stops at the last populated slot. RuleHits
// is zero-valued when the spec omits the rule_hits map (tests).
type LoaderStats struct {
	RuleMeta    MapStats
	RuleSrcV4   MapStats
	RuleSrcV6   MapStats
	RuleDstV4   MapStats
	RuleDstV6   MapStats
	RateStateV4 MapStats
	RateStateV6 MapStats
	RuleHits    MapStats
}

// Stats samples every managed map and returns the counts. Iteration
// runs against the kernel map (not against cached userspace state) so
// drift between syncer bookkeeping and the actual kernel table is
// caught. Intended for Prometheus scrape cadence (~15s) — don't call
// on the packet hot path.
func (l *RulesLoader) Stats() (LoaderStats, error) {
	if l == nil || l.coll == nil {
		return LoaderStats{}, errors.New("loader not initialised")
	}
	pairs := []struct {
		m   *ebpf.Map
		out *MapStats
	}{
		{l.meta, nil},
		{l.srcV4, nil},
		{l.srcV6, nil},
		{l.dstV4, nil},
		{l.dstV6, nil},
		{l.rateV4, nil},
		{l.rateV6, nil},
		{l.ruleHits, nil},
	}
	var out LoaderStats
	pairs[0].out = &out.RuleMeta
	pairs[1].out = &out.RuleSrcV4
	pairs[2].out = &out.RuleSrcV6
	pairs[3].out = &out.RuleDstV4
	pairs[4].out = &out.RuleDstV6
	pairs[5].out = &out.RateStateV4
	pairs[6].out = &out.RateStateV6
	pairs[7].out = &out.RuleHits
	for i, p := range pairs {
		s, err := mapStats(p.m)
		if err != nil {
			return LoaderStats{}, fmt.Errorf("stats[%d]: %w", i, err)
		}
		*p.out = s
	}
	return out, nil
}

// mapStats walks keys only (via NextKey) and returns (entries, cap).
// Values are intentionally not fetched — we only care about
// cardinality, and skipping the Lookup sidesteps the per-CPU value
// marshaling rules. Works uniformly across HASH, LPM_TRIE, and
// PERCPU_HASH.
func mapStats(m *ebpf.Map) (MapStats, error) {
	if m == nil {
		return MapStats{}, nil
	}
	info, err := m.Info()
	if err != nil {
		return MapStats{}, fmt.Errorf("map info: %w", err)
	}
	cur := make([]byte, info.KeySize)
	nxt := make([]byte, info.KeySize)
	var count uint32
	// First call with nil asks the kernel for the first key.
	err = m.NextKey(nil, &nxt)
	for err == nil {
		count++
		cur, nxt = nxt, cur
		err = m.NextKey(cur, &nxt)
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return MapStats{Entries: count, MaxEntries: info.MaxEntries}, nil
	}
	return MapStats{}, fmt.Errorf("next key: %w", err)
}

// Program returns the loaded program with the given SEC() name. The
// second value is false when the name is not in the collection — which
// is the normal state for tests that build a maps-only spec. Callers
// attach the returned *ebpf.Program via link.AttachXDP (for
// ProgramXDPRules) or the tc/tcx helpers (for ProgramTCRulesWg0).
//
// The program remains owned by the loader; do not Close it directly.
// Closing the returned link is the caller's responsibility.
func (l *RulesLoader) Program(name string) (*ebpf.Program, bool) {
	if l == nil || l.coll == nil {
		return nil, false
	}
	p, ok := l.coll.Programs[name]
	return p, ok
}

// PutRuleMeta writes (or overwrites) the meta entry for a rule. The
// key is the rule_id — the same value stored in the src/dst LPM maps
// so the XDP program can correlate a hit back to a meta row.
func (l *RulesLoader) PutRuleMeta(ruleID uint32, meta RuleMeta) error {
	return l.meta.Update(ruleID, meta, ebpf.UpdateAny)
}

// GetRuleMeta reads the meta entry for a rule. Used by the reconciler
// to drift-check DB state against kernel state.
func (l *RulesLoader) GetRuleMeta(ruleID uint32) (RuleMeta, bool, error) {
	var m RuleMeta
	if err := l.meta.Lookup(ruleID, &m); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return RuleMeta{}, false, nil
		}
		return RuleMeta{}, false, err
	}
	return m, true, nil
}

// DeleteRuleMeta removes the meta entry for a rule. Deleting a
// non-existent key returns nil — the end state matches intent.
func (l *RulesLoader) DeleteRuleMeta(ruleID uint32) error {
	return dropENOENT(l.meta.Delete(ruleID))
}

// PutSrcPrefix adds (prefix → ruleID) to the appropriate src LPM map.
// Re-adding an existing prefix overwrites the ruleID (BPF_ANY). This
// matches the "DB is source of truth, maps converge" invariant.
func (l *RulesLoader) PutSrcPrefix(p netip.Prefix, ruleID uint32) error {
	return l.putPrefix(p, ruleID, l.srcV4, l.srcV6)
}

// DeleteSrcPrefix removes a prefix from the src LPM map.
func (l *RulesLoader) DeleteSrcPrefix(p netip.Prefix) error {
	return l.deletePrefix(p, l.srcV4, l.srcV6)
}

// PutDstPrefix / DeleteDstPrefix: same contract, dst maps.
func (l *RulesLoader) PutDstPrefix(p netip.Prefix, ruleID uint32) error {
	return l.putPrefix(p, ruleID, l.dstV4, l.dstV6)
}

func (l *RulesLoader) DeleteDstPrefix(p netip.Prefix) error {
	return l.deletePrefix(p, l.dstV4, l.dstV6)
}

// PutSrcAddr is the /32 or /128 shortcut for per-peer bindings: the
// peer's assigned IP gets added as a host prefix pointing at ruleID.
func (l *RulesLoader) PutSrcAddr(a netip.Addr, ruleID uint32) error {
	return l.PutSrcPrefix(netip.PrefixFrom(a, a.BitLen()), ruleID)
}

func (l *RulesLoader) DeleteSrcAddr(a netip.Addr) error {
	return l.DeleteSrcPrefix(netip.PrefixFrom(a, a.BitLen()))
}

func (l *RulesLoader) putPrefix(p netip.Prefix, ruleID uint32, v4, v6 *ebpf.Map) error {
	if p.Addr().Is4() {
		k, err := prefixToLPMv4(p)
		if err != nil {
			return err
		}
		return v4.Update(k, ruleID, ebpf.UpdateAny)
	}
	k, err := prefixToLPMv6(p)
	if err != nil {
		return err
	}
	return v6.Update(k, ruleID, ebpf.UpdateAny)
}

func (l *RulesLoader) deletePrefix(p netip.Prefix, v4, v6 *ebpf.Map) error {
	if p.Addr().Is4() {
		k, err := prefixToLPMv4(p)
		if err != nil {
			return err
		}
		return dropENOENT(v4.Delete(k))
	}
	k, err := prefixToLPMv6(p)
	if err != nil {
		return err
	}
	return dropENOENT(v6.Delete(k))
}

func dropENOENT(err error) error {
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// LookupSrcAddr returns the rule_id that a packet from addr would
// hit via the src LPM map, honouring the longest-prefix-match the
// kernel would perform. Returns (0, false, nil) when no prefix in
// the trie covers the address. Used by tests and the reconciler's
// drift-check path — never on the packet-processing hot path.
func (l *RulesLoader) LookupSrcAddr(addr netip.Addr) (uint32, bool, error) {
	return l.lookupAddr(addr, l.srcV4, l.srcV6)
}

// LookupDstAddr mirrors LookupSrcAddr but reads the dst LPM maps.
func (l *RulesLoader) LookupDstAddr(addr netip.Addr) (uint32, bool, error) {
	return l.lookupAddr(addr, l.dstV4, l.dstV6)
}

func (l *RulesLoader) lookupAddr(addr netip.Addr, v4, v6 *ebpf.Map) (uint32, bool, error) {
	var rid uint32
	if addr.Is4() {
		k, err := addrToLPMv4(addr)
		if err != nil {
			return 0, false, err
		}
		if err := v4.Lookup(k, &rid); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return 0, false, nil
			}
			return 0, false, err
		}
		return rid, true, nil
	}
	k, err := addrToLPMv6(addr)
	if err != nil {
		return 0, false, err
	}
	if err := v6.Lookup(k, &rid); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return rid, true, nil
}

// ResetRateV4 clears the token bucket for (ruleID, addr) so the next
// packet starts from a fresh state. Used by the reconciler when a
// rule's pps/burst changes and by operator tools that want to lift a
// throttle without waiting for natural refill. Deleting a non-existent
// bucket returns nil (BPF's ENOENT is folded to nil by dropENOENT).
func (l *RulesLoader) ResetRateV4(ruleID uint32, addr netip.Addr) error {
	k, err := newRateKeyV4(ruleID, addr)
	if err != nil {
		return err
	}
	return dropENOENT(l.rateV4.Delete(k))
}

// ResetRateV6 is the v6 counterpart of ResetRateV4.
func (l *RulesLoader) ResetRateV6(ruleID uint32, addr netip.Addr) error {
	k, err := newRateKeyV6(ruleID, addr)
	if err != nil {
		return err
	}
	return dropENOENT(l.rateV6.Delete(k))
}

// PeekRateV4 returns the token bucket for (ruleID, addr) summed across
// all CPUs. PERCPU_HASH reads produce one copy per CPU; summing is the
// right reduction for tokens (total available) but wrong for
// LastSeenNs — we take the max (most recent) instead. Returns
// (zero-value, false, nil) when no bucket exists.
func (l *RulesLoader) PeekRateV4(ruleID uint32, addr netip.Addr) (RateTokens, bool, error) {
	k, err := newRateKeyV4(ruleID, addr)
	if err != nil {
		return RateTokens{}, false, err
	}
	return peekRate(l.rateV4, k)
}

// PeekRateV6 is the v6 counterpart of PeekRateV4.
func (l *RulesLoader) PeekRateV6(ruleID uint32, addr netip.Addr) (RateTokens, bool, error) {
	k, err := newRateKeyV6(ruleID, addr)
	if err != nil {
		return RateTokens{}, false, err
	}
	return peekRate(l.rateV6, k)
}

// PeekRuleHits returns the cumulative (packets, bytes) counter for a
// rule, summed across CPUs. Returns (zero, false, nil) when the rule
// has never fired (no bucket yet) or when the spec omits the
// rule_hits map (tests). The map is PERCPU_HASH so the single read
// translates into NumCPU() separate memory locations; cost is fine
// for API / metric scrape cadences, not for the packet hot path.
func (l *RulesLoader) PeekRuleHits(ruleID uint32) (RuleHits, bool, error) {
	if l == nil || l.ruleHits == nil {
		return RuleHits{}, false, nil
	}
	var perCPU []RuleHits
	if err := l.ruleHits.Lookup(ruleID, &perCPU); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return RuleHits{}, false, nil
		}
		return RuleHits{}, false, err
	}
	var sum RuleHits
	for _, h := range perCPU {
		sum.Packets += h.Packets
		sum.Bytes += h.Bytes
	}
	return sum, true, nil
}

// ResetRuleHits clears the counter for a rule. Used by the reconciler
// when a rule is removed and by operator tools that want to zero a
// counter without waiting for a restart. Deleting a non-existent key
// returns nil (BPF's ENOENT is folded via dropENOENT). No-op when the
// spec omits the counter map.
func (l *RulesLoader) ResetRuleHits(ruleID uint32) error {
	if l == nil || l.ruleHits == nil {
		return nil
	}
	return dropENOENT(l.ruleHits.Delete(ruleID))
}

func peekRate(m *ebpf.Map, key any) (RateTokens, bool, error) {
	var perCPU []RateTokens
	if err := m.Lookup(key, &perCPU); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return RateTokens{}, false, nil
		}
		return RateTokens{}, false, err
	}
	var sum RateTokens
	for _, t := range perCPU {
		sum.TokensX1000 += t.TokensX1000
		if t.LastSeenNs > sum.LastSeenNs {
			sum.LastSeenNs = t.LastSeenNs
		}
	}
	return sum, true, nil
}

func newRateKeyV4(ruleID uint32, addr netip.Addr) (rateKeyV4, error) {
	if !addr.Is4() {
		return rateKeyV4{}, fmt.Errorf("expected IPv4 addr, got %s", addr)
	}
	return rateKeyV4{RuleID: ruleID, Addr: addr.As4()}, nil
}

func newRateKeyV6(ruleID uint32, addr netip.Addr) (rateKeyV6, error) {
	if !addr.Is6() || addr.Is4In6() {
		return rateKeyV6{}, fmt.Errorf("expected IPv6 addr, got %s", addr)
	}
	return rateKeyV6{RuleID: ruleID, Addr: addr.As16()}, nil
}
