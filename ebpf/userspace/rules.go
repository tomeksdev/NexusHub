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
	mapRuleMeta  = "rule_meta"
	mapRuleSrcV4 = "rule_src_v4"
	mapRuleSrcV6 = "rule_src_v6"
	mapRuleDstV4 = "rule_dst_v4"
	mapRuleDstV6 = "rule_dst_v6"
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

// RulesLoader manages the five maps of the XDP rule runtime. Every
// operation is a single map-write — the XDP program picks up changes
// on the next packet without reload.
type RulesLoader struct {
	coll *ebpf.Collection

	meta  *ebpf.Map
	srcV4 *ebpf.Map
	srcV6 *ebpf.Map
	dstV4 *ebpf.Map
	dstV6 *ebpf.Map
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
	return &RulesLoader{
		coll: coll, meta: meta,
		srcV4: srcV4, srcV6: srcV6,
		dstV4: dstV4, dstV6: dstV6,
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
