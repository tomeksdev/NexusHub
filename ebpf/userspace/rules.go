// Package userspace provides the Go-side loader and map-manager for
// NexusHub's eBPF programs.
//
// v2.1 — per-packet iteration. The RulesLoader owns an ebpf.Collection
// built from rules.c, exposing typed CRUD for two packed arrays
// (rule_table_v4 / rule_table_v6) plus a one-slot count map per
// family. ADR 0005 has the design rationale.
//
// Program attach is a separate concern handled by callers via
// cilium/ebpf's link package — keeping it out of this type means the
// Loader is testable against maps only (no netns, no kernel interface
// state).
//
// The Loader is constructed from a *ebpf.CollectionSpec. In production,
// call the bpf2go-generated loader to get a spec embedded from the
// compiled .o; in tests, build a spec in-memory. This two-step
// separates "what the kernel will run" from "how we got the bytes".
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
	mapRuleTableV4 = "rule_table_v4"
	mapRuleCountV4 = "rule_count_v4"
	mapRuleTableV6 = "rule_table_v6"
	mapRuleCountV6 = "rule_count_v6"
	mapRateStateV4 = "rate_state_v4"
	mapRateStateV6 = "rate_state_v6"
	mapRuleHits    = "rule_hits"
	mapLogEvents   = "log_events"
)

// Program names in the compiled ELF. These match the SEC() function
// names in ebpf/src/rules.c.
const (
	ProgramXDPRules   = "xdp_rules"
	ProgramTCRulesWg0 = "tc_rules_wg0"
)

// Per-family active-rule caps. Must agree with MAX_ACTIVE_RULES_{V4,V6}
// in ebpf/headers/nexushub.h. The syncer rejects writes past these
// bounds with a clear error.
const (
	MaxActiveRulesV4 = 256
	MaxActiveRulesV6 = 256
)

// RuleV4Record mirrors struct rule_v4_record in ebpf/headers/nexushub.h.
// Field order + sizes are load-bearing: the kernel reads raw bytes.
//
// Address fields hold on-wire (network byte order) bytes — the same
// layout as iphdr->saddr/daddr — so the kernel can compare them
// directly without endian swaps.
type RuleV4Record struct {
	Action        uint8  // ACTION_{ALLOW,DENY,RATE_LIMIT,LOG}
	Protocol      uint8  // PROTO_{ANY,TCP,UDP,ICMP}
	Direction     uint8  // DIR_{INGRESS,EGRESS,BOTH}
	IsActive      uint8  // 0/1
	HasSrc        uint8  // 1 → gate on SrcAddr/SrcPrefixLen
	HasDst        uint8  // 1 → gate on DstAddr/DstPrefixLen
	HasProtocol   uint8  // 1 → Protocol != PROTO_ANY
	SrcPrefixLen  uint8  // 0..32 (bits)
	DstPrefixLen  uint8  // 0..32 (bits)
	RatePPS       uint32 // rate_limit configuration
	RateBurst     uint32
	SrcPortFrom   uint16
	SrcPortTo     uint16
	DstPortFrom   uint16
	DstPortTo     uint16
	Priority      uint16
	SrcAddr       [4]byte // network byte order
	DstAddr       [4]byte // network byte order
	RuleID        uint32  // stable id used as rule_hits key
}

// ruleV4RecordSize is the on-wire length of struct rule_v4_record
// including compiler padding. Layout (matches the C struct exactly):
//
//	u8 action|protocol|direction|is_active     = 4
//	u8 has_src|has_dst|has_protocol|src_pfx    = 4
//	u8 dst_pfx + u8[3] pad                     = 4
//	u32 rate_pps + u32 rate_burst              = 8
//	u16 src_port_from|to + u16 dst_port_from|to = 8
//	u16 priority + u16 _pad2                   = 4
//	u8[4] src_addr + u8[4] dst_addr            = 8
//	u32 rule_id                                = 4
//	                                       total = 44
const ruleV4RecordSize = 44

// MarshalBinary serializes RuleV4Record into the byte layout the kernel
// expects. Little-endian for the multi-byte scalars on both supported
// targets (amd64, arm64); address fields are copied verbatim because
// they carry network byte order already.
func (r RuleV4Record) MarshalBinary() ([]byte, error) {
	b := make([]byte, ruleV4RecordSize)
	b[0] = r.Action
	b[1] = r.Protocol
	b[2] = r.Direction
	b[3] = r.IsActive
	b[4] = r.HasSrc
	b[5] = r.HasDst
	b[6] = r.HasProtocol
	b[7] = r.SrcPrefixLen
	b[8] = r.DstPrefixLen
	// b[9:12] _pad zeroed by make()
	binary.LittleEndian.PutUint32(b[12:16], r.RatePPS)
	binary.LittleEndian.PutUint32(b[16:20], r.RateBurst)
	binary.LittleEndian.PutUint16(b[20:22], r.SrcPortFrom)
	binary.LittleEndian.PutUint16(b[22:24], r.SrcPortTo)
	binary.LittleEndian.PutUint16(b[24:26], r.DstPortFrom)
	binary.LittleEndian.PutUint16(b[26:28], r.DstPortTo)
	binary.LittleEndian.PutUint16(b[28:30], r.Priority)
	// b[30:32] _pad2 zeroed
	copy(b[32:36], r.SrcAddr[:])
	copy(b[36:40], r.DstAddr[:])
	binary.LittleEndian.PutUint32(b[40:44], r.RuleID)
	return b, nil
}

// UnmarshalBinary is the inverse of MarshalBinary.
func (r *RuleV4Record) UnmarshalBinary(b []byte) error {
	if len(b) != ruleV4RecordSize {
		return fmt.Errorf("rule_v4_record: expected %d bytes, got %d", ruleV4RecordSize, len(b))
	}
	r.Action = b[0]
	r.Protocol = b[1]
	r.Direction = b[2]
	r.IsActive = b[3]
	r.HasSrc = b[4]
	r.HasDst = b[5]
	r.HasProtocol = b[6]
	r.SrcPrefixLen = b[7]
	r.DstPrefixLen = b[8]
	r.RatePPS = binary.LittleEndian.Uint32(b[12:16])
	r.RateBurst = binary.LittleEndian.Uint32(b[16:20])
	r.SrcPortFrom = binary.LittleEndian.Uint16(b[20:22])
	r.SrcPortTo = binary.LittleEndian.Uint16(b[22:24])
	r.DstPortFrom = binary.LittleEndian.Uint16(b[24:26])
	r.DstPortTo = binary.LittleEndian.Uint16(b[26:28])
	r.Priority = binary.LittleEndian.Uint16(b[28:30])
	copy(r.SrcAddr[:], b[32:36])
	copy(r.DstAddr[:], b[36:40])
	r.RuleID = binary.LittleEndian.Uint32(b[40:44])
	return nil
}

// RuleV6Record mirrors struct rule_v6_record. IPv6 mirror of
// RuleV4Record; prefix_len fields range 0..128.
type RuleV6Record struct {
	Action        uint8
	Protocol      uint8
	Direction     uint8
	IsActive      uint8
	HasSrc        uint8
	HasDst        uint8
	HasProtocol   uint8
	SrcPrefixLen  uint8 // 0..128
	DstPrefixLen  uint8 // 0..128
	RatePPS       uint32
	RateBurst     uint32
	SrcPortFrom   uint16
	SrcPortTo     uint16
	DstPortFrom   uint16
	DstPortTo     uint16
	Priority      uint16
	SrcAddr       [16]byte // network byte order
	DstAddr       [16]byte // network byte order
	RuleID        uint32
}

// ruleV6RecordSize: 12 (header bytes) + 8 (rate) + 8 (ports) + 4 (priority+pad) + 32 (addrs) + 4 (rule_id) = 68.
const ruleV6RecordSize = 68

func (r RuleV6Record) MarshalBinary() ([]byte, error) {
	b := make([]byte, ruleV6RecordSize)
	b[0] = r.Action
	b[1] = r.Protocol
	b[2] = r.Direction
	b[3] = r.IsActive
	b[4] = r.HasSrc
	b[5] = r.HasDst
	b[6] = r.HasProtocol
	b[7] = r.SrcPrefixLen
	b[8] = r.DstPrefixLen
	// b[9:12] _pad zeroed
	binary.LittleEndian.PutUint32(b[12:16], r.RatePPS)
	binary.LittleEndian.PutUint32(b[16:20], r.RateBurst)
	binary.LittleEndian.PutUint16(b[20:22], r.SrcPortFrom)
	binary.LittleEndian.PutUint16(b[22:24], r.SrcPortTo)
	binary.LittleEndian.PutUint16(b[24:26], r.DstPortFrom)
	binary.LittleEndian.PutUint16(b[26:28], r.DstPortTo)
	binary.LittleEndian.PutUint16(b[28:30], r.Priority)
	// b[30:32] _pad2 zeroed
	copy(b[32:48], r.SrcAddr[:])
	copy(b[48:64], r.DstAddr[:])
	binary.LittleEndian.PutUint32(b[64:68], r.RuleID)
	return b, nil
}

func (r *RuleV6Record) UnmarshalBinary(b []byte) error {
	if len(b) != ruleV6RecordSize {
		return fmt.Errorf("rule_v6_record: expected %d bytes, got %d", ruleV6RecordSize, len(b))
	}
	r.Action = b[0]
	r.Protocol = b[1]
	r.Direction = b[2]
	r.IsActive = b[3]
	r.HasSrc = b[4]
	r.HasDst = b[5]
	r.HasProtocol = b[6]
	r.SrcPrefixLen = b[7]
	r.DstPrefixLen = b[8]
	r.RatePPS = binary.LittleEndian.Uint32(b[12:16])
	r.RateBurst = binary.LittleEndian.Uint32(b[16:20])
	r.SrcPortFrom = binary.LittleEndian.Uint16(b[20:22])
	r.SrcPortTo = binary.LittleEndian.Uint16(b[22:24])
	r.DstPortFrom = binary.LittleEndian.Uint16(b[24:26])
	r.DstPortTo = binary.LittleEndian.Uint16(b[26:28])
	r.Priority = binary.LittleEndian.Uint16(b[28:30])
	copy(r.SrcAddr[:], b[32:48])
	copy(r.DstAddr[:], b[48:64])
	r.RuleID = binary.LittleEndian.Uint32(b[64:68])
	return nil
}

// RateTokens mirrors struct rate_tokens in ebpf/headers/nexushub.h.
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

// rateKeyV4 mirrors struct rate_key_v4. addr is in network byte order.
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

// rateKeyV6 mirrors struct rate_key_v6: u32 rule_id + u8[16] addr.
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

// RuleHits mirrors struct rule_hits. PERCPU_HASH; PeekRuleHits sums.
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
// is optional: older test specs omit it.
type RulesLoader struct {
	coll *ebpf.Collection

	tableV4   *ebpf.Map
	countV4   *ebpf.Map
	tableV6   *ebpf.Map
	countV6   *ebpf.Map
	rateV4    *ebpf.Map
	rateV6    *ebpf.Map
	ruleHits  *ebpf.Map // nil if the spec omits the counter map (tests)
	logEvents *ebpf.Map // nil if the spec omits the ringbuf (tests)
}

// LoaderOptions controls how NewRulesLoaderWithOptions instantiates the
// underlying ebpf.Collection.
type LoaderOptions struct {
	// PinPath, when non-empty, pins every map in the spec under
	// <PinPath>/<map_name>. Empty disables pinning.
	PinPath string
}

// NewRulesLoader is equivalent to NewRulesLoaderWithOptions with a zero
// LoaderOptions. Tests use this shape because pinning requires bpffs.
func NewRulesLoader(spec *ebpf.CollectionSpec) (*RulesLoader, error) {
	return NewRulesLoaderWithOptions(spec, LoaderOptions{})
}

// NewRulesLoaderWithOptions builds the collection, pulls handles for
// every map the program declares, and returns a ready-to-use loader.
// The caller owns Close().
func NewRulesLoaderWithOptions(spec *ebpf.CollectionSpec, opts LoaderOptions) (*RulesLoader, error) {
	if spec == nil {
		return nil, errors.New("nil spec")
	}
	collOpts := ebpf.CollectionOptions{}
	if opts.PinPath != "" {
		for _, ms := range spec.Maps {
			ms.Pinning = ebpf.PinByName
		}
		collOpts.Maps.PinPath = opts.PinPath
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, collOpts)
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
	tableV4, err := pick(mapRuleTableV4)
	if err != nil {
		coll.Close()
		return nil, err
	}
	countV4, err := pick(mapRuleCountV4)
	if err != nil {
		coll.Close()
		return nil, err
	}
	tableV6, err := pick(mapRuleTableV6)
	if err != nil {
		coll.Close()
		return nil, err
	}
	countV6, err := pick(mapRuleCountV6)
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
	// may omit them.
	ruleHitsMap := coll.Maps[mapRuleHits]
	logEvents := coll.Maps[mapLogEvents]
	return &RulesLoader{
		coll: coll,
		tableV4: tableV4, countV4: countV4,
		tableV6: tableV6, countV6: countV6,
		rateV4:    rateV4,
		rateV6:    rateV6,
		ruleHits:  ruleHitsMap,
		logEvents: logEvents,
	}, nil
}

// Close releases every map and program in the underlying collection.
func (l *RulesLoader) Close() error {
	if l == nil || l.coll == nil {
		return nil
	}
	l.coll.Close()
	l.coll = nil
	return nil
}

// MapStats is a single-map operational snapshot.
type MapStats struct {
	Entries    uint32
	MaxEntries uint32
}

// LoaderStats gathers one MapStats per BPF map the loader owns.
//
// RuleTableV4/V6 report the number of *populated* slots — the
// loader's view of how many rules the syncer has installed, equal
// to the value in rule_count_v4/v6. ARRAY maps always have every
// slot "allocated" so NextKey iteration would just return the
// MaxEntries cap; the count map reading is what operators want.
type LoaderStats struct {
	RuleTableV4 MapStats
	RuleTableV6 MapStats
	RateStateV4 MapStats
	RateStateV6 MapStats
	RuleHits    MapStats
}

// Stats samples every managed map and returns the counts.
func (l *RulesLoader) Stats() (LoaderStats, error) {
	if l == nil || l.coll == nil {
		return LoaderStats{}, errors.New("loader not initialized")
	}
	var out LoaderStats

	// rule_table_v4/v6 are arrays — entries == rule_count_v[46][0],
	// capacity == MaxEntries from the spec.
	v4Count, err := l.readCount(l.countV4)
	if err != nil {
		return LoaderStats{}, fmt.Errorf("read v4 count: %w", err)
	}
	v4Info, err := l.tableV4.Info()
	if err != nil {
		return LoaderStats{}, fmt.Errorf("v4 table info: %w", err)
	}
	out.RuleTableV4 = MapStats{Entries: v4Count, MaxEntries: v4Info.MaxEntries}

	v6Count, err := l.readCount(l.countV6)
	if err != nil {
		return LoaderStats{}, fmt.Errorf("read v6 count: %w", err)
	}
	v6Info, err := l.tableV6.Info()
	if err != nil {
		return LoaderStats{}, fmt.Errorf("v6 table info: %w", err)
	}
	out.RuleTableV6 = MapStats{Entries: v6Count, MaxEntries: v6Info.MaxEntries}

	rateV4Stats, err := mapStats(l.rateV4)
	if err != nil {
		return LoaderStats{}, fmt.Errorf("rate_v4 stats: %w", err)
	}
	out.RateStateV4 = rateV4Stats

	rateV6Stats, err := mapStats(l.rateV6)
	if err != nil {
		return LoaderStats{}, fmt.Errorf("rate_v6 stats: %w", err)
	}
	out.RateStateV6 = rateV6Stats

	hitsStats, err := mapStats(l.ruleHits)
	if err != nil {
		return LoaderStats{}, fmt.Errorf("rule_hits stats: %w", err)
	}
	out.RuleHits = hitsStats

	return out, nil
}

// readCount reads slot 0 of an ARRAY[1] of u32. Returns 0 if the
// map handle is nil.
func (l *RulesLoader) readCount(m *ebpf.Map) (uint32, error) {
	if m == nil {
		return 0, nil
	}
	var key uint32
	var val uint32
	if err := m.Lookup(key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, err
	}
	return val, nil
}

// mapStats walks keys only (via NextKey) and returns (entries, cap).
// Used for PERCPU_HASH maps where cardinality is meaningful; ARRAY
// maps use readCount + MaxEntries instead.
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

// Program returns the loaded program with the given SEC() name.
func (l *RulesLoader) Program(name string) (*ebpf.Program, bool) {
	if l == nil || l.coll == nil {
		return nil, false
	}
	p, ok := l.coll.Programs[name]
	return p, ok
}

// PutRuleV4 writes (or overwrites) a record at slot in rule_table_v4.
// The caller is responsible for slot allocation and for setting
// rule_count_v4 via SetRuleCountV4 once all writes are done.
func (l *RulesLoader) PutRuleV4(slot uint32, r RuleV4Record) error {
	if slot >= MaxActiveRulesV4 {
		return fmt.Errorf("v4 slot %d out of range [0, %d)", slot, MaxActiveRulesV4)
	}
	return l.tableV4.Update(slot, r, ebpf.UpdateAny)
}

// GetRuleV4 reads back a record at slot in rule_table_v4. Used by the
// reconciler to drift-check syncer state against the kernel.
func (l *RulesLoader) GetRuleV4(slot uint32) (RuleV4Record, error) {
	var r RuleV4Record
	if err := l.tableV4.Lookup(slot, &r); err != nil {
		return RuleV4Record{}, err
	}
	return r, nil
}

// ClearRuleV4 writes a zero-valued record into slot. ARRAY maps don't
// support Delete; "removal" is overwrite-with-inactive. Slots past
// rule_count_v4 are never iterated, but we still clear them so a
// stale rule_id never appears in count_hit telemetry.
func (l *RulesLoader) ClearRuleV4(slot uint32) error {
	if slot >= MaxActiveRulesV4 {
		return nil
	}
	return l.tableV4.Update(slot, RuleV4Record{}, ebpf.UpdateAny)
}

// SetRuleCountV4 publishes the new active-rule count. Write this LAST
// after all PutRuleV4 calls — bpf_loop iterates 0..count-1, so
// shrinking count is a safe atomic "remove the tail" operation, and
// growing count after every slot is populated avoids a transient state
// where the kernel reads an empty record.
func (l *RulesLoader) SetRuleCountV4(count uint32) error {
	if count > MaxActiveRulesV4 {
		return fmt.Errorf("v4 count %d exceeds max %d", count, MaxActiveRulesV4)
	}
	var key uint32
	return l.countV4.Update(key, count, ebpf.UpdateAny)
}

// PutRuleV6 / GetRuleV6 / ClearRuleV6 / SetRuleCountV6 are the IPv6
// mirrors of the v4 helpers.
func (l *RulesLoader) PutRuleV6(slot uint32, r RuleV6Record) error {
	if slot >= MaxActiveRulesV6 {
		return fmt.Errorf("v6 slot %d out of range [0, %d)", slot, MaxActiveRulesV6)
	}
	return l.tableV6.Update(slot, r, ebpf.UpdateAny)
}

func (l *RulesLoader) GetRuleV6(slot uint32) (RuleV6Record, error) {
	var r RuleV6Record
	if err := l.tableV6.Lookup(slot, &r); err != nil {
		return RuleV6Record{}, err
	}
	return r, nil
}

func (l *RulesLoader) ClearRuleV6(slot uint32) error {
	if slot >= MaxActiveRulesV6 {
		return nil
	}
	return l.tableV6.Update(slot, RuleV6Record{}, ebpf.UpdateAny)
}

func (l *RulesLoader) SetRuleCountV6(count uint32) error {
	if count > MaxActiveRulesV6 {
		return fmt.Errorf("v6 count %d exceeds max %d", count, MaxActiveRulesV6)
	}
	var key uint32
	return l.countV6.Update(key, count, ebpf.UpdateAny)
}

// RuleCountV4 / RuleCountV6 read the currently-published active count.
// Used by tests and the reconciler.
func (l *RulesLoader) RuleCountV4() (uint32, error) { return l.readCount(l.countV4) }
func (l *RulesLoader) RuleCountV6() (uint32, error) { return l.readCount(l.countV6) }

func dropENOENT(err error) error {
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// ResetRateV4 clears the token bucket for (ruleID, addr).
func (l *RulesLoader) ResetRateV4(ruleID uint32, addr netip.Addr) error {
	k, err := newRateKeyV4(ruleID, addr)
	if err != nil {
		return err
	}
	return dropENOENT(l.rateV4.Delete(k))
}

func (l *RulesLoader) ResetRateV6(ruleID uint32, addr netip.Addr) error {
	k, err := newRateKeyV6(ruleID, addr)
	if err != nil {
		return err
	}
	return dropENOENT(l.rateV6.Delete(k))
}

// PeekRateV4 returns the token bucket for (ruleID, addr) summed across
// CPUs.
func (l *RulesLoader) PeekRateV4(ruleID uint32, addr netip.Addr) (RateTokens, bool, error) {
	k, err := newRateKeyV4(ruleID, addr)
	if err != nil {
		return RateTokens{}, false, err
	}
	return peekRate(l.rateV4, k)
}

func (l *RulesLoader) PeekRateV6(ruleID uint32, addr netip.Addr) (RateTokens, bool, error) {
	k, err := newRateKeyV6(ruleID, addr)
	if err != nil {
		return RateTokens{}, false, err
	}
	return peekRate(l.rateV6, k)
}

// PeekRuleHits returns the cumulative (packets, bytes) counter for a
// rule, summed across CPUs. Returns (zero, false, nil) when the rule
// has never fired or when the spec omits the rule_hits map (tests).
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

// ResetRuleHits clears the counter for a rule.
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
