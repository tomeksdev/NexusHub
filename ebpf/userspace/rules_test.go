package userspace

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// buildTestSpec returns a minimal CollectionSpec that mimics what
// bpf2go emits for rules.c after the v2.1 rewrite: two BPF_MAP_TYPE_ARRAY
// rule tables, two BPF_MAP_TYPE_ARRAY single-slot counters, two
// PERCPU_HASH rate-state maps, and one PERCPU_HASH counter. No
// programs — kernel-attach is exercised against the real .o
// elsewhere; this fixture is for loader unit tests.
func buildTestSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			mapRuleTableV4: {
				Name:       mapRuleTableV4,
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  ruleV4RecordSize,
				MaxEntries: MaxActiveRulesV4,
			},
			mapRuleCountV4: {
				Name:       mapRuleCountV4,
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
			mapRuleTableV6: {
				Name:       mapRuleTableV6,
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  ruleV6RecordSize,
				MaxEntries: MaxActiveRulesV6,
			},
			mapRuleCountV6: {
				Name:       mapRuleCountV6,
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
			mapRateStateV4: {
				Name:       mapRateStateV4,
				Type:       ebpf.PerCPUHash,
				KeySize:    rateKeyV4Size,
				ValueSize:  rateTokensSize,
				MaxEntries: 1024,
			},
			mapRateStateV6: {
				Name:       mapRateStateV6,
				Type:       ebpf.PerCPUHash,
				KeySize:    rateKeyV6Size,
				ValueSize:  rateTokensSize,
				MaxEntries: 1024,
			},
			mapRuleHits: {
				Name:       mapRuleHits,
				Type:       ebpf.PerCPUHash,
				KeySize:    4,
				ValueSize:  ruleHitsSize,
				MaxEntries: 1024,
			},
		},
	}
}

// requireBPF skips the test if the kernel denies map creation.
func requireBPF(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("rlimit memlock: %v (run as root or in a kernel-capable runner)", err)
	}
}

func TestRulesLoaderPutGetClearV4(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	want := RuleV4Record{
		Action: 1 /*DENY*/, Protocol: 1 /*TCP*/, Direction: 0, IsActive: 1,
		HasSrc: 1, SrcPrefixLen: 24, SrcAddr: [4]byte{198, 51, 100, 0},
		HasDst: 1, DstPrefixLen: 32, DstAddr: [4]byte{203, 0, 113, 5},
		SrcPortFrom: 1024, SrcPortTo: 65535,
		DstPortFrom: 443, DstPortTo: 443,
		Priority: 100,
		RuleID:   7,
	}
	if err := l.PutRuleV4(0, want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := l.GetRuleV4(0)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", got, want)
	}

	if err := l.ClearRuleV4(0); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got, err = l.GetRuleV4(0)
	if err != nil {
		t.Fatalf("get after clear: %v", err)
	}
	if got != (RuleV4Record{}) {
		t.Errorf("slot not zero after clear: %+v", got)
	}
}

func TestRulesLoaderPutRuleV4OutOfRange(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	if err := l.PutRuleV4(MaxActiveRulesV4, RuleV4Record{}); err == nil {
		t.Error("expected out-of-range error")
	}
}

func TestRulesLoaderSetAndReadCountV4(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	// Uninitialized: array index 0 reads as zero per BPF semantics.
	c, err := l.RuleCountV4()
	if err != nil {
		t.Fatalf("read count: %v", err)
	}
	if c != 0 {
		t.Errorf("initial count: got %d want 0", c)
	}

	if err := l.SetRuleCountV4(42); err != nil {
		t.Fatalf("set: %v", err)
	}
	c, err = l.RuleCountV4()
	if err != nil {
		t.Fatalf("read count: %v", err)
	}
	if c != 42 {
		t.Errorf("count: got %d want 42", c)
	}

	if err := l.SetRuleCountV4(MaxActiveRulesV4 + 1); err == nil {
		t.Error("expected overflow error")
	}
}

func TestRulesLoaderPutGetClearV6(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	want := RuleV6Record{
		Action: 1, Protocol: 1, IsActive: 1,
		HasSrc: 1, SrcPrefixLen: 64,
		HasDst:   0,
		Priority: 99,
		RuleID:   55,
	}
	for i := 0; i < 8; i++ {
		want.SrcAddr[i] = byte(0x20 + i)
	}
	if err := l.PutRuleV6(3, want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := l.GetRuleV6(3)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", got, want)
	}

	if err := l.ClearRuleV6(3); err != nil {
		t.Fatalf("clear: %v", err)
	}
}

func TestRuleV4RecordMarshalRoundTrip(t *testing.T) {
	orig := RuleV4Record{
		Action: 2, Protocol: 1, Direction: 2, IsActive: 1,
		HasSrc: 1, HasDst: 1, HasProtocol: 1,
		SrcPrefixLen: 24, DstPrefixLen: 32,
		SrcPortFrom: 100, SrcPortTo: 200,
		DstPortFrom: 300, DstPortTo: 400,
		Priority: 500, RatePPS: 1000, RateBurst: 2000,
		SrcAddr: [4]byte{10, 0, 0, 0},
		DstAddr: [4]byte{192, 168, 1, 1},
		RuleID:  0xCAFEBABE,
	}
	b, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != ruleV4RecordSize {
		t.Fatalf("len: got %d, want %d", len(b), ruleV4RecordSize)
	}
	var back RuleV4Record
	if err := back.UnmarshalBinary(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != orig {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", back, orig)
	}
}

func TestRuleV4RecordUnmarshalRejectsWrongLength(t *testing.T) {
	var r RuleV4Record
	if err := r.UnmarshalBinary(make([]byte, ruleV4RecordSize-1)); err == nil {
		t.Error("expected error on short buffer")
	}
}

// TestRuleV4RecordOnWireLayout pins the byte offsets the kernel reads
// from. A future struct-field reorder would silently break enforcement
// without any compile-time error; this test fails first.
func TestRuleV4RecordOnWireLayout(t *testing.T) {
	r := RuleV4Record{
		Action:       0x01,
		Protocol:     0x02,
		Direction:    0x03,
		IsActive:     0x04,
		HasSrc:       0x05,
		HasDst:       0x06,
		HasProtocol:  0x07,
		SrcPrefixLen: 24,
		DstPrefixLen: 16,
		RatePPS:      0xAABBCCDD,
		RateBurst:    0x11223344,
		SrcPortFrom:  0x1111,
		SrcPortTo:    0x2222,
		DstPortFrom:  0x3333,
		DstPortTo:    0x4444,
		Priority:     0x5555,
		SrcAddr:      [4]byte{0xC0, 0xA8, 0x01, 0x01},
		DstAddr:      [4]byte{0x0A, 0x00, 0x00, 0x02},
		RuleID:       0xDEADBEEF,
	}
	b, err := r.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checks := []struct {
		off int
		got byte
		w   byte
	}{
		{0, b[0], 0x01},                      // action
		{1, b[1], 0x02},                      // protocol
		{2, b[2], 0x03},                      // direction
		{3, b[3], 0x04},                      // is_active
		{4, b[4], 0x05},                      // has_src
		{5, b[5], 0x06},                      // has_dst
		{6, b[6], 0x07},                      // has_protocol
		{7, b[7], 24},                        // src_prefix_len
		{8, b[8], 16},                        // dst_prefix_len
		{12, b[12], 0xDD}, {15, b[15], 0xAA}, // rate_pps LE
		{16, b[16], 0x44}, {19, b[19], 0x11}, // rate_burst LE
		{32, b[32], 0xC0}, {35, b[35], 0x01}, // src_addr on-wire
		{36, b[36], 0x0A}, {39, b[39], 0x02}, // dst_addr on-wire
		{40, b[40], 0xEF}, {43, b[43], 0xDE}, // rule_id LE
	}
	for _, c := range checks {
		if c.got != c.w {
			t.Errorf("offset %d: got 0x%02x want 0x%02x", c.off, c.got, c.w)
		}
	}
}

func TestRuleV6RecordMarshalRoundTrip(t *testing.T) {
	orig := RuleV6Record{
		Action: 1, Protocol: 2, Direction: 1, IsActive: 1,
		HasSrc: 1, HasDst: 1, HasProtocol: 1,
		SrcPrefixLen: 64, DstPrefixLen: 128,
		SrcPortFrom: 1, SrcPortTo: 2, DstPortFrom: 3, DstPortTo: 4,
		Priority: 7, RatePPS: 11, RateBurst: 22,
		RuleID: 0x01020304,
	}
	for i := 0; i < 16; i++ {
		orig.SrcAddr[i] = byte(0x10 + i)
		orig.DstAddr[i] = byte(0x40 + i)
	}
	b, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != ruleV6RecordSize {
		t.Fatalf("len: got %d, want %d", len(b), ruleV6RecordSize)
	}
	var back RuleV6Record
	if err := back.UnmarshalBinary(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != orig {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", back, orig)
	}
}

func TestRuleV6RecordUnmarshalRejectsWrongLength(t *testing.T) {
	var r RuleV6Record
	if err := r.UnmarshalBinary(make([]byte, ruleV6RecordSize-1)); err == nil {
		t.Error("expected error on short buffer")
	}
}

func TestNewRulesLoaderRejectsNilSpec(t *testing.T) {
	if _, err := NewRulesLoader(nil); err == nil {
		t.Error("expected error on nil spec")
	}
}

func TestNewRulesLoaderRejectsMissingMap(t *testing.T) {
	requireBPF(t)
	spec := buildTestSpec(t)
	delete(spec.Maps, mapRuleTableV4)
	if _, err := NewRulesLoader(spec); err == nil {
		t.Error("expected error when rule_table_v4 map missing")
	}
}

func TestRateTokensMarshalRoundTrip(t *testing.T) {
	orig := RateTokens{TokensX1000: 0xDEADBEEF_CAFEBABE, LastSeenNs: 0x0102030405060708}
	b, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != rateTokensSize {
		t.Fatalf("len: got %d, want %d", len(b), rateTokensSize)
	}
	var back RateTokens
	if err := back.UnmarshalBinary(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != orig {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", back, orig)
	}
}

func TestRulesLoaderPeekRateV4MissingReturnsFalse(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	_, ok, err := l.PeekRateV4(42, netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if ok {
		t.Error("expected miss for untouched bucket")
	}
}

func TestRulesLoaderResetRateV4MissingIsNoop(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	if err := l.ResetRateV4(999, netip.MustParseAddr("10.0.0.2")); err != nil {
		t.Errorf("reset of missing bucket should be nil, got %v", err)
	}
}

func TestRulesLoaderRateV4SeedAndSumAcrossCPUs(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	addr := netip.MustParseAddr("203.0.113.5")
	key, err := newRateKeyV4(7, addr)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("cpu count: %v", err)
	}
	seed := make([]RateTokens, cpus)
	for i := range seed {
		seed[i] = RateTokens{TokensX1000: 500, LastSeenNs: 1000}
	}
	if err := l.rateV4.Update(key, seed, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, ok, err := l.PeekRateV4(7, addr)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !ok {
		t.Fatal("peek missed seeded bucket")
	}
	if want := uint64(500) * uint64(cpus); got.TokensX1000 != want {
		t.Errorf("summed tokens: got %d, want %d (cpus=%d)", got.TokensX1000, want, cpus)
	}
	if got.LastSeenNs != 1000 {
		t.Errorf("max last_seen_ns: got %d, want 1000", got.LastSeenNs)
	}

	if err := l.ResetRateV4(7, addr); err != nil {
		t.Fatalf("reset: %v", err)
	}
	_, ok, err = l.PeekRateV4(7, addr)
	if err != nil {
		t.Fatalf("peek after reset: %v", err)
	}
	if ok {
		t.Error("bucket should be gone after reset")
	}
}

func TestRateKeyV4RejectsIPv6(t *testing.T) {
	_, err := newRateKeyV4(1, netip.MustParseAddr("2001:db8::1"))
	if err == nil {
		t.Error("expected error on IPv6 address")
	}
}

func TestRateKeyV6RejectsIPv4(t *testing.T) {
	_, err := newRateKeyV6(1, netip.MustParseAddr("10.0.0.1"))
	if err == nil {
		t.Error("expected error on IPv4 address")
	}
}

func TestRateKeyV6MarshalLayout(t *testing.T) {
	k := rateKeyV6{RuleID: 0x01020304}
	for i := range k.Addr {
		k.Addr[i] = byte(0x10 + i)
	}
	b, err := k.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != rateKeyV6Size {
		t.Fatalf("length = %d, want %d", len(b), rateKeyV6Size)
	}
	want := []byte{
		0x04, 0x03, 0x02, 0x01,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	for i, w := range want {
		if b[i] != w {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x", i, b[i], w)
		}
	}
}

func TestRulesLoaderStatsReflectsSeededMaps(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	// Empty loader: tables have MaxEntries=256, count=0; rate/hits empty.
	s, err := l.Stats()
	if err != nil {
		t.Fatalf("stats empty: %v", err)
	}
	if s.RuleTableV4.Entries != 0 || s.RuleTableV4.MaxEntries != MaxActiveRulesV4 {
		t.Errorf("empty RuleTableV4: got %+v", s.RuleTableV4)
	}
	if s.RuleTableV6.Entries != 0 || s.RuleTableV6.MaxEntries != MaxActiveRulesV6 {
		t.Errorf("empty RuleTableV6: got %+v", s.RuleTableV6)
	}

	// Seed 3 v4 slots + 1 v6 slot.
	if err := l.PutRuleV4(0, RuleV4Record{IsActive: 1, RuleID: 1}); err != nil {
		t.Fatal(err)
	}
	if err := l.PutRuleV4(1, RuleV4Record{IsActive: 1, RuleID: 2}); err != nil {
		t.Fatal(err)
	}
	if err := l.PutRuleV4(2, RuleV4Record{IsActive: 1, RuleID: 3}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetRuleCountV4(3); err != nil {
		t.Fatal(err)
	}
	if err := l.PutRuleV6(0, RuleV6Record{IsActive: 1, RuleID: 10}); err != nil {
		t.Fatal(err)
	}
	if err := l.SetRuleCountV6(1); err != nil {
		t.Fatal(err)
	}

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("cpu count: %v", err)
	}
	seed := make([]RateTokens, cpus)
	kv4, _ := newRateKeyV4(1, netip.MustParseAddr("10.0.0.1"))
	if err := l.rateV4.Update(kv4, seed, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed v4 rate: %v", err)
	}
	hitsSeed := make([]RuleHits, cpus)
	hitsSeed[0] = RuleHits{Packets: 1, Bytes: 100}
	if err := l.ruleHits.Update(uint32(1), hitsSeed, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed rule_hits: %v", err)
	}

	s, err = l.Stats()
	if err != nil {
		t.Fatalf("stats seeded: %v", err)
	}
	if s.RuleTableV4.Entries != 3 {
		t.Errorf("RuleTableV4 entries = %d, want 3", s.RuleTableV4.Entries)
	}
	if s.RuleTableV6.Entries != 1 {
		t.Errorf("RuleTableV6 entries = %d, want 1", s.RuleTableV6.Entries)
	}
	if s.RateStateV4.Entries != 1 {
		t.Errorf("RateStateV4 entries = %d, want 1", s.RateStateV4.Entries)
	}
	if s.RuleHits.Entries != 1 {
		t.Errorf("RuleHits entries = %d, want 1", s.RuleHits.Entries)
	}
}

func TestRuleHitsMarshalRoundTrip(t *testing.T) {
	h := RuleHits{Packets: 0xdeadbeef, Bytes: 0xcafebabe00112233}
	b, err := h.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != ruleHitsSize {
		t.Fatalf("size: got %d want %d", len(b), ruleHitsSize)
	}
	var back RuleHits
	if err := back.UnmarshalBinary(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != h {
		t.Fatalf("roundtrip: got %+v want %+v", back, h)
	}
}

func TestRulesLoaderPeekRuleHitsAbsentIsZeroNotError(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	got, ok, err := l.PeekRuleHits(42)
	if err != nil {
		t.Fatalf("peek absent: %v", err)
	}
	if ok {
		t.Fatalf("ok should be false for never-hit rule")
	}
	if got != (RuleHits{}) {
		t.Fatalf("expected zero RuleHits, got %+v", got)
	}
}

func TestRulesLoaderPeekRuleHitsSumsAcrossCPUs(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("cpu count: %v", err)
	}
	seed := make([]RuleHits, cpus)
	var wantP, wantB uint64
	for i := range seed {
		seed[i] = RuleHits{Packets: uint64(i + 1), Bytes: uint64((i + 1) * 100)}
		wantP += seed[i].Packets
		wantB += seed[i].Bytes
	}
	if err := l.ruleHits.Update(uint32(7), seed, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, ok, err := l.PeekRuleHits(7)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !ok {
		t.Fatalf("ok should be true after seed")
	}
	if got.Packets != wantP {
		t.Errorf("Packets: got %d want %d", got.Packets, wantP)
	}
	if got.Bytes != wantB {
		t.Errorf("Bytes: got %d want %d", got.Bytes, wantB)
	}

	if err := l.ResetRuleHits(7); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, ok, _ := l.PeekRuleHits(7); ok {
		t.Fatalf("counter should be gone after ResetRuleHits")
	}
}

func TestRulesLoaderResetRuleHitsMissingIsNoop(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	if err := l.ResetRuleHits(999); err != nil {
		t.Errorf("reset of missing counter should be nil, got %v", err)
	}
}

func TestRulesLoaderResetRateV6MissingIsNoop(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	if err := l.ResetRateV6(999, netip.MustParseAddr("2001:db8::2")); err != nil {
		t.Errorf("reset of missing bucket should be nil, got %v", err)
	}
}

func TestRulesLoaderRateV6SeedAndSumAcrossCPUs(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	addr := netip.MustParseAddr("2001:db8::5")
	key, err := newRateKeyV6(7, addr)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("cpu count: %v", err)
	}
	seed := make([]RateTokens, cpus)
	for i := range seed {
		seed[i] = RateTokens{TokensX1000: 500, LastSeenNs: 1000}
	}
	if err := l.rateV6.Update(key, seed, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, ok, err := l.PeekRateV6(7, addr)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if !ok {
		t.Fatal("peek missed seeded bucket")
	}
	if want := uint64(500) * uint64(cpus); got.TokensX1000 != want {
		t.Errorf("summed tokens: got %d, want %d (cpus=%d)", got.TokensX1000, want, cpus)
	}
	if got.LastSeenNs != 1000 {
		t.Errorf("max last_seen_ns: got %d, want 1000", got.LastSeenNs)
	}

	if err := l.ResetRateV6(7, addr); err != nil {
		t.Fatalf("reset: %v", err)
	}
	_, ok, err = l.PeekRateV6(7, addr)
	if err != nil {
		t.Fatalf("peek after reset: %v", err)
	}
	if ok {
		t.Error("bucket should be gone after reset")
	}
}

func TestRulesLoaderProgramAccessor(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	if p, ok := l.Program(ProgramXDPRules); ok || p != nil {
		t.Errorf("XDP prog in maps-only spec: got (%v, %v), want (nil, false)", p, ok)
	}
	if p, ok := l.Program(ProgramTCRulesWg0); ok || p != nil {
		t.Errorf("TC prog in maps-only spec: got (%v, %v), want (nil, false)", p, ok)
	}
	if p, ok := l.Program("nonexistent"); ok || p != nil {
		t.Errorf("unknown name: got (%v, %v), want (nil, false)", p, ok)
	}
}

func TestRulesLoaderProgramAccessorNilReceiver(t *testing.T) {
	var l *RulesLoader
	if p, ok := l.Program(ProgramXDPRules); ok || p != nil {
		t.Errorf("nil receiver: got (%v, %v), want (nil, false)", p, ok)
	}
}
