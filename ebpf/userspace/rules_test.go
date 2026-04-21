package userspace

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// buildTestSpec returns a minimal CollectionSpec that mimics what
// bpf2go emits for rules.c: one HASH + four LPM_TRIE + two PERCPU_HASH
// maps, no programs. Key/value sizes must match
// ebpf/headers/nexushub.h so Update/Delete/Lookup agree with the kernel.
func buildTestSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			mapRuleMeta: {
				Name:       mapRuleMeta,
				Type:       ebpf.Hash,
				KeySize:    4, // u32 rule_id
				ValueSize:  ruleMetaSize,
				MaxEntries: 1024,
			},
			mapRuleSrcV4: lpmTrieSpec(mapRuleSrcV4, 8),
			mapRuleSrcV6: lpmTrieSpec(mapRuleSrcV6, 20),
			mapRuleDstV4: lpmTrieSpec(mapRuleDstV4, 8),
			mapRuleDstV6: lpmTrieSpec(mapRuleDstV6, 20),
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
		},
	}
}

func lpmTrieSpec(name string, keySize uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.LPMTrie,
		KeySize:    keySize, // prefixlen (4) + addr
		ValueSize:  4,       // u32 rule_id
		MaxEntries: 1024,
		Flags:      1, // BPF_F_NO_PREALLOC, required for LPM_TRIE
	}
}

// requireBPF skips the test if the kernel denies map creation. CI
// runners without /sys/fs/bpf or without CAP_BPF fail gracefully
// instead of poisoning the whole test run.
func requireBPF(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("rlimit memlock: %v (run as root or in a kernel-capable runner)", err)
	}
}

func TestRulesLoaderPutGetDeleteMeta(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	want := RuleMeta{
		Action: 1 /*DENY*/, Protocol: 1 /*TCP*/, Direction: 0, IsActive: 1,
		SrcPortFrom: 1024, SrcPortTo: 65535,
		DstPortFrom: 443, DstPortTo: 443,
		Priority: 100,
		RatePPS:  0, RateBurst: 0,
	}
	if err := l.PutRuleMeta(7, want); err != nil {
		t.Fatalf("put meta: %v", err)
	}
	got, ok, err := l.GetRuleMeta(7)
	if err != nil {
		t.Fatalf("get meta: %v", err)
	}
	if !ok {
		t.Fatal("meta missing after put")
	}
	if got != want {
		t.Errorf("meta round-trip mismatch:\n  got  %+v\n  want %+v", got, want)
	}

	if err := l.DeleteRuleMeta(7); err != nil {
		t.Fatalf("delete meta: %v", err)
	}
	_, ok, err = l.GetRuleMeta(7)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if ok {
		t.Error("meta still present after delete")
	}
}

func TestRulesLoaderDeleteMetaMissingIsNoop(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()
	if err := l.DeleteRuleMeta(999); err != nil {
		t.Errorf("delete of missing meta should be nil, got %v", err)
	}
}

func TestRulesLoaderSrcPrefixV4(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	pfx := netip.MustParsePrefix("198.51.100.0/24")
	if err := l.PutSrcPrefix(pfx, 42); err != nil {
		t.Fatalf("put src: %v", err)
	}

	// Host inside the prefix must hit.
	insideKey, _ := addrToLPMv4(netip.MustParseAddr("198.51.100.5"))
	var got uint32
	if err := l.srcV4.Lookup(insideKey, &got); err != nil {
		t.Fatalf("lookup inside prefix: %v", err)
	}
	if got != 42 {
		t.Errorf("rule_id: got %d, want 42", got)
	}

	// Host outside must miss.
	outsideKey, _ := addrToLPMv4(netip.MustParseAddr("198.51.101.5"))
	if err := l.srcV4.Lookup(outsideKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("lookup outside prefix: expected miss, got %v", err)
	}

	if err := l.DeleteSrcPrefix(pfx); err != nil {
		t.Fatalf("delete src: %v", err)
	}
	if err := l.srcV4.Lookup(insideKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("after delete: expected miss, got %v", err)
	}
}

func TestRulesLoaderSrcAddrV4HostShortcut(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	addr := netip.MustParseAddr("203.0.113.17")
	if err := l.PutSrcAddr(addr, 99); err != nil {
		t.Fatalf("put addr: %v", err)
	}
	key, _ := addrToLPMv4(addr)
	var got uint32
	if err := l.srcV4.Lookup(key, &got); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != 99 {
		t.Errorf("rule_id: got %d, want 99", got)
	}
	if err := l.DeleteSrcAddr(addr); err != nil {
		t.Fatalf("delete addr: %v", err)
	}
}

func TestRulesLoaderDstPrefixRoutesToDstMap(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	pfx := netip.MustParsePrefix("10.0.0.0/8")
	if err := l.PutDstPrefix(pfx, 55); err != nil {
		t.Fatalf("put dst: %v", err)
	}
	// Confirm it went to dst_v4 only, not src_v4.
	hostKey, _ := addrToLPMv4(netip.MustParseAddr("10.1.2.3"))
	var got uint32
	if err := l.dstV4.Lookup(hostKey, &got); err != nil {
		t.Fatalf("dst lookup: %v", err)
	}
	if got != 55 {
		t.Errorf("dst rule_id: got %d, want 55", got)
	}
	if err := l.srcV4.Lookup(hostKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("src_v4 should not have entry, got %v (val=%d)", err, got)
	}
}

func TestRulesLoaderMetaSurvivesLookupWithExplicitBytes(t *testing.T) {
	requireBPF(t)
	l, err := NewRulesLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	// High-bit patterns catch endianness bugs.
	want := RuleMeta{
		Action: 2, Protocol: 2, Direction: 1, IsActive: 1,
		SrcPortFrom: 0xABCD, DstPortTo: 0x1234,
		Priority: 0xDEAD,
		RatePPS:  0xCAFEBABE, RateBurst: 0x01020304,
	}
	if err := l.PutRuleMeta(123, want); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Raw-bytes lookup: confirms the kernel sees the exact wire layout.
	raw := make([]byte, ruleMetaSize)
	if err := l.meta.Lookup(uint32(123), &raw); err != nil {
		t.Fatalf("raw lookup: %v", err)
	}
	var decoded RuleMeta
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded != want {
		t.Errorf("raw round-trip mismatch:\n  got  %+v\n  want %+v", decoded, want)
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
	delete(spec.Maps, mapRuleMeta)
	if _, err := NewRulesLoader(spec); err == nil {
		t.Error("expected error when rule_meta map missing")
	}
}

func TestRuleMetaMarshalRoundTrip(t *testing.T) {
	orig := RuleMeta{
		Action: 1, Protocol: 2, Direction: 2, IsActive: 1,
		SrcPortFrom: 100, SrcPortTo: 200,
		DstPortFrom: 300, DstPortTo: 400,
		Priority: 500, RatePPS: 1000, RateBurst: 2000,
	}
	b, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != ruleMetaSize {
		t.Fatalf("len: got %d, want %d", len(b), ruleMetaSize)
	}
	var back RuleMeta
	if err := back.UnmarshalBinary(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != orig {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", back, orig)
	}
}

func TestRuleMetaUnmarshalRejectsWrongLength(t *testing.T) {
	var m RuleMeta
	if err := m.UnmarshalBinary(make([]byte, ruleMetaSize-1)); err == nil {
		t.Error("expected error on short buffer")
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

	// Seed identical values on every CPU. PERCPU_HASH expects one
	// value per CPU; cilium/ebpf infers the count from runtime.
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
		// rule_id (LE u32)
		0x04, 0x03, 0x02, 0x01,
		// addr
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	for i, w := range want {
		if b[i] != w {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x\n  got  %x\n  want %x", i, b[i], w, b, want)
		}
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
	// Exercises the accessor against a maps-only spec (the one all
	// kernel-free tests use). Programs are intentionally absent so the
	// accessor must report (nil, false) rather than panic. Production
	// specs loaded from the bpf2go .o have both programs populated; the
	// same accessor gives them back by SEC() name.
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
