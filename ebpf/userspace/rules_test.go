package userspace

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// buildTestSpec returns a minimal CollectionSpec that mimics what
// bpf2go emits for rules.c: one HASH + four LPM_TRIE maps, no
// programs. Key/value sizes must match ebpf/headers/nexushub.h so
// Update/Delete/Lookup agree with the kernel.
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
