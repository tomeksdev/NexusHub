package userspace

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// buildTestSpec returns a minimal CollectionSpec that mimics what
// bpf2go emits for blocklist.c: two LPM_TRIE maps, no programs. The
// map type + key/value sizes must match ebpf/headers/nexushub.h so
// the Update/Delete calls agree with the kernel's expectations.
func buildTestSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			mapBlocklistV4: {
				Name:       mapBlocklistV4,
				Type:       ebpf.LPMTrie,
				KeySize:    8,  // prefixlen (4) + addr (4)
				ValueSize:  4,  // u32 ruleID
				MaxEntries: 1024,
				Flags:      1,  // BPF_F_NO_PREALLOC, required for LPM_TRIE
			},
			mapBlocklistV6: {
				Name:       mapBlocklistV6,
				Type:       ebpf.LPMTrie,
				KeySize:    20, // prefixlen (4) + addr (16)
				ValueSize:  4,
				MaxEntries: 1024,
				Flags:      1,
			},
		},
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

func TestBlocklistLoaderBlockAndUnblockV4(t *testing.T) {
	requireBPF(t)
	spec := buildTestSpec(t)
	l, err := NewBlocklistLoader(spec)
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	addr := netip.MustParseAddr("203.0.113.17")
	if err := l.BlockAddr(addr, 42); err != nil {
		t.Fatalf("block: %v", err)
	}

	// Map lookup via the kernel — confirms the key round-trips.
	key, err := addrToLPMv4(addr)
	if err != nil {
		t.Fatalf("key build: %v", err)
	}
	var got uint32
	if err := l.v4.Lookup(key, &got); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got != 42 {
		t.Errorf("ruleID: got %d, want 42", got)
	}

	if err := l.UnblockAddr(addr); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if err := l.v4.Lookup(key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("after unblock: expected ErrKeyNotExist, got %v", err)
	}
}

func TestBlocklistLoaderPrefixV4(t *testing.T) {
	requireBPF(t)
	l, err := NewBlocklistLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	pfx := netip.MustParsePrefix("198.51.100.0/24")
	if err := l.BlockPrefix(pfx, 7); err != nil {
		t.Fatalf("block: %v", err)
	}

	// LPM lookup with a host inside the prefix must hit.
	hostKey, _ := addrToLPMv4(netip.MustParseAddr("198.51.100.5"))
	var got uint32
	if err := l.v4.Lookup(hostKey, &got); err != nil {
		t.Fatalf("lookup inside prefix: %v", err)
	}
	if got != 7 {
		t.Errorf("ruleID: got %d, want 7", got)
	}

	// A host outside the prefix must miss.
	outsideKey, _ := addrToLPMv4(netip.MustParseAddr("198.51.101.5"))
	if err := l.v4.Lookup(outsideKey, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("lookup outside prefix: expected miss, got %v (val=%d)", err, got)
	}
}

func TestBlocklistLoaderUnblockMissingIsNoop(t *testing.T) {
	requireBPF(t)
	l, err := NewBlocklistLoader(buildTestSpec(t))
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	defer l.Close()

	addr := netip.MustParseAddr("192.0.2.1")
	if err := l.UnblockAddr(addr); err != nil {
		t.Errorf("unblock of non-existent key should be nil, got %v", err)
	}
}

func TestNewBlocklistLoaderRejectsNilSpec(t *testing.T) {
	if _, err := NewBlocklistLoader(nil); err == nil {
		t.Error("expected error on nil spec")
	}
}

func TestNewBlocklistLoaderRejectsMissingMap(t *testing.T) {
	requireBPF(t)
	spec := buildTestSpec(t)
	delete(spec.Maps, mapBlocklistV6)
	if _, err := NewBlocklistLoader(spec); err == nil {
		t.Error("expected error when v6 map missing")
	}
}
