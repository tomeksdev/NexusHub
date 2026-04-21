package ebpfkernel

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"

	baseebpf "github.com/tomeksdev/NexusHub/backend/internal/ebpf"
	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

// Map names + sizes mirror the bpf2go-generated CollectionSpec.
// Duplicated here (rather than imported) so the userspace package
// doesn't need to export test fixtures across the module boundary.
const (
	mapRuleMeta    = "rule_meta"
	mapRuleSrcV4   = "rule_src_v4"
	mapRuleSrcV6   = "rule_src_v6"
	mapRuleDstV4   = "rule_dst_v4"
	mapRuleDstV6   = "rule_dst_v6"
	mapRateStateV4 = "rate_state_v4"

	ruleMetaSize   = 28 // see userspace.RuleMeta
	rateTokensSize = 16
	rateKeyV4Size  = 8
)

func newTestLoader(t *testing.T) *userspace.RulesLoader {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("rlimit memlock: %v (run as root or in a kernel-capable runner)", err)
	}
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			mapRuleMeta: {
				Name:       mapRuleMeta,
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  ruleMetaSize,
				MaxEntries: 1024,
			},
			mapRuleSrcV4: lpmSpec(mapRuleSrcV4, 8),
			mapRuleSrcV6: lpmSpec(mapRuleSrcV6, 20),
			mapRuleDstV4: lpmSpec(mapRuleDstV4, 8),
			mapRuleDstV6: lpmSpec(mapRuleDstV6, 20),
			mapRateStateV4: {
				Name:       mapRateStateV4,
				Type:       ebpf.PerCPUHash,
				KeySize:    rateKeyV4Size,
				ValueSize:  rateTokensSize,
				MaxEntries: 1024,
			},
		},
	}
	l, err := userspace.NewRulesLoader(spec)
	if err != nil {
		t.Fatalf("new loader: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func lpmSpec(name string, keySize uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.LPMTrie,
		KeySize:    keySize,
		ValueSize:  4,
		MaxEntries: 1024,
		Flags:      1, // BPF_F_NO_PREALLOC, required for LPM_TRIE
	}
}

func ptrU16(v uint16) *uint16     { return &v }
func ptrU32(v uint32) *uint32     { return &v }
func ptrPrefix(s string) *netip.Prefix {
	p := netip.MustParsePrefix(s)
	return &p
}

func TestNewKernelSyncerRejectsNilLoader(t *testing.T) {
	if _, err := NewKernelSyncer(nil, nil); err == nil {
		t.Error("expected error on nil loader")
	}
}

func TestActionProtocolDirectionEncoding(t *testing.T) {
	cases := []struct {
		action, protocol, direction       string
		wantA, wantP, wantD               uint8
	}{
		{"allow", "any", "ingress", 0, 0, 0},
		{"deny", "tcp", "egress", 1, 1, 1},
		{"rate_limit", "udp", "both", 2, 2, 2},
		{"log", "icmp", "", 3, 3, 0}, // empty direction → ingress
	}
	for _, tc := range cases {
		a, err := actionByte(tc.action)
		if err != nil || a != tc.wantA {
			t.Errorf("actionByte(%q): got (%d, %v), want (%d, nil)", tc.action, a, err, tc.wantA)
		}
		p, err := protocolByte(tc.protocol)
		if err != nil || p != tc.wantP {
			t.Errorf("protocolByte(%q): got (%d, %v), want (%d, nil)", tc.protocol, p, err, tc.wantP)
		}
		d, err := directionByte(tc.direction)
		if err != nil || d != tc.wantD {
			t.Errorf("directionByte(%q): got (%d, %v), want (%d, nil)", tc.direction, d, err, tc.wantD)
		}
	}

	if _, err := actionByte("nonsense"); err == nil {
		t.Error("actionByte: expected error on unknown")
	}
	if _, err := protocolByte("sctp"); err == nil {
		t.Error("protocolByte: expected error on unknown")
	}
	if _, err := directionByte("sideways"); err == nil {
		t.Error("directionByte: expected error on unknown")
	}
}

func TestRuleToMetaRoundTrip(t *testing.T) {
	r := baseebpf.Rule{
		ID:          uuid.New(),
		Action:      "rate_limit",
		Direction:   "both",
		Protocol:    "udp",
		SrcPortFrom: ptrU16(1000),
		SrcPortTo:   ptrU16(2000),
		DstPortFrom: ptrU16(443),
		DstPortTo:   ptrU16(443),
		RatePPS:     ptrU32(500),
		RateBurst:   ptrU32(1500),
		Priority:    77,
	}
	m, err := ruleToMeta(r)
	if err != nil {
		t.Fatalf("ruleToMeta: %v", err)
	}
	if m.Action != 2 || m.Protocol != 2 || m.Direction != 2 || m.IsActive != 1 {
		t.Errorf("header bytes: got %+v", m)
	}
	if m.SrcPortFrom != 1000 || m.SrcPortTo != 2000 {
		t.Errorf("src ports: got %d-%d", m.SrcPortFrom, m.SrcPortTo)
	}
	if m.DstPortFrom != 443 || m.DstPortTo != 443 {
		t.Errorf("dst ports: got %d-%d", m.DstPortFrom, m.DstPortTo)
	}
	if m.RatePPS != 500 || m.RateBurst != 1500 {
		t.Errorf("rate: got pps=%d burst=%d", m.RatePPS, m.RateBurst)
	}
	if m.Priority != 77 {
		t.Errorf("priority: got %d", m.Priority)
	}
}

func TestApplyWritesMetaAndPrefix(t *testing.T) {
	loader := newTestLoader(t)
	s, err := NewKernelSyncer(loader, nil)
	if err != nil {
		t.Fatalf("new syncer: %v", err)
	}

	r := baseebpf.Rule{
		ID: uuid.New(), Action: "deny", Direction: "ingress", Protocol: "tcp",
		SrcCIDR:  ptrPrefix("198.51.100.0/24"),
		Priority: 100,
	}
	if err := s.Apply(context.Background(), r); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Kernel state: meta row present under the assigned u32 id.
	s.mu.Lock()
	rid := s.ids[r.ID]
	s.mu.Unlock()
	got, ok, err := loader.GetRuleMeta(rid)
	if err != nil {
		t.Fatalf("get meta: %v", err)
	}
	if !ok {
		t.Fatal("meta missing in kernel after apply")
	}
	if got.Action != 1 || got.Protocol != 1 || got.IsActive != 1 || got.Priority != 100 {
		t.Errorf("meta fields: got %+v", got)
	}
}

func TestApplyIdempotentAndReusesID(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)

	r := baseebpf.Rule{ID: uuid.New(), Action: "allow", Priority: 10}
	if err := s.Apply(context.Background(), r); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	ridFirst := s.ids[r.ID]
	if err := s.Apply(context.Background(), r); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	ridSecond := s.ids[r.ID]
	if ridFirst != ridSecond {
		t.Errorf("rule_id changed on re-apply: %d → %d", ridFirst, ridSecond)
	}
}

func TestApplyChangedCIDRReplacesPrefix(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)

	id := uuid.New()
	if err := s.Apply(context.Background(), baseebpf.Rule{
		ID: id, Action: "deny", SrcCIDR: ptrPrefix("10.0.0.0/8"),
	}); err != nil {
		t.Fatalf("apply v1: %v", err)
	}
	if err := s.Apply(context.Background(), baseebpf.Rule{
		ID: id, Action: "deny", SrcCIDR: ptrPrefix("172.16.0.0/12"),
	}); err != nil {
		t.Fatalf("apply v2: %v", err)
	}

	// Old CIDR host must miss, new CIDR host must hit.
	if _, ok, err := loader.LookupSrcAddr(netip.MustParseAddr("10.1.2.3")); err != nil || ok {
		t.Errorf("old prefix still present: ok=%v err=%v", ok, err)
	}
	if rid, ok, err := loader.LookupSrcAddr(netip.MustParseAddr("172.16.1.1")); err != nil || !ok || rid == 0 {
		t.Errorf("new prefix missing: rid=%d ok=%v err=%v", rid, ok, err)
	}
}

func TestDeleteRemovesMetaAndPrefix(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)

	id := uuid.New()
	if err := s.Apply(context.Background(), baseebpf.Rule{
		ID: id, Action: "deny", SrcCIDR: ptrPrefix("203.0.113.0/24"),
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	ridBefore := s.ids[id]

	if err := s.Delete(context.Background(), id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Meta gone.
	if _, ok, _ := loader.GetRuleMeta(ridBefore); ok {
		t.Error("meta still present after delete")
	}
	// LPM entry gone.
	if _, ok, err := loader.LookupSrcAddr(netip.MustParseAddr("203.0.113.1")); err != nil || ok {
		t.Errorf("prefix still present after delete: ok=%v err=%v", ok, err)
	}
	// Local bookkeeping gone.
	if _, ok := s.ids[id]; ok {
		t.Error("id mapping still present after delete")
	}
}

func TestDeleteUnknownIsNoop(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)
	if err := s.Delete(context.Background(), uuid.New()); err != nil {
		t.Errorf("delete of unknown: %v", err)
	}
}

func TestReconcileRemovesStaleAndApplies(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)

	ctx := context.Background()
	keep := baseebpf.Rule{ID: uuid.New(), Action: "allow", SrcCIDR: ptrPrefix("10.0.0.0/24")}
	drop := baseebpf.Rule{ID: uuid.New(), Action: "deny", SrcCIDR: ptrPrefix("10.1.0.0/24")}
	add := baseebpf.Rule{ID: uuid.New(), Action: "deny", SrcCIDR: ptrPrefix("10.2.0.0/24")}

	if err := s.Apply(ctx, keep); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, drop); err != nil {
		t.Fatal(err)
	}

	if err := s.Reconcile(ctx, []baseebpf.Rule{keep, add}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// drop is gone, keep is still there, add is present.
	if _, ok := s.ids[drop.ID]; ok {
		t.Error("stale rule not removed")
	}
	if _, ok := s.ids[keep.ID]; !ok {
		t.Error("kept rule lost during reconcile")
	}
	if _, ok := s.ids[add.ID]; !ok {
		t.Error("new rule not applied during reconcile")
	}

	if _, ok, err := loader.LookupSrcAddr(netip.MustParseAddr("10.1.0.1")); err != nil || ok {
		t.Errorf("stale prefix leaked: ok=%v err=%v", ok, err)
	}
	if _, ok, err := loader.LookupSrcAddr(netip.MustParseAddr("10.2.0.1")); err != nil || !ok {
		t.Errorf("new prefix missing: ok=%v err=%v", ok, err)
	}
}

func TestCloseClearsState(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)
	_ = s.Apply(context.Background(), baseebpf.Rule{ID: uuid.New(), Action: "allow"})
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if s.ids != nil || s.srcPrefixes != nil {
		t.Error("state maps not cleared after Close")
	}
	// Loader is caller-owned; a second Close on the loader itself
	// (via t.Cleanup) must still succeed — no double-free.
}

