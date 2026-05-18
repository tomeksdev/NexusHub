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
	mapRuleTableV4 = "rule_table_v4"
	mapRuleCountV4 = "rule_count_v4"
	mapRuleTableV6 = "rule_table_v6"
	mapRuleCountV6 = "rule_count_v6"
	mapRateStateV4 = "rate_state_v4"
	mapRateStateV6 = "rate_state_v6"
	mapRuleHits    = "rule_hits"

	ruleV4RecordSize = 44
	ruleV6RecordSize = 68
	ruleHitsSize     = 16
	rateTokensSize   = 16
	rateKeyV4Size    = 8
	rateKeyV6Size    = 20
)

func newTestLoader(t *testing.T) *userspace.RulesLoader {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("rlimit memlock: %v (run as root or in a kernel-capable runner)", err)
	}
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			mapRuleTableV4: {
				Name: mapRuleTableV4, Type: ebpf.Array,
				KeySize: 4, ValueSize: ruleV4RecordSize,
				MaxEntries: userspace.MaxActiveRulesV4,
			},
			mapRuleCountV4: {
				Name: mapRuleCountV4, Type: ebpf.Array,
				KeySize: 4, ValueSize: 4, MaxEntries: 1,
			},
			mapRuleTableV6: {
				Name: mapRuleTableV6, Type: ebpf.Array,
				KeySize: 4, ValueSize: ruleV6RecordSize,
				MaxEntries: userspace.MaxActiveRulesV6,
			},
			mapRuleCountV6: {
				Name: mapRuleCountV6, Type: ebpf.Array,
				KeySize: 4, ValueSize: 4, MaxEntries: 1,
			},
			mapRateStateV4: {
				Name: mapRateStateV4, Type: ebpf.PerCPUHash,
				KeySize: rateKeyV4Size, ValueSize: rateTokensSize,
				MaxEntries: 1024,
			},
			mapRateStateV6: {
				Name: mapRateStateV6, Type: ebpf.PerCPUHash,
				KeySize: rateKeyV6Size, ValueSize: rateTokensSize,
				MaxEntries: 1024,
			},
			mapRuleHits: {
				Name: mapRuleHits, Type: ebpf.PerCPUHash,
				KeySize: 4, ValueSize: ruleHitsSize,
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

func ptrU16(v uint16) *uint16 { return &v }
func ptrU32(v uint32) *uint32 { return &v }
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
		action, protocol, direction string
		wantA, wantP, wantD         uint8
	}{
		{"allow", "any", "ingress", 0, 0, 0},
		{"deny", "tcp", "egress", 1, 1, 1},
		{"rate_limit", "udp", "both", 2, 2, 2},
		{"log", "icmp", "", 3, 3, 0},
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

func TestFamilyForCIDRs(t *testing.T) {
	cases := []struct {
		name     string
		src, dst *netip.Prefix
		want     family
		wantErr  bool
	}{
		{"both nil → wildcard", nil, nil, familyBoth, false},
		{"v4 src only", ptrPrefix("10.0.0.0/8"), nil, familyV4, false},
		{"v6 src only", ptrPrefix("2001:db8::/32"), nil, familyV6, false},
		{"v4 dst only", nil, ptrPrefix("192.168.0.0/16"), familyV4, false},
		{"v4 both", ptrPrefix("10.0.0.0/8"), ptrPrefix("192.168.0.0/16"), familyV4, false},
		{"v6 both", ptrPrefix("fe80::/10"), ptrPrefix("2001:db8::/32"), familyV6, false},
		{"mixed", ptrPrefix("10.0.0.0/8"), ptrPrefix("2001:db8::/32"), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := familyFor(tc.src, tc.dst)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err: got %v want_err=%v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("family: got %v want %v", got, tc.want)
			}
		})
	}
}

func TestBuildActiveRuleV4(t *testing.T) {
	r := baseebpf.Rule{
		ID: uuid.New(), Action: "deny", Direction: "ingress", Protocol: "tcp",
		SrcCIDR:  ptrPrefix("198.51.100.0/24"),
		DstCIDR:  ptrPrefix("10.0.0.0/8"),
		Priority: 100,
	}
	ar, err := buildActiveRule(r, 42)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if ar.fam != familyV4 {
		t.Errorf("fam: got %v want %v", ar.fam, familyV4)
	}
	if ar.v4Record.Action != 1 || ar.v4Record.Protocol != 1 || ar.v4Record.IsActive != 1 {
		t.Errorf("v4 record header: got %+v", ar.v4Record)
	}
	if ar.v4Record.HasSrc != 1 || ar.v4Record.SrcPrefixLen != 24 {
		t.Errorf("v4 src: got HasSrc=%d Prefix=%d", ar.v4Record.HasSrc, ar.v4Record.SrcPrefixLen)
	}
	if ar.v4Record.HasDst != 1 || ar.v4Record.DstPrefixLen != 8 {
		t.Errorf("v4 dst: got HasDst=%d Prefix=%d", ar.v4Record.HasDst, ar.v4Record.DstPrefixLen)
	}
	if ar.v4Record.SrcAddr != [4]byte{198, 51, 100, 0} {
		t.Errorf("src addr: got %v", ar.v4Record.SrcAddr)
	}
	if ar.v4Record.RuleID != 42 {
		t.Errorf("rule_id: got %d want 42", ar.v4Record.RuleID)
	}
}

func TestApplyWritesV4Slot(t *testing.T) {
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

	count, err := loader.RuleCountV4()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("count: got %d want 1", count)
	}
	got, err := loader.GetRuleV4(0)
	if err != nil {
		t.Fatalf("get slot 0: %v", err)
	}
	if got.IsActive != 1 || got.HasSrc != 1 || got.SrcPrefixLen != 24 {
		t.Errorf("slot 0: got %+v", got)
	}
	if got.SrcAddr != [4]byte{198, 51, 100, 0} {
		t.Errorf("slot 0 src: %v", got.SrcAddr)
	}
}

func TestApplyTwoRulesSameSrcBothEnforce(t *testing.T) {
	// The regression test for round 10's reported bug: two active
	// rules with the same src_cidr both end up in the kernel (one
	// per slot, priority-sorted), so the operator-facing promise of
	// "every active rule applies" is honored. v2.0 LPM would have
	// dropped one.
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)
	ctx := context.Background()

	lowPriID := uuid.New()
	highPriID := uuid.New()
	if err := s.Apply(ctx, baseebpf.Rule{
		ID: lowPriID, Action: "allow",
		SrcCIDR: ptrPrefix("10.0.0.0/24"), Priority: 50,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, baseebpf.Rule{
		ID: highPriID, Action: "deny",
		SrcCIDR: ptrPrefix("10.0.0.0/24"), Priority: 200,
	}); err != nil {
		t.Fatal(err)
	}

	count, _ := loader.RuleCountV4()
	if count != 2 {
		t.Fatalf("count: got %d want 2", count)
	}

	slot0, _ := loader.GetRuleV4(0)
	slot1, _ := loader.GetRuleV4(1)
	// Higher priority wins slot 0 (the first match wins under bpf_loop
	// iteration with userspace-sorted priority).
	if slot0.Action != 1 /*deny*/ || slot0.Priority != 200 {
		t.Errorf("slot 0 should be the high-pri DENY: got %+v", slot0)
	}
	if slot1.Action != 0 /*allow*/ || slot1.Priority != 50 {
		t.Errorf("slot 1 should be the low-pri ALLOW: got %+v", slot1)
	}
	// Both slots carry the same src_addr/prefix — that's the entire
	// fix this round delivers.
	if slot0.SrcAddr != slot1.SrcAddr || slot0.SrcPrefixLen != slot1.SrcPrefixLen {
		t.Errorf("src addr/prefix diverged: %+v vs %+v", slot0, slot1)
	}
}

func TestApplyIdempotentAndReusesKernelID(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)

	r := baseebpf.Rule{ID: uuid.New(), Action: "allow", Priority: 10}
	if err := s.Apply(context.Background(), r); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	kidFirst := s.kernelIDs[r.ID]
	if err := s.Apply(context.Background(), r); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	kidSecond := s.kernelIDs[r.ID]
	if kidFirst != kidSecond {
		t.Errorf("kernel_id changed on re-apply: %d → %d", kidFirst, kidSecond)
	}
}

func TestDeleteRemovesFromTable(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)
	ctx := context.Background()

	r1 := baseebpf.Rule{ID: uuid.New(), Action: "deny", SrcCIDR: ptrPrefix("10.0.0.0/24")}
	r2 := baseebpf.Rule{ID: uuid.New(), Action: "deny", SrcCIDR: ptrPrefix("10.1.0.0/24")}
	if err := s.Apply(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, r2); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(ctx, r1.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	count, _ := loader.RuleCountV4()
	if count != 1 {
		t.Fatalf("count after delete: got %d want 1", count)
	}
	// Tail-clear: slot 1 (formerly r2) should now be zeroed out
	// because count shrank to 1 and slot 0 holds r2.
	tail, _ := loader.GetRuleV4(1)
	if tail.IsActive != 0 {
		t.Errorf("tail slot 1 not cleared: %+v", tail)
	}
	if _, ok := s.rules[r1.ID]; ok {
		t.Error("r1 still in in-memory set")
	}
}

func TestDeleteUnknownIsNoop(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)
	if err := s.Delete(context.Background(), uuid.New()); err != nil {
		t.Errorf("delete of unknown: %v", err)
	}
}

func TestReconcileConverges(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)
	ctx := context.Background()

	keep := baseebpf.Rule{ID: uuid.New(), Action: "allow", SrcCIDR: ptrPrefix("10.0.0.0/24"), Priority: 100}
	drop := baseebpf.Rule{ID: uuid.New(), Action: "deny", SrcCIDR: ptrPrefix("10.1.0.0/24"), Priority: 50}
	add := baseebpf.Rule{ID: uuid.New(), Action: "deny", SrcCIDR: ptrPrefix("10.2.0.0/24"), Priority: 200}

	if err := s.Apply(ctx, keep); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, drop); err != nil {
		t.Fatal(err)
	}

	if err := s.Reconcile(ctx, []baseebpf.Rule{keep, add}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, ok := s.rules[drop.ID]; ok {
		t.Error("stale rule not removed")
	}
	if _, ok := s.rules[keep.ID]; !ok {
		t.Error("kept rule lost during reconcile")
	}
	if _, ok := s.rules[add.ID]; !ok {
		t.Error("new rule not applied during reconcile")
	}
	count, _ := loader.RuleCountV4()
	if count != 2 {
		t.Errorf("count after reconcile: got %d want 2", count)
	}
}

func TestApplyV6Path(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)

	r := baseebpf.Rule{
		ID: uuid.New(), Action: "deny",
		SrcCIDR: ptrPrefix("2001:db8::/32"), Priority: 50,
	}
	if err := s.Apply(context.Background(), r); err != nil {
		t.Fatalf("apply: %v", err)
	}

	v4Count, _ := loader.RuleCountV4()
	v6Count, _ := loader.RuleCountV6()
	if v4Count != 0 {
		t.Errorf("v4 count: got %d want 0", v4Count)
	}
	if v6Count != 1 {
		t.Errorf("v6 count: got %d want 1", v6Count)
	}
	got, _ := loader.GetRuleV6(0)
	if got.HasSrc != 1 || got.SrcPrefixLen != 32 {
		t.Errorf("v6 slot 0: got %+v", got)
	}
}

func TestApplyWildcardRuleLandsInBothFamilies(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)

	// No src, no dst → match every packet on the hook.
	r := baseebpf.Rule{ID: uuid.New(), Action: "log", Priority: 10}
	if err := s.Apply(context.Background(), r); err != nil {
		t.Fatalf("apply: %v", err)
	}
	v4Count, _ := loader.RuleCountV4()
	v6Count, _ := loader.RuleCountV6()
	if v4Count != 1 || v6Count != 1 {
		t.Errorf("wildcard rule should land in both: v4=%d v6=%d", v4Count, v6Count)
	}
}

func TestCloseClearsState(t *testing.T) {
	loader := newTestLoader(t)
	s, _ := NewKernelSyncer(loader, nil)
	_ = s.Apply(context.Background(), baseebpf.Rule{ID: uuid.New(), Action: "allow"})
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if s.rules != nil || s.kernelIDs != nil {
		t.Error("state not cleared after Close")
	}
}

func TestRuleToV4RecordIncludesPortsAndRate(t *testing.T) {
	r := baseebpf.Rule{
		ID:          uuid.New(),
		Action:      "rate_limit",
		Direction:   "both",
		Protocol:    "udp",
		SrcCIDR:     ptrPrefix("198.51.100.0/24"),
		SrcPortFrom: ptrU16(1000),
		SrcPortTo:   ptrU16(2000),
		DstPortFrom: ptrU16(443),
		DstPortTo:   ptrU16(443),
		RatePPS:     ptrU32(500),
		RateBurst:   ptrU32(1500),
		Priority:    77,
	}
	ar, err := buildActiveRule(r, 1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	v4 := ar.v4Record
	if v4.Action != 2 || v4.Protocol != 2 || v4.Direction != 2 || v4.IsActive != 1 {
		t.Errorf("header: got %+v", v4)
	}
	if v4.SrcPortFrom != 1000 || v4.SrcPortTo != 2000 {
		t.Errorf("src ports: got %d-%d", v4.SrcPortFrom, v4.SrcPortTo)
	}
	if v4.DstPortFrom != 443 || v4.DstPortTo != 443 {
		t.Errorf("dst ports: got %d-%d", v4.DstPortFrom, v4.DstPortTo)
	}
	if v4.RatePPS != 500 || v4.RateBurst != 1500 {
		t.Errorf("rate: got pps=%d burst=%d", v4.RatePPS, v4.RateBurst)
	}
	if v4.Priority != 77 {
		t.Errorf("priority: got %d", v4.Priority)
	}
}
