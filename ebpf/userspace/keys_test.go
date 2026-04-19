package userspace

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestPrefixToLPMv4(t *testing.T) {
	cases := []struct {
		prefix string
		want   lpmV4Key
	}{
		{"10.8.0.0/24", lpmV4Key{PrefixLen: 24, Addr: [4]byte{10, 8, 0, 0}}},
		{"192.168.1.1/32", lpmV4Key{PrefixLen: 32, Addr: [4]byte{192, 168, 1, 1}}},
		{"0.0.0.0/0", lpmV4Key{PrefixLen: 0, Addr: [4]byte{0, 0, 0, 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.prefix, func(t *testing.T) {
			p := netip.MustParsePrefix(tc.prefix)
			got, err := prefixToLPMv4(p)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPrefixToLPMv4RejectsIPv6(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/32")
	if _, err := prefixToLPMv4(p); err == nil {
		t.Fatal("expected error for IPv6 prefix")
	}
}

func TestPrefixToLPMv6(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/32")
	got, err := prefixToLPMv6(p)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.PrefixLen != 32 {
		t.Errorf("prefixlen: got %d, want 32", got.PrefixLen)
	}
	want := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	if got.Addr[0] != want[0] || got.Addr[1] != want[1] ||
		got.Addr[2] != want[2] || got.Addr[3] != want[3] {
		t.Errorf("addr[0:4]: got %v, want %v", got.Addr[0:4], want[0:4])
	}
}

func TestMarshalV4KeyLayout(t *testing.T) {
	// prefixlen=24 → 0x18 0x00 0x00 0x00 (LE), then 10.8.0.0 network order.
	k := lpmV4Key{PrefixLen: 24, Addr: [4]byte{10, 8, 0, 0}}
	b, err := k.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{0x18, 0x00, 0x00, 0x00, 10, 8, 0, 0}
	if !bytes.Equal(b, want) {
		t.Errorf("got %v, want %v", b, want)
	}
}

func TestMarshalV6KeyLayout(t *testing.T) {
	k := lpmV6Key{PrefixLen: 128}
	copy(k.Addr[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	b, err := k.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != 20 {
		t.Fatalf("len: got %d, want 20", len(b))
	}
	if b[0] != 128 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		t.Errorf("prefixlen bytes: got %v, want [128 0 0 0]", b[0:4])
	}
	if b[4] != 0x20 || b[5] != 0x01 {
		t.Errorf("addr prefix: got %v, want [0x20 0x01 ...]", b[4:6])
	}
}

func TestAddrToLPMv4(t *testing.T) {
	a := netip.MustParseAddr("8.8.8.8")
	got, err := addrToLPMv4(a)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := lpmV4Key{PrefixLen: 32, Addr: [4]byte{8, 8, 8, 8}}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAddrRejectsMismatchedFamily(t *testing.T) {
	v4 := netip.MustParseAddr("1.2.3.4")
	if _, err := addrToLPMv6(v4); err == nil {
		t.Error("addrToLPMv6 should reject IPv4")
	}
	v6 := netip.MustParseAddr("::1")
	if _, err := addrToLPMv4(v6); err == nil {
		t.Error("addrToLPMv4 should reject IPv6")
	}
}
