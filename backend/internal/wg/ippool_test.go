package wg_test

import (
	"net/netip"
	"testing"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/wg"
)

func mp(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ma(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAllocateIPFirstFreeSkipsReserved(t *testing.T) {
	// 10.8.0.1/24 — interface holds .1, network is .0, broadcast .255.
	// First free peer IP must be .2.
	got, err := wg.AllocateIP(mp(t, "10.8.0.1/24"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10.8.0.2" {
		t.Errorf("first free = %s, want 10.8.0.2", got)
	}
}

func TestAllocateIPSkipsUsed(t *testing.T) {
	used := []netip.Addr{ma(t, "10.8.0.2"), ma(t, "10.8.0.3")}
	got, err := wg.AllocateIP(mp(t, "10.8.0.1/24"), used)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10.8.0.4" {
		t.Errorf("got %s, want 10.8.0.4", got)
	}
}

func TestAllocateIPExhausted(t *testing.T) {
	// /30 has hosts .1, .2 (out of .0/.3). If iface is .1 and .2 is taken,
	// pool is exhausted.
	used := []netip.Addr{ma(t, "10.0.0.2")}
	if _, err := wg.AllocateIP(mp(t, "10.0.0.1/30"), used); err == nil {
		t.Fatal("expected exhaustion")
	}
}

func TestAllocateIPIPv6(t *testing.T) {
	// fd00::1/64 — first free is fd00::2.
	got, err := wg.AllocateIP(mp(t, "fd00::1/64"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "fd00::2" {
		t.Errorf("got %s, want fd00::2", got)
	}
}

func TestAllocateIPRejectsInvalid(t *testing.T) {
	if _, err := wg.AllocateIP(netip.Prefix{}, nil); err == nil {
		t.Error("invalid prefix must fail")
	}
}
