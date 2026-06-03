package handler

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/tomeksdev/NexusHub/backend/internal/repository"
)

// IPv4 peers must export `Address = <ip>/32` so external tooling
// (Mikrotik, OpenWrt `wg setconf`, automated diff tools) gets a
// portable file. Some clients silently normalise the bare IP on
// display, but the .conf we write should be explicit. (#83 P2)
func TestRenderWgQuickConfigAddressCIDRv4(t *testing.T) {
	peer := &repository.Peer{
		AssignedIP: netip.MustParseAddr("10.20.25.3"),
	}
	iface := &repository.Interface{
		PublicKey: "TEST_IFACE_PUBKEY",
		Address:   netip.MustParsePrefix("10.20.25.1/24"),
	}
	got := renderWgQuickConfig(peer, iface, "TEST_PEER_PRIV", "", "host:443", nil)
	want := "Address = 10.20.25.3/32"
	if !strings.Contains(got, want) {
		t.Errorf("missing %q in:\n%s", want, got)
	}
	// Belt-and-braces: the bare form must NOT appear on its own line.
	for _, bad := range []string{"Address = 10.20.25.3\n"} {
		if strings.Contains(got, bad) {
			t.Errorf("found bare Address line %q (should be /32) in:\n%s",
				bad, got)
		}
	}
}

// IPv6 peers must export `Address = <addr>/128` for the same reason
// — the mask must come from the address family, not a hardcoded 32.
func TestRenderWgQuickConfigAddressCIDRv6(t *testing.T) {
	peer := &repository.Peer{
		AssignedIP: netip.MustParseAddr("fd00::3"),
	}
	iface := &repository.Interface{
		PublicKey: "TEST_IFACE_PUBKEY",
		Address:   netip.MustParsePrefix("fd00::1/64"),
	}
	got := renderWgQuickConfig(peer, iface, "TEST_PEER_PRIV", "", "[host]:443", nil)
	want := "Address = fd00::3/128"
	if !strings.Contains(got, want) {
		t.Errorf("missing %q in:\n%s", want, got)
	}
}
