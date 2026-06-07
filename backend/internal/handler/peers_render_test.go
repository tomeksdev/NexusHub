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

// #86 P1: the exported .conf's [Peer] Endpoint must carry the
// listen port of the peer's own interface. Previously the env-side
// WG_ENDPOINT (host:default-port) flowed through verbatim, so an
// operator with wg-a on 443 and wg-b on 444 saw every .conf say
// host:443. The renderer must use defaultEndpoint as host-only when
// it falls back to it.
func TestRenderWgQuickConfigEndpoint(t *testing.T) {
	peerOverride := "peer.example.net:9999"
	ifaceOverride := "iface.example.net:7777"

	cases := []struct {
		name            string
		peerEndpoint    *string
		ifaceEndpoint   *string
		ifaceListenPort int
		defaultEndpoint string
		want            string
	}{
		{
			name:            "default endpoint with port, iface port differs",
			ifaceListenPort: 444,
			defaultEndpoint: "vpn.example.com:443",
			want:            "Endpoint = vpn.example.com:444",
		},
		{
			name:            "default endpoint with port, iface port matches",
			ifaceListenPort: 443,
			defaultEndpoint: "vpn.example.com:443",
			want:            "Endpoint = vpn.example.com:443",
		},
		{
			name:            "default endpoint bare host (no port)",
			ifaceListenPort: 444,
			defaultEndpoint: "vpn.example.com",
			want:            "Endpoint = vpn.example.com:444",
		},
		{
			name:            "default endpoint IPv4 literal with port",
			ifaceListenPort: 51820,
			defaultEndpoint: "192.0.2.1:443",
			want:            "Endpoint = 192.0.2.1:51820",
		},
		{
			name:            "default endpoint IPv6 literal with port",
			ifaceListenPort: 444,
			defaultEndpoint: "[2001:db8::1]:443",
			want:            "Endpoint = [2001:db8::1]:444",
		},
		{
			name:            "iface override beats default",
			ifaceEndpoint:   &ifaceOverride,
			ifaceListenPort: 444,
			defaultEndpoint: "vpn.example.com:443",
			want:            "Endpoint = iface.example.net:7777",
		},
		{
			name:            "peer override beats iface and default",
			peerEndpoint:    &peerOverride,
			ifaceEndpoint:   &ifaceOverride,
			ifaceListenPort: 444,
			defaultEndpoint: "vpn.example.com:443",
			want:            "Endpoint = peer.example.net:9999",
		},
		{
			name:            "iface override without port gets iface listen_port appended",
			ifaceEndpoint:   strPtr("nat.example.net"),
			ifaceListenPort: 4242,
			defaultEndpoint: "ignored.example.com:443",
			want:            "Endpoint = nat.example.net:4242",
		},
		{
			name:            "no default and no overrides emits no Endpoint line",
			ifaceListenPort: 444,
			defaultEndpoint: "",
			want:            "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := &repository.Peer{
				AssignedIP: netip.MustParseAddr("10.20.30.1"),
				Endpoint:   tc.peerEndpoint,
			}
			iface := &repository.Interface{
				PublicKey:  "TEST_IFACE_PUBKEY",
				Address:    netip.MustParsePrefix("10.20.30.254/24"),
				ListenPort: tc.ifaceListenPort,
				Endpoint:   tc.ifaceEndpoint,
			}
			got := renderWgQuickConfig(peer, iface, "TEST_PEER_PRIV", "",
				tc.defaultEndpoint, nil)
			if tc.want == "" {
				if strings.Contains(got, "\nEndpoint = ") {
					t.Errorf("expected no Endpoint line, got:\n%s", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("missing %q in:\n%s", tc.want, got)
			}
		})
	}
}

func strPtr(s string) *string { return &s }
