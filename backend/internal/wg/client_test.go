package wg_test

import (
	"net/netip"
	"testing"

	"github.com/tomeksdev/NexusHub/backend/internal/wg"
)

func TestFakeClientDeviceNotFound(t *testing.T) {
	f := wg.NewFakeClient()
	if _, err := f.Device("wg0"); err == nil {
		t.Error("missing device must error")
	}
}

func TestFakeClientUpsertAndRemovePeer(t *testing.T) {
	f := wg.NewFakeClient()
	f.SetDevice(&wg.Device{Name: "wg0", ListenPort: 51820})

	pfx := netip.MustParsePrefix("10.8.0.2/32")
	err := f.ConfigureDevice("wg0", wg.Config{
		Peers: []wg.PeerConfig{{
			PublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			AllowedIPs: []netip.Prefix{pfx},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := f.Device("wg0")
	if len(d.Peers) != 1 || d.Peers[0].AllowedIPs[0] != pfx {
		t.Fatalf("peer not upserted: %+v", d.Peers)
	}

	// Remove.
	err = f.ConfigureDevice("wg0", wg.Config{
		Peers: []wg.PeerConfig{{
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Remove:    true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _ = f.Device("wg0")
	if len(d.Peers) != 0 {
		t.Fatalf("peer not removed: %+v", d.Peers)
	}
}

func TestFakeClientReplacePeers(t *testing.T) {
	f := wg.NewFakeClient()
	f.SetDevice(&wg.Device{
		Name: "wg0",
		Peers: []wg.Peer{
			{PublicKey: "old-key"},
		},
	})
	err := f.ConfigureDevice("wg0", wg.Config{
		ReplacePeers: true,
		Peers: []wg.PeerConfig{{
			PublicKey: "new-key",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := f.Device("wg0")
	if len(d.Peers) != 1 || d.Peers[0].PublicKey != "new-key" {
		t.Fatalf("replace did not swap peer list: %+v", d.Peers)
	}
}
