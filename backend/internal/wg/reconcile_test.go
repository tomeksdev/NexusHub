package wg

import (
	"context"
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p
}

func TestReconcileAddRemoveUpdate(t *testing.T) {
	f := NewFakeClient()
	// Live state: peer B exists with one allowed IP.
	f.SetDevice(&Device{
		Name: "wg0", ListenPort: 51820,
		Peers: []Peer{
			{PublicKey: "B", AllowedIPs: []netip.Prefix{mustPrefix(t, "10.0.0.2/32")}},
			{PublicKey: "C", AllowedIPs: []netip.Prefix{mustPrefix(t, "10.0.0.3/32")}},
		},
	})

	// Desired state: A (new), B (updated allowed IPs), no C (removed).
	spec := InterfaceSpec{
		Name: "wg0", ListenPort: 51820,
		Peers: []PeerSpec{
			{PublicKey: "A", AllowedIPs: []netip.Prefix{mustPrefix(t, "10.0.0.1/32")}},
			{PublicKey: "B", AllowedIPs: []netip.Prefix{mustPrefix(t, "10.0.0.2/32"), mustPrefix(t, "10.0.1.0/24")}},
		},
	}

	r := &Reconciler{Client: f}
	results := r.Reconcile(context.Background(), []InterfaceSpec{spec})
	if len(results) != 1 {
		t.Fatalf("results=%d", len(results))
	}
	got := results[0]
	if len(got.Added) != 1 || got.Added[0] != "A" {
		t.Errorf("added=%v, want [A]", got.Added)
	}
	if len(got.Updated) != 1 || got.Updated[0] != "B" {
		t.Errorf("updated=%v, want [B]", got.Updated)
	}
	if len(got.Removed) != 1 || got.Removed[0] != "C" {
		t.Errorf("removed=%v, want [C]", got.Removed)
	}
	if len(got.Errors) != 0 {
		t.Fatalf("errors=%v", got.Errors)
	}

	// Fake applied the config; confirm the final peer list.
	d, _ := f.Device("wg0")
	keys := map[string]bool{}
	for _, p := range d.Peers {
		keys[p.PublicKey] = true
	}
	if keys["C"] {
		t.Error("C should have been removed")
	}
	if !keys["A"] || !keys["B"] {
		t.Errorf("peers=%v, want {A,B}", keys)
	}
}

func TestReconcileNoDrift(t *testing.T) {
	f := NewFakeClient()
	f.SetDevice(&Device{
		Name: "wg0", ListenPort: 51820,
		Peers: []Peer{{PublicKey: "A", AllowedIPs: []netip.Prefix{mustPrefix(t, "10.0.0.1/32")}}},
	})
	spec := InterfaceSpec{
		Name: "wg0", ListenPort: 51820,
		Peers: []PeerSpec{{PublicKey: "A", AllowedIPs: []netip.Prefix{mustPrefix(t, "10.0.0.1/32")}}},
	}
	r := &Reconciler{Client: f}
	got := r.Reconcile(context.Background(), []InterfaceSpec{spec})[0]
	if len(got.Added)+len(got.Removed)+len(got.Updated) != 0 {
		t.Errorf("expected no drift, got %+v", got)
	}
}
