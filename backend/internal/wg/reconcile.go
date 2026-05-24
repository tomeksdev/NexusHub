package wg

import (
	"context"
	"log/slog"
	"net/netip"
	"time"
)

// PeerSpec is the DB-side peer view the reconciler consumes. We keep it
// free of repository types so wg/ stays free of a circular import back to
// internal/repository.
type PeerSpec struct {
	PublicKey    string
	PresharedKey []byte // raw (decrypted); nil when not set
	Endpoint     string
	AllowedIPs   []netip.Prefix
	Keepalive    *time.Duration
}

// InterfaceSpec is the DB-side interface view. PrivateKey is raw (already
// decrypted by the caller); the reconciler never sees ciphertext.
type InterfaceSpec struct {
	Name       string
	PrivateKey []byte
	ListenPort int
	// Address is the link-side CIDR (e.g. 10.7.0.1/24). Empty when the
	// reconciler is invoked from a path that doesn't know the address;
	// in that case Links.EnsureAddress is skipped and an operator is
	// expected to have set it out of band.
	Address netip.Prefix
	Peers   []PeerSpec
}

// Reconciler brings the live kernel state in line with the DB-side truth.
// It's called once at startup and is safe to call again on SIGHUP.
//
// Strategy: for each DB interface we compute the drift vs. the live device
// (peers present only in DB → add, only in kernel → remove, present in
// both but with different AllowedIPs/endpoint/PSK → update). We use
// ReplacePeers=false and one PeerConfig per drifted peer so a transient
// netlink error on a single peer doesn't wipe the whole device.
type Reconciler struct {
	Client Client
	// Links is the rtnetlink side. Optional — when nil, the reconciler
	// assumes the operator manages link lifecycle out of band and only
	// drives wgctrl. When set, every interface is ensure-link / ensure-
	// address / ensure-up'd before ConfigureDevice runs.
	Links  LinkManager
	Logger *slog.Logger
}

// ReconcileResult captures what actually changed. Useful for an
// "applied at startup" audit row and for tests that want to assert on drift.
type ReconcileResult struct {
	Interface string
	Added     []string // public keys added to kernel
	Removed   []string // public keys removed from kernel
	Updated   []string // public keys whose config differed
	Errors    []error
}

// Reconcile walks the supplied specs, calling ConfigureDevice per interface.
// Errors on a single interface are logged and accumulated but do NOT abort
// the walk — a broken wg1 should not prevent wg0 from coming up.
func (r *Reconciler) Reconcile(ctx context.Context, specs []InterfaceSpec) []ReconcileResult {
	log := r.Logger
	if log == nil {
		log = slog.Default()
	}
	out := make([]ReconcileResult, 0, len(specs))
	for _, spec := range specs {
		res := r.reconcileOne(ctx, spec, log)
		out = append(out, res)
	}
	return out
}

func (r *Reconciler) reconcileOne(ctx context.Context, spec InterfaceSpec, log *slog.Logger) ReconcileResult {
	res := ReconcileResult{Interface: spec.Name}

	// rtnetlink path first — wgctrl can't create the link itself. When
	// Links is nil we fall through and assume the link exists; the
	// follow-up Device() call will surface the truth either way.
	if r.Links != nil {
		if err := r.Links.EnsureLink(spec.Name); err != nil {
			log.Warn("reconcile: ensure link", "interface", spec.Name, "err", err)
			res.Errors = append(res.Errors, err)
		}
		if spec.Address.IsValid() {
			if err := r.Links.EnsureAddress(spec.Name, spec.Address); err != nil {
				log.Warn("reconcile: ensure address", "interface", spec.Name, "err", err)
				res.Errors = append(res.Errors, err)
			}
		}
		if err := r.Links.EnsureUp(spec.Name); err != nil {
			log.Warn("reconcile: link up", "interface", spec.Name, "err", err)
			res.Errors = append(res.Errors, err)
		}
	}

	live, err := r.Client.Device(spec.Name)
	if err != nil {
		// Device still not visible after the rtnetlink pass — log and
		// fall through with a synthetic empty device so the diff below
		// treats every DB peer as "added". ConfigureDevice will then
		// either succeed (link came up between the two calls) or fail
		// loudly.
		log.Info("reconcile: device not live, treating as fresh",
			"interface", spec.Name, "err", err)
		live = &Device{Name: spec.Name}
	}

	liveByKey := make(map[string]Peer, len(live.Peers))
	for _, p := range live.Peers {
		liveByKey[p.PublicKey] = p
	}

	var peerCfgs []PeerConfig
	seen := make(map[string]struct{}, len(spec.Peers))
	for _, want := range spec.Peers {
		seen[want.PublicKey] = struct{}{}
		have, exists := liveByKey[want.PublicKey]
		if !exists {
			res.Added = append(res.Added, want.PublicKey)
			peerCfgs = append(peerCfgs, peerConfigFromSpec(want, true))
			continue
		}
		if !peerMatches(have, want) {
			res.Updated = append(res.Updated, want.PublicKey)
			peerCfgs = append(peerCfgs, peerConfigFromSpec(want, true))
		}
	}
	for pubkey := range liveByKey {
		if _, ok := seen[pubkey]; ok {
			continue
		}
		res.Removed = append(res.Removed, pubkey)
		peerCfgs = append(peerCfgs, PeerConfig{PublicKey: pubkey, Remove: true})
	}

	// Nothing to do — skip the netlink round-trip entirely.
	if len(peerCfgs) == 0 && live.ListenPort == spec.ListenPort && live.Name != "" {
		return res
	}

	cfg := Config{
		PrivateKey:   spec.PrivateKey,
		ReplacePeers: false,
		Peers:        peerCfgs,
	}
	if spec.ListenPort != 0 && spec.ListenPort != live.ListenPort {
		p := spec.ListenPort
		cfg.ListenPort = &p
	}
	if err := r.Client.ConfigureDevice(spec.Name, cfg); err != nil {
		log.Error("reconcile: configure device", "interface", spec.Name, "err", err)
		res.Errors = append(res.Errors, err)
		return res
	}
	log.Info("reconcile: applied",
		"interface", spec.Name,
		"added", len(res.Added), "removed", len(res.Removed), "updated", len(res.Updated))
	return res
}

func peerConfigFromSpec(p PeerSpec, replaceAllowed bool) PeerConfig {
	return PeerConfig{
		PublicKey:           p.PublicKey,
		PresharedKey:        p.PresharedKey,
		Endpoint:            p.Endpoint,
		AllowedIPs:          append([]netip.Prefix(nil), p.AllowedIPs...),
		PersistentKeepAlive: p.Keepalive,
		Replace:             replaceAllowed,
	}
}

// peerMatches reports whether the live peer matches the desired spec
// closely enough that no kernel-side update is needed. We don't compare
// transient counters (RxBytes, LastHandshake) — only the configured knobs.
func peerMatches(have Peer, want PeerSpec) bool {
	if have.Endpoint != want.Endpoint {
		return false
	}
	if !prefixesEqual(have.AllowedIPs, want.AllowedIPs) {
		return false
	}
	if !bytesEqual(have.PresharedKey, want.PresharedKey) {
		return false
	}
	if want.Keepalive != nil && have.PersistentKeepAlive != *want.Keepalive {
		return false
	}
	return true
}

func prefixesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[netip.Prefix]struct{}, len(a))
	for _, p := range a {
		set[p] = struct{}{}
	}
	for _, p := range b {
		if _, ok := set[p]; !ok {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
