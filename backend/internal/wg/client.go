package wg

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Client is the thin surface over wgctrl that our handlers talk to.
// Everything we need for peer CRUD is expressible in terms of Configure;
// reads go through Device. Keeping this narrow makes the FakeClient trivial
// and the KernelClient a ~20-line wrapper.
type Client interface {
	// Device returns the current live state of a named interface.
	Device(name string) (*Device, error)
	// ConfigureDevice applies a full config. ReplacePeers decides whether
	// the supplied Peers list replaces or merges with existing ones.
	ConfigureDevice(name string, cfg Config) error
	// Close releases any open netlink sockets. Safe to call on the zero
	// value; the Kernel impl forwards to wgctrl.
	Close() error
}

// Device mirrors the subset of wgtypes.Device we actually consume.
type Device struct {
	Name       string
	PublicKey  string
	ListenPort int
	// Type is the wgtypes.DeviceType string — "Linux kernel", "OpenBSD
	// kernel", "Windows kernel", "userspace", or empty on unknown. We keep
	// the raw string to avoid re-importing wgtypes from every caller.
	Type  string
	Peers []Peer
}

// Peer is our transport-agnostic peer view.
type Peer struct {
	PublicKey         string
	PresharedKey      []byte // may be nil
	Endpoint          string
	AllowedIPs        []netip.Prefix
	PersistentKeepAlive time.Duration
	LastHandshake     time.Time
	RxBytes           int64
	TxBytes           int64
}

// Config is the small subset of wgtypes.Config we ever need to write.
// ReplacePeers=true → the device's peer list becomes exactly Peers.
// ReplacePeers=false → each entry is merged or (if Remove is set) deleted.
type Config struct {
	PrivateKey   []byte // nil → leave unchanged
	ListenPort   *int
	ReplacePeers bool
	Peers        []PeerConfig
}

type PeerConfig struct {
	PublicKey         string
	PresharedKey      []byte
	Endpoint          string
	AllowedIPs        []netip.Prefix
	PersistentKeepAlive *time.Duration
	Remove            bool
	Replace           bool
}

// ----- Kernel-backed client ------------------------------------------------

// KernelClient is the real wgctrl-backed Client. It's instantiated by main
// in production; tests use FakeClient.
type KernelClient struct {
	c *wgctrl.Client
}

// NewKernelClient opens a netlink client; callers defer Close().
func NewKernelClient() (*KernelClient, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &KernelClient{c: c}, nil
}

func (k *KernelClient) Device(name string) (*Device, error) {
	d, err := k.c.Device(name)
	if err != nil {
		return nil, err
	}
	out := &Device{
		Name:       d.Name,
		PublicKey:  d.PublicKey.String(),
		ListenPort: d.ListenPort,
		Type:       d.Type.String(),
	}
	for _, p := range d.Peers {
		out.Peers = append(out.Peers, kernelPeerToOurs(p))
	}
	return out, nil
}

func (k *KernelClient) ConfigureDevice(name string, cfg Config) error {
	wc, err := toWgtypesConfig(cfg)
	if err != nil {
		return err
	}
	return k.c.ConfigureDevice(name, wc)
}

func (k *KernelClient) Close() error {
	if k == nil || k.c == nil {
		return nil
	}
	return k.c.Close()
}

func kernelPeerToOurs(p wgtypes.Peer) Peer {
	out := Peer{
		PublicKey:           p.PublicKey.String(),
		PersistentKeepAlive: p.PersistentKeepaliveInterval,
		LastHandshake:       p.LastHandshakeTime,
		RxBytes:             p.ReceiveBytes,
		TxBytes:             p.TransmitBytes,
	}
	if (p.PresharedKey != wgtypes.Key{}) {
		k := p.PresharedKey
		out.PresharedKey = k[:]
	}
	if p.Endpoint != nil {
		out.Endpoint = p.Endpoint.String()
	}
	for _, ipnet := range p.AllowedIPs {
		if pfx, ok := ipnetToPrefix(ipnet); ok {
			out.AllowedIPs = append(out.AllowedIPs, pfx)
		}
	}
	return out
}

func ipnetToPrefix(n net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr, ones), true
}

func toWgtypesConfig(cfg Config) (wgtypes.Config, error) {
	out := wgtypes.Config{
		ReplacePeers: cfg.ReplacePeers,
		ListenPort:   cfg.ListenPort,
	}
	if len(cfg.PrivateKey) > 0 {
		k, err := wgtypes.NewKey(cfg.PrivateKey)
		if err != nil {
			return wgtypes.Config{}, err
		}
		out.PrivateKey = &k
	}
	for _, pc := range cfg.Peers {
		wp, err := toWgtypesPeer(pc)
		if err != nil {
			return wgtypes.Config{}, err
		}
		out.Peers = append(out.Peers, wp)
	}
	return out, nil
}

func toWgtypesPeer(p PeerConfig) (wgtypes.PeerConfig, error) {
	pub, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, err
	}
	out := wgtypes.PeerConfig{
		PublicKey:                   pub,
		Remove:                      p.Remove,
		ReplaceAllowedIPs:           p.Replace,
		PersistentKeepaliveInterval: p.PersistentKeepAlive,
	}
	if len(p.PresharedKey) == PresharedKeyLen {
		k, err := wgtypes.NewKey(p.PresharedKey)
		if err == nil {
			out.PresharedKey = &k
		}
	}
	if p.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, err
		}
		out.Endpoint = addr
	}
	for _, pfx := range p.AllowedIPs {
		ipnet := net.IPNet{
			IP:   pfx.Addr().AsSlice(),
			Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen()),
		}
		out.AllowedIPs = append(out.AllowedIPs, ipnet)
	}
	return out, nil
}

// ----- In-memory fake for tests --------------------------------------------

// FakeClient satisfies Client without touching the kernel. All state lives
// in a map keyed by interface name, guarded by a mutex.
//
// It is deliberately permissive — it does not validate that a peer's
// public key decodes to 32 bytes, for example, so tests can feed it bad
// data to exercise error paths. Wherever the kernel would reject input
// synchronously we document that here and add a matching check in tests
// that need it.
type FakeClient struct {
	mu      sync.Mutex
	devices map[string]*Device
}

func NewFakeClient() *FakeClient {
	return &FakeClient{devices: map[string]*Device{}}
}

// SetDevice seeds the fake with a device. Used by test setup.
func (f *FakeClient) SetDevice(d *Device) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *d
	cp.Peers = append([]Peer(nil), d.Peers...)
	f.devices[d.Name] = &cp
}

func (f *FakeClient) Device(name string) (*Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.devices[name]
	if !ok {
		return nil, errors.New("wg: device not found: " + name)
	}
	cp := *d
	cp.Peers = append([]Peer(nil), d.Peers...)
	return &cp, nil
}

func (f *FakeClient) ConfigureDevice(name string, cfg Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.devices[name]
	if !ok {
		return errors.New("wg: device not found: " + name)
	}
	if cfg.ListenPort != nil {
		d.ListenPort = *cfg.ListenPort
	}
	if cfg.ReplacePeers {
		d.Peers = nil
	}
	for _, pc := range cfg.Peers {
		if pc.Remove {
			d.Peers = removePeer(d.Peers, pc.PublicKey)
			continue
		}
		d.Peers = upsertPeer(d.Peers, pc)
	}
	return nil
}

func (f *FakeClient) Close() error { return nil }

func removePeer(peers []Peer, pubkey string) []Peer {
	out := peers[:0]
	for _, p := range peers {
		if p.PublicKey != pubkey {
			out = append(out, p)
		}
	}
	return out
}

func upsertPeer(peers []Peer, pc PeerConfig) []Peer {
	keepalive := time.Duration(0)
	if pc.PersistentKeepAlive != nil {
		keepalive = *pc.PersistentKeepAlive
	}
	np := Peer{
		PublicKey:           pc.PublicKey,
		PresharedKey:        pc.PresharedKey,
		Endpoint:            pc.Endpoint,
		AllowedIPs:          pc.AllowedIPs,
		PersistentKeepAlive: keepalive,
	}
	for i, p := range peers {
		if p.PublicKey == pc.PublicKey {
			peers[i] = np
			return peers
		}
	}
	return append(peers, np)
}
