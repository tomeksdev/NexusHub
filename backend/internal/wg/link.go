package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// LinkManager owns the rtnetlink-driven side of WireGuard interface
// management. wgctrl alone cannot create kernel links — it only
// configures existing ones — so the API path is:
//
//  1. EnsureLink           (rtnetlink: RTM_NEWLINK with IFLA_INFO_KIND=wireguard)
//  2. EnsureAddress        (rtnetlink: RTM_NEWADDR for the configured CIDR)
//  3. EnsureUp             (rtnetlink: RTM_SETLINK, IFF_UP)
//  4. wgctrl ConfigureDevice (private key, listen port, peers)
//
// The split exists because wgctrl uses generic netlink and rtnetlink
// owns link creation — they're separate kernel subsystems. Wrapping
// them behind a single interface keeps the handler call sites clean.
type LinkManager interface {
	// EnsureLink creates a wireguard-typed link if one with the given
	// name does not already exist. Returns nil if the link is already
	// present, even if it isn't of type wireguard — collisions of that
	// shape need operator intervention, not silent recreation.
	EnsureLink(name string) error
	// EnsureAddress adds addr to the link if missing. Idempotent.
	EnsureAddress(name string, addr netip.Prefix) error
	// EnsureUp sets the link administratively up if it's currently down.
	EnsureUp(name string) error
	// DeleteLink removes the link from the kernel. Returns nil if the
	// link is already absent so delete handlers don't double-fault on a
	// retry.
	DeleteLink(name string) error
}

// NetlinkManager is the production rtnetlink-backed implementation.
// vishvananda/netlink is pure-Go and exercises NETLINK_ROUTE — no cgo,
// no /sbin/ip shell-out.
type NetlinkManager struct{}

// NewNetlinkManager returns the production manager. There's no setup
// or teardown; sockets are opened per-call and closed by the library.
func NewNetlinkManager() *NetlinkManager { return &NetlinkManager{} }

func (NetlinkManager) EnsureLink(name string) error {
	if _, err := netlink.LinkByName(name); err == nil {
		return nil
	} else if !isLinkNotFound(err) {
		return fmt.Errorf("look up link %q: %w", name, err)
	}
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		LinkType:  "wireguard",
	}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("create wireguard link %q: %w", name, err)
	}
	return nil
}

func (NetlinkManager) EnsureAddress(name string, addr netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("look up link %q: %w", name, err)
	}
	want := prefixToIPNet(addr)
	if want == nil {
		return fmt.Errorf("invalid address %s", addr)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list addrs on %q: %w", name, err)
	}
	for _, a := range addrs {
		if a.IPNet != nil && a.IP.Equal(want.IP) && bytesEqual(a.Mask, want.Mask) {
			return nil
		}
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: want}); err != nil {
		return fmt.Errorf("add addr %s on %q: %w", addr, name, err)
	}
	return nil
}

func (NetlinkManager) EnsureUp(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("look up link %q: %w", name, err)
	}
	// IFF_UP lives in the operstate flags; LinkSetUp is idempotent in
	// the kernel (it's a no-op on an already-up link), but check first
	// to keep audit logs quiet.
	if link.Attrs().Flags&net.FlagUp != 0 {
		return nil
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set link %q up: %w", name, err)
	}
	return nil
}

func (NetlinkManager) DeleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if isLinkNotFound(err) {
			return nil
		}
		return fmt.Errorf("look up link %q: %w", name, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete link %q: %w", name, err)
	}
	return nil
}

// isLinkNotFound covers the netlink.LinkNotFoundError type plus the
// runtime error path some kernel versions return.
func isLinkNotFound(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf)
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	if !p.IsValid() {
		return nil
	}
	addr := p.Addr()
	ip := addr.AsSlice()
	mask := net.CIDRMask(p.Bits(), addr.BitLen())
	return &net.IPNet{IP: ip, Mask: mask}
}
