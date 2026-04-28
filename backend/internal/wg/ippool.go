package wg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// ErrPoolExhausted means every usable address in the interface CIDR has
// been taken. The caller can surface this directly to operators.
var ErrPoolExhausted = errors.New("interface ip pool exhausted")

// AllocateIP returns the next free /32 (or /128) address inside ifaceCIDR,
// skipping the network address, the broadcast address (IPv4 only), and the
// interface's own assigned address. Used holds whatever is already taken
// by existing peers on that interface.
//
// The interface-side address comes from ifaceCIDR.Addr(); the mask part
// is what we scan within.
//
// IPv6 uses the same scan — there's no "broadcast" to skip, but because
// peer /128 addresses are individually assigned we still iterate one at a
// time. For a /64 the scan is effectively unbounded; callers supplying
// huge pools should pre-filter used into a set, which we already do.
func AllocateIP(ifaceCIDR netip.Prefix, used []netip.Addr) (netip.Addr, error) {
	if !ifaceCIDR.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid interface cidr")
	}
	network := ifaceCIDR.Masked().Addr()
	bits := ifaceCIDR.Bits()
	isV4 := network.Is4()

	usedSet := make(map[netip.Addr]struct{}, len(used)+2)
	for _, u := range used {
		usedSet[u] = struct{}{}
	}
	// Reserve the network address and the interface's own address.
	usedSet[network] = struct{}{}
	usedSet[ifaceCIDR.Addr()] = struct{}{}
	if isV4 {
		if b, ok := broadcast(ifaceCIDR); ok {
			usedSet[b] = struct{}{}
		}
	}

	cur := network
	// Upper bound on scan iterations to keep this deterministic even on
	// bad input. A /16 would be 65k — small enough to walk; a /8 is too
	// big, but an operator pasting a /8 into WG_ADDRESS is an error we
	// want to surface as pool-exhausted rather than hang.
	maxScan := 1 << 20
	for i := 0; i < maxScan; i++ {
		next, ok := advance(cur)
		if !ok {
			return netip.Addr{}, ErrPoolExhausted
		}
		cur = next
		if !ifaceCIDR.Contains(cur) {
			return netip.Addr{}, ErrPoolExhausted
		}
		if _, taken := usedSet[cur]; taken {
			continue
		}
		// Skip the broadcast even if mask is odd — already in usedSet for v4.
		_ = bits
		return cur, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// advance returns ip + 1, propagating carry through every byte.
func advance(a netip.Addr) (netip.Addr, bool) {
	buf := a.As16()
	if a.Is4() {
		v := binary.BigEndian.Uint32(buf[12:])
		if v == 0xFFFFFFFF {
			return netip.Addr{}, false
		}
		binary.BigEndian.PutUint32(buf[12:], v+1)
		return netip.AddrFrom4([4]byte{buf[12], buf[13], buf[14], buf[15]}), true
	}
	for i := 15; i >= 0; i-- {
		buf[i]++
		if buf[i] != 0 {
			return netip.AddrFrom16(buf), true
		}
	}
	return netip.Addr{}, false
}

func broadcast(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() {
		return netip.Addr{}, false
	}
	host := 32 - p.Bits()
	if host <= 0 {
		return netip.Addr{}, false
	}
	ip := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(ip[:]) | ((1 << host) - 1)
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out), true
}
