package userspace

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// lpmV4Key mirrors struct lpm_v4_key in ebpf/headers/nexushub.h.
//
// The on-wire layout is:
//
//	offset 0..3  : prefixlen (LE u32, value in BITS, 0..32)
//	offset 4..7  : IPv4 address (network byte order)
//
// Kernel LPM_TRIE treats the address bytes as a big-endian bit string
// and walks prefixlen bits into the trie. The Go side writes the
// address in network order so what the kernel sees matches the wire.
type lpmV4Key struct {
	PrefixLen uint32
	Addr      [4]byte
}

func (k lpmV4Key) MarshalBinary() ([]byte, error) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:4], k.PrefixLen)
	copy(b[4:8], k.Addr[:])
	return b, nil
}

// lpmV6Key mirrors struct lpm_v6_key. 128-bit address, same rules.
type lpmV6Key struct {
	PrefixLen uint32
	Addr      [16]byte
}

func (k lpmV6Key) MarshalBinary() ([]byte, error) {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[0:4], k.PrefixLen)
	copy(b[4:20], k.Addr[:])
	return b, nil
}

// prefixToLPMv4 converts an IPv4 netip.Prefix to the kernel's LPM key.
// The kernel requires the prefix be canonical (host bits zero); we do
// not enforce that here because netip.ParsePrefix accepts either form
// and callers building policies may want 10.8.0.1/24 to match just
// that address. Use prefix.Masked() upstream if you need a network.
func prefixToLPMv4(p netip.Prefix) (lpmV4Key, error) {
	if !p.Addr().Is4() {
		return lpmV4Key{}, fmt.Errorf("expected IPv4 prefix, got %s", p)
	}
	if p.Bits() < 0 || p.Bits() > 32 {
		return lpmV4Key{}, fmt.Errorf("invalid prefixlen %d", p.Bits())
	}
	return lpmV4Key{
		PrefixLen: uint32(p.Bits()),
		Addr:      p.Addr().As4(),
	}, nil
}

func prefixToLPMv6(p netip.Prefix) (lpmV6Key, error) {
	if !p.Addr().Is6() || p.Addr().Is4In6() {
		return lpmV6Key{}, fmt.Errorf("expected IPv6 prefix, got %s", p)
	}
	if p.Bits() < 0 || p.Bits() > 128 {
		return lpmV6Key{}, fmt.Errorf("invalid prefixlen %d", p.Bits())
	}
	return lpmV6Key{
		PrefixLen: uint32(p.Bits()),
		Addr:      p.Addr().As16(),
	}, nil
}

// addrToLPMv4 is the common /32 shortcut for the blocklist path, where
// most entries are single hosts.
func addrToLPMv4(a netip.Addr) (lpmV4Key, error) {
	if !a.Is4() {
		return lpmV4Key{}, fmt.Errorf("expected IPv4 addr, got %s", a)
	}
	return lpmV4Key{PrefixLen: 32, Addr: a.As4()}, nil
}

func addrToLPMv6(a netip.Addr) (lpmV6Key, error) {
	if !a.Is6() || a.Is4In6() {
		return lpmV6Key{}, fmt.Errorf("expected IPv6 addr, got %s", a)
	}
	return lpmV6Key{PrefixLen: 128, Addr: a.As16()}, nil
}
