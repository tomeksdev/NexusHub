package wg

import (
	"net/netip"
	"sync"
)

// FakeLinkManager is the in-memory test double for LinkManager. It
// records every operation against a per-link state map so tests can
// assert on what the handler attempted without bringing up a kernel.
type FakeLinkManager struct {
	mu    sync.Mutex
	links map[string]*fakeLink
	// Errors injected per operation. nil = success. Set by tests when
	// they want to exercise the error paths.
	EnsureLinkErr    error
	EnsureAddressErr error
	EnsureUpErr      error
	DeleteLinkErr    error
}

type fakeLink struct {
	name      string
	addresses []netip.Prefix
	up        bool
}

func NewFakeLinkManager() *FakeLinkManager {
	return &FakeLinkManager{links: map[string]*fakeLink{}}
}

func (f *FakeLinkManager) EnsureLink(name string) error {
	if f.EnsureLinkErr != nil {
		return f.EnsureLinkErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.links[name]; !ok {
		f.links[name] = &fakeLink{name: name}
	}
	return nil
}

func (f *FakeLinkManager) EnsureAddress(name string, addr netip.Prefix) error {
	if f.EnsureAddressErr != nil {
		return f.EnsureAddressErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	link := f.links[name]
	if link == nil {
		link = &fakeLink{name: name}
		f.links[name] = link
	}
	for _, a := range link.addresses {
		if a == addr {
			return nil
		}
	}
	link.addresses = append(link.addresses, addr)
	return nil
}

func (f *FakeLinkManager) EnsureUp(name string) error {
	if f.EnsureUpErr != nil {
		return f.EnsureUpErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if link, ok := f.links[name]; ok {
		link.up = true
	}
	return nil
}

func (f *FakeLinkManager) DeleteLink(name string) error {
	if f.DeleteLinkErr != nil {
		return f.DeleteLinkErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.links, name)
	return nil
}

// HasLink reports whether name has been EnsureLink'd. Test helper.
func (f *FakeLinkManager) HasLink(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.links[name]
	return ok
}

// Addresses returns the current address set for name, in insertion order.
func (f *FakeLinkManager) Addresses(name string) []netip.Prefix {
	f.mu.Lock()
	defer f.mu.Unlock()
	if link, ok := f.links[name]; ok {
		out := make([]netip.Prefix, len(link.addresses))
		copy(out, link.addresses)
		return out
	}
	return nil
}

// IsUp reports whether the link has had EnsureUp called on it.
func (f *FakeLinkManager) IsUp(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if link, ok := f.links[name]; ok {
		return link.up
	}
	return false
}
