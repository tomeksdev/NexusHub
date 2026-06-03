package handler

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomeksdev/NexusHub/backend/internal/diag"
	"github.com/tomeksdev/NexusHub/backend/internal/wg"
)

// stubbornPortClient lets a test pin the *kernel-reported* ListenPort
// to a value of its choosing, regardless of what ConfigureDevice asked
// for. This emulates the real-world #83 P0 case: the kernel UDP bind
// for a privileged port (<1024) silently fails over to an ephemeral
// port when the process lacks CAP_NET_BIND_SERVICE, even though
// ConfigureDevice itself returns no error.
type stubbornPortClient struct {
	mu      sync.Mutex
	fixed   int // what Device() reports for ListenPort
	yields  bool
	configs []wg.Config // every config payload ConfigureDevice saw
}

func (c *stubbornPortClient) Device(name string) (*wg.Device, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &wg.Device{Name: name, ListenPort: c.fixed}, nil
}

func (c *stubbornPortClient) ConfigureDevice(name string, cfg wg.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configs = append(c.configs, cfg)
	if c.yields && cfg.ListenPort != nil {
		c.fixed = *cfg.ListenPort
	}
	return nil
}

func (c *stubbornPortClient) Close() error { return nil }

func newTestInterfaceHandler(client wg.Client) (*InterfaceHandler, *diag.KernelWarnings) {
	kw := diag.New(8, time.Minute)
	return &InterfaceHandler{Client: client, KernelWarnings: kw}, kw
}

// Happy path: live port already matches, helper should not retry and
// not push any warning.
func TestEnsureKernelListenPortNoDrift(t *testing.T) {
	client := &stubbornPortClient{fixed: 51820}
	h, kw := newTestInterfaceHandler(client)
	ensureKernelListenPort(context.Background(), h, "wg0", 51820, "wg.create.port_drift")
	if got := len(client.configs); got != 0 {
		t.Errorf("expected 0 ConfigureDevice calls (no drift), got %d", got)
	}
	if got := len(kw.List()); got != 0 {
		t.Errorf("expected 0 warnings, got %d", got)
	}
}

// Drift on first read; retry-with-port-only succeeds. Warning ring
// should stay empty.
func TestEnsureKernelListenPortDriftThenRetrySucceeds(t *testing.T) {
	client := &stubbornPortClient{fixed: 54321, yields: true}
	h, kw := newTestInterfaceHandler(client)
	ensureKernelListenPort(context.Background(), h, "wg0", 443, "wg.create.port_drift")
	if got := len(client.configs); got != 1 {
		t.Fatalf("expected 1 retry ConfigureDevice call, got %d", got)
	}
	cfg := client.configs[0]
	if cfg.ListenPort == nil || *cfg.ListenPort != 443 {
		t.Errorf("retry payload should carry ListenPort=&443, got %v", cfg.ListenPort)
	}
	if cfg.PrivateKey != nil {
		t.Errorf("retry payload should be port-only, got PrivateKey set")
	}
	if got := len(kw.List()); got != 0 {
		t.Errorf("expected 0 warnings after successful retry, got %d", got)
	}
}

// Drift persists even after retry — the kernel keeps the random port.
// This is the CAP_NET_BIND_SERVICE-missing case in #83 P0.
// Helper must push an actionable warning into the ring naming the
// most common cause.
func TestEnsureKernelListenPortDriftPersists(t *testing.T) {
	client := &stubbornPortClient{fixed: 54321, yields: false}
	h, kw := newTestInterfaceHandler(client)
	ensureKernelListenPort(context.Background(), h, "wg0", 443, "wg.create.port_drift")
	if got := len(client.configs); got != 1 {
		t.Fatalf("expected 1 retry ConfigureDevice call, got %d", got)
	}
	warnings := kw.List()
	if len(warnings) != 1 {
		t.Fatalf("expected 1 kernel warning, got %d", len(warnings))
	}
	w := warnings[0]
	if w.Origin != "wg.create.port_drift" {
		t.Errorf("wrong origin: %q", w.Origin)
	}
	if w.Iface != "wg0" {
		t.Errorf("wrong iface: %q", w.Iface)
	}
	for _, want := range []string{"CAP_NET_BIND_SERVICE", "443", "54321", "scripts/install.sh"} {
		if !strings.Contains(w.Message, want) {
			t.Errorf("warning message missing %q: %s", want, w.Message)
		}
	}
}

// want=0 means "operator didn't pick a port; let kernel choose" — the
// helper must not retry or warn in that case.
func TestEnsureKernelListenPortZeroWant(t *testing.T) {
	client := &stubbornPortClient{fixed: 54321}
	h, kw := newTestInterfaceHandler(client)
	ensureKernelListenPort(context.Background(), h, "wg0", 0, "wg.create.port_drift")
	if got := len(client.configs); got != 0 {
		t.Errorf("expected 0 ConfigureDevice calls when want=0, got %d", got)
	}
	if got := len(kw.List()); got != 0 {
		t.Errorf("expected 0 warnings when want=0, got %d", got)
	}
}

// Nil client (deployment shape where we don't manage the kernel
// directly) → helper is a no-op rather than nil-panic.
func TestEnsureKernelListenPortNilClient(t *testing.T) {
	h := &InterfaceHandler{}
	ensureKernelListenPort(context.Background(), h, "wg0", 443, "wg.create.port_drift")
}
