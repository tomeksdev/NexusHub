package userspace

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
)

// Capabilities is a snapshot of kernel-side features the rule loader
// cares about. Fields are meant to be read by the caller before
// NewRulesLoader so startup can emit a useful diagnostic — cilium/ebpf's
// load-time error ("could not load program: invalid argument") is
// accurate but hides which missing feature caused the failure.
//
// v2.1 — LPM trie is gone (the engine no longer uses LPM_TRIE maps).
// bpf_loop replaces it as the load-bearing kernel feature: rules.c
// invokes it per packet to iterate the active rule table.
type Capabilities struct {
	// HasKernelBTF reports whether the running kernel exposes BTF at
	// /sys/kernel/btf/vmlinux. rules.c compiles without CO-RE so the
	// program loads either way — the flag is informational.
	HasKernelBTF bool

	// HasRingbuf reports whether BPF_MAP_TYPE_RINGBUF is supported
	// (kernel 5.8+). log_events is a ringbuf, so a false here means
	// NewRulesLoader will fail.
	HasRingbuf bool

	// HasPerCPUHash reports whether BPF_MAP_TYPE_PERCPU_HASH is
	// supported (kernel 4.6+). Required for rate_state_v4/v6.
	HasPerCPUHash bool

	// HasBPFLoop reports whether the bpf_loop helper is available
	// (kernel 5.17+). v2.1 rules.c calls bpf_loop on every packet to
	// iterate the active rule table; without it the program won't
	// load. This is the load-bearing capability that v2.0 didn't need.
	HasBPFLoop bool

	// ProbeErrs collects errors that were neither "supported" nor
	// "not supported" — typically EPERM when the process lacks CAP_BPF
	// or CAP_SYS_ADMIN.
	ProbeErrs []error
}

// Probe tests the running kernel for every feature the loader
// exercises.
func Probe() Capabilities {
	var c Capabilities
	c.HasKernelBTF, c.ProbeErrs = runProbe("btf", btfProbe, c.ProbeErrs)
	c.HasRingbuf, c.ProbeErrs = runProbe("ringbuf", mapProbe(ebpf.RingBuf), c.ProbeErrs)
	c.HasPerCPUHash, c.ProbeErrs = runProbe("percpu_hash", mapProbe(ebpf.PerCPUHash), c.ProbeErrs)
	c.HasBPFLoop, c.ProbeErrs = runProbe("bpf_loop", bpfLoopProbe, c.ProbeErrs)
	return c
}

// MissingRequired returns a descriptive error listing every feature
// whose absence prevents the loader from starting, or nil when every
// required feature is present.
func (c Capabilities) MissingRequired() error {
	missing := c.missingList()
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("required kernel features missing: %s", strings.Join(missing, ", "))
}

// MissingFeatures returns the names of load-blocking features that
// Probe found unavailable.
func (c Capabilities) MissingFeatures() []string {
	return c.missingList()
}

func (c Capabilities) missingList() []string {
	var missing []string
	if !c.HasRingbuf {
		missing = append(missing, "BPF_MAP_TYPE_RINGBUF (kernel 5.8+)")
	}
	if !c.HasPerCPUHash {
		missing = append(missing, "BPF_MAP_TYPE_PERCPU_HASH (kernel 4.6+)")
	}
	if !c.HasBPFLoop {
		missing = append(missing, "bpf_loop helper (kernel 5.17+)")
	}
	return missing
}

// Summary returns a single-line human-readable string for startup logs.
func (c Capabilities) Summary() string {
	parts := []string{
		feat("kernel_btf", c.HasKernelBTF),
		feat("ringbuf", c.HasRingbuf),
		feat("percpu_hash", c.HasPerCPUHash),
		feat("bpf_loop", c.HasBPFLoop),
	}
	return strings.Join(parts, " ")
}

func feat(name string, ok bool) string {
	if ok {
		return name + "=ok"
	}
	return name + "=missing"
}

// runProbe invokes one feature probe and classifies the result:
//   - nil          → supported (returns true)
//   - NotSupported → unsupported (returns false, no diag)
//   - other        → supported=false AND collected as diagnostic
func runProbe(name string, fn func() error, diags []error) (bool, []error) {
	err := fn()
	if err == nil {
		return true, diags
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		return false, diags
	}
	return false, append(diags, fmt.Errorf("%s: %w", name, err))
}

func mapProbe(mt ebpf.MapType) func() error {
	return func() error { return features.HaveMapType(mt) }
}

// btfProbe wraps btf.LoadKernelSpec so tests can substitute it.
var btfProbe = func() error {
	_, err := btf.LoadKernelSpec()
	return err
}

// bpfLoopProbe checks for BPF_FUNC_loop by attempting a HaveProgramHelper
// probe with a tracepoint program. Reassignable for tests.
var bpfLoopProbe = func() error {
	return features.HaveProgramHelper(ebpf.SocketFilter, asm.FnLoop)
}
