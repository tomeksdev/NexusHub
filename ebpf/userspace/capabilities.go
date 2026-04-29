package userspace

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
)

// Capabilities is a snapshot of kernel-side features the rule loader
// cares about. Fields are meant to be read by the caller before
// NewRulesLoader so startup can emit a useful diagnostic — cilium/ebpf's
// load-time error ("could not load program: invalid argument") is
// accurate but hides which missing feature caused the failure.
//
// Probe returns the default, cheaply-obtained view. Callers MUST decide
// themselves whether a missing feature is fatal: HasKernelBTF can be
// absent on many production kernels (the compiled .o does not use
// CO-RE relocations), while HasRingbuf is load-bearing because
// log_events is BPF_MAP_TYPE_RINGBUF.
type Capabilities struct {
	// HasKernelBTF reports whether the running kernel exposes BTF at
	// /sys/kernel/btf/vmlinux. rules.c compiles without CO-RE so the
	// program loads either way — the flag is informational, surfacing
	// that the kernel was built without CONFIG_DEBUG_INFO_BTF=y.
	HasKernelBTF bool

	// HasRingbuf reports whether BPF_MAP_TYPE_RINGBUF is supported
	// (kernel 5.8+). log_events is a ringbuf, so a false here means
	// NewRulesLoader will fail; Probe surfaces the gap earlier and
	// with a clearer name than the verifier error.
	HasRingbuf bool

	// HasLPMTrie reports whether BPF_MAP_TYPE_LPM_TRIE is supported
	// (kernel 4.11+). The four rule_src/dst_v4/v6 maps are LPM tries,
	// so this too is load-bearing.
	HasLPMTrie bool

	// HasPerCPUHash reports whether BPF_MAP_TYPE_PERCPU_HASH is
	// supported (kernel 4.6+). Required for rate_state_v4/v6.
	HasPerCPUHash bool

	// ProbeErrs collects errors that were neither "supported" nor
	// "not supported" — typically EPERM when the process lacks CAP_BPF
	// or CAP_SYS_ADMIN. Treat these as diagnostic hints: the real
	// load will fail with the same root cause.
	ProbeErrs []error
}

// Probe tests the running kernel for every feature the loader
// exercises. Safe to call multiple times — cilium/ebpf caches probe
// results internally after the first call.
func Probe() Capabilities {
	var c Capabilities
	c.HasKernelBTF, c.ProbeErrs = runProbe("btf", btfProbe, c.ProbeErrs)
	c.HasRingbuf, c.ProbeErrs = runProbe("ringbuf", mapProbe(ebpf.RingBuf), c.ProbeErrs)
	c.HasLPMTrie, c.ProbeErrs = runProbe("lpm_trie", mapProbe(ebpf.LPMTrie), c.ProbeErrs)
	c.HasPerCPUHash, c.ProbeErrs = runProbe("percpu_hash", mapProbe(ebpf.PerCPUHash), c.ProbeErrs)
	return c
}

// MissingRequired returns a descriptive error listing every feature
// whose absence prevents the loader from starting, or nil when every
// required feature is present. HasKernelBTF is NOT treated as required
// because the compiled program has no CO-RE relocations.
//
// Typical caller:
//
//	caps := userspace.Probe()
//	if err := caps.MissingRequired(); err != nil {
//	    return fmt.Errorf("ebpf kernel check: %w", err)
//	}
func (c Capabilities) MissingRequired() error {
	missing := c.missingList()
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("required kernel features missing: %s", strings.Join(missing, ", "))
}

// MissingFeatures returns the names of load-blocking features that
// Probe found unavailable. The list is stable — callers can match
// specific strings in alerting rules or tests.
func (c Capabilities) MissingFeatures() []string {
	return c.missingList()
}

func (c Capabilities) missingList() []string {
	var missing []string
	if !c.HasRingbuf {
		missing = append(missing, "BPF_MAP_TYPE_RINGBUF (kernel 5.8+)")
	}
	if !c.HasLPMTrie {
		missing = append(missing, "BPF_MAP_TYPE_LPM_TRIE (kernel 4.11+)")
	}
	if !c.HasPerCPUHash {
		missing = append(missing, "BPF_MAP_TYPE_PERCPU_HASH (kernel 4.6+)")
	}
	return missing
}

// Summary returns a single-line human-readable string suitable for
// startup logging. Includes both present and missing features so
// operators can see the full state at a glance.
func (c Capabilities) Summary() string {
	parts := []string{
		feat("kernel_btf", c.HasKernelBTF),
		feat("ringbuf", c.HasRingbuf),
		feat("lpm_trie", c.HasLPMTrie),
		feat("percpu_hash", c.HasPerCPUHash),
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
//   - nil        → supported (returns true)
//   - NotSupported → unsupported (returns false, no diag)
//   - other      → supported=false AND collected as diagnostic
//
// The three-way classification matters: EPERM or a broken /sys mount
// should not silently look the same as "kernel too old".
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

// btfProbe wraps btf.LoadKernelSpec so tests can substitute it. The
// function is reassignable within the package; production callers
// should not touch it.
var btfProbe = func() error {
	_, err := btf.LoadKernelSpec()
	return err
}
