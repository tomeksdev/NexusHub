package userspace

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestLoadRulesVerifier smoke-tests that the embedded rules.c blob
// survives the kernel verifier. It catches the class of regression
// behind #104, where preview.6/.7 shipped a .c that produced
//
//	program xdp_rules: load program: permission denied:
//	  R7 pointer -= pointer prohibited
//
// or
//
//	program tc_rules_wg0: load program: permission denied:
//	  R3 has pointer with unsupported alu operation,
//	  pointer arithmetic with it prohibited for !root
//
// at every API startup — the loader fell back to NoopSyncer and no
// rule enforced. Before #104 the only signal was journalctl on a
// real host; this test moves the signal into CI.
//
// Skipped (not failed) on:
//   - no kernel BPF (e.g. macOS dev box)
//   - bpf_loop missing (kernel < 5.17)
//   - permission denied on map create (run without CAP_BPF)
//
// Failed on:
//   - any verifier rejection — including the "prohibited for !root"
//     family that masquerades as EACCES but actually means "the
//     verifier said no", because the loader still surfaces them as
//     load-program errors.
func TestLoadRulesVerifier(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("rlimit memlock: %v — kernel-capable runner required", err)
	}

	spec, err := LoadRules()
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Use LoaderOptions{PinPath: ""} so the test never touches
	// /sys/fs/bpf — the kernel is the only resource we exercise.
	loader, err := NewRulesLoaderWithOptions(spec, LoaderOptions{})
	if err == nil {
		defer loader.Close()
		return
	}

	// Kernel features the program legitimately requires. Skip rather
	// than fail when the host lacks them — the loader's own probe
	// will refuse to start in production for the same reason.
	msg := err.Error()
	switch {
	case errors.Is(err, ebpf.ErrNotSupported),
		strings.Contains(msg, "bpf_loop"),
		strings.Contains(msg, "unknown func"),
		strings.Contains(msg, "operation not permitted"),
		strings.Contains(msg, "no kernel support"):
		t.Skipf("kernel lacks a required BPF feature: %v", err)
	}

	// Anything else is a real verifier rejection or a regression we
	// want loud. Surface the full message — the verifier log is the
	// first thing to look at.
	t.Fatalf("rules.o failed to load against the kernel verifier: %v", err)
}
