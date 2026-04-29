package userspace

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestCapabilitiesMissingRequiredEmptyWhenAllPresent(t *testing.T) {
	c := Capabilities{
		HasKernelBTF:  true,
		HasRingbuf:    true,
		HasLPMTrie:    true,
		HasPerCPUHash: true,
	}
	if err := c.MissingRequired(); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if got := c.MissingFeatures(); len(got) != 0 {
		t.Fatalf("expected empty missing list, got %v", got)
	}
}

func TestCapabilitiesMissingRequiredOmitsBTF(t *testing.T) {
	// Missing BTF must NOT be treated as load-blocking — rules.c
	// compiles without CO-RE so the program loads fine either way.
	c := Capabilities{
		HasKernelBTF:  false,
		HasRingbuf:    true,
		HasLPMTrie:    true,
		HasPerCPUHash: true,
	}
	if err := c.MissingRequired(); err != nil {
		t.Fatalf("BTF-less kernel should not be fatal, got %v", err)
	}
}

func TestCapabilitiesMissingRequiredReportsEachGap(t *testing.T) {
	cases := []struct {
		name   string
		caps   Capabilities
		expect string
	}{
		{
			name:   "no ringbuf",
			caps:   Capabilities{HasLPMTrie: true, HasPerCPUHash: true},
			expect: "RINGBUF",
		},
		{
			name:   "no lpm",
			caps:   Capabilities{HasRingbuf: true, HasPerCPUHash: true},
			expect: "LPM_TRIE",
		},
		{
			name:   "no percpu hash",
			caps:   Capabilities{HasRingbuf: true, HasLPMTrie: true},
			expect: "PERCPU_HASH",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.caps.MissingRequired()
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("error %q missing %q", err.Error(), tc.expect)
			}
		})
	}
}

func TestCapabilitiesMissingRequiredListsAllWhenNothingSupported(t *testing.T) {
	c := Capabilities{}
	err := c.MissingRequired()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"RINGBUF", "LPM_TRIE", "PERCPU_HASH"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestCapabilitiesSummary(t *testing.T) {
	c := Capabilities{HasRingbuf: true, HasLPMTrie: true}
	got := c.Summary()
	want := []string{"kernel_btf=missing", "ringbuf=ok", "lpm_trie=ok", "percpu_hash=missing"}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("summary %q missing %q", got, w)
		}
	}
}

func TestRunProbeClassification(t *testing.T) {
	// Verifies the three-way classifier: nil → ok (no diag);
	// ErrNotSupported → missing (no diag); other → missing + diag.
	probeErr := errors.New("kaboom")
	cases := []struct {
		name     string
		err      error
		wantOK   bool
		wantDiag bool
	}{
		{"supported", nil, true, false},
		{"unsupported", ebpf.ErrNotSupported, false, false},
		{"unsupported wrapped", wrapf("wrapped: %w", ebpf.ErrNotSupported), false, false},
		{"other error", probeErr, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, diags := runProbe("t", func() error { return tc.err }, nil)
			if got != tc.wantOK {
				t.Fatalf("got ok=%v, want %v", got, tc.wantOK)
			}
			if (len(diags) > 0) != tc.wantDiag {
				t.Fatalf("diag presence: got %v want %v (diags=%v)", len(diags) > 0, tc.wantDiag, diags)
			}
		})
	}
}

// wrapf keeps the test readable; fmt.Errorf("...%w", ...) is the
// production call site this simulates.
func wrapf(format string, args ...any) error {
	return wrapped{format: format, args: args}
}

type wrapped struct {
	format string
	args   []any
}

func (w wrapped) Error() string {
	if len(w.args) == 1 {
		if e, ok := w.args[0].(error); ok {
			return "wrapped: " + e.Error()
		}
	}
	return w.format
}

func (w wrapped) Unwrap() error {
	for _, a := range w.args {
		if e, ok := a.(error); ok {
			return e
		}
	}
	return nil
}

func TestProbeDoesNotPanic(t *testing.T) {
	// Kernel-gated smoke test: on CI workers without BPF support,
	// Probe should still return — populating ProbeErrs for EPERM is
	// acceptable; it must not panic or deadlock.
	c := Probe()
	_ = c.Summary()
	_ = c.MissingRequired()
}
