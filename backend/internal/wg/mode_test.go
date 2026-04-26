package wg

import "testing"

func TestModeFromType(t *testing.T) {
	cases := []struct {
		in   string
		want Mode
	}{
		{"Linux kernel", ModeLinuxKernel},
		{"linux kernel", ModeLinuxKernel},
		{"OpenBSD kernel", ModeLinuxKernel},
		{"Windows kernel", ModeLinuxKernel},
		{"userspace", ModeUserspace},
		{"Userspace", ModeUserspace},
		{"unknown", ModeUnknown},
		{"", ModeUnknown},
	}
	for _, tc := range cases {
		if got := modeFromType(tc.in); got != tc.want {
			t.Errorf("modeFromType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDetectModeUsesDeviceType(t *testing.T) {
	f := NewFakeClient()
	f.SetDevice(&Device{Name: "wg0", Type: "userspace"})
	if got := DetectMode(f, "wg0"); got != ModeUserspace {
		t.Errorf("DetectMode userspace = %q, want %q", got, ModeUserspace)
	}
	f.SetDevice(&Device{Name: "wg1", Type: "Linux kernel"})
	if got := DetectMode(f, "wg1"); got != ModeLinuxKernel {
		t.Errorf("DetectMode kernel = %q, want %q", got, ModeLinuxKernel)
	}
}
