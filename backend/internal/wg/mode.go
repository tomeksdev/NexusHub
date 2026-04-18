package wg

import (
	"os"
	"strings"
)

// Mode reports which WireGuard data-plane is active. LinuxKernel is the
// in-tree driver; Userspace covers boringtun / wireguard-go / wintun-style
// implementations that expose the same netlink API over a tun device. We
// don't need to distinguish *which* userspace impl — the control surface is
// identical, and operational concerns (CPU, MTU tuning) cut the same way.
type Mode string

const (
	ModeLinuxKernel Mode = "linux_kernel"
	ModeUserspace   Mode = "userspace"
	ModeUnknown     Mode = "unknown"
)

// DetectMode decides which data-plane backs a WireGuard device. The
// authoritative signal is wgtypes.DeviceType (plumbed through our Device
// struct as a string) — it tells us exactly what wgctrl connected to. We
// fall back to /sys/module/wireguard so callers that haven't created a
// device yet still get a useful answer at startup.
//
// Pass an empty ifaceName to probe module presence only.
func DetectMode(c Client, ifaceName string) Mode {
	if ifaceName != "" && c != nil {
		if d, err := c.Device(ifaceName); err == nil && d != nil {
			if m := modeFromType(d.Type); m != ModeUnknown {
				return m
			}
		}
	}
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		return ModeLinuxKernel
	}
	return ModeUnknown
}

// modeFromType maps the wgtypes.DeviceType string form to our Mode. The
// wgtypes strings are stable ("Linux kernel", "OpenBSD kernel", "FreeBSD
// kernel", "Windows kernel", "unknown") — anything not matching "kernel"
// is treated as userspace.
func modeFromType(t string) Mode {
	if t == "" {
		return ModeUnknown
	}
	lower := strings.ToLower(t)
	if strings.Contains(lower, "linux") && strings.Contains(lower, "kernel") {
		return ModeLinuxKernel
	}
	if strings.Contains(lower, "kernel") {
		// Non-Linux kernel drivers also count as kernel-mode for our
		// performance/tuning purposes; we collapse them under the same
		// flag and let callers branch on OS if they need finer detail.
		return ModeLinuxKernel
	}
	if strings.Contains(lower, "userspace") {
		return ModeUserspace
	}
	return ModeUnknown
}
