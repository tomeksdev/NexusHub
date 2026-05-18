package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"

	"github.com/tomeksdev/NexusHub/backend/internal/diag"
	baseebpf "github.com/tomeksdev/NexusHub/backend/internal/ebpf"
	"github.com/tomeksdev/NexusHub/backend/internal/ebpfkernel"
	"github.com/tomeksdev/NexusHub/backend/internal/metrics"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

// bpfPinDir is the bpffs subdirectory NexusHub pins maps under. Lives
// directly on /sys/fs/bpf so external tooling (bpftool, the systemd
// nexushub-uninstall handler) finds it at a stable path. Operators
// running multiple NexusHub instances on one host need a downstream
// fix — we don't namespace by listen port today.
const bpfPinDir = "/sys/fs/bpf/nexushub"

// ebpfStack bundles the kernel-side runtime (loader + syncer +
// optional consumer + program attachments). main.go owns the
// lifetime: build at startup, defer Close, hand the syncer to the
// router.
//
// Every field is optional: a host without CAP_BPF, without eth0, or
// without wg0 still produces a usable stack — just one with fewer
// hooks attached. The syncer field is always non-nil because callers
// (handler.NewRouter) treat it as a Syncer interface and the
// NoopSyncer is the cheap fallback.
//
// Runtime attach (AttachTC/DetachTC) is the round-5 fix for the bug
// where Locations created after API startup never got a TC program —
// rules existed in the maps but no hook was running on the new
// interface to consult them. The handlers call AttachTC after
// EnsureUp and DetachTC before the rtnetlink delete.
type ebpfStack struct {
	loader   *userspace.RulesLoader
	syncer   baseebpf.Syncer
	consumer *ebpfkernel.LogConsumer
	logger   *slog.Logger
	warns    *diag.KernelWarnings

	// mu guards tcLinks + xdpLinks. Handlers run on gin's worker
	// pool so concurrent AttachTC calls for two different Locations
	// must be safe.
	mu sync.Mutex
	// tcLinks is keyed by interface name so DetachTC can find the
	// right link without scanning. Maps to ingress only today;
	// egress can grow alongside if needed.
	tcLinks map[string]link.Link
	// xdpLinks is keyed the same way. XDP is env-driven and
	// rarely runtime-attached, but the shape is symmetric.
	xdpLinks map[string]link.Link
}

// startEBPF tries to bring up the kernel datapath. Returns a stack
// where every field may be a no-op equivalent — the caller never has
// to nil-check syncer. Errors are logged, not propagated; the API
// runs DB-only when the kernel can't be reached.
//
// xdpIface stays env-driven (NEXUSHUB_XDP_IFACE) — auto-detecting the
// default-route NIC is a foot-gun on hosts with multiple uplinks.
// tcIfaces is the slice of WireGuard interface names from the DB that
// the caller has already reconciled; we attach the TC program to each
// one. NEXUSHUB_TC_IFACE remains as an override for operators running
// a single hand-managed wg device.
func startEBPF(
	ctx context.Context,
	logs *repository.ConnectionLogRepo,
	xdpIface string, tcIfaces []string,
	warns *diag.KernelWarnings,
	logger *slog.Logger,
) *ebpfStack {
	st := &ebpfStack{
		syncer:   baseebpf.NoopSyncer{},
		logger:   logger,
		warns:    warns,
		tcLinks:  map[string]link.Link{},
		xdpLinks: map[string]link.Link{},
	}

	caps := userspace.Probe()
	logger.Info("ebpf capability probe", "summary", caps.Summary())
	for _, e := range caps.ProbeErrs {
		logger.Warn("ebpf probe diagnostic", "err", e)
	}
	if err := caps.MissingRequired(); err != nil {
		logger.Warn("ebpf disabled — required kernel features missing", "err", err)
		return st
	}

	// memlock raise is required for older kernels (< 5.11 without
	// the BPF token / unprivileged_bpf_disabled tightening); a no-op
	// on modern hosts.
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Warn("ebpf disabled — could not raise memlock", "err", err)
		return st
	}

	spec, err := userspace.LoadRules()
	if err != nil {
		logger.Warn("ebpf disabled — bpf2go spec load failed", "err", err)
		return st
	}

	// Try to enable bpffs pinning. If the directory can't be created
	// (no bpffs mount, no permission), fall back to anonymous maps so
	// the API still loads — operators get an unpinned datapath rather
	// than no datapath. Operators who care about persistence will see
	// the warning and fix the mount.
	pinPath := ensureBPFPinDir(logger)

	loader, err := userspace.NewRulesLoaderWithOptions(spec, userspace.LoaderOptions{PinPath: pinPath})
	if err != nil {
		// Most common cause: the kernel rejected one of the maps
		// (verifier complaint, missing helper) or the pin path
		// already holds maps from an older binary with an
		// incompatible signature. The log here is the only signal —
		// move on without kernel sync.
		logger.Warn("ebpf disabled — loader init failed", "err", err, "pin_path", pinPath)
		return st
	}
	st.loader = loader

	// Attach XDP first. Failure here is recoverable — the program
	// is loaded into the kernel and the maps are usable; we just
	// don't get the WAN-side hook on this run.
	if xdpIface != "" {
		st.attachXDP(loader, xdpIface, logger)
	}
	// Attach TC to every supplied WG interface. attachTCLocked
	// de-dupes by name, so an operator who sets NEXUSHUB_TC_IFACE
	// to a name that's also in the DB list is harmless.
	for _, name := range tcIfaces {
		if name == "" {
			continue
		}
		st.attachTC(loader, name, logger)
	}

	// Wire the syncer + metrics collector + log consumer.
	syncer, err := ebpfkernel.NewKernelSyncer(loader, logger)
	if err != nil {
		logger.Warn("ebpf syncer init failed — running DB-only", "err", err)
		_ = loader.Close()
		st.loader = nil
		return st
	}
	st.syncer = syncer

	metrics.Registry.MustRegister(ebpfkernel.NewMetricsCollector(loader, logger))

	if logs != nil {
		st.startConsumer(ctx, loader, syncer, logs, logger)
	}

	return st
}

// attachXDP is the boot-time helper. AttachXDP (exported below) is
// the runtime entry point — they share a body via attachXDPLocked.
func (s *ebpfStack) attachXDP(l *userspace.RulesLoader, ifaceName string, logger *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.attachXDPLocked(l, ifaceName); err != nil {
		logger.Warn("xdp attach failed", "iface", ifaceName, "err", err)
		return
	}
	logger.Info(
		"xdp attached",
		"iface", ifaceName,
		"hook", "xdp",
		"program", userspace.ProgramXDPRules,
		"prog_id", progIDFor(l, userspace.ProgramXDPRules),
	)
}

func (s *ebpfStack) attachXDPLocked(l *userspace.RulesLoader, ifaceName string) error {
	if _, dup := s.xdpLinks[ifaceName]; dup {
		return nil // idempotent — already attached
	}
	prog, ok := l.Program(userspace.ProgramXDPRules)
	if !ok {
		return fmt.Errorf("xdp_rules program not in spec")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface lookup: %w", err)
	}
	lk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		// Generic mode: works on any kernel, slower than DRV.
		Flags: link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("AttachXDP: %w", err)
	}
	s.xdpLinks[ifaceName] = lk
	return nil
}

// attachTC is the boot-time helper. AttachTC (exported) is the
// runtime entry point that the InterfaceHandler calls when a
// Location is created via the API.
func (s *ebpfStack) attachTC(l *userspace.RulesLoader, ifaceName string, logger *slog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.attachTCLocked(l, ifaceName); err != nil {
		logger.Warn("tc attach failed", "iface", ifaceName, "err", err)
		return
	}
	// Spell out the iface, the hook, and the running program ID so
	// the operator can sanity-check `bpftool prog show | grep <id>`
	// against this log line. The old "tc_rules_wg0 attached" read
	// like a static program-name reference and confused operators
	// running on non-wg0 interfaces.
	logger.Info(
		"tc attached",
		"iface", ifaceName,
		"hook", "ingress",
		"program", userspace.ProgramTCRulesWg0,
		"prog_id", progIDFor(l, userspace.ProgramTCRulesWg0),
	)
}

func (s *ebpfStack) attachTCLocked(l *userspace.RulesLoader, ifaceName string) error {
	if _, dup := s.tcLinks[ifaceName]; dup {
		return nil // idempotent
	}
	prog, ok := l.Program(userspace.ProgramTCRulesWg0)
	if !ok {
		return fmt.Errorf("tc_rules_wg0 program not in spec")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface lookup: %w", err)
	}
	lk, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("AttachTCX: %w", err)
	}
	s.tcLinks[ifaceName] = lk
	return nil
}

// AttachTC is the runtime entry point. Called from
// InterfaceHandler.Create after the rtnetlink link is up. Returns
// nil if the loader isn't initialized (host without CAP_BPF) so
// the caller never has to nil-check us — the kernel just stays
// quiet on this Location until the next process restart.
func (s *ebpfStack) AttachTC(name string) error {
	if s == nil || s.loader == nil || name == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.attachTCLocked(s.loader, name); err != nil {
		s.recordWarning("ebpf.tc.attach", name, err.Error())
		return err
	}
	if s.logger != nil {
		s.logger.Info(
			"tc attached at runtime",
			"iface", name,
			"hook", "ingress",
			"program", userspace.ProgramTCRulesWg0,
			"prog_id", progIDFor(s.loader, userspace.ProgramTCRulesWg0),
		)
	}
	return nil
}

// DetachTC removes a previously-attached TC program for the named
// interface. Idempotent on a name that was never attached. Called
// from InterfaceHandler.Delete before the rtnetlink delete tears
// the link down.
func (s *ebpfStack) DetachTC(name string) error {
	if s == nil || name == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lk, ok := s.tcLinks[name]
	if !ok {
		return nil
	}
	delete(s.tcLinks, name)
	if err := lk.Close(); err != nil {
		s.recordWarning("ebpf.tc.detach", name, err.Error())
		return err
	}
	if s.logger != nil {
		s.logger.Info(
			"tc detached",
			"iface", name,
			"hook", "ingress",
			"program", userspace.ProgramTCRulesWg0,
		)
	}
	return nil
}

// AttachedPrograms returns a snapshot of every TC / XDP program
// this stack has bound to a kernel interface. Used by the Support
// page so an operator can confirm attachment without ssh-ing in.
// Locked-snapshot to avoid racing concurrent attach/detach.
func (s *ebpfStack) AttachedPrograms() []diag.EBPFAttachment {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]diag.EBPFAttachment, 0, len(s.tcLinks)+len(s.xdpLinks))
	for name := range s.tcLinks {
		out = append(out, diag.EBPFAttachment{
			Iface:   name,
			Hook:    "ingress",
			Program: userspace.ProgramTCRulesWg0,
			ProgID:  progIDFor(s.loader, userspace.ProgramTCRulesWg0),
		})
	}
	for name := range s.xdpLinks {
		out = append(out, diag.EBPFAttachment{
			Iface:   name,
			Hook:    "xdp",
			Program: userspace.ProgramXDPRules,
			ProgID:  progIDFor(s.loader, userspace.ProgramXDPRules),
		})
	}
	return out
}

// PinPath returns the bpffs directory the loader uses, or "" when
// pinning is disabled. Surfaced in /diag/ebpf so the operator can
// `ls /sys/fs/bpf/<path>` and confirm the maps survive restart.
func (s *ebpfStack) PinPath() string {
	if s == nil || s.loader == nil {
		return ""
	}
	return bpfPinDir
}

// progIDFor returns the kernel-assigned program id for the named
// program in the loader's collection, or 0 if the program is
// missing or the kernel-side info isn't available. Used in attach
// log lines so the operator can correlate `bpftool prog show`
// output with what the API attached.
func progIDFor(l *userspace.RulesLoader, name string) uint32 {
	if l == nil {
		return 0
	}
	prog, ok := l.Program(name)
	if !ok || prog == nil {
		return 0
	}
	info, err := prog.Info()
	if err != nil || info == nil {
		return 0
	}
	id, ok := info.ID()
	if !ok {
		return 0
	}
	return uint32(id)
}

// recordWarning is the bridge from the eBPF stack into the
// kernel-warnings ring — same shape as InterfaceHandler's helper.
// Locked-caller-safe: pure pass-through to the ring's own mutex.
func (s *ebpfStack) recordWarning(origin, iface, msg string) {
	if s == nil || s.warns == nil {
		return
	}
	s.warns.Push(diag.KernelWarning{Origin: origin, Iface: iface, Message: msg})
}

// startConsumer opens the ringbuf and runs the drain goroutine. A
// missing log_events map (older spec, or future opt-out) makes
// OpenLogReader return a sentinel error which we treat as "logging
// disabled" rather than a startup failure.
func (s *ebpfStack) startConsumer(
	ctx context.Context,
	loader *userspace.RulesLoader,
	syncer *ebpfkernel.KernelSyncer,
	logs *repository.ConnectionLogRepo,
	logger *slog.Logger,
) {
	reader, err := loader.OpenLogReader()
	if err != nil {
		if errors.Is(err, userspace.ErrLogRingbufUnavailable) {
			logger.Info("ebpf log ringbuf not in spec — datapath logging disabled")
			return
		}
		logger.Warn("open log ringbuf failed", "err", err)
		return
	}
	consumer, err := ebpfkernel.NewLogConsumer(reader, syncer, &dbLogSink{logs: logs}, logger)
	if err != nil {
		logger.Warn("log consumer init failed", "err", err)
		_ = reader.Close()
		return
	}
	s.consumer = consumer
	go func() {
		// Run blocks until ctx is canceled or the reader is closed.
		// Either is a clean shutdown — the error is nil for both
		// paths and only carries a payload on a real read failure.
		if err := consumer.Run(ctx); err != nil {
			logger.Warn("ebpf log consumer exited with error", "err", err)
		}
	}()
}

// Close detaches every program and closes the loader. Safe on a
// stack that was never fully populated — every step is nil-checked.
// Detach failures are logged but not returned; main.go is exiting
// anyway and a bound program is reclaimed at process death.
func (s *ebpfStack) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, lk := range s.tcLinks {
		if err := lk.Close(); err != nil {
			slog.Warn("ebpf tc link close", "iface", name, "err", err)
		}
	}
	s.tcLinks = nil
	for name, lk := range s.xdpLinks {
		if err := lk.Close(); err != nil {
			slog.Warn("ebpf xdp link close", "iface", name, "err", err)
		}
	}
	s.xdpLinks = nil
	if s.loader != nil {
		_ = s.loader.Close()
		s.loader = nil
	}
}

// dbLogSink bridges userspace.LogEvent → ConnectionLogRepo.Insert.
// The translation is mostly mechanical; ProtocolString + SrcIP +
// DstIP + ActionString do the heavy lifting on the LogEvent side.
//
// ConnectionLogEntry fields the kernel side can't fill in
// (PeerID / InterfaceID / packet counts) stay at their zero values;
// the repository's INSERT uses NULLIF gating so they land as NULL
// rather than 0/empty-uuid.
type dbLogSink struct {
	logs *repository.ConnectionLogRepo
}

func (s *dbLogSink) Handle(ctx context.Context, ev userspace.LogEvent, matched *uuid.UUID) error {
	src := ev.SrcIP()
	if !src.IsValid() {
		// The kernel only emits IPv4/IPv6 events; an unknown family
		// byte means a malformed message that didn't survive the
		// ringbuf write. Skip rather than insert a NULL src_ip.
		return nil
	}
	entry := repository.ConnectionLogEntry{
		SrcIP:         src,
		DstIP:         ev.DstIP(),
		Protocol:      ev.ProtocolString(),
		Action:        ev.ActionString(),
		MatchedRuleID: matched,
		BytesIn:       int64(ev.Bytes),
	}
	if ev.SrcPort != 0 {
		p := int(ev.SrcPort)
		entry.SrcPort = &p
	}
	if ev.DstPort != 0 {
		p := int(ev.DstPort)
		entry.DstPort = &p
	}
	return s.logs.Insert(ctx, entry)
}

// ensureBPFPinDir creates the pin directory under /sys/fs/bpf so the
// loader can place maps there. Returns the path on success; "" when
// the directory can't be created (no bpffs mount, EACCES, or the
// kernel doesn't expose bpffs at all). The empty-string return is the
// signal the loader uses to fall back to anonymous maps.
func ensureBPFPinDir(logger *slog.Logger) string {
	// /sys/fs/bpf must already be a bpffs mount — making one ourselves
	// would require CAP_SYS_ADMIN and would surprise operators who
	// have it mounted elsewhere. We just check the parent exists.
	parent := filepath.Dir(bpfPinDir)
	if _, err := os.Stat(parent); err != nil {
		logger.Warn("bpffs not present — disabling map pinning",
			"path", parent, "err", err)
		return ""
	}
	if err := os.MkdirAll(bpfPinDir, 0o700); err != nil {
		logger.Warn("could not create bpf pin dir — disabling map pinning",
			"path", bpfPinDir, "err", err)
		return ""
	}
	return bpfPinDir
}

// xdpInterfaceFromEnv reads NEXUSHUB_XDP_IFACE (default empty —
// "don't attach"). Operators on production hardware set this to
// their WAN-facing NIC; dev environments leave it empty.
func xdpInterfaceFromEnv() string {
	return os.Getenv("NEXUSHUB_XDP_IFACE")
}

// tcInterfaceFromEnv reads NEXUSHUB_TC_IFACE (default empty). When
// set, points at the WireGuard tunnel interface; the chart's data-
// plane mode populates this to wg0.
func tcInterfaceFromEnv() string {
	return os.Getenv("NEXUSHUB_TC_IFACE")
}
