package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"

	baseebpf "github.com/tomeksdev/NexusHub/backend/internal/ebpf"
	"github.com/tomeksdev/NexusHub/backend/internal/ebpfkernel"
	"github.com/tomeksdev/NexusHub/backend/internal/metrics"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

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
type ebpfStack struct {
	loader   *userspace.RulesLoader
	syncer   baseebpf.Syncer
	consumer *ebpfkernel.LogConsumer

	// Closers for any link.Link returned by AttachXDP/AttachTCX.
	// Detaching at shutdown is best-effort; a forced exit leaves
	// the program bound until the next process load replaces it.
	links []link.Link
}

// startEBPF tries to bring up the kernel datapath. Returns a stack
// where every field may be a no-op equivalent — the caller never has
// to nil-check syncer. Errors are logged, not propagated; the API
// runs DB-only when the kernel can't be reached.
func startEBPF(
	ctx context.Context,
	logs *repository.ConnectionLogRepo,
	xdpIface, tcIface string,
	logger *slog.Logger,
) *ebpfStack {
	st := &ebpfStack{syncer: baseebpf.NoopSyncer{}}

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
	loader, err := userspace.NewRulesLoader(spec)
	if err != nil {
		// Most common cause: the kernel rejected one of the maps
		// (verifier complaint, missing helper). The log here is
		// the only signal — move on without kernel sync.
		logger.Warn("ebpf disabled — loader init failed", "err", err)
		return st
	}
	st.loader = loader

	// Attach XDP first. Failure here is recoverable — the program
	// is loaded into the kernel and the maps are usable; we just
	// don't get the WAN-side hook on this run.
	if xdpIface != "" {
		st.attachXDP(loader, xdpIface, logger)
	}
	if tcIface != "" {
		st.attachTC(loader, tcIface, logger)
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

// attachXDP loads the xdp_rules program onto the named interface in
// generic mode (driver mode would be faster but isn't universally
// supported). Generic mode runs the program in the kernel's
// netif_receive_skb path which is enough for our current use case.
func (s *ebpfStack) attachXDP(l *userspace.RulesLoader, ifaceName string, logger *slog.Logger) {
	prog, ok := l.Program(userspace.ProgramXDPRules)
	if !ok {
		logger.Warn("xdp_rules program not in spec — skipping XDP attach")
		return
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		logger.Warn("xdp attach: interface lookup failed", "iface", ifaceName, "err", err)
		return
	}
	lk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		// Generic mode: works on any kernel, slower than DRV. Operators
		// who want native-mode XDP can opt in via env later.
		Flags: link.XDPGenericMode,
	})
	if err != nil {
		logger.Warn("xdp attach failed", "iface", ifaceName, "err", err)
		return
	}
	s.links = append(s.links, lk)
	logger.Info("xdp_rules attached", "iface", ifaceName)
}

// attachTC pins tc_rules_wg0 to the WireGuard interface's clsact
// ingress hook. tcx is the modern replacement for tc-bpf and is
// what cilium/ebpf's link package builds on top of.
func (s *ebpfStack) attachTC(l *userspace.RulesLoader, ifaceName string, logger *slog.Logger) {
	prog, ok := l.Program(userspace.ProgramTCRulesWg0)
	if !ok {
		logger.Warn("tc_rules_wg0 program not in spec — skipping TC attach")
		return
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		logger.Warn("tc attach: interface lookup failed", "iface", ifaceName, "err", err)
		return
	}
	lk, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		logger.Warn("tc attach failed", "iface", ifaceName, "err", err)
		return
	}
	s.links = append(s.links, lk)
	logger.Info("tc_rules_wg0 attached", "iface", ifaceName)
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
	for _, lk := range s.links {
		if err := lk.Close(); err != nil {
			slog.Warn("ebpf link close", "err", err)
		}
	}
	s.links = nil
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
