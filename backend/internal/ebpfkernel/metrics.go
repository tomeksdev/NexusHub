package ebpfkernel

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

// StatsProvider is the narrow surface the collector needs from
// RulesLoader. Taking an interface lets tests stub the data source
// without booting a kernel-backed loader — and keeps the collector
// package free of the cilium/ebpf import graph when it's exercised
// from unit tests.
type StatsProvider interface {
	Stats() (userspace.LoaderStats, error)
}

// mapLabel names each managed BPF map for the "map" label. The values
// match the ebpf/src/rules.c identifiers so operator dashboards line
// up with `bpftool map show` output.
const (
	labelRuleMeta    = "rule_meta"
	labelRuleSrcV4   = "rule_src_v4"
	labelRuleSrcV6   = "rule_src_v6"
	labelRuleDstV4   = "rule_dst_v4"
	labelRuleDstV6   = "rule_dst_v6"
	labelRateStateV4 = "rate_state_v4"
	labelRateStateV6 = "rate_state_v6"
)

var (
	mapEntriesDesc = prometheus.NewDesc(
		"nexushub_ebpf_map_entries",
		"Live entry count in each managed BPF map.",
		[]string{"map"}, nil,
	)
	mapCapacityDesc = prometheus.NewDesc(
		"nexushub_ebpf_map_capacity",
		"Compile-time maximum entry count for each managed BPF map.",
		[]string{"map"}, nil,
	)
	statsErrorsDesc = prometheus.NewDesc(
		"nexushub_ebpf_stats_errors_total",
		"Counter of failed stats scrapes — non-zero indicates Stats() is erroring.",
		nil, nil,
	)
)

// MetricsCollector reports per-map cardinality and capacity from the
// eBPF rule loader. Each Prometheus scrape triggers one Stats() call;
// an empty deploy is ~seven no-op iterations over empty maps.
//
// Errors during Stats() are logged and counted on
// nexushub_ebpf_stats_errors_total rather than failing the scrape, so
// /metrics keeps returning a useful response even if the kernel-side
// map handles are momentarily unavailable.
type MetricsCollector struct {
	provider StatsProvider
	logger   *slog.Logger

	// errors accumulates scrape failures. It's a plain atomic-free
	// uint64 because the scrape goroutine is the sole writer; the
	// Prometheus exposition pipeline reads it from the same goroutine.
	errors uint64
}

// NewMetricsCollector wires the collector around a stats provider.
// The loader implements StatsProvider directly; tests substitute a
// fake. A nil logger falls back to slog.Default.
func NewMetricsCollector(provider StatsProvider, logger *slog.Logger) *MetricsCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &MetricsCollector{provider: provider, logger: logger}
}

// Describe emits the full descriptor set. Prometheus needs this up
// front so it can reject collectors that would emit duplicate metric
// names at registration time.
func (c *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mapEntriesDesc
	ch <- mapCapacityDesc
	ch <- statsErrorsDesc
}

// Collect samples Stats() once and emits two series (entries, cap)
// per map plus the cumulative error counter. On a Stats error the
// error counter increments and we skip the per-map series entirely
// rather than emitting zero values that would be indistinguishable
// from an empty deploy.
func (c *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	if c.provider == nil {
		ch <- prometheus.MustNewConstMetric(statsErrorsDesc, prometheus.CounterValue, float64(c.errors))
		return
	}
	stats, err := c.provider.Stats()
	if err != nil {
		c.errors++
		c.logger.Warn("ebpf stats scrape", "err", err)
		ch <- prometheus.MustNewConstMetric(statsErrorsDesc, prometheus.CounterValue, float64(c.errors))
		return
	}

	for _, pair := range []struct {
		label string
		s     userspace.MapStats
	}{
		{labelRuleMeta, stats.RuleMeta},
		{labelRuleSrcV4, stats.RuleSrcV4},
		{labelRuleSrcV6, stats.RuleSrcV6},
		{labelRuleDstV4, stats.RuleDstV4},
		{labelRuleDstV6, stats.RuleDstV6},
		{labelRateStateV4, stats.RateStateV4},
		{labelRateStateV6, stats.RateStateV6},
	} {
		ch <- prometheus.MustNewConstMetric(
			mapEntriesDesc, prometheus.GaugeValue,
			float64(pair.s.Entries), pair.label)
		ch <- prometheus.MustNewConstMetric(
			mapCapacityDesc, prometheus.GaugeValue,
			float64(pair.s.MaxEntries), pair.label)
	}
	ch <- prometheus.MustNewConstMetric(statsErrorsDesc, prometheus.CounterValue, float64(c.errors))
}
