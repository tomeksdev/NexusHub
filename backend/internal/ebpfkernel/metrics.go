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
//
// v2.1 — the LPM tries and rule_meta map are gone; rule_table_v4/v6
// are the new per-family rule arrays and rule_count_v4/v6 are
// informational so we don't emit them as gauges.
const (
	labelRuleTableV4 = "rule_table_v4"
	labelRuleTableV6 = "rule_table_v6"
	labelRateStateV4 = "rate_state_v4"
	labelRateStateV6 = "rate_state_v6"
	labelRuleHits    = "rule_hits"
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
// eBPF rule loader.
type MetricsCollector struct {
	provider StatsProvider
	logger   *slog.Logger
	errors   uint64
}

func NewMetricsCollector(provider StatsProvider, logger *slog.Logger) *MetricsCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &MetricsCollector{provider: provider, logger: logger}
}

func (c *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- mapEntriesDesc
	ch <- mapCapacityDesc
	ch <- statsErrorsDesc
}

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
		{labelRuleTableV4, stats.RuleTableV4},
		{labelRuleTableV6, stats.RuleTableV6},
		{labelRateStateV4, stats.RateStateV4},
		{labelRateStateV6, stats.RateStateV6},
		{labelRuleHits, stats.RuleHits},
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
