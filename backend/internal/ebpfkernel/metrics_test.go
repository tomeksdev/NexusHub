package ebpfkernel

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

type fakeStats struct {
	s   userspace.LoaderStats
	err error
}

func (f *fakeStats) Stats() (userspace.LoaderStats, error) { return f.s, f.err }

func TestMetricsCollectorEmitsAllSeries(t *testing.T) {
	stats := userspace.LoaderStats{
		RuleTableV4: userspace.MapStats{Entries: 3, MaxEntries: userspace.MaxActiveRulesV4},
		RuleTableV6: userspace.MapStats{Entries: 1, MaxEntries: userspace.MaxActiveRulesV6},
		RateStateV4: userspace.MapStats{Entries: 42, MaxEntries: 65536},
		RateStateV6: userspace.MapStats{Entries: 7, MaxEntries: 65536},
		RuleHits:    userspace.MapStats{Entries: 5, MaxEntries: 512},
	}
	c := NewMetricsCollector(&fakeStats{s: stats}, nil)

	want := `
# HELP nexushub_ebpf_map_capacity Compile-time maximum entry count for each managed BPF map.
# TYPE nexushub_ebpf_map_capacity gauge
nexushub_ebpf_map_capacity{map="rate_state_v4"} 65536
nexushub_ebpf_map_capacity{map="rate_state_v6"} 65536
nexushub_ebpf_map_capacity{map="rule_hits"} 512
nexushub_ebpf_map_capacity{map="rule_table_v4"} 256
nexushub_ebpf_map_capacity{map="rule_table_v6"} 256
# HELP nexushub_ebpf_map_entries Live entry count in each managed BPF map.
# TYPE nexushub_ebpf_map_entries gauge
nexushub_ebpf_map_entries{map="rate_state_v4"} 42
nexushub_ebpf_map_entries{map="rate_state_v6"} 7
nexushub_ebpf_map_entries{map="rule_hits"} 5
nexushub_ebpf_map_entries{map="rule_table_v4"} 3
nexushub_ebpf_map_entries{map="rule_table_v6"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"nexushub_ebpf_map_entries", "nexushub_ebpf_map_capacity"); err != nil {
		t.Fatalf("unexpected metrics:\n%v", err)
	}
}

func TestMetricsCollectorSkipsSeriesOnStatsError(t *testing.T) {
	c := NewMetricsCollector(&fakeStats{err: errors.New("boom")}, nil)

	count := testutil.CollectAndCount(c,
		"nexushub_ebpf_map_entries", "nexushub_ebpf_map_capacity")
	if count != 0 {
		t.Fatalf("expected zero per-map series on error, got %d", count)
	}

	want := `
# HELP nexushub_ebpf_stats_errors_total Counter of failed stats scrapes — non-zero indicates Stats() is erroring.
# TYPE nexushub_ebpf_stats_errors_total counter
nexushub_ebpf_stats_errors_total 2
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"nexushub_ebpf_stats_errors_total"); err != nil {
		t.Fatalf("unexpected error counter:\n%v", err)
	}
}

func TestMetricsCollectorErrorCounterAccumulates(t *testing.T) {
	c := NewMetricsCollector(&fakeStats{err: errors.New("boom")}, nil)

	for i := 0; i < 2; i++ {
		_ = testutil.CollectAndCount(c, "nexushub_ebpf_stats_errors_total")
	}
	want := `
# HELP nexushub_ebpf_stats_errors_total Counter of failed stats scrapes — non-zero indicates Stats() is erroring.
# TYPE nexushub_ebpf_stats_errors_total counter
nexushub_ebpf_stats_errors_total 3
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"nexushub_ebpf_stats_errors_total"); err != nil {
		t.Fatalf("counter did not accumulate:\n%v", err)
	}
}

func TestMetricsCollectorRegistersWithoutConflict(t *testing.T) {
	c := NewMetricsCollector(&fakeStats{}, nil)
	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
}
