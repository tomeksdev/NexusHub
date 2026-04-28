package wg

import (
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// WGCollector exports per-interface and per-peer WireGuard state to
// Prometheus. It holds no cached counters — every scrape fetches live
// device state via the injected Client, so there is no goroutine to
// manage and metrics reflect reality at scrape time.
//
// Cardinality: series fan out as O(interfaces × peers). A typical VPN
// deployment is 1 interface + tens to low-thousands of peers, which
// Prometheus handles comfortably. Operators who add many interfaces
// should pass only the ones they want scraped via interfaces — the
// collector does NOT auto-discover devices.
type WGCollector struct {
	client     Client
	interfaces []string
	logger     *slog.Logger

	mu           sync.Mutex
	scrapeErrors map[string]uint64
}

// NewWGCollector wires a collector around a client and a fixed list
// of interface names to scrape. nil logger falls back to slog.Default.
// Interfaces absent from the kernel at scrape time emit device_up=0
// and tick the per-interface error counter, rather than failing the
// whole scrape — other interfaces keep reporting.
func NewWGCollector(client Client, interfaces []string, logger *slog.Logger) *WGCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &WGCollector{
		client:       client,
		interfaces:   append([]string(nil), interfaces...),
		logger:       logger,
		scrapeErrors: make(map[string]uint64, len(interfaces)),
	}
}

var (
	wgPeersDesc = prometheus.NewDesc(
		"nexushub_wg_peers",
		"Number of peers configured on a WireGuard interface.",
		[]string{"interface"}, nil,
	)
	wgDeviceUpDesc = prometheus.NewDesc(
		"nexushub_wg_device_up",
		"1 if the WireGuard device responded to the last scrape, 0 otherwise.",
		[]string{"interface"}, nil,
	)
	wgListenPortDesc = prometheus.NewDesc(
		"nexushub_wg_listen_port",
		"The UDP port the WireGuard device is listening on.",
		[]string{"interface"}, nil,
	)
	wgScrapeErrorsDesc = prometheus.NewDesc(
		"nexushub_wg_scrape_errors_total",
		"Cumulative count of failed Device() calls, labeled by interface.",
		[]string{"interface"}, nil,
	)
	wgPeerHandshakeDesc = prometheus.NewDesc(
		"nexushub_wg_peer_last_handshake_seconds",
		"Unix-seconds timestamp of the last successful handshake per peer. Zero means no handshake yet since device load.",
		[]string{"interface", "public_key"}, nil,
	)
	wgPeerRxBytesDesc = prometheus.NewDesc(
		"nexushub_wg_peer_receive_bytes_total",
		"Bytes received from a peer since the device was loaded.",
		[]string{"interface", "public_key"}, nil,
	)
	wgPeerTxBytesDesc = prometheus.NewDesc(
		"nexushub_wg_peer_transmit_bytes_total",
		"Bytes transmitted to a peer since the device was loaded.",
		[]string{"interface", "public_key"}, nil,
	)
)

// Describe emits every descriptor the collector may publish. Required
// by the Collector interface for registration-time conflict detection.
func (c *WGCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- wgPeersDesc
	ch <- wgDeviceUpDesc
	ch <- wgListenPortDesc
	ch <- wgScrapeErrorsDesc
	ch <- wgPeerHandshakeDesc
	ch <- wgPeerRxBytesDesc
	ch <- wgPeerTxBytesDesc
}

// Collect samples every configured interface. A failed Device() for
// one interface does not short-circuit the rest — dashboards keep
// working even while one device is bouncing.
func (c *WGCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, name := range c.interfaces {
		dev, err := c.client.Device(name)
		if err != nil {
			c.scrapeErrors[name]++
			c.logger.Warn("wg metrics scrape", "interface", name, "err", err)
			ch <- prometheus.MustNewConstMetric(wgDeviceUpDesc, prometheus.GaugeValue, 0, name)
			ch <- prometheus.MustNewConstMetric(wgScrapeErrorsDesc, prometheus.CounterValue, float64(c.scrapeErrors[name]), name)
			continue
		}
		ch <- prometheus.MustNewConstMetric(wgDeviceUpDesc, prometheus.GaugeValue, 1, name)
		ch <- prometheus.MustNewConstMetric(wgPeersDesc, prometheus.GaugeValue, float64(len(dev.Peers)), name)
		ch <- prometheus.MustNewConstMetric(wgListenPortDesc, prometheus.GaugeValue, float64(dev.ListenPort), name)
		ch <- prometheus.MustNewConstMetric(wgScrapeErrorsDesc, prometheus.CounterValue, float64(c.scrapeErrors[name]), name)
		for _, p := range dev.Peers {
			ch <- prometheus.MustNewConstMetric(
				wgPeerHandshakeDesc, prometheus.GaugeValue,
				handshakeUnix(p.LastHandshake),
				name, p.PublicKey,
			)
			ch <- prometheus.MustNewConstMetric(
				wgPeerRxBytesDesc, prometheus.CounterValue,
				float64(p.RxBytes),
				name, p.PublicKey,
			)
			ch <- prometheus.MustNewConstMetric(
				wgPeerTxBytesDesc, prometheus.CounterValue,
				float64(p.TxBytes),
				name, p.PublicKey,
			)
		}
	}
}

// handshakeUnix returns the Unix timestamp of the last handshake, or 0
// when the peer has no handshake yet. wgctrl returns a zero time.Time
// for peers that never completed a handshake since the device was
// loaded; emitting 0 keeps the "time() - metric" dashboard pattern
// sane (it produces "now" seconds-since-epoch, clearly flagging the
// peer as stale).
func handshakeUnix(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Unix())
}
