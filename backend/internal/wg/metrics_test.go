package wg

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestWGCollectorEmitsPerInterfaceAndPeerSeries(t *testing.T) {
	client := NewFakeClient()
	client.SetDevice(&Device{
		Name:       "wg0",
		ListenPort: 51820,
		Peers: []Peer{
			{
				PublicKey:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				LastHandshake: time.Unix(1700000000, 0),
				RxBytes:       1024,
				TxBytes:       2048,
			},
			{
				PublicKey:     "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
				LastHandshake: time.Time{}, // never
				RxBytes:       0,
				TxBytes:       0,
			},
		},
	})
	c := NewWGCollector(client, []string{"wg0"}, nil)

	want := `
# HELP nexushub_wg_device_up 1 if the WireGuard device responded to the last scrape, 0 otherwise.
# TYPE nexushub_wg_device_up gauge
nexushub_wg_device_up{interface="wg0"} 1
# HELP nexushub_wg_listen_port The UDP port the WireGuard device is listening on.
# TYPE nexushub_wg_listen_port gauge
nexushub_wg_listen_port{interface="wg0"} 51820
# HELP nexushub_wg_peer_last_handshake_seconds Unix-seconds timestamp of the last successful handshake per peer. Zero means no handshake yet since device load.
# TYPE nexushub_wg_peer_last_handshake_seconds gauge
nexushub_wg_peer_last_handshake_seconds{interface="wg0",public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} 1.7e+09
nexushub_wg_peer_last_handshake_seconds{interface="wg0",public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="} 0
# HELP nexushub_wg_peer_receive_bytes_total Bytes received from a peer since the device was loaded.
# TYPE nexushub_wg_peer_receive_bytes_total counter
nexushub_wg_peer_receive_bytes_total{interface="wg0",public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} 1024
nexushub_wg_peer_receive_bytes_total{interface="wg0",public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="} 0
# HELP nexushub_wg_peer_transmit_bytes_total Bytes transmitted to a peer since the device was loaded.
# TYPE nexushub_wg_peer_transmit_bytes_total counter
nexushub_wg_peer_transmit_bytes_total{interface="wg0",public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} 2048
nexushub_wg_peer_transmit_bytes_total{interface="wg0",public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="} 0
# HELP nexushub_wg_peers Number of peers configured on a WireGuard interface.
# TYPE nexushub_wg_peers gauge
nexushub_wg_peers{interface="wg0"} 2
# HELP nexushub_wg_scrape_errors_total Cumulative count of failed Device() calls, labeled by interface.
# TYPE nexushub_wg_scrape_errors_total counter
nexushub_wg_scrape_errors_total{interface="wg0"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Fatalf("unexpected metrics:\n%v", err)
	}
}

func TestWGCollectorMissingDeviceEmitsDeviceDownAndTicksErrors(t *testing.T) {
	// FakeClient.Device returns an error for unknown names. That path
	// must keep the scrape alive for other interfaces and accumulate
	// the error counter.
	client := NewFakeClient()
	c := NewWGCollector(client, []string{"wg0"}, nil)

	// Scrape twice so the counter reads 2.
	for i := 0; i < 2; i++ {
		_ = testutil.CollectAndCount(c, "nexushub_wg_device_up")
	}
	want := `
# HELP nexushub_wg_device_up 1 if the WireGuard device responded to the last scrape, 0 otherwise.
# TYPE nexushub_wg_device_up gauge
nexushub_wg_device_up{interface="wg0"} 0
# HELP nexushub_wg_scrape_errors_total Cumulative count of failed Device() calls, labeled by interface.
# TYPE nexushub_wg_scrape_errors_total counter
nexushub_wg_scrape_errors_total{interface="wg0"} 3
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"nexushub_wg_device_up", "nexushub_wg_scrape_errors_total"); err != nil {
		t.Fatalf("unexpected metrics:\n%v", err)
	}
}

func TestWGCollectorPartialFailureDoesNotSkipHealthyInterface(t *testing.T) {
	client := NewFakeClient()
	client.SetDevice(&Device{Name: "wg0", ListenPort: 51820})
	c := NewWGCollector(client, []string{"wg0", "wg-missing"}, nil)

	want := `
# HELP nexushub_wg_device_up 1 if the WireGuard device responded to the last scrape, 0 otherwise.
# TYPE nexushub_wg_device_up gauge
nexushub_wg_device_up{interface="wg-missing"} 0
nexushub_wg_device_up{interface="wg0"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want),
		"nexushub_wg_device_up"); err != nil {
		t.Fatalf("unexpected metrics:\n%v", err)
	}
}

func TestWGCollectorRegistersWithoutConflict(t *testing.T) {
	c := NewWGCollector(NewFakeClient(), []string{"wg0"}, nil)
	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
}

func TestHandshakeUnixZeroForZeroTime(t *testing.T) {
	if got := handshakeUnix(time.Time{}); got != 0 {
		t.Fatalf("zero time → 0, got %v", got)
	}
	ts := time.Unix(1234567890, 0)
	if got := handshakeUnix(ts); got != 1234567890 {
		t.Fatalf("want 1234567890, got %v", got)
	}
}
