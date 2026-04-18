package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/wg"
)

// PeerEventsHandler streams live peer state over Server-Sent Events. The
// kernel doesn't notify userspace when handshakes complete or counters
// move — wgctrl is poll-only — so we poll on a short interval and diff
// against the previous snapshot, emitting one event per changed peer.
// Polling is cheaper than it looks because wgctrl dumps the whole device
// in a single netlink round-trip.
type PeerEventsHandler struct {
	Client     wg.Client
	Interfaces *repository.InterfaceRepo
	// PollInterval controls how often we re-read each device. Zero means
	// use the default (5s) — short enough to feel real-time in a UI, long
	// enough that a dozen connected clients won't saturate netlink.
	PollInterval time.Duration
}

// peerEvent is the SSE payload shape. Clients demultiplex on the `event:`
// field rather than a discriminator inside the body.
type peerEvent struct {
	Interface     string    `json:"interface"`
	PublicKey     string    `json:"public_key"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	Endpoint      string    `json:"endpoint,omitempty"`
}

type peerSnapshot struct {
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Events is the SSE endpoint. Three event types are emitted:
//
//	event: snapshot  — full list of every known peer, sent once on connect
//	event: peer      — one peer whose handshake/bytes changed since last poll
//	event: ping      — heartbeat (every ~15s) to keep proxy buffers flushed
func (h *PeerEventsHandler) Events(c *gin.Context) {
	if h.Client == nil || h.Interfaces == nil {
		writeError(c, http.StatusServiceUnavailable, "UNAVAILABLE", "live peer state unavailable")
		return
	}
	interval := h.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	c.Writer.WriteHeader(http.StatusOK)

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		// Shouldn't happen with gin's default writer, but fail loudly if it
		// ever does — SSE without a flusher silently accumulates in buffers.
		slog.ErrorContext(c, "response writer does not support flushing")
		return
	}

	ctx := c.Request.Context()

	state := map[string]peerSnapshot{} // key = iface|pubkey
	initial := h.pollAll(ctx, state, true)
	writeSSE(c.Writer, flusher, "snapshot", initial)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			writeSSERaw(c.Writer, flusher, "ping", []byte(`{}`))
		case <-ticker.C:
			changes := h.pollAll(ctx, state, false)
			for i := range changes {
				writeSSE(c.Writer, flusher, "peer", changes[i])
			}
		}
	}
}

// pollAll walks every DB interface, queries the kernel for live peer
// state, and updates `state` in place. When emitAll is true, every peer
// produces an event (for the initial snapshot); otherwise only peers
// whose handshake time or byte counters actually changed.
func (h *PeerEventsHandler) pollAll(ctx context.Context, state map[string]peerSnapshot, emitAll bool) []peerEvent {
	ifaces, err := h.Interfaces.List(ctx)
	if err != nil {
		return nil
	}
	var out []peerEvent
	for _, iface := range ifaces {
		d, err := h.Client.Device(iface.Name)
		if err != nil || d == nil {
			continue
		}
		for _, p := range d.Peers {
			key := iface.Name + "|" + p.PublicKey
			prev, had := state[key]
			now := peerSnapshot{
				LastHandshake: p.LastHandshake,
				RxBytes:       p.RxBytes,
				TxBytes:       p.TxBytes,
			}
			changed := !had ||
				!prev.LastHandshake.Equal(now.LastHandshake) ||
				prev.RxBytes != now.RxBytes ||
				prev.TxBytes != now.TxBytes
			state[key] = now
			if emitAll || changed {
				out = append(out, peerEvent{
					Interface: iface.Name, PublicKey: p.PublicKey,
					LastHandshake: p.LastHandshake,
					RxBytes:       p.RxBytes, TxBytes: p.TxBytes,
					Endpoint: p.Endpoint,
				})
			}
		}
	}
	return out
}

func writeSSE(w io.Writer, f http.Flusher, event string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	writeSSERaw(w, f, event, b)
}

func writeSSERaw(w io.Writer, f http.Flusher, event string, body []byte) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body)
	f.Flush()
}
