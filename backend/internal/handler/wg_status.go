package handler

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/NexusHub/backend/internal/repository"
	"github.com/tomeksdev/NexusHub/backend/internal/wg"
)

// StatusHandler reports data-plane mode plus live device counters. Surfaced
// on /api/v1/wg/status so operators can confirm a running install actually
// picked up the kernel module rather than silently falling back to
// userspace (which has materially different performance).
type StatusHandler struct {
	Client     wg.Client
	Interfaces *repository.InterfaceRepo
}

type wgDeviceStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	ListenPort int    `json:"listen_port"`
	PeerCount  int    `json:"peer_count"`
}

type wgStatus struct {
	Mode    wg.Mode          `json:"mode"`
	Devices []wgDeviceStatus `json:"devices"`
}

// Status returns the current mode plus a snapshot per active interface.
// Missing devices (DB has a row, kernel doesn't) appear with PeerCount=-1
// so the frontend can badge them as "not running" without a second call.
func (h *StatusHandler) Status(c *gin.Context) {
	ctx := c.Request.Context()
	out := wgStatus{Mode: wg.ModeUnknown, Devices: []wgDeviceStatus{}}

	if h.Interfaces != nil {
		ifaces, err := h.Interfaces.List(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "list interfaces", "err", err)
		}
		for _, iface := range ifaces {
			entry := wgDeviceStatus{
				Name: iface.Name, ListenPort: iface.ListenPort, PeerCount: -1,
			}
			if h.Client != nil {
				if d, err := h.Client.Device(iface.Name); err == nil && d != nil {
					entry.Type = d.Type
					entry.PeerCount = len(d.Peers)
					if out.Mode == wg.ModeUnknown {
						out.Mode = wg.DetectMode(h.Client, iface.Name)
					}
				}
			}
			out.Devices = append(out.Devices, entry)
		}
	}
	if out.Mode == wg.ModeUnknown {
		out.Mode = wg.DetectMode(h.Client, "")
	}
	c.JSON(http.StatusOK, out)
}
