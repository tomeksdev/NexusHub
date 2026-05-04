package handler

import (
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/NexusHub/backend/internal/apierror"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
	"github.com/tomeksdev/NexusHub/backend/internal/wg"
)

// DashboardHandler aggregates the snapshots the admin landing page
// shows: total counts + currently online peers + top-N by traffic.
// Reads only — every value is derived from existing repos and the
// wgctrl client. Wired into the router under GET /api/v1/dashboard.
type DashboardHandler struct {
	Users      *repository.UserRepo
	Interfaces *repository.InterfaceRepo
	Peers      *repository.PeerRepo
	Client     wg.Client
}

type dashboardResponse struct {
	Counts       dashboardCounts   `json:"counts"`
	TopPeers     []dashboardPeer   `json:"top_peers"`
	Locations    []dashboardLoc    `json:"locations"`
	GeneratedAt  time.Time         `json:"generated_at"`
}

type dashboardCounts struct {
	Locations    int `json:"locations"`
	Users        int `json:"users"`
	Peers        int `json:"peers"`
	PeersOnline  int `json:"peers_online"`
}

type dashboardPeer struct {
	PublicKey     string    `json:"public_key"`
	Interface     string    `json:"interface"`
	OwnerEmail    string    `json:"owner_email,omitempty"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
}

type dashboardLoc struct {
	Name        string `json:"name"`
	ListenPort  int    `json:"listen_port"`
	Live        bool   `json:"live"`
	PeersTotal  int    `json:"peers_total"`
	PeersOnline int    `json:"peers_online"`
}

// online = handshake within the last 3 minutes. Same threshold the
// PeersPage uses so the dashboard count and the per-row "live" dot
// agree on what "online" means.
const onlineWindow = 3 * time.Minute

// topPeerLimit is the size of the "top N" list returned to the
// dashboard. 10 fits the sidebar layout without scrolling.
const topPeerLimit = 10

func (h *DashboardHandler) Get(c *gin.Context) {
	ctx := c.Request.Context()
	now := time.Now()

	resp := dashboardResponse{GeneratedAt: now}

	// ---- counts: cheap COUNTs against the DB ------------------------
	if h.Interfaces != nil {
		ifaces, err := h.Interfaces.List(ctx)
		if err != nil {
			slog.WarnContext(ctx, "dashboard: list interfaces", "err", err)
		} else {
			resp.Counts.Locations = len(ifaces)
			// Pre-seed the location panel so the frontend doesn't
			// have to merge two payloads to render the table.
			for _, iface := range ifaces {
				resp.Locations = append(resp.Locations, dashboardLoc{
					Name: iface.Name, ListenPort: iface.ListenPort,
				})
			}
		}
	}

	// User and peer counts via tiny dedicated queries — cheaper than
	// ListPage's full row scan.
	if h.Users != nil {
		// ListPage with limit=1 returns total alongside the row, which
		// is the cheapest way to get the count without a new repo
		// method.
		_, total, err := h.Users.ListPage(ctx, 1, 0, "email", false)
		if err != nil {
			slog.WarnContext(ctx, "dashboard: count users", "err", err)
		} else {
			resp.Counts.Users = total
		}
	}

	// ---- live peer state: walk the kernel ---------------------------
	type peerRow struct {
		iface         string
		pub           string
		lastHandshake time.Time
		rx, tx        int64
	}
	var live []peerRow
	if h.Client != nil {
		for i := range resp.Locations {
			loc := &resp.Locations[i]
			dev, err := h.Client.Device(loc.Name)
			if err != nil || dev == nil {
				continue
			}
			loc.Live = true
			loc.PeersTotal = len(dev.Peers)
			for _, p := range dev.Peers {
				row := peerRow{
					iface:         dev.Name,
					pub:           p.PublicKey,
					lastHandshake: p.LastHandshake,
					rx:            p.RxBytes,
					tx:            p.TxBytes,
				}
				live = append(live, row)
				if !p.LastHandshake.IsZero() &&
					now.Sub(p.LastHandshake) < onlineWindow {
					loc.PeersOnline++
					resp.Counts.PeersOnline++
				}
			}
		}
	}
	resp.Counts.Peers = len(live)

	// ---- top peers by RX+TX -----------------------------------------
	sort.Slice(live, func(a, b int) bool {
		return live[a].rx+live[a].tx > live[b].rx+live[b].tx
	})
	if len(live) > topPeerLimit {
		live = live[:topPeerLimit]
	}

	// Owner-email lookup. We resolve via a single owner_user_id ->
	// email map built from the admin user list — same query the
	// frontend already caches under the "users-picker" key.
	ownerByPubKey := map[string]string{}
	if h.Peers != nil && h.Users != nil && len(live) > 0 {
		// Build pub_key -> owner_user_id by scanning every interface.
		// Scale-wise this is bounded by the DB peer count; for the
		// dashboard's at-a-glance use case that's fine.
		// (A dedicated SQL would beat this — keep it simple for now.)
		users, _, err := h.Users.ListPage(ctx, 200, 0, "email", false)
		if err == nil && h.Interfaces != nil {
			ifaces, _ := h.Interfaces.List(ctx)
			emailByID := map[string]string{}
			for _, u := range users {
				emailByID[u.ID.String()] = u.Email
			}
			for _, iface := range ifaces {
				peers, _ := h.Peers.ListByInterface(ctx, iface.ID)
				for _, p := range peers {
					if p.OwnerUserID != nil {
						if email, ok := emailByID[p.OwnerUserID.String()]; ok {
							ownerByPubKey[p.PublicKey] = email
						}
					}
				}
			}
		}
	}

	for _, r := range live {
		resp.TopPeers = append(resp.TopPeers, dashboardPeer{
			PublicKey:     r.pub,
			Interface:     r.iface,
			OwnerEmail:    ownerByPubKey[r.pub],
			LastHandshake: r.lastHandshake,
			RxBytes:       r.rx,
			TxBytes:       r.tx,
		})
	}

	c.JSON(http.StatusOK, resp)
}

// EnsureNotNil makes sure JSON encoding produces empty arrays instead
// of nulls, matching what the frontend treats as the empty case. Kept
// out of the hot path — only invoked by tests today.
func (r *dashboardResponse) EnsureNotNil() {
	if r.TopPeers == nil {
		r.TopPeers = []dashboardPeer{}
	}
	if r.Locations == nil {
		r.Locations = []dashboardLoc{}
	}
}

// silence unused-import warnings in the rare configuration where
// apierror is dropped by future refactors. The handler returns errors
// via writeError elsewhere in this package.
var _ = apierror.CodeInternal
