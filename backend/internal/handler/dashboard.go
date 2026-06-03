package handler

import (
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

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
	Counts      dashboardCounts `json:"counts"`
	TopPeers    []dashboardPeer `json:"top_peers"`
	Locations   []dashboardLoc  `json:"locations"`
	GeneratedAt time.Time       `json:"generated_at"`
}

type dashboardCounts struct {
	Locations   int `json:"locations"`
	Users       int `json:"users"`
	Peers       int `json:"peers"`
	PeersOnline int `json:"peers_online"`
}

type dashboardPeer struct {
	PublicKey string `json:"public_key"`
	Interface string `json:"interface"`
	// OwnerUsername is the operator-friendly identifier the dashboard
	// renders by default. OwnerEmail stays in the payload so the UI
	// can surface it on hover for support workflows. Both empty when
	// the peer is unassigned.
	OwnerUsername string    `json:"owner_username,omitempty"`
	OwnerEmail    string    `json:"owner_email,omitempty"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
}

type dashboardOwner struct {
	username string
	email    string
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

	// ---- interfaces + per-interface DB peer rows --------------------
	// We hoist the per-interface peer fetch here so the dashboard's
	// "Peers" totals (#83 P1) come from the DB-of-record, not the
	// live kernel walk. Live counts can read as 0 when the kernel
	// failed to apply (CAP_NET_BIND_SERVICE missing, eBPF degraded,
	// reconcile gap) — yet the /peers page reads N from the same DB
	// and the operator gets a contradiction. By making "Peers" mean
	// "DB peer rows", the dashboard agrees with /peers. The kernel
	// walk below only contributes PeersOnline (handshake-based) and
	// rx/tx for the top-peers list.
	type dbPeerRow struct {
		ifaceName   string
		ownerUserID *uuid.UUID
	}
	dbPeersByPubKey := map[string]dbPeerRow{}
	if h.Interfaces != nil {
		ifaces, err := h.Interfaces.List(ctx)
		if err != nil {
			slog.WarnContext(ctx, "dashboard: list interfaces", "err", err)
		} else {
			resp.Counts.Locations = len(ifaces)
			for _, iface := range ifaces {
				loc := dashboardLoc{Name: iface.Name, ListenPort: iface.ListenPort}
				if h.Peers != nil {
					rows, perr := h.Peers.ListByInterface(ctx, iface.ID)
					if perr != nil {
						slog.WarnContext(ctx, "dashboard: list peers",
							"iface", iface.Name, "err", perr)
					} else {
						loc.PeersTotal = len(rows)
						resp.Counts.Peers += len(rows)
						for _, p := range rows {
							dbPeersByPubKey[p.PublicKey] = dbPeerRow{
								ifaceName:   iface.Name,
								ownerUserID: p.OwnerUserID,
							}
						}
					}
				}
				resp.Locations = append(resp.Locations, loc)
			}
		}
	}

	// User count via tiny dedicated query — ListPage(limit=1) returns
	// the total alongside the row, cheaper than a separate COUNT.
	if h.Users != nil {
		_, total, err := h.Users.ListPage(ctx, 1, 0, "email", false)
		if err != nil {
			slog.WarnContext(ctx, "dashboard: count users", "err", err)
		} else {
			resp.Counts.Users = total
		}
	}

	// ---- live peer state: walk the kernel ---------------------------
	// Used for PeersOnline (handshake within onlineWindow) and the
	// top-peers RX/TX list. NOT used for total counts — see note
	// above.
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

	// ---- top peers by RX+TX -----------------------------------------
	sort.Slice(live, func(a, b int) bool {
		return live[a].rx+live[a].tx > live[b].rx+live[b].tx
	})
	if len(live) > topPeerLimit {
		live = live[:topPeerLimit]
	}

	// Owner lookup keyed by peer public key. Built from the DB-side
	// dbPeersByPubKey map we populated up top — no second pass over
	// the per-interface peer rows.
	ownerByPubKey := map[string]dashboardOwner{}
	if h.Users != nil && len(live) > 0 && len(dbPeersByPubKey) > 0 {
		users, _, err := h.Users.ListPage(ctx, 200, 0, "email", false)
		if err == nil {
			ownersByID := map[string]dashboardOwner{}
			for _, u := range users {
				ownersByID[u.ID.String()] = dashboardOwner{
					username: u.Username,
					email:    u.Email,
				}
			}
			for pubkey, row := range dbPeersByPubKey {
				if row.ownerUserID != nil {
					if o, ok := ownersByID[row.ownerUserID.String()]; ok {
						ownerByPubKey[pubkey] = o
					}
				}
			}
		}
	}

	for _, r := range live {
		o := ownerByPubKey[r.pub]
		resp.TopPeers = append(resp.TopPeers, dashboardPeer{
			PublicKey:     r.pub,
			Interface:     r.iface,
			OwnerUsername: o.username,
			OwnerEmail:    o.email,
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
