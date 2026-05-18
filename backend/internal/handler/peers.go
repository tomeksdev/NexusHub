package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/tomeksdev/NexusHub/backend/internal/apierror"
	"github.com/tomeksdev/NexusHub/backend/internal/crypto"
	"github.com/tomeksdev/NexusHub/backend/internal/httppage"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
	"github.com/tomeksdev/NexusHub/backend/internal/wg"
)

// peerPrivateKeyAAD is bound to the ciphertext of every peer private key,
// so a row copied between tables won't decrypt under the same master key.
var peerPrivateKeyAAD = []byte("wg_peers.private_key")

// peerPSKAAD binds each preshared-key ciphertext to its storage location,
// so a retired row cannot be copied into the active slot for another peer.
var peerPSKAAD = []byte("wg_peer_preshared_keys.preshared_key")

// PeerHandler owns CRUD on wg_peers plus the .conf and QR exports.
type PeerHandler struct {
	Peers      *repository.PeerRepo
	Interfaces *repository.InterfaceRepo
	// Users is optional. When set, peer create rejects an
	// owner_user_id pointing at a disabled user — without this the
	// operator can hand out VPN credentials to an account that can no
	// longer log in to manage them.
	Users *repository.UserRepo
	AEAD  *crypto.AEAD
	// Client pushes peer changes into the kernel WireGuard device. Nil in
	// tests and dev environments without the kernel module — handlers
	// degrade to DB-only writes in that case.
	Client wg.Client
	// DefaultEndpoint is the `host:port` we fall back to when neither the
	// peer nor its interface carries an Endpoint — this is what operators
	// set via WG_ENDPOINT so a single server can be reached from behind
	// NAT without per-peer config.
	DefaultEndpoint string
	// DefaultDNS is pushed to peers that don't override it. Same fall-back
	// chain as endpoint: peer → interface → default.
	DefaultDNS []string
}

type peerResponse struct {
	ID                  uuid.UUID  `json:"id"`
	InterfaceID         uuid.UUID  `json:"interface_id"`
	OwnerUserID         *uuid.UUID `json:"owner_user_id,omitempty"`
	Name                string     `json:"name"`
	Description         *string    `json:"description,omitempty"`
	PublicKey           string     `json:"public_key"`
	AllowedIPs          []string   `json:"allowed_ips"`
	ClientAllowedIPs    []string   `json:"client_allowed_ips"`
	AssignedIP          string     `json:"assigned_ip"`
	Endpoint            *string    `json:"endpoint,omitempty"`
	PersistentKeepalive *int       `json:"persistent_keepalive,omitempty"`
	DNS                 []string   `json:"dns"`
	Status              string     `json:"status"`
	LastHandshake       *time.Time `json:"last_handshake,omitempty"`
	RxBytes             int64      `json:"rx_bytes"`
	TxBytes             int64      `json:"tx_bytes"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

func toPeerResponse(p *repository.Peer) peerResponse {
	allowed := make([]string, len(p.AllowedIPs))
	for i, a := range p.AllowedIPs {
		allowed[i] = a.String()
	}
	clientAllowed := make([]string, len(p.ClientAllowedIPs))
	for i, a := range p.ClientAllowedIPs {
		clientAllowed[i] = a.String()
	}
	return peerResponse{
		ID: p.ID, InterfaceID: p.InterfaceID, OwnerUserID: p.OwnerUserID,
		Name: p.Name, Description: p.Description, PublicKey: p.PublicKey,
		AllowedIPs: allowed, ClientAllowedIPs: clientAllowed,
		AssignedIP: p.AssignedIP.String(),
		Endpoint:   p.Endpoint, PersistentKeepalive: p.PersistentKeepalive,
		DNS: p.DNS, Status: p.Status, LastHandshake: p.LastHandshake,
		RxBytes: p.RxBytes, TxBytes: p.TxBytes, ExpiresAt: p.ExpiresAt,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

type createPeerRequest struct {
	InterfaceID string  `json:"interface_id"        binding:"required,uuid"`
	Name        string  `json:"name"                binding:"required"`
	Description *string `json:"description"`
	PublicKey   *string `json:"public_key"`
	// AllowedIPs is the server-side filter — what the kernel accepts
	// from this peer / routes to this peer.
	AllowedIPs []string `json:"allowed_ips"`
	// ClientAllowedIPs is what gets emitted into the peer's exported
	// .conf [Peer] block. Different concept than AllowedIPs; see
	// renderWgQuickConfig for fallback semantics.
	ClientAllowedIPs    []string   `json:"client_allowed_ips"`
	AssignedIP          *string    `json:"assigned_ip"`
	Endpoint            *string    `json:"endpoint"`
	PersistentKeepalive *int       `json:"persistent_keepalive"`
	DNS                 []string   `json:"dns"`
	ExpiresAt           *time.Time `json:"expires_at"`
	OwnerUserID         *string    `json:"owner_user_id"`
}

// Create wires together: derive/generate keys, allocate IP, encrypt
// private key (if generated), insert. The branch on PublicKey lets clients
// either keep their key material on the device (preferred — server never
// holds the secret) or have the server generate it (convenience for QR
// onboarding flows).
func (h *PeerHandler) Create(c *gin.Context) {
	var req createPeerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	ifaceID := uuid.MustParse(req.InterfaceID)

	ctx := c.Request.Context()
	iface, err := h.Interfaces.GetByID(ctx, ifaceID)
	if errors.Is(err, repository.ErrInterfaceNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "interface not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "get interface", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	// Key material.
	var (
		pubKey     string
		sealedPriv []byte
	)
	if req.PublicKey != nil && *req.PublicKey != "" {
		if _, err := wg.DecodePublicKey(*req.PublicKey); err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "public_key must be 44-char base64")
			return
		}
		pubKey = *req.PublicKey
	} else {
		kp, err := wg.GenerateKeyPair()
		if err != nil {
			slog.ErrorContext(ctx, "generate keypair", "err", err)
			writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return
		}
		pubKey = kp.Public
		sealedPriv, err = h.AEAD.Seal(kp.Private, peerPrivateKeyAAD)
		if err != nil {
			slog.ErrorContext(ctx, "seal private", "err", err)
			writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return
		}
	}

	// Validate persistent_keepalive bound at the boundary so the DB
	// CHECK constraint isn't the first line of defense.
	if req.PersistentKeepalive != nil &&
		(*req.PersistentKeepalive < 0 || *req.PersistentKeepalive > 65535) {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
			"persistent_keepalive must be 0–65535")
		return
	}

	// Endpoint, when supplied, must parse as host:port — wgctrl rejects
	// anything else with an opaque netlink error otherwise.
	if req.Endpoint != nil && *req.Endpoint != "" {
		if _, _, err := net.SplitHostPort(*req.Endpoint); err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
				"endpoint must be host:port")
			return
		}
	}

	// Assigned IP — explicit if supplied, else next free.
	var assigned netip.Addr
	if req.AssignedIP != nil && *req.AssignedIP != "" {
		a, err := netip.ParseAddr(*req.AssignedIP)
		if err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "assigned_ip must be an IP address")
			return
		}
		if !iface.Address.Contains(a) {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "assigned_ip not in interface CIDR")
			return
		}
		// Reject the addresses the allocator would have skipped: the
		// network address, the v4 broadcast, and the interface's own
		// address. Letting any of these through would silently break
		// routing for the whole subnet.
		if a == iface.Address.Masked().Addr() {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
				"assigned_ip is the network address")
			return
		}
		if a == iface.Address.Addr() {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
				"assigned_ip collides with the interface address")
			return
		}
		if a.Is4() {
			if b, ok := wg.Broadcast(iface.Address); ok && a == b {
				writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
					"assigned_ip is the broadcast address")
				return
			}
		}
		assigned = a
	} else {
		used, err := h.Peers.AssignedIPsByInterface(ctx, ifaceID)
		if err != nil {
			slog.ErrorContext(ctx, "list assigned ips", "err", err)
			writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return
		}
		assigned, err = wg.AllocateIP(iface.Address, used)
		if errors.Is(err, wg.ErrPoolExhausted) {
			writeError(c, http.StatusConflict, apierror.CodePoolExhausted, "interface IP pool exhausted")
			return
		}
		if err != nil {
			slog.ErrorContext(ctx, "allocate ip", "err", err)
			writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return
		}
	}

	allowed, err := parsePrefixesStrict(req.AllowedIPs)
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
			"allowed_ips: "+err.Error())
		return
	}
	if err := rejectFullTunnelServerSide(allowed); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	// The assigned /32 (or /128) is load-bearing — the WG kernel module
	// rejects the peer's own source IP without it, which would break
	// every broader route. Always present in the saved list, whether
	// the operator supplied it explicitly or not.
	bits := 32
	if !assigned.Is4() {
		bits = 128
	}
	assignedPfx := netip.PrefixFrom(assigned, bits)
	covered := false
	for _, p := range allowed {
		if p.Contains(assigned) {
			covered = true
			break
		}
	}
	if !covered {
		allowed = append([]netip.Prefix{assignedPfx}, allowed...)
	}

	dns := req.DNS
	if dns == nil {
		dns = []string{}
	}

	var owner *uuid.UUID
	if req.OwnerUserID != nil && *req.OwnerUserID != "" {
		ou, err := uuid.Parse(*req.OwnerUserID)
		if err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "owner_user_id must be uuid")
			return
		}
		// Block assigning peers to a disabled (or non-existent) user.
		// is_active is the soft-delete flag; an owner who can't log in
		// can't manage their own VPN credentials, which defeats the
		// purpose of the linkage.
		if h.Users != nil {
			u, uerr := h.Users.GetByID(ctx, ou)
			if errors.Is(uerr, repository.ErrUserNotFound) {
				writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
					"owner_user_id does not exist")
				return
			}
			if uerr != nil {
				slog.ErrorContext(ctx, "lookup peer owner", "err", uerr)
				writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
				return
			}
			if !u.IsActive {
				writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
					"owner_user_id refers to a disabled user")
				return
			}
		}
		owner = &ou
	}

	clientAllowed, err := parsePrefixesStrict(req.ClientAllowedIPs)
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
			"client_allowed_ips: "+err.Error())
		return
	}

	out, err := h.Peers.Create(ctx, repository.CreatePeerParams{
		InterfaceID: ifaceID, OwnerUserID: owner,
		Name: req.Name, Description: req.Description,
		PublicKey: pubKey, PrivateKey: sealedPriv,
		AllowedIPs: allowed, ClientAllowedIPs: clientAllowed,
		AssignedIP: assigned,
		Endpoint:   req.Endpoint, PersistentKeepalive: req.PersistentKeepalive,
		DNS: dns, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(c, http.StatusConflict, apierror.CodeConflict, "peer name, public key, or IP already in use")
			return
		}
		slog.ErrorContext(ctx, "create peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	// Push the new peer into the live kernel device. Failures here are
	// logged but non-fatal for the request — the DB is now source of
	// truth, and the reconciler will re-converge on next restart.
	if h.Client != nil {
		allowedForKernel := append([]netip.Prefix(nil), out.AllowedIPs...)
		allowedForKernel = append(allowedForKernel,
			netip.PrefixFrom(out.AssignedIP, assignedBits(out.AssignedIP)))
		cfg := wg.Config{Peers: []wg.PeerConfig{{
			PublicKey:  out.PublicKey,
			Endpoint:   optString(out.Endpoint),
			AllowedIPs: allowedForKernel,
			Replace:    true,
		}}}
		if err := h.Client.ConfigureDevice(iface.Name, cfg); err != nil {
			slog.WarnContext(ctx, "kernel apply peer", "err", err, "iface", iface.Name)
		}
	}
	c.JSON(http.StatusCreated, toPeerResponse(out))
}

func optString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func assignedBits(a netip.Addr) int {
	if a.Is4() {
		return 32
	}
	return 128
}

func (h *PeerHandler) List(c *gin.Context) {
	pg := httppage.Parse(c)
	sortField, sortDesc := pg.ResolveSort(repository.PeerSortFields, "name")
	ctx := c.Request.Context()

	// Two filter modes: by interface_id (the per-Location admin
	// flow) OR by owner_user_id (the User detail view). Exactly
	// one must be supplied — combining them would need a third
	// repo method and we haven't found a use case yet.
	ifaceParam := c.Query("interface_id")
	ownerParam := c.Query("owner_user_id")
	if ifaceParam == "" && ownerParam == "" {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
			"interface_id or owner_user_id query parameter required")
		return
	}
	if ifaceParam != "" && ownerParam != "" {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
			"interface_id and owner_user_id cannot be combined")
		return
	}

	var (
		peers []repository.Peer
		total int
		err   error
	)
	if ownerParam != "" {
		ownerID, perr := uuid.Parse(ownerParam)
		if perr != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "owner_user_id must be uuid")
			return
		}
		peers, total, err = h.Peers.ListPageByOwner(ctx, ownerID, pg.Limit, pg.Offset, sortField, sortDesc)
	} else {
		ifaceID, perr := uuid.Parse(ifaceParam)
		if perr != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "interface_id must be uuid")
			return
		}
		peers, total, err = h.Peers.ListPage(ctx, ifaceID, pg.Limit, pg.Offset, sortField, sortDesc)
	}
	if err != nil {
		slog.ErrorContext(ctx, "list peers", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	out := make([]peerResponse, 0, len(peers))
	for i := range peers {
		out = append(out, toPeerResponse(&peers[i]))
	}
	c.JSON(http.StatusOK, httppage.Wrap(out, total, pg, sortField, sortDesc))
}

func (h *PeerHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	p, err := h.Peers.GetByID(c.Request.Context(), id)
	if errors.Is(err, repository.ErrPeerNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "peer not found")
		return
	}
	if err != nil {
		slog.ErrorContext(c, "get peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.JSON(http.StatusOK, toPeerResponse(p))
}

func (h *PeerHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	ctx := c.Request.Context()

	// Snapshot iface + pubkey BEFORE delete so we can issue the kernel
	// remove afterward. Doing this in the reverse order means a crash
	// between DB-delete and kernel-delete leaves the kernel holding a
	// dangling peer — recoverable by the reconciler on next startup.
	var ifaceName, pubKey string
	if h.Client != nil {
		peer, perr := h.Peers.GetByID(ctx, id)
		if perr == nil {
			pubKey = peer.PublicKey
			if iface, ierr := h.Interfaces.GetByID(ctx, peer.InterfaceID); ierr == nil {
				ifaceName = iface.Name
			}
		}
	}

	err = h.Peers.Delete(ctx, id)
	if errors.Is(err, repository.ErrPeerNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "peer not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "delete peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	if h.Client != nil && ifaceName != "" && pubKey != "" {
		cfg := wg.Config{Peers: []wg.PeerConfig{{PublicKey: pubKey, Remove: true}}}
		if err := h.Client.ConfigureDevice(ifaceName, cfg); err != nil {
			slog.WarnContext(ctx, "kernel remove peer", "err", err, "iface", ifaceName)
		}
	}
	c.Status(http.StatusNoContent)
}

// updatePeerRequest is the PATCH body for /peers/:id. Pointer fields
// opt in per-column; the inner pointer-to-pointer pattern on text
// columns lets callers explicitly clear them (JSON null) vs. leave
// alone (field absent).
type updatePeerRequest struct {
	Name                *string     `json:"name"`
	Description         **string    `json:"description,omitempty"`
	OwnerUserID         **string    `json:"owner_user_id,omitempty"`
	AllowedIPs          *[]string   `json:"allowed_ips"`
	ClientAllowedIPs    *[]string   `json:"client_allowed_ips"`
	Endpoint            **string    `json:"endpoint,omitempty"`
	DNS                 *[]string   `json:"dns"`
	PersistentKeepalive **int       `json:"persistent_keepalive,omitempty"`
	ExpiresAt           **time.Time `json:"expires_at,omitempty"`
	Status              *string     `json:"status"`
}

// Update applies a partial change to a peer row and pushes the diff
// to the kernel device. Operators reach this when they need to add a
// network to an existing peer's AllowedIPs without rotating keys.
func (h *PeerHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	var req updatePeerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	ctx := c.Request.Context()

	// Pull the current row first — needed for the kernel apply
	// path (we need to know the interface to talk to the right
	// device) and for cross-validation of allowed_ips against
	// assigned_ip.
	current, err := h.Peers.GetByID(ctx, id)
	if errors.Is(err, repository.ErrPeerNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "peer not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "get peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	params := repository.UpdatePeerParams{
		Name:        req.Name,
		Description: req.Description,
		Endpoint:    req.Endpoint,
		DNS:         req.DNS,
		Status:      req.Status,
		ExpiresAt:   req.ExpiresAt,
	}
	if req.PersistentKeepalive != nil {
		if inner := *req.PersistentKeepalive; inner != nil &&
			(*inner < 0 || *inner > 65535) {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
				"persistent_keepalive must be 0–65535")
			return
		}
		params.PersistentKeepalive = req.PersistentKeepalive
	}
	if req.OwnerUserID != nil {
		var ownerPtr *uuid.UUID
		if inner := *req.OwnerUserID; inner != nil && *inner != "" {
			ou, perr := uuid.Parse(*inner)
			if perr != nil {
				writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "owner_user_id must be uuid")
				return
			}
			// Block reassigning to a disabled user — same rule as Create.
			if h.Users != nil {
				u, uerr := h.Users.GetByID(ctx, ou)
				if errors.Is(uerr, repository.ErrUserNotFound) {
					writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
						"owner_user_id does not exist")
					return
				}
				if uerr != nil {
					slog.ErrorContext(ctx, "lookup peer owner", "err", uerr)
					writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
					return
				}
				if !u.IsActive {
					writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
						"owner_user_id refers to a disabled user")
					return
				}
			}
			ownerPtr = &ou
		}
		// JSON null on owner_user_id ⇒ ownerPtr stays nil ⇒ clear.
		params.OwnerUserID = &ownerPtr
	}
	if req.AllowedIPs != nil {
		ips, perr := parsePrefixesStrict(*req.AllowedIPs)
		if perr != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
				"allowed_ips: "+perr.Error())
			return
		}
		if err := rejectFullTunnelServerSide(ips); err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
			return
		}
		// The assigned /32 (or /128) is load-bearing: without it the WG
		// kernel module won't accept the peer's own source IP, which
		// breaks every other route. Auto-add when missing so the operator
		// can't lock themselves out by forgetting it. Mirrors the Create
		// path's "empty → default to assigned /32" rule but applied here
		// as "non-empty but missing → augment, not replace".
		assignedBitsN := assignedBits(current.AssignedIP)
		assignedPfx := netip.PrefixFrom(current.AssignedIP, assignedBitsN)
		covered := false
		for _, p := range ips {
			if p.Contains(current.AssignedIP) {
				covered = true
				break
			}
		}
		if !covered {
			// Prepend so the operator's added networks remain visible
			// in the order they typed them when the row round-trips.
			ips = append([]netip.Prefix{assignedPfx}, ips...)
		}
		params.AllowedIPs = &ips
	}
	if req.ClientAllowedIPs != nil {
		ips, perr := parsePrefixesStrict(*req.ClientAllowedIPs)
		if perr != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
				"client_allowed_ips: "+perr.Error())
			return
		}
		params.ClientAllowedIPs = &ips
	}
	if req.Endpoint != nil {
		if inner := *req.Endpoint; inner != nil && *inner != "" {
			if _, _, err := net.SplitHostPort(*inner); err != nil {
				writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
					"endpoint must be host:port")
				return
			}
		}
	}

	out, err := h.Peers.Update(ctx, id, params)
	if errors.Is(err, repository.ErrPeerNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "peer not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "update peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	// Kernel re-apply: push the new AllowedIPs / endpoint /
	// keepalive into the live device so existing handshakes pick
	// up the change without a wg restart. ReplaceAllowedIPs=true
	// clears the kernel's old set in one shot.
	if h.Client != nil {
		iface, ierr := h.Interfaces.GetByID(ctx, out.InterfaceID)
		if ierr == nil {
			allowed := append([]netip.Prefix(nil), out.AllowedIPs...)
			allowed = append(allowed, netip.PrefixFrom(out.AssignedIP, assignedBits(out.AssignedIP)))
			cfg := wg.Config{Peers: []wg.PeerConfig{{
				PublicKey:  out.PublicKey,
				Endpoint:   optString(out.Endpoint),
				AllowedIPs: allowed,
				Replace:    true,
			}}}
			if out.PersistentKeepalive != nil {
				ka := time.Duration(*out.PersistentKeepalive) * time.Second
				cfg.Peers[0].PersistentKeepAlive = &ka
			}
			if err := h.Client.ConfigureDevice(iface.Name, cfg); err != nil {
				slog.WarnContext(ctx, "kernel apply peer update", "err", err, "iface", iface.Name)
			}
		}
	}

	c.JSON(http.StatusOK, toPeerResponse(out))
}

// RotatePSK generates a fresh 32-byte preshared key, encrypts it under the
// master AEAD, retires the previous active row, and inserts the new one.
// Returns the peer record; the new PSK itself is not surfaced in the
// response — clients pull it via /peers/:id/config on the next fetch.
func (h *PeerHandler) RotatePSK(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	ctx := c.Request.Context()

	peer, err := h.Peers.GetByID(ctx, id)
	if errors.Is(err, repository.ErrPeerNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "peer not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "get peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		slog.ErrorContext(ctx, "generate psk", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	sealed, err := h.AEAD.Seal(psk, peerPSKAAD)
	if err != nil {
		slog.ErrorContext(ctx, "seal psk", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if err := h.Peers.RotatePSK(ctx, id, sealed); err != nil {
		slog.ErrorContext(ctx, "rotate psk", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	// Apply the new PSK to the kernel so existing tunnels re-key without
	// waiting for a reconciler pass. A failure here is logged but not
	// surfaced — the DB row is authoritative and a retry is cheap.
	if h.Client != nil {
		if iface, ierr := h.Interfaces.GetByID(ctx, peer.InterfaceID); ierr == nil {
			cfg := wg.Config{Peers: []wg.PeerConfig{{
				PublicKey:    peer.PublicKey,
				PresharedKey: psk,
			}}}
			if err := h.Client.ConfigureDevice(iface.Name, cfg); err != nil {
				slog.WarnContext(ctx, "kernel apply psk", "err", err, "iface", iface.Name)
			}
		}
	}
	c.JSON(http.StatusOK, toPeerResponse(peer))
}

// Config returns the .conf text the peer should drop into wg-quick. If the
// server has no private key for this peer (operator-managed key flow), we
// substitute a placeholder so the file still has the right shape for the
// human to fill in — this is preferable to a 404 because operators expect
// "give me the config" to always work.
func (h *PeerHandler) Config(c *gin.Context) {
	text, _, err := h.renderConfig(c)
	if err != nil {
		return
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, text)
}

// ConfigQR returns the same .conf as a PNG QR — what mobile WireGuard
// clients scan during onboarding.
func (h *PeerHandler) ConfigQR(c *gin.Context) {
	text, _, err := h.renderConfig(c)
	if err != nil {
		return
	}
	png, err := qrcode.Encode(text, qrcode.Medium, 512)
	if err != nil {
		slog.ErrorContext(c, "encode qr", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.Data(http.StatusOK, "image/png", png)
}

// renderConfig parses the peer id from the URL and delegates to
// renderConfigFor. Used by the admin Config + ConfigQR endpoints.
func (h *PeerHandler) renderConfig(c *gin.Context) (string, *repository.Peer, error) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return "", nil, err
	}
	return h.RenderConfigFor(c, id)
}

// RenderConfigFor builds the wg-quick config for a specific peer id.
// Exported so the user self-service handler (/me/peers) can reuse
// the renderer after performing its own ownership check. Writes its
// own error responses and returns the error so callers can short-
// circuit; on success the third return is nil.
func (h *PeerHandler) RenderConfigFor(c *gin.Context, id uuid.UUID) (string, *repository.Peer, error) {
	ctx := c.Request.Context()
	peer, err := h.Peers.GetByID(ctx, id)
	if errors.Is(err, repository.ErrPeerNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "peer not found")
		return "", nil, err
	}
	if err != nil {
		slog.ErrorContext(ctx, "get peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return "", nil, err
	}
	iface, err := h.Interfaces.GetByID(ctx, peer.InterfaceID)
	if err != nil {
		slog.ErrorContext(ctx, "get interface for peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return "", nil, err
	}

	privB64 := "<<insert-your-private-key>>"
	if peer.PrivateKey != nil {
		raw, err := h.AEAD.Open(peer.PrivateKey, peerPrivateKeyAAD)
		if err != nil {
			slog.ErrorContext(ctx, "open peer key", "err", err)
			writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return "", nil, err
		}
		privB64 = wg.EncodeKey(raw)
	}

	// Preshared key is optional; if rotation has never run there's no row.
	pskSealed, err := h.Peers.ActivePSK(ctx, peer.ID)
	if err != nil {
		slog.ErrorContext(ctx, "load psk", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return "", nil, err
	}
	var pskB64 string
	if pskSealed != nil {
		raw, err := h.AEAD.Open(pskSealed, peerPSKAAD)
		if err != nil {
			slog.ErrorContext(ctx, "open psk", "err", err)
			writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return "", nil, err
		}
		pskB64 = wg.EncodeKey(raw)
	}

	cfg := renderWgQuickConfig(peer, iface, privB64, pskB64, h.DefaultEndpoint, h.DefaultDNS)
	return cfg, peer, nil
}

// renderWgQuickConfig builds a wg-quick formatted config. Kept as a free
// function so it's trivially testable without a router.
//
// Endpoint / DNS resolution follows peer → interface → server default so an
// operator can set a single WG_ENDPOINT for a NAT-fronted install and have
// every exported config point at the public hostname without per-peer edits.
func renderWgQuickConfig(
	p *repository.Peer, iface *repository.Interface,
	peerPrivateB64, pskB64, defaultEndpoint string,
	defaultDNS []string,
) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", peerPrivateB64)
	fmt.Fprintf(&sb, "Address = %s\n", p.AssignedIP.String())

	dns := p.DNS
	if len(dns) == 0 {
		dns = iface.DNS
	}
	if len(dns) == 0 {
		dns = defaultDNS
	}
	if len(dns) > 0 {
		fmt.Fprintf(&sb, "DNS = %s\n", strings.Join(dns, ", "))
	}

	sb.WriteString("\n[Peer]\n")
	fmt.Fprintf(&sb, "PublicKey = %s\n", iface.PublicKey)
	if pskB64 != "" {
		fmt.Fprintf(&sb, "PresharedKey = %s\n", pskB64)
	}
	// AllowedIPs in the [Peer] block is what the CLIENT routes through
	// the tunnel — different concept than wg_peers.allowed_ips, which
	// is the server-side filter. Operator-supplied client_allowed_ips
	// wins; otherwise default to the interface CIDR (split-tunnel —
	// reaches the server's network only). Operators wanting full-tunnel
	// set client_allowed_ips=[0.0.0.0/0,::/0] explicitly.
	var allowed []string
	if len(p.ClientAllowedIPs) > 0 {
		allowed = make([]string, 0, len(p.ClientAllowedIPs))
		for _, a := range p.ClientAllowedIPs {
			allowed = append(allowed, a.String())
		}
	} else {
		allowed = []string{iface.Address.Masked().String()}
	}
	fmt.Fprintf(&sb, "AllowedIPs = %s\n", strings.Join(allowed, ", "))

	endpoint := ""
	if p.Endpoint != nil && *p.Endpoint != "" {
		endpoint = *p.Endpoint
	} else if iface.Endpoint != nil && *iface.Endpoint != "" {
		endpoint = *iface.Endpoint
	} else {
		endpoint = defaultEndpoint
	}
	if endpoint != "" {
		// WireGuard requires Endpoint to include an explicit UDP
		// port. Operators sometimes save the location's endpoint
		// as bare "vpn.example.com" — without a port the exported
		// .conf produces "Endpoint = vpn.example.com" which
		// silently fails to parse. Append the location's listen
		// port when one is missing. SplitHostPort doubles as the
		// validity check; if it fails, the string lacks a port.
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			endpoint = net.JoinHostPort(endpoint, fmt.Sprintf("%d", iface.ListenPort))
		}
		fmt.Fprintf(&sb, "Endpoint = %s\n", endpoint)
	}
	if p.PersistentKeepalive != nil && *p.PersistentKeepalive > 0 {
		fmt.Fprintf(&sb, "PersistentKeepalive = %d\n", *p.PersistentKeepalive)
	}
	return sb.String()
}

// rejectFullTunnelServerSide blocks 0.0.0.0/0 and ::/0 in the server-side
// AllowedIPs list. Operationally these are footguns: the WG kernel module
// would accept any source IP from the peer, defeating the per-peer source
// validation that the rest of the security model relies on. The client-
// side `client_allowed_ips` (what gets exported into the peer's .conf)
// can still carry 0.0.0.0/0 — full-tunnel routing is a legitimate client
// configuration, just not a legitimate server-side filter.
func rejectFullTunnelServerSide(in []netip.Prefix) error {
	for _, p := range in {
		if p.Bits() == 0 {
			return fmt.Errorf(
				"allowed_ips: %s is not allowed server-side (use client_allowed_ips for full-tunnel client routing)",
				p,
			)
		}
	}
	return nil
}

// parsePrefixesStrict refuses any unparseable entry. parsePrefixes was
// silently dropping bad input, which let typos like "10.0.0/24" or
// "10.0.0.0/240" escape into requests; the strict variant returns an
// error so the handler can 400.
func parsePrefixesStrict(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}
