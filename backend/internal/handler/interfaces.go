package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/tomeksdev/NexusHub/backend/internal/apierror"
	"github.com/tomeksdev/NexusHub/backend/internal/crypto"
	"github.com/tomeksdev/NexusHub/backend/internal/diag"
	"github.com/tomeksdev/NexusHub/backend/internal/httppage"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
	"github.com/tomeksdev/NexusHub/backend/internal/wg"
)

// InterfaceHandler owns CRUD on wg_interfaces.
type InterfaceHandler struct {
	Interfaces *repository.InterfaceRepo
	AEAD       *crypto.AEAD
	// Client pushes private key + listen port + peers into the kernel
	// device once it exists. Nil in tests and dev environments without
	// the WG kernel module loaded.
	Client wg.Client
	// Links creates / deletes the kernel link itself. wgctrl can only
	// configure existing devices, so without this every Create lands
	// in the DB but nothing reaches the kernel. Nil ⇒ skip the
	// rtnetlink steps (acceptable for tests and for hosts where the
	// operator manages link lifecycle out-of-band).
	Links wg.LinkManager
	// KernelWarnings, when set, captures the slog.Warn-level kernel
	// apply failures so the Support page can surface them. Nil ⇒
	// failures stay in slog only.
	KernelWarnings *diag.KernelWarnings
}

// recordKernelWarning is the bridge between the existing slog.Warn
// sites and the operator-visible ring. Both still happen so the
// systemd journal captures the full record; the ring is the
// abbreviated UI feed.
func (h *InterfaceHandler) recordKernelWarning(origin, iface, msg string) {
	if h == nil || h.KernelWarnings == nil {
		return
	}
	h.KernelWarnings.Push(diag.KernelWarning{
		Origin:  origin,
		Iface:   iface,
		Message: msg,
	})
}

type interfaceResponse struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	ListenPort int       `json:"listen_port"`
	Address    string    `json:"address"`
	DNS        []string  `json:"dns"`
	MTU        *int      `json:"mtu,omitempty"`
	Endpoint   *string   `json:"endpoint,omitempty"`
	PublicKey  string    `json:"public_key"`
	PostUp     *string   `json:"post_up,omitempty"`
	PostDown   *string   `json:"post_down,omitempty"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func toInterfaceResponse(i *repository.Interface) interfaceResponse {
	return interfaceResponse{
		ID: i.ID, Name: i.Name, ListenPort: i.ListenPort,
		Address: i.Address.String(), DNS: i.DNS, MTU: i.MTU,
		Endpoint: i.Endpoint, PublicKey: i.PublicKey,
		PostUp: i.PostUp, PostDown: i.PostDown,
		IsActive: i.IsActive, CreatedAt: i.CreatedAt, UpdatedAt: i.UpdatedAt,
	}
}

type createInterfaceRequest struct {
	Name       string   `json:"name"        binding:"required"`
	ListenPort int      `json:"listen_port" binding:"required,min=1,max=65535"`
	Address    string   `json:"address"     binding:"required"`
	DNS        []string `json:"dns"`
	MTU        *int     `json:"mtu"`
	Endpoint   *string  `json:"endpoint"`
	PostUp     *string  `json:"post_up"`
	PostDown   *string  `json:"post_down"`
}

// Create generates a fresh key pair, encrypts the private half, and stores
// the row. The caller never supplies key material — operators picking their
// own private keys is a footgun (typo → unrecoverable interface) and there
// is no scenario where uploading is preferable.
func (h *InterfaceHandler) Create(c *gin.Context) {
	var req createInterfaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	addr, err := netip.ParsePrefix(req.Address)
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "address must be a CIDR")
		return
	}

	// Pre-validate the listen port. The DB unique constraint catches
	// the same case but with an opaque "duplicate key" message; this
	// surface is the operator-facing error.
	if inUse, perr := h.Interfaces.ListenPortInUse(c.Request.Context(), req.ListenPort, nil); perr != nil {
		slog.ErrorContext(c, "check listen port", "err", perr)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	} else if inUse {
		writeError(c, http.StatusConflict, "LISTEN_PORT_CONFLICT",
			"listen port already in use by another location")
		return
	}

	kp, err := wg.GenerateKeyPair()
	if err != nil {
		slog.ErrorContext(c, "generate keypair", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	sealed, err := h.AEAD.Seal(kp.Private, []byte("wg_interfaces.private_key"))
	if err != nil {
		slog.ErrorContext(c, "seal private key", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	dns := req.DNS
	if dns == nil {
		dns = []string{}
	}
	out, err := h.Interfaces.Create(c.Request.Context(), repository.CreateInterfaceParams{
		Name: req.Name, ListenPort: req.ListenPort, Address: addr, DNS: dns,
		MTU: req.MTU, Endpoint: req.Endpoint, PrivateKey: sealed,
		PublicKey: kp.Public, PostUp: req.PostUp, PostDown: req.PostDown,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Disambiguate the two unique constraints — operators
			// hitting a port conflict get a different message than
			// the name-clash case so they can fix the right field.
			if pgErr.ConstraintName == "wg_interfaces_listen_port_unique" {
				writeError(c, http.StatusConflict, "LISTEN_PORT_CONFLICT",
					"listen port already in use by another location")
				return
			}
			writeError(c, http.StatusConflict, apierror.CodeConflict, "interface name already exists")
			return
		}
		slog.ErrorContext(c, "create interface", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	// Bring the kernel device up. Order matters: rtnetlink creates +
	// addresses + ups the link, then wgctrl pushes the private key /
	// listen port over generic netlink. Failures here are logged rather
	// than rolled back — the DB row is the source of truth and the
	// startup reconciler will converge on next API restart.
	if h.Links != nil {
		if err := h.Links.EnsureLink(out.Name); err != nil {
			slog.WarnContext(c, "kernel ensure link", "err", err, "iface", out.Name)
			h.recordKernelWarning("wg.create.link", out.Name, err.Error())
		}
		if err := h.Links.EnsureAddress(out.Name, out.Address); err != nil {
			slog.WarnContext(c, "kernel ensure address", "err", err, "iface", out.Name)
			h.recordKernelWarning("wg.create.address", out.Name, err.Error())
		}
		if err := h.Links.EnsureUp(out.Name); err != nil {
			slog.WarnContext(c, "kernel link up", "err", err, "iface", out.Name)
			h.recordKernelWarning("wg.create.up", out.Name, err.Error())
		}
	}
	if h.Client != nil {
		port := out.ListenPort
		kcfg := wg.Config{
			PrivateKey: kp.Private,
			ListenPort: &port,
		}
		if err := h.Client.ConfigureDevice(out.Name, kcfg); err != nil {
			slog.WarnContext(c, "kernel configure interface", "err", err, "iface", out.Name)
			h.recordKernelWarning("wg.create.configure", out.Name, err.Error())
		}
		// Read-back: confirm the kernel actually accepted the port we
		// asked for. wgctrl can pick a different port silently when
		// the requested one is in use by something netlink doesn't
		// see (e.g. a non-WG UDP socket). Surfacing the drift in the
		// API response means the UI can warn instead of lying.
		if live, derr := h.Client.Device(out.Name); derr == nil &&
			live.ListenPort != 0 && live.ListenPort != out.ListenPort {
			slog.WarnContext(c, "kernel listen-port drift after create",
				"iface", out.Name,
				"requested", out.ListenPort, "actual", live.ListenPort)
			h.recordKernelWarning("wg.create.port_drift", out.Name,
				"kernel chose a different listen port than requested")
		}
	}
	c.JSON(http.StatusCreated, toInterfaceResponse(out))
}

func (h *InterfaceHandler) List(c *gin.Context) {
	pg := httppage.Parse(c)
	sortField, sortDesc := pg.ResolveSort(repository.InterfaceSortFields, "name")
	items, total, err := h.Interfaces.ListPage(c.Request.Context(),
		pg.Limit, pg.Offset, sortField, sortDesc)
	if err != nil {
		slog.ErrorContext(c, "list interfaces", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	out := make([]interfaceResponse, 0, len(items))
	for i := range items {
		out = append(out, toInterfaceResponse(&items[i]))
	}
	c.JSON(http.StatusOK, httppage.Wrap(out, total, pg, sortField, sortDesc))
}

func (h *InterfaceHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	iface, err := h.Interfaces.GetByID(c.Request.Context(), id)
	if errors.Is(err, repository.ErrInterfaceNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "interface not found")
		return
	}
	if err != nil {
		slog.ErrorContext(c, "get interface", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.JSON(http.StatusOK, toInterfaceResponse(iface))
}

// updateInterfaceRequest is the PATCH-shaped payload. Pointer-to-
// pointer for optional columns so the JSON decoder can distinguish
// "absent" (don't touch) from "null" (clear) — gin's binding gives us
// the latter via explicit JSON null with the inner pointer nil.
type updateInterfaceRequest struct {
	ListenPort *int      `json:"listen_port"`
	Address    *string   `json:"address"`
	DNS        *[]string `json:"dns"`
	MTU        **int     `json:"mtu,omitempty"`
	Endpoint   **string  `json:"endpoint,omitempty"`
	PostUp     **string  `json:"post_up,omitempty"`
	PostDown   **string  `json:"post_down,omitempty"`
	IsActive   *bool     `json:"is_active"`
}

// Update applies a partial change to a wg_interfaces row. Name and key
// material are intentionally not editable — renaming a kernel link
// requires a delete + recreate, and rotating the server private key
// invalidates every peer's PSK in one shot. Both are fixable by the
// operator deleting the location and recreating it.
func (h *InterfaceHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	var req updateInterfaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	params := repository.UpdateInterfaceParams{
		ListenPort: req.ListenPort,
		DNS:        req.DNS,
		MTU:        req.MTU,
		Endpoint:   req.Endpoint,
		PostUp:     req.PostUp,
		PostDown:   req.PostDown,
		IsActive:   req.IsActive,
	}
	if req.Address != nil {
		pfx, err := netip.ParsePrefix(*req.Address)
		if err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "address must be a CIDR")
			return
		}
		params.Address = &pfx
	}
	if req.ListenPort != nil &&
		(*req.ListenPort < 1 || *req.ListenPort > 65535) {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest,
			"listen_port must be 1–65535")
		return
	}

	ctx := c.Request.Context()

	// Pre-validate listen-port change. Same rationale as Create — the
	// DB constraint would catch this anyway, but the API-layer message
	// is much clearer.
	if req.ListenPort != nil {
		if inUse, perr := h.Interfaces.ListenPortInUse(ctx, *req.ListenPort, &id); perr != nil {
			slog.ErrorContext(ctx, "check listen port", "err", perr)
			writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
			return
		} else if inUse {
			writeError(c, http.StatusConflict, "LISTEN_PORT_CONFLICT",
				"listen port already in use by another location")
			return
		}
	}

	out, err := h.Interfaces.Update(ctx, id, params)
	if errors.Is(err, repository.ErrInterfaceNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "interface not found")
		return
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Unique constraint hit — most likely the listen_port one
			// (migration 009). Surface as 409 with a code the
			// frontend can branch on.
			writeError(c, http.StatusConflict, "LISTEN_PORT_CONFLICT",
				"listen port already in use by another location")
			return
		}
		slog.ErrorContext(ctx, "update interface", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	// Push the changed knobs into the kernel. Address / port changes
	// are the operator-visible bits the rtnetlink + wgctrl layers
	// need to know about. Failures are logged; the DB row is
	// authoritative and the reconciler will re-converge on restart.
	if h.Links != nil && req.Address != nil {
		if err := h.Links.EnsureAddress(out.Name, out.Address); err != nil {
			slog.WarnContext(ctx, "kernel ensure address on update", "err", err, "iface", out.Name)
		}
	}
	if h.Client != nil && req.ListenPort != nil {
		port := out.ListenPort
		if err := h.Client.ConfigureDevice(out.Name, wg.Config{
			ListenPort: &port,
		}); err != nil {
			slog.WarnContext(ctx, "kernel apply listen port", "err", err, "iface", out.Name)
		}
	}

	c.JSON(http.StatusOK, toInterfaceResponse(out))
}

func (h *InterfaceHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	ctx := c.Request.Context()

	// Snapshot the device name before DB delete so we can flush its peers
	// from the kernel after. We can't `ip link delete` from wgctrl itself
	// — that needs rtnetlink — but clearing the peer list plus the
	// operator's existing PostDown handler is enough to stop traffic.
	var name string
	if h.Client != nil {
		if iface, gerr := h.Interfaces.GetByID(ctx, id); gerr == nil {
			name = iface.Name
		}
	}

	err = h.Interfaces.Delete(ctx, id)
	if errors.Is(err, repository.ErrInterfaceNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "interface not found")
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "delete interface", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	if h.Client != nil && name != "" {
		cfg := wg.Config{ReplacePeers: true}
		if err := h.Client.ConfigureDevice(name, cfg); err != nil {
			slog.WarnContext(ctx, "kernel clear interface peers", "err", err, "iface", name)
		}
	}
	// Tear the rtnetlink link down. Done after the wgctrl peer-clear so
	// in-flight handshakes see a closed door rather than a still-up
	// device with no auth.
	if h.Links != nil && name != "" {
		if err := h.Links.DeleteLink(name); err != nil {
			slog.WarnContext(ctx, "kernel delete link", "err", err, "iface", name)
		}
	}
	c.Status(http.StatusNoContent)
}
