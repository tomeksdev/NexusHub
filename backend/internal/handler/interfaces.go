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
		}
		if err := h.Links.EnsureAddress(out.Name, out.Address); err != nil {
			slog.WarnContext(c, "kernel ensure address", "err", err, "iface", out.Name)
		}
		if err := h.Links.EnsureUp(out.Name); err != nil {
			slog.WarnContext(c, "kernel link up", "err", err, "iface", out.Name)
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
