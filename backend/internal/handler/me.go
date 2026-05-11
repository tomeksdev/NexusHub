package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/tomeksdev/NexusHub/backend/internal/apierror"
	"github.com/tomeksdev/NexusHub/backend/internal/httppage"
	"github.com/tomeksdev/NexusHub/backend/internal/middleware"
	"github.com/tomeksdev/NexusHub/backend/internal/repository"
)

// MeHandler exposes the user-self-service surface — the
// authenticated principal's own peers + their .conf / QR exports.
// Lives outside the admin group; every method enforces ownership
// against the principal stashed by RequireAuth so a regular user
// cannot reach another user's peer by id.
//
// Reuses PeerHandler for the actual config rendering — that path
// is non-trivial (key decryption, PSK lookup, location resolution)
// and we'd rather not duplicate it.
type MeHandler struct {
	Peers *repository.PeerRepo
	// PeerH is the admin PeerHandler instance we reuse for the
	// config rendering helpers. Nil during early bootstrap; routes
	// guarded by deps wiring.
	PeerH *PeerHandler
}

// ListPeers returns the peers owned by the calling principal. Empty
// array when the user has no peers — that's the common case for a
// freshly-invited user with no config yet.
func (h *MeHandler) ListPeers(c *gin.Context) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		writeError(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "unauthenticated")
		return
	}
	pg := httppage.Parse(c)
	sortField, sortDesc := pg.ResolveSort(repository.PeerSortFields, "name")
	peers, total, err := h.Peers.ListPageByOwner(c.Request.Context(),
		principal.UserID, pg.Limit, pg.Offset, sortField, sortDesc)
	if err != nil {
		slog.ErrorContext(c, "list my peers", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	out := make([]peerResponse, 0, len(peers))
	for i := range peers {
		out = append(out, toPeerResponse(&peers[i]))
	}
	c.JSON(http.StatusOK, httppage.Wrap(out, total, pg, sortField, sortDesc))
}

// Config serves the wg-quick text for one of the principal's own
// peers. Ownership is enforced against the principal's user id —
// a 404 is returned for a peer that exists but belongs to someone
// else, matching the admin endpoint's "peer not found" so the
// existence of foreign ids isn't leaked via error code.
func (h *MeHandler) Config(c *gin.Context) {
	peerID, ok := h.ownedPeerID(c)
	if !ok {
		return
	}
	text, _, err := h.PeerH.RenderConfigFor(c, peerID)
	if err != nil {
		return
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, text)
}

// ConfigQR is Config rendered as a QR PNG — same shape as the
// admin equivalent, with ownership enforced.
func (h *MeHandler) ConfigQR(c *gin.Context) {
	peerID, ok := h.ownedPeerID(c)
	if !ok {
		return
	}
	text, _, err := h.PeerH.RenderConfigFor(c, peerID)
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

// ownedPeerID returns the peer id from the URL after verifying the
// caller owns it. Writes the error response and returns ok=false on
// any failure (unauthenticated, invalid id, foreign peer, lookup
// error).
func (h *MeHandler) ownedPeerID(c *gin.Context) (uuid.UUID, bool) {
	principal, ok := middleware.PrincipalFrom(c)
	if !ok {
		writeError(c, http.StatusUnauthorized, apierror.CodeUnauthorized, "unauthenticated")
		return uuid.Nil, false
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return uuid.Nil, false
	}
	peer, err := h.Peers.GetByID(c.Request.Context(), id)
	if errors.Is(err, repository.ErrPeerNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "peer not found")
		return uuid.Nil, false
	}
	if err != nil {
		slog.ErrorContext(c, "lookup peer", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return uuid.Nil, false
	}
	if peer.OwnerUserID == nil || *peer.OwnerUserID != principal.UserID {
		// Treat foreign peers identically to "not found" so the API
		// doesn't leak that an id exists under another owner.
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "peer not found")
		return uuid.Nil, false
	}
	return id, true
}
