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

	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/apierror"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/ebpf"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/httppage"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/middleware"
	"github.com/tomeksdev/wireguard-install-with-gui/backend/internal/repository"
)

// Allowed enum values, mirroring ebpf_rule_action/direction/protocol in
// migration 003. Declared as small sets rather than pulled from the DB
// so validation errors come back without a round-trip.
var (
	validActions    = []string{"allow", "deny", "rate_limit", "log"}
	validDirections = []string{"ingress", "egress", "both"}
	validProtocols  = []string{"tcp", "udp", "icmp", "any"}
)

// RuleHandler owns CRUD on ebpf_rules + ebpf_rule_bindings. Every
// successful write triggers a Syncer call so the kernel converges
// before the handler returns — if the sync fails, the handler still
// returns success (kernel is best-effort, DB is source of truth)
// but the event is logged for operator follow-up.
type RuleHandler struct {
	Rules      *repository.RuleRepo
	Peers      *repository.PeerRepo
	Interfaces *repository.InterfaceRepo
	Sync       ebpf.Syncer
}

type ruleResponse struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	Action      string     `json:"action"`
	Direction   string     `json:"direction"`
	Protocol    string     `json:"protocol"`
	SrcCIDR     *string    `json:"src_cidr,omitempty"`
	DstCIDR     *string    `json:"dst_cidr,omitempty"`
	SrcPortFrom *int       `json:"src_port_from,omitempty"`
	SrcPortTo   *int       `json:"src_port_to,omitempty"`
	DstPortFrom *int       `json:"dst_port_from,omitempty"`
	DstPortTo   *int       `json:"dst_port_to,omitempty"`
	RatePPS     *int       `json:"rate_pps,omitempty"`
	RateBurst   *int       `json:"rate_burst,omitempty"`
	Priority    int        `json:"priority"`
	IsActive    bool       `json:"is_active"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func toRuleResponse(r *repository.Rule) ruleResponse {
	var src, dst *string
	if r.SrcCIDR != nil {
		s := r.SrcCIDR.String()
		src = &s
	}
	if r.DstCIDR != nil {
		s := r.DstCIDR.String()
		dst = &s
	}
	return ruleResponse{
		ID: r.ID, Name: r.Name, Description: r.Description,
		Action: r.Action, Direction: r.Direction, Protocol: r.Protocol,
		SrcCIDR: src, DstCIDR: dst,
		SrcPortFrom: r.SrcPortFrom, SrcPortTo: r.SrcPortTo,
		DstPortFrom: r.DstPortFrom, DstPortTo: r.DstPortTo,
		RatePPS: r.RatePPS, RateBurst: r.RateBurst,
		Priority: r.Priority, IsActive: r.IsActive,
		CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

// toSyncRule flattens a repo rule to the shape the syncer wants. Lives
// here (handler layer) so neither repository nor ebpf packages need
// to know about each other.
func toSyncRule(r *repository.Rule) ebpf.Rule {
	u16 := func(v *int) *uint16 {
		if v == nil {
			return nil
		}
		x := uint16(*v)
		return &x
	}
	u32 := func(v *int) *uint32 {
		if v == nil {
			return nil
		}
		x := uint32(*v)
		return &x
	}
	return ebpf.Rule{
		ID:          r.ID,
		Action:      r.Action,
		Direction:   r.Direction,
		Protocol:    r.Protocol,
		SrcCIDR:     r.SrcCIDR,
		DstCIDR:     r.DstCIDR,
		SrcPortFrom: u16(r.SrcPortFrom),
		SrcPortTo:   u16(r.SrcPortTo),
		DstPortFrom: u16(r.DstPortFrom),
		DstPortTo:   u16(r.DstPortTo),
		RatePPS:     u32(r.RatePPS),
		RateBurst:   u32(r.RateBurst),
		Priority:    uint16(r.Priority),
	}
}

type createRuleRequest struct {
	Name        string  `json:"name"         binding:"required,min=1,max=128"`
	Description *string `json:"description"`
	Action      string  `json:"action"       binding:"required"`
	Direction   string  `json:"direction"`
	Protocol    string  `json:"protocol"`
	SrcCIDR     *string `json:"src_cidr"`
	DstCIDR     *string `json:"dst_cidr"`
	SrcPortFrom *int    `json:"src_port_from"`
	SrcPortTo   *int    `json:"src_port_to"`
	DstPortFrom *int    `json:"dst_port_from"`
	DstPortTo   *int    `json:"dst_port_to"`
	RatePPS     *int    `json:"rate_pps"`
	RateBurst   *int    `json:"rate_burst"`
	Priority    *int    `json:"priority"`
	IsActive    *bool   `json:"is_active"`
}

func (h *RuleHandler) Create(c *gin.Context) {
	var req createRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	// Default enum values — mirrors the DB column defaults so clients
	// that omit them get the same row as if they posted the defaults.
	direction := req.Direction
	if direction == "" {
		direction = "ingress"
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = "any"
	}
	if !inSet(req.Action, validActions) {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "action must be one of allow|deny|rate_limit|log")
		return
	}
	if !inSet(direction, validDirections) {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "direction must be one of ingress|egress|both")
		return
	}
	if !inSet(protocol, validProtocols) {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "protocol must be one of tcp|udp|icmp|any")
		return
	}
	if req.Action == "rate_limit" && (req.RatePPS == nil || *req.RatePPS <= 0) {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "rate_pps required and > 0 when action=rate_limit")
		return
	}
	if req.Action != "rate_limit" && (req.RatePPS != nil || req.RateBurst != nil) {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "rate_pps/rate_burst only valid when action=rate_limit")
		return
	}
	if err := validatePortPair(req.SrcPortFrom, req.SrcPortTo, "src"); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	if err := validatePortPair(req.DstPortFrom, req.DstPortTo, "dst"); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	src, err := parseOptionalCIDR(req.SrcCIDR, "src_cidr")
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	dst, err := parseOptionalCIDR(req.DstCIDR, "dst_cidr")
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	priority := 100
	if req.Priority != nil {
		priority = *req.Priority
	}
	if priority < 0 || priority > 1000 {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "priority must be in [0, 1000]")
		return
	}
	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}

	ctx := c.Request.Context()
	createdBy := actorIDFromContext(c)
	out, err := h.Rules.Create(ctx, repository.CreateRuleParams{
		Name: req.Name, Description: req.Description,
		Action: req.Action, Direction: direction, Protocol: protocol,
		SrcCIDR: src, DstCIDR: dst,
		SrcPortFrom: req.SrcPortFrom, SrcPortTo: req.SrcPortTo,
		DstPortFrom: req.DstPortFrom, DstPortTo: req.DstPortTo,
		RatePPS: req.RatePPS, RateBurst: req.RateBurst,
		Priority: priority, IsActive: active,
		CreatedBy: createdBy,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(c, http.StatusConflict, apierror.CodeConflict, "rule name already in use")
			return
		}
		slog.ErrorContext(ctx, "create rule", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	if out.IsActive {
		if err := h.Sync.Apply(ctx, toSyncRule(out)); err != nil {
			slog.WarnContext(ctx, "sync apply after create", "rule_id", out.ID, "err", err)
		}
	}
	c.JSON(http.StatusCreated, toRuleResponse(out))
}

func (h *RuleHandler) List(c *gin.Context) {
	pg := httppage.Parse(c)
	sortField, sortDesc := pg.ResolveSort(repository.RuleSortFields, "priority")
	onlyActive := c.Query("active") == "true"

	items, total, err := h.Rules.ListPage(c.Request.Context(),
		pg.Limit, pg.Offset, sortField, sortDesc, onlyActive)
	if err != nil {
		slog.ErrorContext(c, "list rules", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	out := make([]ruleResponse, 0, len(items))
	for i := range items {
		out = append(out, toRuleResponse(&items[i]))
	}
	c.JSON(http.StatusOK, httppage.Wrap(out, total, pg, sortField, sortDesc))
}

func (h *RuleHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	r, err := h.Rules.GetByID(c.Request.Context(), id)
	if errors.Is(err, repository.ErrRuleNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "rule not found")
		return
	}
	if err != nil {
		slog.ErrorContext(c, "get rule", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.JSON(http.StatusOK, toRuleResponse(r))
}

// updateRuleRequest uses the cleared/set-to/leave-alone trichotomy via
// JSON null + presence. Fields omitted from the JSON leave the column
// alone; fields present with null clear the column; fields present
// with a value overwrite. Gin's binding can't express that directly,
// so we unmarshal into a map first and translate.
type updateRuleRequest struct {
	raw map[string]any
}

func (h *RuleHandler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}

	var raw map[string]any
	if err := c.ShouldBindJSON(&raw); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	p, err := buildUpdateParams(raw)
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}

	ctx := c.Request.Context()
	out, err := h.Rules.Update(ctx, id, p)
	if errors.Is(err, repository.ErrRuleNotFound) {
		writeError(c, http.StatusNotFound, apierror.CodeNotFound, "rule not found")
		return
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(c, http.StatusConflict, apierror.CodeConflict, "rule name already in use")
			return
		}
		slog.ErrorContext(ctx, "update rule", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	// A rule that just flipped inactive should also be removed from the
	// kernel; one that became active (or stayed active with new fields)
	// needs re-apply.
	if out.IsActive {
		if err := h.Sync.Apply(ctx, toSyncRule(out)); err != nil {
			slog.WarnContext(ctx, "sync apply after update", "rule_id", out.ID, "err", err)
		}
	} else {
		if err := h.Sync.Delete(ctx, out.ID); err != nil {
			slog.WarnContext(ctx, "sync delete after deactivate", "rule_id", out.ID, "err", err)
		}
	}
	c.JSON(http.StatusOK, toRuleResponse(out))
}

func (h *RuleHandler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	ctx := c.Request.Context()
	if err := h.Rules.Delete(ctx, id); err != nil {
		if errors.Is(err, repository.ErrRuleNotFound) {
			writeError(c, http.StatusNotFound, apierror.CodeNotFound, "rule not found")
			return
		}
		slog.ErrorContext(ctx, "delete rule", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if err := h.Sync.Delete(ctx, id); err != nil {
		slog.WarnContext(ctx, "sync delete after row delete", "rule_id", id, "err", err)
	}
	c.Status(http.StatusNoContent)
}

// ListBindings returns every binding (peer or interface) for a rule.
func (h *RuleHandler) ListBindings(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	bs, err := h.Rules.ListBindings(c.Request.Context(), id)
	if err != nil {
		slog.ErrorContext(c, "list bindings", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": bs})
}

type createBindingRequest struct {
	PeerID      *string `json:"peer_id"`
	InterfaceID *string `json:"interface_id"`
}

func (h *RuleHandler) CreateBinding(c *gin.Context) {
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	var req createBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, err.Error())
		return
	}
	setPeer := req.PeerID != nil && *req.PeerID != ""
	setIface := req.InterfaceID != nil && *req.InterfaceID != ""
	if setPeer == setIface {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "exactly one of peer_id or interface_id is required")
		return
	}

	ctx := c.Request.Context()
	var (
		b  *repository.RuleBinding
		bErr error
	)
	if setPeer {
		peerID, err := uuid.Parse(*req.PeerID)
		if err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "peer_id must be uuid")
			return
		}
		b, bErr = h.Rules.BindToPeer(ctx, ruleID, peerID)
	} else {
		ifaceID, err := uuid.Parse(*req.InterfaceID)
		if err != nil {
			writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "interface_id must be uuid")
			return
		}
		b, bErr = h.Rules.BindToInterface(ctx, ruleID, ifaceID)
	}
	if bErr != nil {
		var pgErr *pgconn.PgError
		if errors.As(bErr, &pgErr) && pgErr.Code == "23503" {
			writeError(c, http.StatusNotFound, apierror.CodeNotFound, "rule, peer, or interface not found")
			return
		}
		slog.ErrorContext(ctx, "create binding", "err", bErr)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}

	// Binding changes which packets the rule matches, so we re-apply.
	if rule, err := h.Rules.GetByID(ctx, ruleID); err == nil && rule.IsActive {
		if err := h.Sync.Apply(ctx, toSyncRule(rule)); err != nil {
			slog.WarnContext(ctx, "sync apply after bind", "rule_id", ruleID, "err", err)
		}
	}
	c.JSON(http.StatusCreated, b)
}

func (h *RuleHandler) DeleteBinding(c *gin.Context) {
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid id")
		return
	}
	bindingID, err := uuid.Parse(c.Param("binding_id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, apierror.CodeInvalidRequest, "invalid binding id")
		return
	}
	ctx := c.Request.Context()
	if err := h.Rules.DeleteBinding(ctx, bindingID); err != nil {
		if errors.Is(err, repository.ErrBindingNotFound) {
			writeError(c, http.StatusNotFound, apierror.CodeNotFound, "binding not found")
			return
		}
		slog.ErrorContext(ctx, "delete binding", "err", err)
		writeError(c, http.StatusInternalServerError, apierror.CodeInternal, "internal error")
		return
	}
	if rule, err := h.Rules.GetByID(ctx, ruleID); err == nil && rule.IsActive {
		if err := h.Sync.Apply(ctx, toSyncRule(rule)); err != nil {
			slog.WarnContext(ctx, "sync apply after unbind", "rule_id", ruleID, "err", err)
		}
	}
	c.Status(http.StatusNoContent)
}

// buildUpdateParams translates the raw JSON map into an UpdateRuleParams.
// Presence of a key in raw means "change this field"; absence means
// "leave alone". The pointer-to-pointer trick in UpdateRuleParams lets
// us distinguish "set to null" (clear) from "not present" (keep).
func buildUpdateParams(raw map[string]any) (repository.UpdateRuleParams, error) {
	var p repository.UpdateRuleParams

	if v, ok := raw["name"]; ok {
		s, err := asString(v, "name")
		if err != nil {
			return p, err
		}
		p.Name = s
	}
	if v, ok := raw["description"]; ok {
		p.Description = mapOptString(v)
	}
	if v, ok := raw["action"]; ok {
		s, err := asString(v, "action")
		if err != nil {
			return p, err
		}
		if !inSet(*s, validActions) {
			return p, errors.New("action must be one of allow|deny|rate_limit|log")
		}
		p.Action = s
	}
	if v, ok := raw["direction"]; ok {
		s, err := asString(v, "direction")
		if err != nil {
			return p, err
		}
		if !inSet(*s, validDirections) {
			return p, errors.New("direction must be one of ingress|egress|both")
		}
		p.Direction = s
	}
	if v, ok := raw["protocol"]; ok {
		s, err := asString(v, "protocol")
		if err != nil {
			return p, err
		}
		if !inSet(*s, validProtocols) {
			return p, errors.New("protocol must be one of tcp|udp|icmp|any")
		}
		p.Protocol = s
	}
	if v, ok := raw["src_cidr"]; ok {
		cp, err := mapOptCIDR(v, "src_cidr")
		if err != nil {
			return p, err
		}
		p.SrcCIDR = &cp
	}
	if v, ok := raw["dst_cidr"]; ok {
		cp, err := mapOptCIDR(v, "dst_cidr")
		if err != nil {
			return p, err
		}
		p.DstCIDR = &cp
	}
	if v, ok := raw["src_port_from"]; ok {
		ip, err := mapOptInt(v, "src_port_from")
		if err != nil {
			return p, err
		}
		p.SrcPortFrom = &ip
	}
	if v, ok := raw["src_port_to"]; ok {
		ip, err := mapOptInt(v, "src_port_to")
		if err != nil {
			return p, err
		}
		p.SrcPortTo = &ip
	}
	if v, ok := raw["dst_port_from"]; ok {
		ip, err := mapOptInt(v, "dst_port_from")
		if err != nil {
			return p, err
		}
		p.DstPortFrom = &ip
	}
	if v, ok := raw["dst_port_to"]; ok {
		ip, err := mapOptInt(v, "dst_port_to")
		if err != nil {
			return p, err
		}
		p.DstPortTo = &ip
	}
	if v, ok := raw["rate_pps"]; ok {
		ip, err := mapOptInt(v, "rate_pps")
		if err != nil {
			return p, err
		}
		p.RatePPS = &ip
	}
	if v, ok := raw["rate_burst"]; ok {
		ip, err := mapOptInt(v, "rate_burst")
		if err != nil {
			return p, err
		}
		p.RateBurst = &ip
	}
	if v, ok := raw["priority"]; ok {
		i, err := asIntInRange(v, "priority", 0, 1000)
		if err != nil {
			return p, err
		}
		p.Priority = &i
	}
	if v, ok := raw["is_active"]; ok {
		b, ok := v.(bool)
		if !ok {
			return p, errors.New("is_active must be boolean")
		}
		p.IsActive = &b
	}
	return p, nil
}

// Helpers ---

func inSet(s string, set []string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

func validatePortPair(from, to *int, side string) error {
	if from == nil && to == nil {
		return nil
	}
	if from == nil || to == nil {
		return errors.New(side + "_port_from and " + side + "_port_to must both be set or both absent")
	}
	if *from < 0 || *from > 65535 || *to < 0 || *to > 65535 {
		return errors.New(side + " port must be in [0, 65535]")
	}
	if *from > *to {
		return errors.New(side + "_port_from must be ≤ " + side + "_port_to")
	}
	return nil
}

func parseOptionalCIDR(s *string, field string) (*netip.Prefix, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	p, err := netip.ParsePrefix(*s)
	if err != nil {
		return nil, errors.New(field + " must be a CIDR")
	}
	// CIDR columns reject host-bit addresses; force the canonical form
	// here so we don't hand a surprising error back from PG.
	m := p.Masked()
	return &m, nil
}

func asString(v any, field string) (*string, error) {
	if v == nil {
		return nil, errors.New(field + " cannot be null")
	}
	s, ok := v.(string)
	if !ok {
		return nil, errors.New(field + " must be a string")
	}
	return &s, nil
}

func mapOptString(v any) *string {
	if v == nil {
		empty := ""
		return &empty
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func mapOptCIDR(v any, field string) (*netip.Prefix, error) {
	if v == nil {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, errors.New(field + " must be a string or null")
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, errors.New(field + " must be a CIDR")
	}
	m := p.Masked()
	return &m, nil
}

func mapOptInt(v any, field string) (*int, error) {
	if v == nil {
		return nil, nil
	}
	// JSON numbers decode to float64 by default.
	f, ok := v.(float64)
	if !ok {
		return nil, errors.New(field + " must be a number or null")
	}
	i := int(f)
	return &i, nil
}

func asIntInRange(v any, field string, lo, hi int) (int, error) {
	f, ok := v.(float64)
	if !ok {
		return 0, errors.New(field + " must be a number")
	}
	i := int(f)
	if i < lo || i > hi {
		return 0, errors.New(field + " out of range")
	}
	return i, nil
}

// actorIDFromContext pulls the authenticated user's UUID out of the
// gin context (set by RequireAuth middleware). Returns nil for
// requests that aren't authenticated — test helpers and health
// probes — rather than faking an ID.
func actorIDFromContext(c *gin.Context) *uuid.UUID {
	p, ok := middleware.PrincipalFrom(c)
	if !ok {
		return nil
	}
	return &p.UserID
}
