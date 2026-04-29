package repository

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrRuleNotFound is returned when a rule lookup matches no row.
var ErrRuleNotFound = errors.New("rule not found")

// ErrBindingNotFound is returned when a binding row is absent.
var ErrBindingNotFound = errors.New("rule binding not found")

type RuleRepo struct {
	pool *pgxpool.Pool
}

func NewRuleRepo(pool *pgxpool.Pool) *RuleRepo {
	return &RuleRepo{pool: pool}
}

// Rule mirrors one ebpf_rules row. CIDRs are netip.Prefix so callers
// can keep mask bits intact without shuttling strings around. Port
// ranges are pointer-typed to distinguish "rule matches any port"
// (nil) from "rule matches port 0" (concrete).
type Rule struct {
	ID          uuid.UUID
	Name        string
	Description *string
	Action      string
	Direction   string
	Protocol    string
	SrcCIDR     *netip.Prefix
	DstCIDR     *netip.Prefix
	SrcPortFrom *int
	SrcPortTo   *int
	DstPortFrom *int
	DstPortTo   *int
	RatePPS     *int
	RateBurst   *int
	Priority    int
	IsActive    bool
	CreatedBy   *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RuleBinding attaches a rule to a peer or to an interface. Exactly
// one of PeerID / InterfaceID is non-nil — the CHECK constraint in
// migration 003 enforces that at the DB level, so repo callers can
// rely on the shape.
type RuleBinding struct {
	ID          uuid.UUID
	RuleID      uuid.UUID
	PeerID      *uuid.UUID
	InterfaceID *uuid.UUID
	CreatedAt   time.Time
}

// CreateRuleParams is the write-side input. Name uniqueness is enforced
// in SQL; duplicate inserts return pgx's unique-violation wrapped in
// the standard error path — handlers translate that to 409.
type CreateRuleParams struct {
	Name        string
	Description *string
	Action      string
	Direction   string
	Protocol    string
	SrcCIDR     *netip.Prefix
	DstCIDR     *netip.Prefix
	SrcPortFrom *int
	SrcPortTo   *int
	DstPortFrom *int
	DstPortTo   *int
	RatePPS     *int
	RateBurst   *int
	Priority    int
	IsActive    bool
	CreatedBy   *uuid.UUID
}

// UpdateRuleParams is the PATCH-shaped input. Nil fields leave the
// current column value alone; non-nil overwrites. This avoids the
// null/zero ambiguity that a plain struct would introduce.
type UpdateRuleParams struct {
	Name        *string
	Description *string
	Action      *string
	Direction   *string
	Protocol    *string
	// Pointer-to-pointer so callers can distinguish "leave as-is" (nil)
	// from "clear the field" (non-nil pointing at nil).
	SrcCIDR     **netip.Prefix
	DstCIDR     **netip.Prefix
	SrcPortFrom **int
	SrcPortTo   **int
	DstPortFrom **int
	DstPortTo   **int
	RatePPS     **int
	RateBurst   **int
	Priority    *int
	IsActive    *bool
}

func (r *RuleRepo) Create(ctx context.Context, p CreateRuleParams) (*Rule, error) {
	const q = `
		INSERT INTO ebpf_rules
		   (name, description, action, direction, protocol,
		    src_cidr, dst_cidr,
		    src_port_from, src_port_to, dst_port_from, dst_port_to,
		    rate_pps, rate_burst, priority, is_active, created_by)
		VALUES ($1, $2, $3::ebpf_rule_action, $4::ebpf_rule_direction,
		        $5::ebpf_rule_protocol,
		        $6::cidr, $7::cidr,
		        $8, $9, $10, $11,
		        $12, $13, $14, $15, $16)
		RETURNING id, created_at, updated_at`
	out := Rule{
		Name: p.Name, Description: p.Description,
		Action: p.Action, Direction: p.Direction, Protocol: p.Protocol,
		SrcCIDR: p.SrcCIDR, DstCIDR: p.DstCIDR,
		SrcPortFrom: p.SrcPortFrom, SrcPortTo: p.SrcPortTo,
		DstPortFrom: p.DstPortFrom, DstPortTo: p.DstPortTo,
		RatePPS: p.RatePPS, RateBurst: p.RateBurst,
		Priority: p.Priority, IsActive: p.IsActive,
		CreatedBy: p.CreatedBy,
	}
	err := r.pool.QueryRow(ctx, q,
		p.Name, p.Description, p.Action, p.Direction, p.Protocol,
		prefixArg(p.SrcCIDR), prefixArg(p.DstCIDR),
		p.SrcPortFrom, p.SrcPortTo, p.DstPortFrom, p.DstPortTo,
		p.RatePPS, p.RateBurst, p.Priority, p.IsActive, p.CreatedBy,
	).Scan(&out.ID, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert rule: %w", err)
	}
	return &out, nil
}

func (r *RuleRepo) GetByID(ctx context.Context, id uuid.UUID) (*Rule, error) {
	return r.scanOne(ctx, `WHERE id = $1`, id)
}

// RuleSortFields is the whitelist of columns exposed to ?sort=.
var RuleSortFields = []string{"name", "priority", "created_at", "updated_at"}

// ListPage returns a paginated + sortable slice plus the total count.
// Filters: if onlyActive is true, inactive rules are excluded.
func (r *RuleRepo) ListPage(ctx context.Context, limit, offset int, sortField string, sortDesc, onlyActive bool) ([]Rule, int, error) {
	if !contains(RuleSortFields, sortField) {
		sortField = "priority"
	}
	dir := "ASC"
	if sortDesc {
		dir = "DESC"
	}
	where := ""
	var args []any
	if onlyActive {
		where = "WHERE is_active = true "
	}
	query := fmt.Sprintf("%s %sORDER BY %s %s, name ASC LIMIT $%d OFFSET $%d",
		selectRule, where, sortField, dir, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list rules page: %w", err)
	}
	defer rows.Close()

	var items []Rule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *rule)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	countQ := `SELECT count(*) FROM ebpf_rules`
	if onlyActive {
		countQ += ` WHERE is_active = true`
	}
	var total int
	if err := r.pool.QueryRow(ctx, countQ).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count rules: %w", err)
	}
	return items, total, nil
}

// ActiveSnapshot returns every active rule ordered by (priority, id).
// Used by the sync layer on startup and during reconciliation sweeps —
// callers that want the full picture, not a page.
func (r *RuleRepo) ActiveSnapshot(ctx context.Context) ([]Rule, error) {
	rows, err := r.pool.Query(ctx,
		selectRule+` WHERE is_active = true ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("snapshot rules: %w", err)
	}
	defer rows.Close()

	var out []Rule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rule)
	}
	return out, rows.Err()
}

// Update applies a PATCH-shaped param set. Only non-nil fields are
// written; everything else is left alone. If no fields are set the
// call still returns the current row (cheap no-op from the caller's
// point of view).
func (r *RuleRepo) Update(ctx context.Context, id uuid.UUID, p UpdateRuleParams) (*Rule, error) {
	sets := []string{}
	args := []any{}
	next := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if p.Name != nil {
		sets = append(sets, "name = "+next(*p.Name))
	}
	if p.Description != nil {
		sets = append(sets, "description = "+next(*p.Description))
	}
	if p.Action != nil {
		sets = append(sets, "action = "+next(*p.Action)+"::ebpf_rule_action")
	}
	if p.Direction != nil {
		sets = append(sets, "direction = "+next(*p.Direction)+"::ebpf_rule_direction")
	}
	if p.Protocol != nil {
		sets = append(sets, "protocol = "+next(*p.Protocol)+"::ebpf_rule_protocol")
	}
	if p.SrcCIDR != nil {
		sets = append(sets, "src_cidr = "+next(prefixArg(*p.SrcCIDR))+"::cidr")
	}
	if p.DstCIDR != nil {
		sets = append(sets, "dst_cidr = "+next(prefixArg(*p.DstCIDR))+"::cidr")
	}
	if p.SrcPortFrom != nil {
		sets = append(sets, "src_port_from = "+next(*p.SrcPortFrom))
	}
	if p.SrcPortTo != nil {
		sets = append(sets, "src_port_to = "+next(*p.SrcPortTo))
	}
	if p.DstPortFrom != nil {
		sets = append(sets, "dst_port_from = "+next(*p.DstPortFrom))
	}
	if p.DstPortTo != nil {
		sets = append(sets, "dst_port_to = "+next(*p.DstPortTo))
	}
	if p.RatePPS != nil {
		sets = append(sets, "rate_pps = "+next(*p.RatePPS))
	}
	if p.RateBurst != nil {
		sets = append(sets, "rate_burst = "+next(*p.RateBurst))
	}
	if p.Priority != nil {
		sets = append(sets, "priority = "+next(*p.Priority))
	}
	if p.IsActive != nil {
		sets = append(sets, "is_active = "+next(*p.IsActive))
	}
	if len(sets) == 0 {
		return r.GetByID(ctx, id)
	}
	args = append(args, id)
	q := fmt.Sprintf("UPDATE ebpf_rules SET %s WHERE id = $%d", joinComma(sets), len(args))
	cmd, err := r.pool.Exec(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return nil, ErrRuleNotFound
	}
	return r.GetByID(ctx, id)
}

func (r *RuleRepo) Delete(ctx context.Context, id uuid.UUID) error {
	cmd, err := r.pool.Exec(ctx, `DELETE FROM ebpf_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrRuleNotFound
	}
	return nil
}

// BindToPeer attaches a rule to a peer. The partial unique index
// (rule_id, peer_id) means a second call with the same pair is a
// no-op from the DB's point of view — we reuse the existing row
// rather than erroring, to make the endpoint idempotent.
func (r *RuleRepo) BindToPeer(ctx context.Context, ruleID, peerID uuid.UUID) (*RuleBinding, error) {
	const q = `
		INSERT INTO ebpf_rule_bindings (rule_id, peer_id)
		VALUES ($1, $2)
		ON CONFLICT (rule_id, peer_id) WHERE peer_id IS NOT NULL
		DO UPDATE SET created_at = ebpf_rule_bindings.created_at
		RETURNING id, created_at`
	out := RuleBinding{RuleID: ruleID, PeerID: &peerID}
	err := r.pool.QueryRow(ctx, q, ruleID, peerID).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("bind rule→peer: %w", err)
	}
	return &out, nil
}

func (r *RuleRepo) BindToInterface(ctx context.Context, ruleID, ifaceID uuid.UUID) (*RuleBinding, error) {
	const q = `
		INSERT INTO ebpf_rule_bindings (rule_id, interface_id)
		VALUES ($1, $2)
		ON CONFLICT (rule_id, interface_id) WHERE interface_id IS NOT NULL
		DO UPDATE SET created_at = ebpf_rule_bindings.created_at
		RETURNING id, created_at`
	out := RuleBinding{RuleID: ruleID, InterfaceID: &ifaceID}
	err := r.pool.QueryRow(ctx, q, ruleID, ifaceID).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("bind rule→interface: %w", err)
	}
	return &out, nil
}

func (r *RuleRepo) DeleteBinding(ctx context.Context, bindingID uuid.UUID) error {
	cmd, err := r.pool.Exec(ctx, `DELETE FROM ebpf_rule_bindings WHERE id = $1`, bindingID)
	if err != nil {
		return fmt.Errorf("delete binding: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrBindingNotFound
	}
	return nil
}

func (r *RuleRepo) ListBindings(ctx context.Context, ruleID uuid.UUID) ([]RuleBinding, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, rule_id, peer_id, interface_id, created_at
		   FROM ebpf_rule_bindings
		  WHERE rule_id = $1
		  ORDER BY created_at ASC`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer rows.Close()

	var out []RuleBinding
	for rows.Next() {
		var b RuleBinding
		if err := rows.Scan(&b.ID, &b.RuleID, &b.PeerID, &b.InterfaceID, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

const selectRule = `
	SELECT id, name, description, action::text, direction::text, protocol::text,
	       src_cidr::text, dst_cidr::text,
	       src_port_from, src_port_to, dst_port_from, dst_port_to,
	       rate_pps, rate_burst, priority, is_active,
	       created_by, created_at, updated_at
	  FROM ebpf_rules`

func (r *RuleRepo) scanOne(ctx context.Context, where string, args ...any) (*Rule, error) {
	row := r.pool.QueryRow(ctx, selectRule+" "+where, args...)
	rule, err := scanRule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRuleNotFound
	}
	return rule, err
}

func scanRule(s scannable) (*Rule, error) {
	var (
		rule   Rule
		srcStr *string
		dstStr *string
	)
	err := s.Scan(
		&rule.ID, &rule.Name, &rule.Description,
		&rule.Action, &rule.Direction, &rule.Protocol,
		&srcStr, &dstStr,
		&rule.SrcPortFrom, &rule.SrcPortTo,
		&rule.DstPortFrom, &rule.DstPortTo,
		&rule.RatePPS, &rule.RateBurst,
		&rule.Priority, &rule.IsActive,
		&rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if srcStr != nil {
		p, perr := netip.ParsePrefix(*srcStr)
		if perr != nil {
			return nil, fmt.Errorf("parse src_cidr %q: %w", *srcStr, perr)
		}
		rule.SrcCIDR = &p
	}
	if dstStr != nil {
		p, perr := netip.ParsePrefix(*dstStr)
		if perr != nil {
			return nil, fmt.Errorf("parse dst_cidr %q: %w", *dstStr, perr)
		}
		rule.DstCIDR = &p
	}
	return &rule, nil
}

// prefixArg converts an optional prefix to the driver-friendly form.
// Nil → nil (SQL NULL); non-nil → String() for the cast to ::cidr.
func prefixArg(p *netip.Prefix) any {
	if p == nil {
		return nil
	}
	return p.String()
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
