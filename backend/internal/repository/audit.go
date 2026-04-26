package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditRepo struct {
	pool *pgxpool.Pool
}

func NewAuditRepo(pool *pgxpool.Pool) *AuditRepo {
	return &AuditRepo{pool: pool}
}

// AuditResult values mirror the audit_log.result CHECK constraint.
const (
	AuditResultSuccess = "success"
	AuditResultFailure = "failure"
	AuditResultDenied  = "denied"
)

type AuditEntry struct {
	ActorUserID  *uuid.UUID
	ActorIP      net.IP
	ActorUA      string
	Action       string
	TargetType   string
	TargetID     string
	Metadata     map[string]any
	Result       string
	ErrorMessage string
}

// Log inserts an audit row. It logs (slog) but does not return errors from
// the caller's path — a failed audit insert must not block the user action.
// Callers interested in the write failure should call LogStrict.
func (r *AuditRepo) Log(ctx context.Context, e AuditEntry) {
	_ = r.LogStrict(ctx, e)
}

func (r *AuditRepo) LogStrict(ctx context.Context, e AuditEntry) error {
	if e.Result == "" {
		e.Result = AuditResultSuccess
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO audit_log
		   (actor_user_id, actor_ip, actor_ua, action, target_type,
		    target_id, metadata, result, error_message)
		 VALUES ($1, NULLIF($2, '')::inet, NULLIF($3, ''), $4, $5,
		         NULLIF($6, ''), $7::jsonb, $8, NULLIF($9, ''))`,
		e.ActorUserID, ipString(e.ActorIP), e.ActorUA, e.Action, e.TargetType,
		e.TargetID, meta, e.Result, e.ErrorMessage,
	)
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// AuditListItem is the read-side projection of an audit_log row. Metadata
// is decoded back into a map so callers can forward it to JSON without an
// extra round-trip through bytes.
type AuditListItem struct {
	ID           int64
	OccurredAt   time.Time
	ActorUserID  *uuid.UUID
	ActorIP      *string
	ActorUA      *string
	Action       string
	TargetType   string
	TargetID     *string
	Metadata     map[string]any
	Result       string
	ErrorMessage *string
}

// AuditSortFields is the allow-list of sortable columns. occurred_at is the
// default — an admin scrolling the audit log almost always wants chrono order.
var AuditSortFields = []string{"occurred_at", "action", "result"}

// AuditListFilter is the WHERE filter bundle for ListPage. All fields are
// optional; zero-values disable that particular predicate.
type AuditListFilter struct {
	ActorUserID *uuid.UUID
	Action      string
	Result      string
	Since       *time.Time
}

// ListPage returns a slice of audit rows matching the filter plus the total
// matching count. ORDER BY is built from the AuditSortFields allow-list and
// all filter values flow through parameterised placeholders.
func (r *AuditRepo) ListPage(ctx context.Context, f AuditListFilter, limit, offset int, sortField string, sortDesc bool) ([]AuditListItem, int, error) {
	if !auditContains(AuditSortFields, sortField) {
		sortField = "occurred_at"
	}
	dir := "ASC"
	if sortDesc {
		dir = "DESC"
	}

	var (
		conds []string
		args  []any
	)
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.ActorUserID != nil {
		add("actor_user_id = $%d", *f.ActorUserID)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.Result != "" {
		add("result = $%d", f.Result)
	}
	if f.Since != nil {
		add("occurred_at >= $%d", *f.Since)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	args = append(args, limit, offset)
	limOffIdx := len(args) - 1
	q := fmt.Sprintf(`
		SELECT id, occurred_at, actor_user_id,
		       actor_ip::text, actor_ua, action, target_type, target_id,
		       metadata, result, error_message
		  FROM audit_log%s
		 ORDER BY %s %s
		 LIMIT $%d OFFSET $%d`, where, sortField, dir, limOffIdx, limOffIdx+1)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()

	var items []AuditListItem
	for rows.Next() {
		var (
			it      AuditListItem
			metaRaw []byte
		)
		if err := rows.Scan(&it.ID, &it.OccurredAt, &it.ActorUserID,
			&it.ActorIP, &it.ActorUA, &it.Action, &it.TargetType, &it.TargetID,
			&metaRaw, &it.Result, &it.ErrorMessage); err != nil {
			return nil, 0, fmt.Errorf("scan audit: %w", err)
		}
		if len(metaRaw) > 0 {
			if err := json.Unmarshal(metaRaw, &it.Metadata); err != nil {
				return nil, 0, fmt.Errorf("decode metadata: %w", err)
			}
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	// Count uses the same WHERE but without limit/offset.
	countArgs := args[:len(args)-2]
	var total int
	countQ := "SELECT count(*) FROM audit_log" + where
	if err := r.pool.QueryRow(ctx, countQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit: %w", err)
	}
	return items, total, nil
}

func auditContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// PruneOlderThan deletes audit rows whose occurred_at is strictly
// before cutoff and returns the number of rows removed. Used by the
// retention loop; also callable ad-hoc for operator cleanup. The
// DELETE streams via the occurred_at index so this is cheap even on
// large tables.
//
// The "append-only" comment on the audit_log table is an application
// invariant (handlers must not UPDATE/DELETE individual rows); an
// operator-driven retention pass is a separate concern.
func (r *AuditRepo) PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM audit_log WHERE occurred_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune audit: %w", err)
	}
	return tag.RowsAffected(), nil
}
