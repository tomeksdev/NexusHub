package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

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
