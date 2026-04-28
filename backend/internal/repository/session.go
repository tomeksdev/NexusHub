// Package repository holds data-access types that wrap the connection pool
// and expose behavior-level methods (not plain CRUD) to the rest of the
// backend.
package repository

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrRefreshTokenInvalid is returned when a presented refresh token does not
// match any active row. The handler should respond 401.
var ErrRefreshTokenInvalid = errors.New("refresh token invalid")

// ErrRefreshTokenReused is returned when a presented refresh token matches a
// row that has already been used or revoked. On this signal the entire
// session family is revoked — a classic indicator that a stolen token is in
// circulation.
var ErrRefreshTokenReused = errors.New("refresh token reused")

// SessionRepo handles sessions and rotating refresh tokens.
type SessionRepo struct {
	pool *pgxpool.Pool
}

func NewSessionRepo(pool *pgxpool.Pool) *SessionRepo {
	return &SessionRepo{pool: pool}
}

// IssueResult carries the IDs and expiry metadata needed by the handler to
// build an auth response. The refresh-token plaintext is never returned by
// this layer — the caller passes a hash and keeps the plaintext.
type IssueResult struct {
	SessionID        uuid.UUID
	RefreshTokenID   uuid.UUID
	RefreshExpiresAt time.Time
}

// CreateSession opens a new session and issues the first refresh token.
// refreshHash is the SHA-256 of the opaque token (see auth.NewRefreshToken).
func (r *SessionRepo) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	refreshHash []byte,
	refreshTTL time.Duration,
	ip net.IP,
	userAgent string,
) (IssueResult, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return IssueResult{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var sessionID uuid.UUID
	if err := tx.QueryRow(ctx,
		`INSERT INTO sessions (user_id, ip_addr, user_agent)
		 VALUES ($1, $2, NULLIF($3, ''))
		 RETURNING id`,
		userID, ipToNullable(ip), userAgent,
	).Scan(&sessionID); err != nil {
		return IssueResult{}, fmt.Errorf("insert session: %w", err)
	}

	expiresAt := time.Now().Add(refreshTTL)
	var refreshID uuid.UUID
	if err := tx.QueryRow(ctx,
		`INSERT INTO refresh_tokens (session_id, user_id, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		sessionID, userID, refreshHash, expiresAt,
	).Scan(&refreshID); err != nil {
		return IssueResult{}, fmt.Errorf("insert refresh: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return IssueResult{}, fmt.Errorf("commit: %w", err)
	}

	return IssueResult{
		SessionID:        sessionID,
		RefreshTokenID:   refreshID,
		RefreshExpiresAt: expiresAt,
	}, nil
}

// RotateRefreshToken validates the presented refresh-token hash, marks the
// old row as used, and issues a new one. If the presented token has already
// been used or revoked, the whole session is revoked and ErrRefreshTokenReused
// is returned — this is the detection signal for a leaked token.
func (r *SessionRepo) RotateRefreshToken(
	ctx context.Context,
	presentedHash []byte,
	newHash []byte,
	refreshTTL time.Duration,
) (userID uuid.UUID, sessionID uuid.UUID, role string, result IssueResult, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the row to prevent concurrent rotation races.
	var (
		tokenID    uuid.UUID
		usedAt     *time.Time
		revokedAt  *time.Time
		expiresAt  time.Time
		sessionRev *time.Time
	)
	err = tx.QueryRow(ctx,
		`SELECT rt.id, rt.session_id, rt.user_id, rt.used_at, rt.revoked_at,
		        rt.expires_at, s.revoked_at, u.role::text
		   FROM refresh_tokens rt
		   JOIN sessions s ON s.id = rt.session_id
		   JOIN users    u ON u.id = rt.user_id
		  WHERE rt.token_hash = $1
		    FOR UPDATE OF rt`,
		presentedHash,
	).Scan(&tokenID, &sessionID, &userID, &usedAt, &revokedAt, &expiresAt, &sessionRev, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, ErrRefreshTokenInvalid
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, fmt.Errorf("lookup refresh: %w", err)
	}

	if sessionRev != nil {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, ErrRefreshTokenInvalid
	}
	if expiresAt.Before(time.Now()) {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, ErrRefreshTokenInvalid
	}

	// Reuse: the presented token was already used or explicitly revoked.
	// Revoke the entire session family to invalidate whoever else holds copies.
	if usedAt != nil || revokedAt != nil {
		if _, err := tx.Exec(ctx,
			`UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`,
			sessionID,
		); err != nil {
			return uuid.Nil, uuid.Nil, "", IssueResult{}, fmt.Errorf("revoke on reuse: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return uuid.Nil, uuid.Nil, "", IssueResult{}, fmt.Errorf("commit reuse revoke: %w", err)
		}
		return uuid.Nil, uuid.Nil, "", IssueResult{}, ErrRefreshTokenReused
	}

	// Mark the presented token used.
	if _, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET used_at = now() WHERE id = $1`, tokenID,
	); err != nil {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, fmt.Errorf("mark used: %w", err)
	}

	// Issue the replacement.
	newExpires := time.Now().Add(refreshTTL)
	var newID uuid.UUID
	if err := tx.QueryRow(ctx,
		`INSERT INTO refresh_tokens (session_id, user_id, token_hash, parent_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		sessionID, userID, newHash, tokenID, newExpires,
	).Scan(&newID); err != nil {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, fmt.Errorf("insert new refresh: %w", err)
	}

	// Bump last_seen_at on the session.
	if _, err := tx.Exec(ctx,
		`UPDATE sessions SET last_seen_at = now() WHERE id = $1`, sessionID,
	); err != nil {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, fmt.Errorf("touch session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, uuid.Nil, "", IssueResult{}, fmt.Errorf("commit: %w", err)
	}

	return userID, sessionID, role, IssueResult{
		SessionID:        sessionID,
		RefreshTokenID:   newID,
		RefreshExpiresAt: newExpires,
	}, nil
}

// RevokeSession marks a specific session revoked. Idempotent. Returns true
// if the session existed and was newly revoked by this call.
func (r *SessionRepo) RevokeSession(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	cmd, err := r.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		  WHERE id = $1 AND revoked_at IS NULL`,
		sessionID,
	)
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	return cmd.RowsAffected() > 0, nil
}

// RevokeAllForUser revokes every active session for a user. Used on password
// change and on admin-forced logout.
func (r *SessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		  WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	); err != nil {
		return fmt.Errorf("revoke all: %w", err)
	}
	return nil
}

// LookupByRefreshHash returns the session and user owning a refresh-token
// hash. Does not check expiry or reuse state — callers that need policy
// enforcement must use RotateRefreshToken. This method exists for logout,
// which is intentionally lenient.
func (r *SessionRepo) LookupByRefreshHash(ctx context.Context, hash []byte) (sessionID, userID uuid.UUID, err error) {
	err = r.pool.QueryRow(ctx,
		`SELECT session_id, user_id FROM refresh_tokens WHERE token_hash = $1`, hash,
	).Scan(&sessionID, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrRefreshTokenInvalid
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("lookup refresh: %w", err)
	}
	return sessionID, userID, nil
}

// SessionActive returns true if the session exists and is not revoked.
// Used by the RequireAuth middleware to validate that a JWT's session has
// not been revoked since the token was issued.
func (r *SessionRepo) SessionActive(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	var active bool
	err := r.pool.QueryRow(ctx,
		`SELECT revoked_at IS NULL FROM sessions WHERE id = $1`, sessionID,
	).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("session lookup: %w", err)
	}
	return active, nil
}

func ipToNullable(ip net.IP) any {
	if ip == nil {
		return nil
	}
	return ip.String()
}
