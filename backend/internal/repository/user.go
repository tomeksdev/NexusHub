package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserListItem is the admin-facing projection of a user row. Intentionally
// omits password_hash and totp_secret — those never leave the repo layer.
type UserListItem struct {
	ID           uuid.UUID
	Email        string
	Username     string
	Role         string
	IsActive     bool
	TOTPEnabled  bool
	LastLoginAt  *time.Time
	FailedLogins int
	LockedUntil  *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserSortFields is the allow-list of sortable columns for the admin users
// list. Kept next to ListPage so the whitelist lives with the SQL.
var UserSortFields = []string{"email", "username", "role", "last_login_at", "created_at"}

// ListPage returns the paginated users slice plus the total count. ORDER BY
// is built from UserSortFields only — no caller string reaches SQL.
func (r *UserRepo) ListPage(ctx context.Context, limit, offset int, sortField string, sortDesc bool) ([]UserListItem, int, error) {
	if !containsString(UserSortFields, sortField) {
		sortField = "email"
	}
	dir := "ASC"
	if sortDesc {
		dir = "DESC"
	}
	q := fmt.Sprintf(`
		SELECT id, email::text, username, role::text, is_active, totp_enabled,
		       last_login_at, failed_logins, locked_until, created_at, updated_at
		  FROM users
		 ORDER BY %s %s NULLS LAST, id ASC
		 LIMIT $1 OFFSET $2`, sortField, dir)

	rows, err := r.pool.Query(ctx, q, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var items []UserListItem
	for rows.Next() {
		var u UserListItem
		if err := rows.Scan(&u.ID, &u.Email, &u.Username, &u.Role, &u.IsActive,
			&u.TOTPEnabled, &u.LastLoginAt, &u.FailedLogins, &u.LockedUntil,
			&u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan user: %w", err)
		}
		items = append(items, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}
	return items, total, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ErrUserNotFound is returned by user lookups that match no row. Handlers
// must treat this identically to a password mismatch to avoid user
// enumeration via timing or error codes.
var ErrUserNotFound = errors.New("user not found")

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

// UserCredentials carries the minimum fields needed by the login handler.
type UserCredentials struct {
	ID           uuid.UUID
	PasswordHash string
	Role         string
	IsActive     bool
	LockedUntil  *time.Time
	FailedLogins int
}

// GetCredentialsByEmail returns the credential bundle for the given email
// (case-insensitive, CITEXT). Returns ErrUserNotFound when the email is
// unknown.
func (r *UserRepo) GetCredentialsByEmail(ctx context.Context, email string) (*UserCredentials, error) {
	var c UserCredentials
	err := r.pool.QueryRow(ctx,
		`SELECT id, password_hash, role::text, is_active, locked_until, failed_logins
		   FROM users WHERE email = $1`,
		email,
	).Scan(&c.ID, &c.PasswordHash, &c.Role, &c.IsActive, &c.LockedUntil, &c.FailedLogins)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup user: %w", err)
	}
	return &c, nil
}

// MarkLoginSuccess resets the failed-login counter and stamps last_login_at.
func (r *UserRepo) MarkLoginSuccess(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users
		    SET last_login_at = now(),
		        failed_logins = 0,
		        locked_until  = NULL
		  WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("mark success: %w", err)
	}
	return nil
}

// MarkLoginFailure increments the failed-login counter and, after a
// threshold, sets a lockout. Threshold + lockout duration are intentionally
// fixed here rather than configurable — changing them is a security decision
// that should be reviewed, not tuned at runtime.
func (r *UserRepo) MarkLoginFailure(ctx context.Context, userID uuid.UUID) error {
	const (
		lockThreshold = 5
		lockDuration  = 15 * time.Minute
	)
	_, err := r.pool.Exec(ctx,
		`UPDATE users
		    SET failed_logins = failed_logins + 1,
		        locked_until  = CASE
		                          WHEN failed_logins + 1 >= $2
		                          THEN now() + $3::interval
		                          ELSE locked_until
		                        END
		  WHERE id = $1`,
		userID, lockThreshold, fmt.Sprintf("%d milliseconds", lockDuration.Milliseconds()),
	)
	if err != nil {
		return fmt.Errorf("mark failure: %w", err)
	}
	return nil
}

// UpdatePassword replaces the password hash for a user.
func (r *UserRepo) UpdatePassword(ctx context.Context, userID uuid.UUID, newHash string) error {
	cmd, err := r.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2 WHERE id = $1`,
		userID, newHash,
	)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// GetPasswordHash returns just the current password hash, for re-authenticating
// before sensitive actions like a password change.
func (r *UserRepo) GetPasswordHash(ctx context.Context, userID uuid.UUID) (string, error) {
	var hash string
	err := r.pool.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1`, userID,
	).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get hash: %w", err)
	}
	return hash, nil
}
