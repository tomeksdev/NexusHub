-- 001_users_auth.up.sql
-- Users, sessions, and rotating refresh tokens.

BEGIN;

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE user_role AS ENUM ('super_admin', 'admin', 'user');

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           CITEXT UNIQUE NOT NULL,
    username        VARCHAR(64)  UNIQUE NOT NULL,
    password_hash   TEXT         NOT NULL,
    role            user_role    NOT NULL DEFAULT 'user',
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    totp_secret     BYTEA,
    totp_enabled    BOOLEAN      NOT NULL DEFAULT FALSE,
    last_login_at   TIMESTAMPTZ,
    failed_logins   INTEGER      NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT users_username_format CHECK (username ~ '^[a-zA-Z0-9_.-]{3,64}$')
);

CREATE INDEX users_role_idx     ON users (role);
CREATE INDEX users_active_idx   ON users (is_active) WHERE is_active;

-- Sessions track the currently valid access-token issuance for a user.
-- The access-token JWT is self-contained; this table exists so we can
-- revoke all sessions for a user (e.g. password change) without rotating
-- JWT signing keys.
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_addr         INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX sessions_user_idx       ON sessions (user_id);
CREATE INDEX sessions_active_idx     ON sessions (user_id) WHERE revoked_at IS NULL;

-- Refresh tokens are rotated on every use. token_hash is the SHA-256 of the
-- opaque token string; we never store plaintext.
CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID         NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id         UUID         NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    token_hash      BYTEA        NOT NULL,
    parent_id       UUID         REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    issued_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ  NOT NULL,
    used_at         TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    CONSTRAINT refresh_tokens_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_tokens_hash_unique UNIQUE (token_hash)
);

CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_user_idx    ON refresh_tokens (user_id);
CREATE INDEX refresh_tokens_active_idx  ON refresh_tokens (session_id)
    WHERE used_at IS NULL AND revoked_at IS NULL;

-- Auto-update updated_at on users.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
