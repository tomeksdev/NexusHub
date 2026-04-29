-- 005_api_keys.up.sql
-- API keys for CLI and automation clients.
-- Tokens are shown once at creation and only the SHA-256 hash is stored.

BEGIN;

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(128) NOT NULL,
    token_hash      BYTEA        NOT NULL,
    -- Short, non-secret prefix used by the UI to identify a key without
    -- revealing the secret (e.g. "nxh_abc12…").
    token_prefix    VARCHAR(16)  NOT NULL,
    scopes          TEXT[]       NOT NULL DEFAULT '{}',
    last_used_at    TIMESTAMPTZ,
    last_used_ip    INET,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT api_keys_token_hash_len    CHECK (octet_length(token_hash) = 32),
    CONSTRAINT api_keys_token_hash_unique UNIQUE (token_hash),
    CONSTRAINT api_keys_name_per_user     UNIQUE (user_id, name)
);

CREATE INDEX api_keys_user_idx    ON api_keys (user_id);
-- Partial index predicates must be immutable; callers filter expires_at at
-- query time.
CREATE INDEX api_keys_active_idx  ON api_keys (user_id, expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX api_keys_prefix_idx  ON api_keys (token_prefix);

COMMIT;
