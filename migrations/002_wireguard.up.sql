-- 002_wireguard.up.sql
-- WireGuard interfaces, peers, and per-peer pre-shared keys.
--
-- Public keys: curve25519 base64 = exactly 44 chars ending in '='. We check
-- both length and charset so bad config cannot enter the DB.
-- Private keys: AES-256-GCM encrypted at rest. Never logged. Never returned
-- by the API. The ciphertext carries its nonce; see internal/crypto.

BEGIN;

CREATE TYPE wg_peer_status AS ENUM ('enabled', 'disabled', 'revoked');

CREATE TABLE wg_interfaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(15)  UNIQUE NOT NULL,
    listen_port     INTEGER      NOT NULL,
    address         CIDR         NOT NULL,
    dns             TEXT[]       NOT NULL DEFAULT '{}',
    mtu             INTEGER,
    endpoint        TEXT,
    private_key     BYTEA        NOT NULL,
    public_key      VARCHAR(44)  NOT NULL,
    post_up         TEXT,
    post_down       TEXT,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT wg_interfaces_name_format     CHECK (name ~ '^[a-zA-Z0-9_-]{1,15}$'),
    CONSTRAINT wg_interfaces_listen_port_rng CHECK (listen_port BETWEEN 1 AND 65535),
    CONSTRAINT wg_interfaces_pubkey_format   CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    CONSTRAINT wg_interfaces_mtu_range       CHECK (mtu IS NULL OR mtu BETWEEN 576 AND 9000)
);

CREATE TABLE wg_peers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    interface_id    UUID         NOT NULL REFERENCES wg_interfaces(id) ON DELETE CASCADE,
    owner_user_id   UUID         REFERENCES users(id) ON DELETE SET NULL,
    name            VARCHAR(128) NOT NULL,
    description     TEXT,
    public_key      VARCHAR(44)  NOT NULL,
    private_key     BYTEA,
    allowed_ips     CIDR[]       NOT NULL DEFAULT '{}',
    assigned_ip     INET         NOT NULL,
    endpoint        TEXT,
    persistent_keepalive INTEGER,
    dns             TEXT[]       NOT NULL DEFAULT '{}',
    status          wg_peer_status NOT NULL DEFAULT 'enabled',
    last_handshake  TIMESTAMPTZ,
    rx_bytes        BIGINT       NOT NULL DEFAULT 0,
    tx_bytes        BIGINT       NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT wg_peers_pubkey_unique        UNIQUE (public_key),
    CONSTRAINT wg_peers_ip_per_interface     UNIQUE (interface_id, assigned_ip),
    CONSTRAINT wg_peers_name_per_interface   UNIQUE (interface_id, name),
    CONSTRAINT wg_peers_pubkey_format        CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    CONSTRAINT wg_peers_keepalive_range      CHECK (persistent_keepalive IS NULL
                                                OR persistent_keepalive BETWEEN 0 AND 65535)
);

CREATE INDEX wg_peers_interface_idx       ON wg_peers (interface_id);
CREATE INDEX wg_peers_owner_idx           ON wg_peers (owner_user_id);
CREATE INDEX wg_peers_status_idx          ON wg_peers (status);
CREATE INDEX wg_peers_last_handshake_idx  ON wg_peers (last_handshake DESC NULLS LAST);
CREATE INDEX wg_peers_expires_idx         ON wg_peers (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE wg_peer_preshared_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    peer_id         UUID         NOT NULL REFERENCES wg_peers(id) ON DELETE CASCADE,
    preshared_key   BYTEA        NOT NULL,
    rotated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    retired_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX wg_psk_active_unique
    ON wg_peer_preshared_keys (peer_id) WHERE retired_at IS NULL;
CREATE INDEX wg_psk_peer_idx ON wg_peer_preshared_keys (peer_id);

CREATE TRIGGER wg_interfaces_set_updated_at
    BEFORE UPDATE ON wg_interfaces
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER wg_peers_set_updated_at
    BEFORE UPDATE ON wg_peers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
