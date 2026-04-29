-- 003_ebpf_rules.up.sql
-- eBPF security rules plus their per-peer and per-interface bindings.
--
-- A rule is a declarative policy (allow/deny IP/port/proto, rate limit,
-- bandwidth cap). The userspace loader reads rows from ebpf_rules and
-- updates BPF maps in place — no program reload needed. See CLAUDE.md
-- "BPF map-based rule updates".

BEGIN;

CREATE TYPE ebpf_rule_action AS ENUM ('allow', 'deny', 'rate_limit', 'log');
CREATE TYPE ebpf_rule_direction AS ENUM ('ingress', 'egress', 'both');
CREATE TYPE ebpf_rule_protocol AS ENUM ('tcp', 'udp', 'icmp', 'any');

CREATE TABLE ebpf_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(128) UNIQUE NOT NULL,
    description     TEXT,
    action          ebpf_rule_action    NOT NULL,
    direction       ebpf_rule_direction NOT NULL DEFAULT 'ingress',
    protocol        ebpf_rule_protocol  NOT NULL DEFAULT 'any',
    src_cidr        CIDR,
    dst_cidr        CIDR,
    src_port_from   INTEGER,
    src_port_to     INTEGER,
    dst_port_from   INTEGER,
    dst_port_to     INTEGER,
    -- rate_limit action: packets per second per src addr.
    rate_pps        INTEGER,
    -- burst allowance for rate_limit.
    rate_burst      INTEGER,
    priority        INTEGER      NOT NULL DEFAULT 100,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by      UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ebpf_rules_src_port_range  CHECK (
        (src_port_from IS NULL AND src_port_to IS NULL) OR
        (src_port_from BETWEEN 0 AND 65535 AND src_port_to BETWEEN 0 AND 65535
         AND src_port_from <= src_port_to)
    ),
    CONSTRAINT ebpf_rules_dst_port_range  CHECK (
        (dst_port_from IS NULL AND dst_port_to IS NULL) OR
        (dst_port_from BETWEEN 0 AND 65535 AND dst_port_to BETWEEN 0 AND 65535
         AND dst_port_from <= dst_port_to)
    ),
    CONSTRAINT ebpf_rules_rate_fields CHECK (
        (action = 'rate_limit' AND rate_pps IS NOT NULL AND rate_pps > 0) OR
        (action <> 'rate_limit' AND rate_pps IS NULL AND rate_burst IS NULL)
    ),
    CONSTRAINT ebpf_rules_priority_range CHECK (priority BETWEEN 0 AND 1000)
);

CREATE INDEX ebpf_rules_active_priority_idx ON ebpf_rules (is_active, priority)
    WHERE is_active;

-- Bindings attach a rule to a peer or to an entire interface. Exactly one of
-- peer_id / interface_id must be set.
CREATE TABLE ebpf_rule_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID         NOT NULL REFERENCES ebpf_rules(id) ON DELETE CASCADE,
    peer_id         UUID         REFERENCES wg_peers(id) ON DELETE CASCADE,
    interface_id    UUID         REFERENCES wg_interfaces(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ebpf_rule_bindings_target_xor CHECK (
        (peer_id IS NOT NULL)::int + (interface_id IS NOT NULL)::int = 1
    )
);

CREATE UNIQUE INDEX ebpf_rule_bindings_peer_unique
    ON ebpf_rule_bindings (rule_id, peer_id) WHERE peer_id IS NOT NULL;
CREATE UNIQUE INDEX ebpf_rule_bindings_iface_unique
    ON ebpf_rule_bindings (rule_id, interface_id) WHERE interface_id IS NOT NULL;

CREATE INDEX ebpf_rule_bindings_peer_idx  ON ebpf_rule_bindings (peer_id)
    WHERE peer_id IS NOT NULL;
CREATE INDEX ebpf_rule_bindings_iface_idx ON ebpf_rule_bindings (interface_id)
    WHERE interface_id IS NOT NULL;

CREATE TRIGGER ebpf_rules_set_updated_at
    BEFORE UPDATE ON ebpf_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
