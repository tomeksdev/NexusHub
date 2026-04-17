-- 006_connection_logs.up.sql
-- High-volume connection/handshake telemetry from the eBPF user-space loader.
--
-- PARTITION BY RANGE (recorded_at) — monthly partitions. Partition creation
-- is the responsibility of the application's partition manager (runs on
-- startup and via a periodic job); we seed a handful of partitions here so a
-- fresh install can insert immediately.
--
-- NOTE (CLAUDE.md): foreign keys from this table are logical-only (not
-- enforced) for performance. Deleting a peer or interface does not cascade
-- into connection_logs; a separate retention/archival job handles cleanup.

BEGIN;

CREATE TABLE connection_logs (
    id              BIGSERIAL,
    recorded_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    peer_id         UUID,
    interface_id    UUID,
    src_ip          INET         NOT NULL,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(8),
    bytes_in        BIGINT       NOT NULL DEFAULT 0,
    bytes_out       BIGINT       NOT NULL DEFAULT 0,
    packets_in      BIGINT       NOT NULL DEFAULT 0,
    packets_out     BIGINT       NOT NULL DEFAULT 0,
    action          VARCHAR(16),
    matched_rule_id UUID,
    PRIMARY KEY (id, recorded_at)
) PARTITION BY RANGE (recorded_at);

CREATE INDEX connection_logs_recorded_idx ON connection_logs (recorded_at DESC);
CREATE INDEX connection_logs_peer_idx     ON connection_logs (peer_id, recorded_at DESC)
    WHERE peer_id IS NOT NULL;
CREATE INDEX connection_logs_iface_idx    ON connection_logs (interface_id, recorded_at DESC)
    WHERE interface_id IS NOT NULL;
CREATE INDEX connection_logs_src_ip_idx   ON connection_logs (src_ip, recorded_at DESC);
CREATE INDEX connection_logs_rule_idx     ON connection_logs (matched_rule_id, recorded_at DESC)
    WHERE matched_rule_id IS NOT NULL;

-- Default partition catches any row whose recorded_at falls outside the
-- managed window. The partition manager should drain it into the correct
-- monthly partition and keep it empty.
CREATE TABLE connection_logs_default PARTITION OF connection_logs DEFAULT;

-- Helper to create monthly partitions idempotently. The partition manager
-- will call this for rolling windows (current month ± N).
CREATE OR REPLACE FUNCTION create_connection_logs_partition(target_month DATE)
RETURNS VOID AS $$
DECLARE
    start_ts   TIMESTAMPTZ := date_trunc('month', target_month)::TIMESTAMPTZ;
    end_ts     TIMESTAMPTZ := (date_trunc('month', target_month) + INTERVAL '1 month')::TIMESTAMPTZ;
    part_name  TEXT := format('connection_logs_%s', to_char(start_ts, 'YYYY_MM'));
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF connection_logs FOR VALUES FROM (%L) TO (%L)',
        part_name, start_ts, end_ts
    );
END;
$$ LANGUAGE plpgsql;

-- Seed current and next month so fresh installs have a place to land rows.
SELECT create_connection_logs_partition(date_trunc('month', now())::date);
SELECT create_connection_logs_partition((date_trunc('month', now()) + INTERVAL '1 month')::date);

COMMIT;
