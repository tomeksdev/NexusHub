-- 004_audit_log.up.sql
-- Append-only audit trail of every state-changing API action.

BEGIN;

CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    actor_user_id   UUID         REFERENCES users(id) ON DELETE SET NULL,
    actor_api_key_id UUID,
    actor_ip        INET,
    actor_ua        TEXT,
    action          VARCHAR(64)  NOT NULL,
    target_type     VARCHAR(64)  NOT NULL,
    target_id       TEXT,
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    result          VARCHAR(16)  NOT NULL DEFAULT 'success',
    error_message   TEXT,
    CONSTRAINT audit_log_result_values CHECK (result IN ('success', 'failure', 'denied'))
);

CREATE INDEX audit_log_occurred_idx   ON audit_log (occurred_at DESC);
CREATE INDEX audit_log_actor_idx      ON audit_log (actor_user_id, occurred_at DESC)
    WHERE actor_user_id IS NOT NULL;
CREATE INDEX audit_log_action_idx     ON audit_log (action, occurred_at DESC);
CREATE INDEX audit_log_target_idx     ON audit_log (target_type, target_id, occurred_at DESC)
    WHERE target_id IS NOT NULL;
CREATE INDEX audit_log_metadata_gin   ON audit_log USING GIN (metadata jsonb_path_ops);

COMMENT ON TABLE audit_log IS 'Append-only. Do not UPDATE or DELETE rows; rotate via partition or archive job.';

COMMIT;
