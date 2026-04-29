-- 003_ebpf_rules.down.sql

BEGIN;

DROP TRIGGER IF EXISTS ebpf_rules_set_updated_at ON ebpf_rules;

DROP TABLE IF EXISTS ebpf_rule_bindings;
DROP TABLE IF EXISTS ebpf_rules;

DROP TYPE IF EXISTS ebpf_rule_protocol;
DROP TYPE IF EXISTS ebpf_rule_direction;
DROP TYPE IF EXISTS ebpf_rule_action;

COMMIT;
