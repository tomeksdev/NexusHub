-- 012_ebpf_rules_owner.down.sql
-- Drop the owner column + its index. Auto-generated system rules
-- become indistinguishable from admin-authored rules afterward, which
-- is the expected effect of rolling back: handlers re-enable all the
-- edit/delete paths the owner check was gating.

BEGIN;

DROP INDEX IF EXISTS idx_ebpf_rules_owner_system;
ALTER TABLE ebpf_rules DROP COLUMN owner;

COMMIT;
