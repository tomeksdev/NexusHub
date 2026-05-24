-- 011_purge_full_tunnel_server_allowed_ips.down.sql
-- One-way data fix; nothing to restore. The original 0.0.0.0/0 / ::/0
-- entries are gone and we don't keep a snapshot. Down-migrating is a
-- no-op so a roll-back doesn't break the migrator's bookkeeping.

BEGIN;
COMMIT;
