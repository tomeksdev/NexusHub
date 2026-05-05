-- 010_drop_listen_port_unique.up.sql
-- Round-4 spec change: same listen_port on different endpoint hosts
-- is now allowed (operators may bind interfaces to different host
-- IPs). Uniqueness moves to (endpoint_host, listen_port) and is
-- enforced at the API layer rather than the DB — endpoint is a TEXT
-- column with a host:port string, and a generated index over a
-- partial parse is more pain than precision is worth.
--
-- Idempotent: DROP CONSTRAINT IF EXISTS so re-running doesn't error
-- on a fresh schema where 009 might have been replayed.

BEGIN;

ALTER TABLE wg_interfaces
    DROP CONSTRAINT IF EXISTS wg_interfaces_listen_port_unique;

COMMIT;
