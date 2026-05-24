-- 008_peer_client_allowed_ips.down.sql

BEGIN;

ALTER TABLE wg_peers DROP COLUMN client_allowed_ips;

COMMIT;
