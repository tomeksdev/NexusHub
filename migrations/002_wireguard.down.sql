-- 002_wireguard.down.sql

BEGIN;

DROP TRIGGER IF EXISTS wg_peers_set_updated_at ON wg_peers;
DROP TRIGGER IF EXISTS wg_interfaces_set_updated_at ON wg_interfaces;

DROP TABLE IF EXISTS wg_peer_preshared_keys;
DROP TABLE IF EXISTS wg_peers;
DROP TABLE IF EXISTS wg_interfaces;

DROP TYPE IF EXISTS wg_peer_status;

COMMIT;
