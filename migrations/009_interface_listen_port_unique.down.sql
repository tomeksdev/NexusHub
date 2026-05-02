-- 009_interface_listen_port_unique.down.sql

BEGIN;

ALTER TABLE wg_interfaces
    DROP CONSTRAINT IF EXISTS wg_interfaces_listen_port_unique;

COMMIT;
