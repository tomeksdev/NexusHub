-- 006_connection_logs.down.sql
-- Dropping the parent cascades to every partition.

BEGIN;

DROP FUNCTION IF EXISTS create_connection_logs_partition(DATE);
DROP TABLE IF EXISTS connection_logs CASCADE;

COMMIT;
