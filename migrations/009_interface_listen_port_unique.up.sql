-- 009_interface_listen_port_unique.up.sql
-- Reject duplicate listen_port values across wg_interfaces.
--
-- A WireGuard kernel device cannot share a UDP port with another wg
-- interface — the second one fails to bind silently and packets get
-- routed to whichever device claimed the port first. Surfacing the
-- conflict at insert time lets the API return a clean 409 instead of
-- letting the operator discover the breakage post-deploy.
--
-- Operators who already had duplicate ports from earlier testing hit a
-- bare unique-violation when this constraint was first added in v0.x
-- and the migration left the DB in dirty state at version 9. The
-- DO-block pre-flight below replaces that opaque error with a
-- RAISE EXCEPTION naming the offending interfaces so the operator can
-- dedupe and re-run without filing a support ticket.
--
-- Idempotency: DROP CONSTRAINT IF EXISTS at the top means re-running
-- after a successful add (or after a `force 8 → up` recovery) is a
-- no-op + re-add rather than an error.

BEGIN;

ALTER TABLE wg_interfaces
    DROP CONSTRAINT IF EXISTS wg_interfaces_listen_port_unique;

DO $$
DECLARE
    dup_list text;
BEGIN
    SELECT string_agg(
               format('%s(port=%s)', name, listen_port),
               ', '
               ORDER BY listen_port, name
           )
      INTO dup_list
      FROM wg_interfaces
     WHERE listen_port IN (
         SELECT listen_port
           FROM wg_interfaces
          GROUP BY listen_port
         HAVING count(*) > 1
     );
    IF dup_list IS NOT NULL THEN
        RAISE EXCEPTION
            'Cannot add UNIQUE(listen_port): conflicting interfaces share ports: %. Reassign or delete duplicates and re-run `migrate up` (no force needed — this migration is idempotent).',
            dup_list
        USING HINT =
            'Run: SELECT name, listen_port FROM wg_interfaces ORDER BY listen_port; then UPDATE the duplicates to free ports.';
    END IF;
END $$;

ALTER TABLE wg_interfaces
    ADD CONSTRAINT wg_interfaces_listen_port_unique UNIQUE (listen_port);

COMMIT;
