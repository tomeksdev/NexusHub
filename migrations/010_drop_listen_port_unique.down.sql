-- 010_drop_listen_port_unique.down.sql
-- Re-add the strict listen_port uniqueness if rolling back. Includes
-- the same DO-block guard as 009 so the down migration also fails
-- cleanly when there are duplicates rather than entering dirty
-- state.

BEGIN;

DO $$
DECLARE
    dup_list text;
BEGIN
    SELECT string_agg(format('%s(port=%s)', name, listen_port), ', ' ORDER BY listen_port, name)
      INTO dup_list
      FROM wg_interfaces
     WHERE listen_port IN (
         SELECT listen_port FROM wg_interfaces GROUP BY listen_port HAVING count(*) > 1
     );
    IF dup_list IS NOT NULL THEN
        RAISE EXCEPTION
            'Cannot restore UNIQUE(listen_port): conflicting interfaces share ports: %.',
            dup_list;
    END IF;
END $$;

ALTER TABLE wg_interfaces
    ADD CONSTRAINT wg_interfaces_listen_port_unique UNIQUE (listen_port);

COMMIT;
