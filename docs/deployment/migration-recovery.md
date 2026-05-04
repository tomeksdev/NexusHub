# Migration recovery

If `migrate up` failed and the schema is now in **dirty state**, this is
the canonical recovery flow.

## Symptom

```
$ ./nexushub-migrate up -path /opt/NexusHub/migrations
ERR migration command failed cmd=up err="Dirty database version 9. Fix and force version."
```

`migrate version` reports a non-zero version with `dirty=true`. Every
subsequent `up` refuses to run until the dirty flag is cleared.

## Why it happens

A migration ran a statement that errored mid-transaction. golang-migrate
records the version + dirty=true so it doesn't silently re-run a partial
migration over a corrupted schema.

The most common cause for v2.0.0 is migration **009** (UNIQUE
`listen_port`) hitting pre-existing duplicate ports left over from
earlier testing. Newer copies of `009_*.up.sql` raise a clear
`RAISE EXCEPTION` naming the conflicting interfaces, but if you applied
an older copy you'll see a bare `unique_violation` instead.

## Recovery

### 1. Identify the conflict

```sql
-- Connect with psql and run:
SELECT name, listen_port
  FROM wg_interfaces
 ORDER BY listen_port;
```

Look for rows that share `listen_port`. Pick which one keeps the port and
which one moves.

### 2. Reassign or delete the duplicates

```sql
-- Option A: move the duplicate to a free port (preferred — keeps peers).
UPDATE wg_interfaces SET listen_port = 51821 WHERE name = 'wg1';

-- Option B: delete the duplicate (destructive — peers go with it).
DELETE FROM wg_interfaces WHERE name = 'wg1';
```

If wg1 still exists in the kernel after option B, drop the link with
`ip link delete wg1` so the next API restart doesn't reconcile it back.

### 3. Roll the migration version back to before the failure

```bash
./nexushub-migrate -path /opt/NexusHub/migrations force 8
```

`force 8` clears the dirty flag and tells migrate the schema is at v8
(the version *before* 009). The schema itself is unchanged — only the
recorded version moves.

> **Flag positioning** is fixed in v2.0.0+. If you're on an older binary
> and `force 8 -path ...` opens `.: no such file or directory`, put
> `-path` **before** the subcommand: `migrate -path ... force 8`.

### 4. Re-run `up`

```bash
./nexushub-migrate -path /opt/NexusHub/migrations up
```

Migration 009 (the new copy) is idempotent — it drops the constraint if
present, runs the duplicate pre-check, and re-adds the constraint. With
the duplicates resolved in step 2 it succeeds cleanly.

## Avoiding it next time

- Apply migrations on a copy of production first (`pg_dump` →
  `pg_restore` to a staging DB → `migrate up`).
- Take a `pg_dump` snapshot before every `migrate up` in production.
  `scripts/backup.sh` does this and keeps the most recent 14.
- Don't run `migrate up` and the API simultaneously — stop the systemd
  unit (`systemctl stop nexushub-api`) before migrating.

## When the schema itself is destroyed

If a partial migration corrupted data (rare — most migrations are
DDL-only), restore from the most recent dump:

```bash
sudo systemctl stop nexushub-api
./scripts/restore.sh --force /var/backups/nexushub/2026-05-03_10-00.sql.gz
sudo systemctl start nexushub-api
```

See [backup-restore.md](backup-restore.md) for the full procedure and
the `PEER_KEY_ENCRYPTION_KEY` caveat (the DB is useless without it).
