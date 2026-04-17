# ADR 0001 — Database stack

- **Status:** Accepted
- **Date:** 2026-04-17
- **Deciders:** @tomeksdev

## Context

NexusHub v2.0.0 needs a relational datastore for users, sessions, WireGuard
configuration, eBPF rule metadata, audit logs, and high-volume connection
logs. The backend is Go 1.22+. We want:

- Type-safe SQL (compile-time errors, not runtime reflection surprises).
- A driver that is fast enough to meet the <100 ms query budget in CLAUDE.md.
- Schema evolution with forward and backward migrations.
- Support for PostgreSQL features we rely on: `JSONB`, `BYTEA`, native
  partitioning (`PARTITION BY RANGE`), `CHECK` constraints, arrays, `inet`.

## Decision

| Concern | Choice |
|---|---|
| Driver | `github.com/jackc/pgx/v5` in native mode (no `database/sql` wrapper). |
| Pool | `pgxpool` with `MaxConns=25`. |
| Query generation | `sqlc` (`github.com/sqlc-dev/sqlc`) targeting `pgx/v5`. |
| Migrations | `github.com/golang-migrate/migrate/v4` with file-based driver. |
| Migration layout | `migrations/NNN_name.up.sql` + `migrations/NNN_name.down.sql`. |

### Why pgx native mode

`pgx` in native mode skips `database/sql`'s interface abstraction and uses the
protocol directly. Benchmarks put it roughly 30–50% faster than
`lib/pq`+`database/sql` for typical workloads and it exposes PostgreSQL
features (`COPY`, listen/notify, native types for `inet`, `jsonb`, arrays)
without ceremony.

### Why sqlc over alternatives

- **sqlc vs. ent:** sqlc is SQL-first — queries are written in SQL files and
  generated into typed Go. `ent` is schema-first and introduces a query DSL
  that we would then have to debug. Operators reading this repo should be
  able to grep for the exact SQL we execute.
- **sqlc vs. pgx + `scany`/`pgxscan`:** `pgxscan` gives you scanning but not
  parameter typing. sqlc gives both, and refuses to generate for a query
  whose parameter or result types drift from the schema.
- **sqlc vs. GORM:** no. GORM's magic makes performance tuning and query
  auditing painful.

### Why golang-migrate

Mature, single-binary, matches the `NNN_name.up.sql` convention we already
use, and plays well with CI (`migrate -path ... -database $DATABASE_URL up`).
The `cmd/migrate` binary wraps this so operators do not need `migrate` on
their `$PATH`.

## Consequences

- All queries live in `backend/internal/db/queries/*.sql` and are generated
  into `backend/internal/db/gen/` by `sqlc generate`. Generated code is
  checked in so `go build` never needs the sqlc toolchain.
- Schema changes require a paired up/down migration file. Irreversible
  migrations should still ship a best-effort down that documents what cannot
  be undone.
- `connection_logs` partitions are managed by application code, not by
  migrations (see ADR to follow — partition manager design).
- Encrypted columns (`wg_peers.private_key`) are `BYTEA`; encryption is
  performed in application code with a KEK supplied via env var.

## Rejected alternatives

- **SQLite** — not suitable for write-heavy partitioned logs or concurrent
  peer/ACL updates.
- **CockroachDB / YugabyteDB** — unnecessary for a single-node VPN appliance;
  would forfeit `PARTITION BY RANGE` ergonomics we rely on.
- **ORM (GORM, Bun)** — hides SQL, complicates perf tuning, unnecessary for a
  mid-sized schema.
