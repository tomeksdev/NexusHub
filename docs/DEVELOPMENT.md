# NexusHub — development playbook

This is the contributor's reference. It covers what to install,
how to run each layer in dev mode, how to test + lint, and what
the repo expects from a PR. The makefile at the repo root is the
canonical source for every command; this doc explains _why_ each
one matters.

For the architectural picture (what NexusHub is and how the planes
fit together), start in [`README.md`](../README.md). For
deployment, see [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## 🏗️ Local workspace setup

### Required binaries

| Tool | Min version | Why |
|---|---|---|
| **Go** | 1.25 | `backend/go.mod` and `ebpf/go.mod` pin `go 1.25`. The Makefile sets `GOTOOLCHAIN=auto` so a 1.22 host can still build by fetching the right toolchain on demand. |
| **Node.js** | 22.x LTS | Frontend tooling (Vite, TypeScript, ESLint, Vitest). 20.x works but isn't tested. |
| **npm** | bundled with Node 22 | The repo doesn't standardise on `pnpm`/`yarn`; `package-lock.json` is `npm`'s. |
| **PostgreSQL** | 16+ | The schema uses `CIDR[]`, `CHECK`, native partitioning, and `inet`. Use the bundled compose service in dev — don't install Postgres on bare metal unless you have a reason. |
| **Docker** + **Docker compose** | recent | Drives the dev DB, runs `testcontainers-go` integration tests, and produces release images. |
| **Air** (live-reload) | `air-verse/air` | `go install github.com/air-verse/air@latest`. Reads `backend/.air.toml`. |
| **clang** | 14+ | Only at **build time** for eBPF (`bpf2go` invokes it). Not needed at runtime. |
| **Linux headers** | matching the build host's kernel | `bpf2go` includes `/usr/include/x86_64-linux-gnu` or aarch64. Skip if you're not regenerating eBPF artifacts. |
| **golangci-lint** | recent | Backend + ebpf linting. `make lint` calls it. |
| **redocly** (optional) | `npm i -g @redocly/cli` | Regenerates `docs/api/index.html` from OpenAPI. Only needed if you change the API surface. |

### Repo clone + env file

```bash
git clone https://github.com/tomeksdev/NexusHub.git
cd NexusHub
cp .env.example .env
```

Open `.env` and fill in at least:

- `JWT_SECRET` — `openssl rand -hex 32`
- `PEER_KEY_ENCRYPTION_KEY` — `openssl rand -base64 32` (must be a
  raw 32-byte key, base64-encoded; the loader fails fast if the
  decoded length is wrong)
- `NEXUSHUB_ADMIN_PASSWORD` — rotate the seeded admin's password
  through the UI immediately after first login

The full env reference (including OTLP, SMTP, audit retention,
WG defaults) lives in [`DEPLOYMENT.md`](DEPLOYMENT.md).

### Mock dev database

The dev compose stack runs Postgres only — backend + frontend
stay on the host so live-reload works:

```bash
docker compose -f docker/docker-compose.dev.yml up -d postgres
```

This brings up Postgres 16 on `localhost:5432` with the credentials
matching `.env.example`. Migrations:

```bash
make migrate-up
# Seed the first admin + (optionally) a default wg0 interface:
cd backend && go run ./cmd/seed
```

Reset the dev DB without losing the compose volume:

```bash
make migrate-down   # drops one step; loop with `cd backend && go run ./cmd/migrate down -all` for a full reset
```

For integration tests, **don't** point `testcontainers-go` at the
dev DB — the test harness spins up an ephemeral container per
suite so prod-shaped schema assertions don't trip over your dev
data.

---

## 💻 Codebase mechanics

The repo is a Go workspace with three modules
(`backend/`, `cli/`, `ebpf/`) plus the React app in `frontend/`.
Makefile targets bridge the per-language idioms.

### Backend hot-reload

```bash
make backend-dev          # equivalent to `cd backend && air`
```

Air watches `*.go`, rebuilds into `tmp/api`, and restarts on
change. `backend/.air.toml` excludes `tmp/`, `bin/`, `vendor/`,
`testdata/`.

If you don't want to install `air`, the explicit equivalent is:

```bash
cd backend && go run ./cmd/api
```

…but you'll need to Ctrl-C + re-run on every change.

### Frontend hot-reload

```bash
cd frontend && npm install   # first time only
npm run dev                  # Vite dev server on http://localhost:5173
```

Vite proxies API calls to `http://localhost:8080` by default
(see `frontend/vite.config.ts`). If you change the API port, set
`VITE_API_BASE` accordingly.

### Migrations

```bash
make migrate-up                          # apply outstanding
make migrate-down                        # roll back one step
cd backend && go run ./cmd/migrate create my_change   # new pair of files in migrations/
cd backend && go run ./cmd/migrate goto 7             # jump to a specific version
```

The migration runner is `golang-migrate` driven via
`backend/cmd/migrate`. Files live in `/migrations/`, paired as
`NNN_<slug>.up.sql` / `NNN_<slug>.down.sql`. Up migrations must
be idempotent under reapply (use `IF NOT EXISTS`, `ON CONFLICT
DO NOTHING`) so a partial failure doesn't tombstone the chain.

### eBPF regeneration

The `.o` and bpf2go `.go` files under `ebpf/userspace/` are
committed so downstream packages compile without `clang`.
Regenerate after touching anything under `ebpf/src/` or
`ebpf/headers/`:

```bash
make ebpf-gen
```

This shells out to `cd ebpf && go generate ./...`, which invokes
`bpf2go` for both `amd64` and `arm64`. Commit the updated `.o`
files alongside the C change.

### CLI

```bash
make cli-build      # produces cli/bin/nexushub
make cli-install    # installs to $GOBIN (or $GOPATH/bin)
./cli/bin/nexushub --help
```

---

## 🧪 Testing + linting

### Backend

```bash
make backend-test                # unit tests (fast, no Docker)
make backend-test-integration    # uses testcontainers-go → needs Docker daemon
make backend-lint                # golangci-lint on backend + ebpf
```

Tests follow Go's standard layout. Integration tests live behind
the `-tags=integration` build tag and the
`backend/internal/dbtest` harness; they spin up a fresh
Postgres 16 container per suite via `testcontainers-go` v0.42 +
the `postgres.Run` adapter.

### eBPF userspace

```bash
make ebpf-test
```

Map-level tests (`buildTestSpec`) need `CAP_BPF` + `rlimit
memlock` headroom. On hosts without those, the tests skip
gracefully rather than failing. Run as root or in a VM if you
need them.

### Frontend

```bash
make frontend-test         # vitest run (CI default)
make frontend-typecheck    # tsc --noEmit (strict mode)
make frontend-lint         # eslint
cd frontend && npm run test:watch   # vitest watch mode for TDD
```

The build pipeline `tsc -b && vite build` runs both typecheck and
bundle; `npm run build` is the integrated form.

### End-to-end (Playwright)

```bash
cd tests/e2e
npx playwright install      # first time — downloads browser binaries
npx playwright test
```

E2E expects the full stack up via
`docker compose -f docker/docker-compose.yml up -d` against a
clean DB.

### Aggregate targets

```bash
make test     # backend + ebpf + cli + frontend unit
make build    # backend + cli + frontend production artifacts
make lint     # backend + frontend
```

CI runs the same `make` targets (`.github/workflows/ci.yml`), so
green locally usually means green on PR.

---

## 📐 Contribution rules

The full set lives in [`CONTRIBUTING.md`](../CONTRIBUTING.md). Key
points:

### Branching

- **`main`** is production-only and locked. Direct pushes are
  rejected by branch protection. Merges from `dev` only when a
  release is ready.
- **`dev`** is the active branch. Every feature, fix, doc, or
  chore branch starts here and merges back here via PR.
- Branch naming prefix is enforced (`feature/`, `fix/`, `docs/`,
  `chore/`, `hotfix/`). Hotfixes alone branch off `main`.

```bash
git checkout dev && git pull
git checkout -b feature/short-description
# work, commit, push
git push -u origin feature/short-description
# open PR targeting dev
```

### Commit style — Conventional Commits

Commitlint enforces this on PRs. The first line is
`type(scope): summary` where:

- **type** ∈ `feat`, `fix`, `docs`, `chore`, `refactor`, `test`,
  `perf`, `ci`, `build`, `revert`
- **scope** ∈ `backend`, `frontend`, `ebpf`, `cli`, `docker`,
  `ci`, `docs`, `db`, `scripts`

Breaking change → `feat!:` or trailer
`BREAKING CHANGE: …`. Subject capped at ~72 chars; body explains
the _why_, not the _what_ (the diff says what).

### What lands in the body

- Why the change is needed (the bug, the constraint, the operator
  story)
- What you considered and rejected
- Operator-visible consequences (env vars, migrations, rebuilds,
  pinned-map wipes for eBPF changes)
- Test plan if non-obvious

The repo's `.github/pull_request_template.md` mirrors this.

### Code style

- **Go**: `gofmt` + `golangci-lint` (see `.golangci.yml`).
  Acronyms stay uppercase (`URL`, `ID`, `HTTP`). Errors wrapped
  with `fmt.Errorf("context: %w", err)`. `context.Context` as
  first parameter on anything that talks to the DB / kernel.
- **TypeScript**: strict mode. No `any`, no `@ts-ignore`. Props
  + return types explicit. Functional components only.
- **eBPF / C**: `snake_case`, `SEC()` macros for program type,
  every map lookup null-checked, every packet access
  bounds-verified against `data_end`. Loops must be statically
  bounded (the verifier rejects unbounded loops outright; use
  `bpf_loop` for runtime-bounded iteration).
- **SQL**: migrations are reversible (an `.up.sql` must have a
  semantically meaningful `.down.sql`, even if it's just a
  comment explaining why down-migrating is a no-op).

### What NOT to commit

- Secrets: `.env`, `*.pem`, anything containing `PEER_KEY_*` or
  `JWT_SECRET`. The repo's `.gitignore` blocks the common shapes
  but a vigilant grep over your diff is still worth it.
- Big binaries (>1 MiB) other than the bpf2go `.o` files under
  `ebpf/userspace/`. Use GitHub releases for artifact distribution.
- Generated content that the build system already produces from
  source (e.g. `frontend/dist/`, `backend/tmp/`).

### What CI runs on your PR

- `make test` — every unit suite
- `make lint` — golangci-lint + eslint
- Trivy + CodeQL + Gitleaks (`.github/workflows/security.yml`)
- Conventional Commits check via commitlint
- Build verification (compose stack starts, migration round-trip
  passes)

If any of those fail, fix locally before pushing again — don't
push "fixup" commits expecting CI to do the verification work.
