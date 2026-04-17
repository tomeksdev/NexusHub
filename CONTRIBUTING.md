# Contributing to NexusHub

Thanks for your interest in contributing! This document describes the branching model, commit conventions, and local workflow.

## Branching strategy

NexusHub uses a two-branch trunk model: **`main`** and **`dev`**.

- **`main`** is production-only and locked. It only receives merges from `dev` (or `hotfix/*`) when a release is fully tested and release-ready. **Never push or commit directly to `main`.**
- **`dev`** is the active development branch. All feature, fix, docs, and chore branches are created from `dev` and merged back to `dev` via pull request. **Never push directly to `dev`.**

### Feature branch naming

Create branches off `dev` using one of these prefixes:

| Prefix       | Purpose                                  |
| ------------ | ---------------------------------------- |
| `feature/`   | New features                             |
| `fix/`       | Bug fixes                                |
| `docs/`      | Documentation-only changes               |
| `chore/`     | Tooling, deps, CI, refactors (no features) |
| `hotfix/`    | Urgent production fix (branches off `main`) |

Examples: `feature/peer-import`, `fix/ebpf-map-leak`, `docs/api-auth`, `chore/bump-go-1.23`.

### Typical workflow

```bash
git checkout dev
git pull
git checkout -b feature/<short-description>
# ... work, commit ...
git push -u origin feature/<short-description>
# open PR targeting dev
```

## Commit messages — Conventional Commits

We use [Conventional Commits](https://www.conventionalcommits.org/) with a restricted set of scopes. Commitlint enforces this on PRs.

Format:

```
<type>(<scope>): <subject>

[optional body]

[optional footer(s)]
```

**Types**: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `perf`, `ci`, `build`, `style`, `revert`.

**Scopes** (must be one of): `backend`, `frontend`, `ebpf`, `cli`, `docker`, `ci`, `docs`, `db`, `scripts`.

Examples:

```
feat(backend): add peer rotation endpoint
fix(ebpf): prevent map leak on detach
chore(ci): bump golangci-lint to v1.60
docs(user-guide): document eBPF rule syntax
```

Breaking changes use `!` after the scope and a `BREAKING CHANGE:` footer:

```
feat(backend)!: replace JWT with PASETO

BREAKING CHANGE: existing JWT tokens are invalidated; clients must re-authenticate.
```

## Pull request process

1. Push your branch and open a PR targeting `dev`.
2. Ensure all required CI checks pass (ci, security).
3. At least **one** approving review is required before merge.
4. Use **Squash & merge** to keep `dev` history linear. The squash commit message must follow Conventional Commits.
5. Delete the branch after merge.

Releases are cut by merging `dev` into `main` via PR. The `release-please` workflow then generates a Release PR on `main` from Conventional Commit history.

## Running things locally

### Backend

```bash
cd backend
go mod tidy
go test ./...
go build ./cmd/api
```

### Frontend

```bash
cd frontend
npm install
npm run dev          # dev server
npm run build        # production build
npx vitest run       # unit tests
npx playwright test  # e2e (from tests/e2e/)
```

### Full stack (Docker)

```bash
cp .env.example .env
docker compose -f docker/docker-compose.dev.yml up --build
```

### Linting & formatting

- Go: `golangci-lint run` (config: `.golangci.yml`)
- TS/JS: `npx eslint .` and `npx prettier --check .`

## Security

Please do **not** file security issues on the public tracker. See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Code of conduct

Be kind, be constructive, assume good intent. Harassment of any kind is not tolerated.
