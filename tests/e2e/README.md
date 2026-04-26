# End-to-end tests

Playwright tests that exercise the full stack — API, frontend,
Postgres, all running under Docker Compose. Use for change-risk
signals that unit + integration tests can't give you: the login
flow actually lands on the peers page, the SPA renders login
unauthenticated, etc.

## Running locally

```sh
# From the repo root:
cd docker
docker compose up -d --build --wait

# Seed a super_admin. The Playwright config defaults match these
# names; override via env if you want different credentials.
cd ../backend
DATABASE_URL='postgres://nexushub:nexushub@localhost:5432/nexushub?sslmode=disable' \
  NEXUSHUB_ADMIN_EMAIL=admin@example.com \
  NEXUSHUB_ADMIN_USERNAME=admin \
  NEXUSHUB_ADMIN_PASSWORD='TestPass1234!' \
  go run ./cmd/seed

# Run the tests.
cd ../tests/e2e
npm ci
npx playwright install --with-deps chromium
npx playwright test

# Or with the UI runner for local debugging:
npx playwright test --ui
```

## Running in CI

`.github/workflows/e2e-tests.yml` handles the whole flow: brings
up the stack, seeds, installs Playwright, runs tests, uploads the
report + compose logs as artefacts. Runs on PRs to `dev`, nightly
at 03:00 UTC, and on `workflow_dispatch`.

## Writing new tests

Tests live under `tests/`; one `.spec.ts` file per broad surface
(smoke / auth / peers / rules etc.). Keep tests hermetic — each
test must either not mutate shared state, or restore it on its
own (create + delete inside the same test).

Two patterns worth knowing:

- `page.getByLabel(/name/i)` / `page.getByRole('button', { name: /x/i })`
  for user-visible locators. These stay stable across UI tweaks
  that only affect class names.
- `request` fixture for API-only checks (no browser). Faster than
  `page.goto` when the assertion is about a response body.

Credentials come from env — never hardcode the seeded password,
because it's shared with the workflow via `env:` and rotating it
should be a one-place change.
