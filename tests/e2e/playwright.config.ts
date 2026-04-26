import { defineConfig, devices } from '@playwright/test'

// Playwright projects against the production compose stack. The stack
// is brought up externally (docker compose up --wait in CI; manually
// during local runs); this config does NOT start it, because Playwright's
// webServer option doesn't do multi-container orchestration cleanly.
//
// Local usage:
//   cd docker && docker compose up -d --build --wait
//   cd tests/e2e && npm ci && npx playwright install --with-deps
//   DATABASE_URL='postgres://nexushub:nexushub@localhost:5432/nexushub?sslmode=disable' \
//     NEXUSHUB_ADMIN_EMAIL=admin@example.com \
//     NEXUSHUB_ADMIN_USERNAME=admin \
//     NEXUSHUB_ADMIN_PASSWORD=TestPass1234! \
//     go run ../../backend/cmd/seed
//   npx playwright test

const BASE_URL = process.env.NEXUSHUB_BASE_URL || 'http://localhost:8080'

export default defineConfig({
  testDir: './tests',
  // One worker in CI so tests that mutate the shared DB don't race.
  // Local runs can parallelise via --workers= on the CLI.
  fullyParallel: false,
  workers: process.env.CI ? 1 : undefined,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI
    ? [['html', { open: 'never' }], ['list']]
    : [['list']],
  use: {
    baseURL: BASE_URL,
    // Trace on the first retry so a flaky test surfaces a trace
    // viewer payload without recording on every green run.
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    // One browser pinned in CI — Chromium has the best coverage of
    // web platform features we use (SSE, Clipboard API, QR rendering).
    // Expanding to firefox/webkit is additive.
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
})
