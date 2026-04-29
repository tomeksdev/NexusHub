import { test, expect } from '@playwright/test'

// Smoke tests exercise the no-auth surface: health probe + an
// unauthenticated page render. Together they confirm the compose
// stack is reachable before any auth-bearing test runs.

test('health endpoint returns ok', async ({ request }) => {
  const res = await request.get('/api/v1/health')
  expect(res.ok()).toBeTruthy()
  const body = await res.json()
  expect(body.status).toBe('ok')
})

test('OpenAPI spec is served publicly', async ({ request }) => {
  // /api/v1/openapi.yaml is deliberately public so client generators
  // work without a token. A regression here breaks codegen silently.
  const res = await request.get('/api/v1/openapi.yaml')
  expect(res.ok()).toBeTruthy()
  const body = await res.text()
  expect(body).toContain('openapi:')
})

test('unauthenticated root renders the login screen', async ({ page }) => {
  // The SPA shows LoginPage when there's no session. We don't
  // navigate anywhere afterwards — just confirm the first paint
  // exposes an email input + submit button so a screen-reader or
  // keyboard user lands somewhere useful.
  await page.goto('/')
  await expect(page.getByLabel(/email/i)).toBeVisible()
  await expect(page.getByLabel(/password/i)).toBeVisible()
  await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible()
})
