import { test, expect } from '@playwright/test'

// Credentials must match what the seed step in .github/workflows/
// e2e-tests.yml feeds into cmd/seed. Local runs export the same
// values before invoking playwright; see playwright.config.ts header.
const ADMIN_EMAIL = process.env.NEXUSHUB_ADMIN_EMAIL || 'admin@example.com'
const ADMIN_PASSWORD = process.env.NEXUSHUB_ADMIN_PASSWORD || 'TestPass1234!'

test.describe('login', () => {
  test('rejects bad credentials', async ({ page }) => {
    await page.goto('/')
    await page.getByLabel(/email/i).fill(ADMIN_EMAIL)
    await page.getByLabel(/password/i).fill('wrong-password')
    await page.getByRole('button', { name: /sign in/i }).click()
    // App reveals the error inline rather than navigating — assert
    // the error surface appears and we're still on the login view.
    await expect(page.getByText(/invalid email or password/i)).toBeVisible()
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible()
  })

  test('accepts the seeded admin and lands on peers', async ({ page }) => {
    await page.goto('/')
    await page.getByLabel(/email/i).fill(ADMIN_EMAIL)
    await page.getByLabel(/password/i).fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: /sign in/i }).click()

    // After login the sidebar becomes visible. The Peers nav button
    // is the first entry and is the default page, so we assert it
    // appears with aria-current="page".
    const peersNav = page.getByRole('button', { name: /^peers$/i })
    await expect(peersNav).toBeVisible()
    await expect(peersNav).toHaveAttribute('aria-current', 'page')

    // The sign-out button in the sidebar footer is proof the auth
    // context populated successfully.
    await expect(page.getByRole('button', { name: /sign out/i })).toBeVisible()
  })
})
