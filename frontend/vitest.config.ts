import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Vitest config is deliberately separate from vite.config.ts: the dev server
// config pulls in the tailwind plugin, which reads CSS at bundle-time and
// adds nothing useful to unit tests. Keeping them split also means test
// runs don't need the /api proxy at all — MSW intercepts fetch directly.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.{ts,tsx}'],
      // Exclude boilerplate that tests shouldn't be measured against:
      // entry shim, i18n bootstrap (no branches), and locale JSON
      // dictionaries (not code).
      exclude: [
        'src/main.tsx',
        'src/vite-env.d.ts',
        'src/test/**',
        'src/lib/i18n.ts',
        'src/lib/locales/**',
      ],
    },
  },
})
