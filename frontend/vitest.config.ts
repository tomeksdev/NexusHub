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
  },
})
