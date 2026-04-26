import { setupServer } from 'msw/node'

// Shared MSW server. Tests register per-case handlers via server.use();
// we don't define any defaults here so a forgotten handler fails loudly
// (see onUnhandledRequest: 'error' in setup.ts).
export const server = setupServer()
