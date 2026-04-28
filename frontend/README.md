# NexusHub frontend

React 19 + TypeScript + Vite + Tailwind 4. TanStack Query for server
state. Talks to the Go backend at `/api/v1/*`.

## Dev

```bash
npm install
npm run dev          # starts Vite on :5173
```

The dev server proxies `/api` → `http://localhost:8080` (see
`vite.config.ts`), so start the backend separately:

```bash
cd ../backend && go run ./cmd/api
```

## Build

```bash
npm run build
```

## Structure

- `src/lib/api.ts` — fetch wrapper with automatic access-token refresh
- `src/lib/auth.tsx` — React context holding auth state
- `src/pages/` — one file per screen
- `src/App.tsx` — authenticated shell (sidebar + page switcher)
