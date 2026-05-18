# `frontend/public/`

Static assets served at the site root by Vite. Anything here ships
verbatim — no bundling, no rewriting — so paths in the app reference
e.g. `/logo.png`, not `import logoUrl from "..."`.

## Files

- `logo.png` — the official NexusHub mark, 512×512, including the
  hexagon icon AND the "NexusHub" wordmark beneath it. The sidebar
  - login screen render only the icon portion via SVG-viewBox
    cropping in `src/components/Logo.tsx`. The favicon uses the full
    image (a tab-bar icon shows both the mark and the wordmark — that
    works fine at favicon sizes).
- `favicon.svg`, `icons.svg` — leftovers from the Vite scaffolding.
  Not referenced anywhere in the running app; deleting them is
  fine.

## Rebranding

Two paths:

1. **Drop-in replacement** — overwrite `logo.png` with a different
   512×512 image. If the icon position differs, adjust `CROP_*`
   constants in `src/components/Logo.tsx`.
2. **New shape entirely** — edit `src/components/Logo.tsx` to
   render an inline SVG. The sidebar + login both consume the
   same component, so one file rebrands both.
