# `frontend/public/`

Static assets served at the site root by Vite. Anything here ships
verbatim — no bundling, no rewriting — so paths in the app reference
e.g. `/logo.svg`, not `import logoUrl from "..."`.

## Files

- `logo.svg` — favicon. Mirrors the inline `<Logo>` component in
  `src/components/Logo.tsx`. The two are kept in sync by hand;
  rebrands edit both.
- `logo.png` — legacy raster logo from earlier rounds. Unused by
  the running app since round 5 (the inline SVG component
  replaces it). Kept on disk in case an operator wants to drop in
  a custom raster mark and reference it from a fork. Safe to
  delete.
- `favicon.svg`, `icons.svg` — leftovers from the Vite scaffolding.
  Not referenced anywhere in the running app; deleting them is
  fine.

## Rebranding

Two files change for a custom mark:

1. `src/components/Logo.tsx` — the React component used in the
   sidebar + login screen.
2. `frontend/public/logo.svg` — the favicon.

There's no longer a "drop a PNG here" path because that's what
got us into the embedded-text mess in the first place.
