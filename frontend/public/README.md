# `frontend/public/`

Static assets served at the site root by Vite. Anything here ships
verbatim — no bundling, no rewriting — so paths in the app reference
e.g. `/logo.png`, not `import logoUrl from "..."`.

## Files

- `logo.png` — sidebar + login + favicon brand mark. **Should be
  icon-only** (no embedded text). The wordmark "NexusHub" lives in
  the UI as real text next to it. Replace with a clean icon-only PNG
  (~64–128 px square, transparent background, dark-theme readable)
  before tagging a release. The current upload has small embedded
  text that hurts readability when scaled to sidebar size.
- `favicon.svg` — legacy SVG favicon. The site uses `logo.png` as the
  favicon today; this file is kept for the case where an operator
  rebrands and wants a vector source.
- `icons.svg` — SVG sprite sheet (currently unused; kept for the
  same reason as favicon.svg).
