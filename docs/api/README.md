# API reference

Two ways to consume the API surface:

1. **Browse the rendered docs** — open
   [`index.html`](./index.html) in a browser. Pre-rendered from the
   spec via Redocly so it works without a server.

2. **Pull the raw spec** — the canonical OpenAPI 3.0 spec lives at
   [`backend/internal/openapi/openapi.yaml`](../../backend/internal/openapi/openapi.yaml).
   It's embedded in the API binary via `go:embed` and served at
   `GET /api/v1/openapi.yaml` on any running instance:

   ```sh
   curl http://localhost:8080/api/v1/openapi.yaml
   ```

   Use it to generate typed clients (`openapi-typescript-codegen`,
   `oapi-codegen`, etc.).

## Regenerating the rendered docs

The HTML in this directory is a build artefact, but it's checked in
so the docs work without a build step. Refresh after any change to
the OpenAPI spec:

```sh
make api-docs   # wraps `redocly build-docs` + `redocly lint`
```
