# API reference

The canonical OpenAPI 3.1 spec lives at
[`backend/internal/openapi/openapi.yaml`](../../backend/internal/openapi/openapi.yaml).
It's embedded in the API binary via `go:embed` and served at
`GET /api/v1/openapi.yaml` on any running instance, so you can also grab
it with:

```bash
curl http://localhost:8080/api/v1/openapi.yaml
```

Regenerate typed clients from there (e.g. `openapi-typescript-codegen`,
`oapi-codegen`).
