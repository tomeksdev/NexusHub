// Package openapi embeds the hand-written OpenAPI 3.1 spec so a running
// instance can serve it at /api/v1/openapi.yaml. Keeping the spec inside
// the binary (rather than loading from disk) means `go run` works with
// no filesystem layout assumptions and Docker images don't need the
// docs/ tree copied into them.
//
// The canonical source file lives at docs/api/openapi.yaml in the repo
// root; `go generate ./...` from the backend directory copies it in. We
// commit the copy too so builds don't require the generator to be run
// first.
package openapi

import _ "embed"

//go:embed openapi.yaml
var Spec []byte

// SpecContentType is the media type we serve Spec with. application/yaml
// is the IANA-registered type for OpenAPI YAML; some tools sniff the
// `.yaml` suffix instead but the header is the right thing to set.
const SpecContentType = "application/yaml"
