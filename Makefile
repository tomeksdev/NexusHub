# NexusHub development makefile. All commands expect to run from the
# repo root. The backend module pins Go 1.22 and the module cache has
# been known to auto-upgrade without an explicit toolchain pin, so we
# force GOTOOLCHAIN=local + GOFLAGS=-mod=mod for every Go invocation.
#
# Run `make help` for the full list.

SHELL := /bin/bash
GO_ENV := GOTOOLCHAIN=local GOFLAGS=-mod=mod

# ---- Help (default) -------------------------------------------------------

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "NexusHub dev targets:\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ---- Backend --------------------------------------------------------------

.PHONY: backend-build
backend-build: ## Build every backend command
	cd backend && $(GO_ENV) go build ./...

.PHONY: backend-test
backend-test: ## Run backend unit tests
	cd backend && $(GO_ENV) go test ./...

.PHONY: backend-test-integration
backend-test-integration: ## Run backend integration tests (needs Docker for testcontainers)
	cd backend && $(GO_ENV) go test -tags=integration ./...

.PHONY: backend-lint
backend-lint: ## Run golangci-lint on backend + ebpf Go sources
	cd backend && golangci-lint run ./...
	cd ebpf && golangci-lint run ./...

.PHONY: backend-dev
backend-dev: ## Run the API with live reload (requires `air`)
	cd backend && air

.PHONY: migrate-up
migrate-up: ## Apply all outstanding database migrations
	cd backend && $(GO_ENV) go run ./cmd/migrate up

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	cd backend && $(GO_ENV) go run ./cmd/migrate down 1

# ---- eBPF -----------------------------------------------------------------

.PHONY: ebpf-test
ebpf-test: ## Run ebpf userspace unit tests (map tests skip without kernel)
	cd ebpf && $(GO_ENV) go test ./...

.PHONY: ebpf-gen
ebpf-gen: ## Regenerate bpf2go artifacts from C sources (needs clang + kernel headers)
	cd ebpf && $(GO_ENV) go generate ./...

# ---- CLI ------------------------------------------------------------------

.PHONY: cli-build
cli-build: ## Build the `nexushub` CLI binary into cli/bin/
	cd cli && mkdir -p bin && $(GO_ENV) go build -o bin/nexushub .

.PHONY: cli-test
cli-test: ## Run CLI unit tests
	cd cli && $(GO_ENV) go test ./...

.PHONY: cli-install
cli-install: ## Install the CLI to $GOBIN (or $GOPATH/bin)
	cd cli && $(GO_ENV) go install .

# ---- Frontend -------------------------------------------------------------

.PHONY: frontend-install
frontend-install: ## Install frontend dependencies
	cd frontend && npm install

.PHONY: frontend-dev
frontend-dev: ## Start the Vite dev server
	cd frontend && npm run dev

.PHONY: frontend-build
frontend-build: ## Build the production frontend bundle
	cd frontend && npm run build

.PHONY: frontend-test
frontend-test: ## Run frontend unit tests
	cd frontend && npx vitest run

.PHONY: frontend-typecheck
frontend-typecheck: ## Typecheck the frontend (no emit)
	cd frontend && npx tsc --noEmit

.PHONY: frontend-lint
frontend-lint: ## Run eslint on frontend sources
	cd frontend && npx eslint 'src/**/*.tsx' 'src/**/*.ts'

# ---- Aggregate ------------------------------------------------------------

.PHONY: test
test: backend-test ebpf-test cli-test frontend-test ## Run every unit test suite

.PHONY: build
build: backend-build cli-build frontend-build ## Build every deployable artifact

.PHONY: lint
lint: backend-lint frontend-lint ## Lint everything
	cd frontend && npx tsc --noEmit

# ---- Docs -----------------------------------------------------------------

.PHONY: api-docs
api-docs: ## Lint OpenAPI + render docs/api/index.html via redocly
	redocly lint backend/internal/openapi/openapi.yaml
	redocly build-docs backend/internal/openapi/openapi.yaml -o docs/api/index.html

# ---- Docker ---------------------------------------------------------------

.PHONY: docker-up
docker-up: ## Start the full stack via docker compose
	docker compose -f docker/docker-compose.yml up --build

.PHONY: docker-dev
docker-dev: ## Start the dev stack (Postgres only)
	docker compose -f docker/docker-compose.dev.yml up

.PHONY: docker-down
docker-down: ## Stop any running compose stack
	docker compose -f docker/docker-compose.yml down
	docker compose -f docker/docker-compose.dev.yml down

# ---- Cleanup --------------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts
	cd backend && rm -rf bin/
	cd frontend && rm -rf dist/ node_modules/.vite/
