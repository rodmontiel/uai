# Universal Agent Identity — developer entrypoints
#
# Targets here reflect what actually exists. Targets for phases that are not
# implemented yet are deliberately absent rather than present-and-failing:
# see docs/protocol/19-roadmap.md for what is coming.
SHELL := /bin/bash
GO ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/go/bin/go)
COMPOSE ?= docker compose -f deploy/compose/docker-compose.yml
PG_DSN ?= postgres://uai:uai@localhost:5432/uai?sslmode=disable

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

## ---------- environment ----------
.PHONY: dev
dev: up migrate ## Bring up the local stack and apply the schema

.PHONY: up
up: ## Start infrastructure containers
	$(COMPOSE) up -d
	@echo "waiting for postgres..."
	@until $(COMPOSE) exec -T postgres pg_isready -U uai >/dev/null 2>&1; do sleep 1; done
	@echo "ready"

.PHONY: down
down: ## Stop containers, keeping volumes
	$(COMPOSE) down

.PHONY: nuke
nuke: ## Stop containers and delete volumes
	$(COMPOSE) down -v

## ---------- database ----------
.PHONY: migrate
migrate: ## Apply database migrations
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/migrations up

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/migrations -steps 1 down

## ---------- quality ----------
.PHONY: build
build: ## Build everything
	$(GO) build ./...

.PHONY: test
test: ## Run Go unit tests
	$(GO) test ./... -count=1

.PHONY: conformance
conformance: ## Run the normative vectors, schemas and API checks
	$(GO) run ./tools/uai-conformance

.PHONY: vectors
vectors: ## Regenerate the conformance vectors (maintainers only; must be a no-op)
	$(GO) run ./tools/uai-vectors

.PHONY: vectors-check
vectors-check: ## Fail if regenerating the vectors would change them
	@$(GO) run ./tools/uai-vectors >/dev/null
	@if ! git diff --quiet -- spec/test-vectors; then \
		echo "spec/test-vectors changed after regeneration:"; \
		git --no-pager diff --stat -- spec/test-vectors; \
		echo "A vector diff means the protocol changed. Commit it deliberately."; \
		exit 1; \
	fi
	@echo "vectors are reproducible"

.PHONY: invariants
invariants: ## Assert that the forbidden operations fail (INV-001..010)
	@psql "$(PG_DSN)" -v ON_ERROR_STOP=1 -f test/invariants/invariants.sql 2>&1 \
		| grep -E 'PASS|FAIL|ERROR' | sed -E 's/^psql:[^:]+:[0-9]+: NOTICE:  //'

.PHONY: lint
lint: ## Static analysis and formatting check
	$(GO) vet ./...
	@unformatted=$$(gofmt -l .); \
		test -z "$$unformatted" || { echo "unformatted files:"; echo "$$unformatted"; exit 1; }

.PHONY: fmt
fmt: ## Format Go sources
	$(GO) fmt ./...

.PHONY: check
check: build lint test conformance vectors-check ## Everything that must pass before a commit

## ---------- knowledge graph ----------
.PHONY: graph
graph: ## Update the graphify knowledge graph
	graphify update .
