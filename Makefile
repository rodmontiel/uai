# Universal Agent Identity — developer entrypoints
SHELL := /bin/bash
GO ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/go/bin/go)
COMPOSE ?= docker compose -f deploy/compose/docker-compose.yml
PG_DSN ?= postgres://uai:uai@localhost:5432/uai?sslmode=disable

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

## ---------- development ----------
.PHONY: dev
dev: up migrate seed ## Bring up the full local stack, migrated and seeded

.PHONY: up
up: ## Start infrastructure containers
	$(COMPOSE) up -d

.PHONY: down
down: ## Stop containers (keeps volumes)
	$(COMPOSE) down

.PHONY: nuke
nuke: ## Stop containers and delete volumes
	$(COMPOSE) down -v

## ---------- database ----------
.PHONY: migrate
migrate: ## Apply database migrations
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/migrations up

.PHONY: migrate-down
migrate-down: ## Roll back the last migration
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/migrations down 1

.PHONY: seed
seed: ## Load seed data derived from the GASC bundle
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/seed up

## ---------- quality ----------
.PHONY: build
build: ## Build all Go packages and services
	$(GO) build ./...

.PHONY: test
test: ## Run unit tests
	$(GO) test ./... -count=1

.PHONY: test-vectors
test-vectors: ## Verify the normative conformance vectors
	$(GO) test ./pkg/... -run TestVectors -count=1 -v

.PHONY: invariants
invariants: ## Run the INV-001..010 negative tests (blocking in CI)
	$(GO) test ./test/invariants/... -count=1 -v

.PHONY: lint
lint: ## Static analysis
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format Go sources
	$(GO) fmt ./...

## ---------- demo ----------
.PHONY: demo
demo: ## Run the ACME Robotics end-to-end scenario
	$(GO) run ./demo

## ---------- knowledge graph ----------
.PHONY: graph
graph: ## Rebuild the graphify knowledge graph
	graphify . --update

.PHONY: invariants-sql
invariants-sql: ## Run the SQL invariant assertions against a running database
	psql "$(PG_DSN)" -v ON_ERROR_STOP=1 -f test/invariants/invariants.sql
