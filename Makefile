# Universal Agent Identity — developer entrypoints
#
# Targets here reflect what actually exists. Targets for phases that are not
# implemented yet are deliberately absent rather than present-and-failing:
# see docs/protocol/19-roadmap.md for what is coming.
SHELL := /bin/bash
GO ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/go/bin/go)
PG_DSN ?= postgres://uai:uai@localhost:5432/uai?sslmode=disable
# The credential issuer key. It is never generated at boot: a key that changes on
# restart issues credentials that stop verifying, and the operator would find out
# from verification failures rather than from a startup error.
ISSUER_KEY ?= .keys/issuer.jwk
ISSUER_DID ?= did:web:credentials.uai.world
# The signed policy bundle. Editing a rule or a threshold without re-signing
# makes `make policy-verify` fail, which is the point: policy cannot be changed
# by whoever can write to the repository.
POLICY_BUNDLE    ?= policy/gasc-2027.4
POLICY_AUTHORITY ?= policy/authority.json

## ---------- container runtime ----------
# Rootless Podman is the reference runtime: docs/adr/0001-podman-rootless-runtime.md.
# Docker remains supported on every target — `make CONTAINER=docker <target>` —
# because a protocol that only runs on one vendor's runtime is not portable, and
# portability is exactly what we are asking other implementers to give us.
CONTAINER    ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)
COMPOSE_FILE := deploy/compose/compose.yaml
# Provider preference:
#   podman-compose  drives podman directly — no socket, no daemon, nothing to enable
#   podman compose  delegates to the Compose binary over the rootless podman socket
#   docker compose  the Docker path
COMPOSE ?= $(shell \
	if [ "$(CONTAINER)" != podman ]; then echo "docker compose"; \
	elif command -v podman-compose >/dev/null 2>&1; then echo podman-compose; \
	else echo "podman compose"; fi) -f $(COMPOSE_FILE)
# The throwaway integration database must be the same build as the dev stack:
# asserting the invariants against a different PostgreSQL than developers run is
# how a version-specific trigger behaviour ships green and breaks on a laptop.
PG_IMAGE := $(shell sed -n 's/.*image: \(docker.io\/library\/postgres.*\)/\1/p' $(COMPOSE_FILE))
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE    ?= localhost/uai-gateway:$(VERSION)
# podman can build byte-reproducible images by fixing every timestamp; docker
# has no equivalent flag, so it is added only where it exists rather than
# breaking the other path.
REPRO    := $(shell [ "$(CONTAINER)" = podman ] && echo --timestamp=0)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

## ---------- environment ----------
.PHONY: dev
dev: up migrate seed ## Bring up the local stack, apply the schema and seed it

.PHONY: runtime
runtime: ## Show the detected container runtime and compose provider
	@echo "runtime : $(CONTAINER)  ($$($(CONTAINER) --version 2>/dev/null))"
	@echo "compose : $(COMPOSE)"
	@echo "image   : $(IMAGE)"
	@echo "postgres: $(PG_IMAGE)"
	@if [ "$(CONTAINER)" = podman ]; then \
		echo "rootless: $$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)"; fi

.PHONY: up
up: ## Start infrastructure containers
	@# Only the delegating provider needs the socket; podman-compose does not.
	@case "$(COMPOSE)" in "podman compose"*) \
		systemctl --user start podman.socket 2>/dev/null \
		|| echo "warn: podman.socket unavailable — install podman-compose for a socket-free path";; \
	esac
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

.PHONY: seed
seed: ## Load development bootstrap data (jurisdictions)
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/seed up

.PHONY: migrate-down
migrate-down: ## Roll back the most recent migration
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/migrations -steps 1 down

## ---------- quality ----------
.PHONY: issuer-key
issuer-key: ## Create the credential issuer signing key (once per deployment)
	@test ! -f $(ISSUER_KEY) || { echo "$(ISSUER_KEY) already exists; replacing it would"; \
		echo "invalidate every credential issued under it. Delete it deliberately first."; exit 1; }
	$(GO) run ./tools/uai-keygen -out $(ISSUER_KEY) -did "$(ISSUER_DID)"

.PHONY: policy-verify
policy-verify: ## Verify the committed GASC bundle against the published authority set
	$(GO) run ./tools/uai-policy verify -bundle $(POLICY_BUNDLE) -authority $(POLICY_AUTHORITY)

.PHONY: policy-sign
policy-sign: ## Re-sign the bundle (requires the governance keys; see docs/protocol/08-guardrail.md)
	$(GO) run ./tools/uai-policy sign -bundle $(POLICY_BUNDLE) \
		-keys .keys/gasc-1.jwk,.keys/gasc-2.jwk,.keys/gasc-3.jwk -threshold 3-of-5

.PHONY: run-gateway
run-gateway: $(ISSUER_KEY) ## Run the API gateway against the local stack
	$(GO) run ./services/gateway -dsn "$(PG_DSN)" -addr :8080 -scheme http \
		-issuer-key $(ISSUER_KEY) -issuer-did "$(ISSUER_DID)"

$(ISSUER_KEY):
	@$(MAKE) --no-print-directory issuer-key

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

.PHONY: integration
integration: ## Run store integration tests against a throwaway PostgreSQL
	@$(CONTAINER) rm -f uai-pg-test >/dev/null 2>&1 || true
	@$(CONTAINER) run -d --name uai-pg-test -e POSTGRES_USER=uai -e POSTGRES_PASSWORD=uai \
		-e POSTGRES_DB=uai -p 127.0.0.1:55433:5432 $(PG_IMAGE) >/dev/null
	@for i in $$(seq 1 40); do \
		$(CONTAINER) exec uai-pg-test pg_isready -U uai >/dev/null 2>&1 && break; sleep 1; done
	@# Every migration, in order, discovered rather than listed: a hardcoded list
	@# means a new migration is silently untested the day it is added.
	@for f in $$(ls db/migrations/*.up.sql db/seed/*.up.sql | sort); do \
		$(CONTAINER) exec -i uai-pg-test psql -U uai -d uai -v ON_ERROR_STOP=1 -q < $$f || exit 1; \
	done
	@UAI_TEST_DSN="postgres://uai:uai@localhost:55433/uai?sslmode=disable" \
		$(GO) test ./internal/store/... ./internal/api/... -count=1 -race
	@$(CONTAINER) exec -i uai-pg-test psql -U uai -d uai -v ON_ERROR_STOP=1 -q -f - < test/invariants/invariants.sql 2>&1 \
		| grep -E 'PASS|FAIL|ERROR' | sed -E 's/^psql:[^:]+:[0-9]+: NOTICE:  //'
	@$(CONTAINER) rm -f uai-pg-test >/dev/null

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
check: build lint test conformance vectors-check policy-verify ## Everything that must pass before a commit

## ---------- container images ----------
.PHONY: image
image: ## Build the gateway image (rootless, scratch-based, reproducible)
	$(CONTAINER) build $(REPRO) \
		--file deploy/containers/Containerfile.gateway \
		--build-arg VERSION=$(VERSION) \
		--tag $(IMAGE) .
	@$(CONTAINER) image inspect $(IMAGE) --format \
		'built $(IMAGE){{"\n"}}  size {{.Size}} bytes{{"\n"}}  user {{.Config.User}}'

## ---------- knowledge graph ----------
.PHONY: graph
graph: ## Update the graphify knowledge graph
	graphify update .
