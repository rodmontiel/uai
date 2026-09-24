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

## ---------- agent-side (SDKs and the MCP server) ----------
# These name ONE registered identity. There is no default agent id or key: an
# SDK that invented one would sign as an identity nobody registered, and the
# signature would be indistinguishable from a real one until someone went
# looking for the agent behind it.
UAI_ENDPOINT  ?= http://127.0.0.1:8080
UAI_AGENT_ID  ?=
UAI_AGENT_KEY ?= .keys/agent.jwk

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

## ---------- contracts ----------
FORGE ?= $(shell command -v forge 2>/dev/null || echo $(HOME)/.local/foundry/bin/forge)

.PHONY: contracts
contracts: ## Compile the contracts and export their ABIs to spec/contracts/
	@command -v $(FORGE) >/dev/null 2>&1 || { \
		echo "forge not found. Install Foundry, or skip: the committed ABIs in"; \
		echo "spec/contracts/ let `make check` verify INV-007/008 without it."; exit 1; }
	cd contracts && $(FORGE) build
	./contracts/export-abi.sh

.PHONY: contracts-test
contracts-test: ## Run the Solidity tests, including fuzzing
	cd contracts && $(FORGE) test

.PHONY: contracts-check
contracts-check: contracts ## Fail if recompiling would change a published ABI
	@if ! git diff --quiet -- spec/contracts; then \
		echo "spec/contracts changed after recompiling:"; \
		git --no-pager diff --stat -- spec/contracts; \
		echo "A contract's published surface changed. Commit it deliberately."; \
		exit 1; \
	fi
	@echo "contract ABIs are unchanged"

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

.PHONY: run-web
run-web: ## Serve the frontend on :8081, proxying /v1 to the gateway
	$(GO) run ./services/web -addr :8081 -root web -api http://127.0.0.1:8080

.PHONY: run-ledger-writer
run-ledger-writer: ## Drain the anchor queue once against a local EVM
	$(GO) run ./services/ledger-writer -dsn "$(PG_DSN)" -once \
		-rpc "$(UAI_CHAIN_RPC)" -from "$(UAI_CHAIN_FROM)" -anchor-contract "$(UAI_ANCHOR_CONTRACT)"

## ---------- the demo ----------
DEMO_PORT ?= 8088
DEMO_DSN  ?= postgres://uai:uai@localhost:55466/uai?sslmode=disable
DEMO_KEYS ?= .keys/demo

.PHONY: demo
demo: ## Run the ACME scenario end to end and check all 21 MVP criteria
	@$(MAKE) --no-print-directory demo-up
	@trap '$(MAKE) --no-print-directory demo-down' EXIT; \
		$(GO) build -o $(DEMO_KEYS)/uai-verify ./tools/uai-verify && \
		PG_DSN="$(DEMO_DSN)" UAI_VERIFY="$(PWD)/$(DEMO_KEYS)/uai-verify" \
			python3 demo/demo.py --endpoint http://127.0.0.1:$(DEMO_PORT) --dsn "$(DEMO_DSN)" \
				--keys $(DEMO_KEYS)

# A throwaway stack, torn down afterwards. The demo must not depend on state a
# previous run left behind: a scenario that only works the second time is a
# scenario nobody else can reproduce.
.PHONY: demo-up
demo-up:
	@$(CONTAINER) rm -f uai-pg-demo >/dev/null 2>&1 || true
	@$(CONTAINER) run -d --name uai-pg-demo -e POSTGRES_USER=uai -e POSTGRES_PASSWORD=uai \
		-e POSTGRES_DB=uai -p 127.0.0.1:55466:5432 $(PG_IMAGE) >/dev/null
	@for i in $$(seq 1 60); do \
		$(CONTAINER) exec uai-pg-demo psql -U uai -d uai -qtAc 'select 1' >/dev/null 2>&1 \
			&& break; sleep 1; done
	@for f in $$(ls db/migrations/*.up.sql db/seed/*.up.sql | sort); do \
		$(CONTAINER) exec -i uai-pg-demo psql -U uai -d uai -v ON_ERROR_STOP=1 -q < $$f || exit 1; \
	done
	@# Anything already on the port is a previous run that did not clean up. It
	@# is killed rather than worked around: a demo that silently talks to a
	@# stale gateway pointed at a deleted database reports whatever that
	@# gateway happens to say, which is the least reproducible failure there is.
	@stale=$$(ss -ltnp 2>/dev/null | grep ":$(DEMO_PORT) " | grep -oP 'pid=\K[0-9]+' | head -1); \
		if [ -n "$$stale" ]; then echo "stopping a previous demo gateway (pid $$stale)"; \
		kill $$stale 2>/dev/null || true; sleep 1; fi
	@if ss -ltn 2>/dev/null | grep -q ":$(DEMO_PORT) "; then \
		echo "port $(DEMO_PORT) is in use by something this target did not start."; \
		echo "Stop it, or run: make demo DEMO_PORT=<free port>"; exit 1; fi
	@mkdir -p $(DEMO_KEYS) && chmod 700 $(DEMO_KEYS)
	@test -f $(DEMO_KEYS)/issuer.jwk || \
		$(GO) run ./tools/uai-keygen -out $(DEMO_KEYS)/issuer.jwk -did "$(ISSUER_DID)" >/dev/null
	@PG_DSN="$(DEMO_DSN)" $(GO) run ./services/gateway -addr 127.0.0.1:$(DEMO_PORT) \
		-scheme http -issuer-key $(DEMO_KEYS)/issuer.jwk > $(DEMO_KEYS)/gateway.log 2>&1 & \
		echo $$! > $(DEMO_KEYS)/gateway.pid
	@for i in $$(seq 1 40); do \
		curl -sf http://127.0.0.1:$(DEMO_PORT)/v1/quarantines >/dev/null 2>&1 && break; sleep 1; done
	@curl -sf http://127.0.0.1:$(DEMO_PORT)/v1/quarantines >/dev/null 2>&1 || { \
		echo "the gateway did not come up:"; tail -5 $(DEMO_KEYS)/gateway.log; exit 1; }

.PHONY: demo-down
demo-down:
	@test -f $(DEMO_KEYS)/gateway.pid && kill $$(cat $(DEMO_KEYS)/gateway.pid) 2>/dev/null || true
	@rm -f $(DEMO_KEYS)/gateway.pid
	@$(CONTAINER) rm -f uai-pg-demo >/dev/null 2>&1 || true

## ---------- the pentest ----------
PENTEST_PORT ?= 8089
PENTEST_DSN  ?= postgres://uai:uai@localhost:55467/uai?sslmode=disable
PENTEST_KEYS ?= .keys/pentest

.PHONY: pentest
pentest: ## Attack a live gateway from outside and fail if anything succeeds
	@$(MAKE) --no-print-directory pentest-up
	@trap '$(MAKE) --no-print-directory pentest-down' EXIT; \
		PG_DSN="$(PENTEST_DSN)" python3 test/attacks/pentest.py \
			--endpoint http://127.0.0.1:$(PENTEST_PORT) --dsn "$(PENTEST_DSN)" \
			--keys $(PENTEST_KEYS)

# Its own stack, on its own port. Sharing the demo's would make the two
# interfere: the pentest registers agents and files requests the demo would then
# find already there, and a scenario whose result depends on what ran before it
# is not a scenario.
.PHONY: pentest-up
pentest-up:
	@$(CONTAINER) rm -f uai-pg-pentest >/dev/null 2>&1 || true
	@$(CONTAINER) run -d --name uai-pg-pentest -e POSTGRES_USER=uai -e POSTGRES_PASSWORD=uai \
		-e POSTGRES_DB=uai -p 127.0.0.1:55467:5432 $(PG_IMAGE) >/dev/null
	@for i in $$(seq 1 60); do \
		$(CONTAINER) exec uai-pg-pentest psql -U uai -d uai -qtAc 'select 1' >/dev/null 2>&1 \
			&& break; sleep 1; done
	@for f in $$(ls db/migrations/*.up.sql db/seed/*.up.sql | sort); do \
		$(CONTAINER) exec -i uai-pg-pentest psql -U uai -d uai -v ON_ERROR_STOP=1 -q < $$f || exit 1; \
	done
	@stale=$$(ss -ltnp 2>/dev/null | grep ":$(PENTEST_PORT) " | grep -oP 'pid=\K[0-9]+' | head -1); \
		if [ -n "$$stale" ]; then kill $$stale 2>/dev/null || true; sleep 1; fi
	@if ss -ltn 2>/dev/null | grep -q ":$(PENTEST_PORT) "; then \
		echo "port $(PENTEST_PORT) is in use by something this target did not start."; exit 1; fi
	@mkdir -p $(PENTEST_KEYS) && chmod 700 $(PENTEST_KEYS)
	@test -f $(PENTEST_KEYS)/issuer.jwk || \
		$(GO) run ./tools/uai-keygen -out $(PENTEST_KEYS)/issuer.jwk -did "$(ISSUER_DID)" >/dev/null
	@PG_DSN="$(PENTEST_DSN)" $(GO) run ./services/gateway -addr 127.0.0.1:$(PENTEST_PORT) \
		-scheme http -issuer-key $(PENTEST_KEYS)/issuer.jwk > $(PENTEST_KEYS)/gateway.log 2>&1 & \
		echo $$! > $(PENTEST_KEYS)/gateway.pid
	@for i in $$(seq 1 40); do \
		curl -sf http://127.0.0.1:$(PENTEST_PORT)/v1/quarantines >/dev/null 2>&1 && break; sleep 1; done
	@curl -sf http://127.0.0.1:$(PENTEST_PORT)/v1/quarantines >/dev/null 2>&1 || { \
		echo "the gateway did not come up:"; tail -5 $(PENTEST_KEYS)/gateway.log; exit 1; }

.PHONY: pentest-down
pentest-down:
	@test -f $(PENTEST_KEYS)/gateway.pid && kill $$(cat $(PENTEST_KEYS)/gateway.pid) 2>/dev/null || true
	@rm -f $(PENTEST_KEYS)/gateway.pid
	@$(CONTAINER) rm -f uai-pg-pentest >/dev/null 2>&1 || true

.PHONY: build
build: ## Build everything
	$(GO) build ./...

.PHONY: test
test: test-web test-sdk ## Run Go unit tests, the browser tests and the SDK tests
	$(GO) test ./... -count=1

.PHONY: test-web
test-web: ## Check the browser verification code against the committed vectors
	@command -v node >/dev/null 2>&1 || { \
		echo "node not found; skipping the browser verification tests"; exit 0; }
	node --test "test/web/**/*.test.mjs"

.PHONY: test-sdk
test-sdk: test-sdk-python test-sdk-ts ## Run the Python and TypeScript SDK tests

# Each SDK reimplements RFC 8785 and RFC 9421 in its own language (ADR-0004), so
# each one is held to the SAME committed vectors. That is what keeps three
# implementations from drifting into three subtly different protocols.
.PHONY: test-sdk-python
test-sdk-python: ## Check the Python SDK against the committed vectors
	@command -v python3 >/dev/null 2>&1 || { \
		echo "python3 not found; skipping the Python SDK tests"; exit 0; }
	@python3 -c 'import cryptography' 2>/dev/null || { \
		echo "python3 cryptography not installed; skipping the Python SDK tests"; exit 0; }
	cd sdk/python && python3 -m unittest discover -s tests -t . -q

.PHONY: test-sdk-ts
test-sdk-ts: ## Check the TypeScript SDK against the committed vectors
	@command -v node >/dev/null 2>&1 || { \
		echo "node not found; skipping the TypeScript SDK tests"; exit 0; }
	cd sdk/typescript && node --test "test/**/*.test.mjs"

.PHONY: run-mcp
run-mcp: ## Serve the 8 MCP tools over stdio as one agent identity
	$(GO) run ./mcp -endpoint "$(UAI_ENDPOINT)" -uai-id "$(UAI_AGENT_ID)" -key "$(UAI_AGENT_KEY)"

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
	@# A real query, not pg_isready: postgres restarts itself during first-time
	@# initialisation, so pg_isready can say yes to a server about to shut down.
	@for i in $$(seq 1 60); do \
		$(CONTAINER) exec uai-pg-test psql -U uai -d uai -qtAc 'select 1' >/dev/null 2>&1 \
			&& break; sleep 1; done
	@# Every migration, in order, discovered rather than listed: a hardcoded list
	@# means a new migration is silently untested the day it is added.
	@for f in $$(ls db/migrations/*.up.sql db/seed/*.up.sql | sort); do \
		$(CONTAINER) exec -i uai-pg-test psql -U uai -d uai -v ON_ERROR_STOP=1 -q < $$f || exit 1; \
	done
	@UAI_TEST_DSN="postgres://uai:uai@localhost:55433/uai?sslmode=disable" \
		$(GO) test ./internal/... -count=1 -race
	@# Through the runner, never through a pipe. `psql | grep` reports a
	@# failing invariant and exits 0, which is how this suite ran green for
	@# nine phases without ever having been enforced.
	@set -e; trap '$(CONTAINER) rm -f uai-pg-test >/dev/null 2>&1 || true' EXIT; \
		./test/invariants/run.sh $(CONTAINER) exec -i uai-pg-test psql -U uai -d uai

.PHONY: invariants
invariants: ## Assert that the forbidden operations fail (INV-001..010)
	@./test/invariants/run.sh psql "$(PG_DSN)"

.PHONY: invariant-coverage
invariant-coverage: ## Check that every invariant in §20.3 has a negative test, in two layers
	$(GO) test ./test/invariants/ -count=1 -v -run TestCoverageIsReported 2>&1 \
		| sed -n 's/^ *coverage_test.go:[0-9]*: //p'
	$(GO) test ./test/invariants/ -count=1

.PHONY: lint
lint: ## Static analysis and formatting check
	$(GO) vet ./...
	@unformatted=$$(gofmt -l .); \
		test -z "$$unformatted" || { echo "unformatted files:"; echo "$$unformatted"; exit 1; }

.PHONY: fmt
fmt: ## Format Go sources
	$(GO) fmt ./...

.PHONY: threats
threats: ## Check that every threat in §20.1 names evidence that exists
	$(GO) test ./test/threatmodel/ -count=1

.PHONY: check
check: build lint test conformance vectors-check policy-verify threats ## Everything that must pass before a commit

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
