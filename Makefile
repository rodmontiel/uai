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
# The SPIRE agent runs on the host and must be the SAME build as the server in
# the stack. Read from the compose file rather than pinned twice: two pins drift,
# and a workload attestor one minor version from its server fails in ways that
# look like the workload's fault.
SPIRE_SERVER_IMAGE := $(shell sed -n 's|.*image: \(ghcr.io/spiffe/spire-server.*\)|\1|p' $(COMPOSE_FILE))
# Pinned here by its own digest rather than derived from the server's: they are
# different images with different digests, and deriving one from the other would
# silently degrade to a floating tag -- an unreviewed dependency update run at
# every setup, which is the compose file's stated rule and threat T-07.
# `make spire-version-check` fails if the two versions drift apart.
SPIRE_AGENT_IMAGE  ?= ghcr.io/spiffe/spire-agent:1.11.2@sha256:7561ee91bfe07812f335d5b9e564bbb2ab77ef601558898a23177f692db15fc1
SPIRE_TRUST_DOMAIN ?= uai.test
SPIRE_PORT         ?= 18081
SPIRE_DIR          ?= .spire
# The compose provider names containers <project>_<service>_<n>; podman-compose
# and docker compose agree on it for this project.
SPIRE_CONTAINER    ?= uai_spire-server_1
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
dev: up migrate seed spire-up ## Bring up the local stack, apply the schema, seed it and attest it
	@echo
	@echo "The stack is up and SPIRE is attesting. To run the gateway against it:"
	@echo "  make run-gateway UAI_SPIRE_BUNDLE=$(SPIRE_DIR)/bootstrap.pem \\"
	@echo "                   UAI_SPIRE_TRUST_DOMAIN=$(SPIRE_TRUST_DOMAIN)"
	@echo "Without those, bindings record self-declared runtimes (see 6.8)."

.PHONY: runtime
runtime: ## Show the detected container runtime and compose provider
	@echo "runtime : $(CONTAINER)  ($$($(CONTAINER) --version 2>/dev/null))"
	@echo "compose : $(COMPOSE)"
	@echo "image   : $(IMAGE)"
	@echo "postgres: $(PG_IMAGE)"
	@if [ "$(CONTAINER)" = podman ]; then \
		echo "rootless: $$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)"; fi

# Named explicitly rather than "everything in the file". The compose stack also
# carries uai-gateway and uai-web, and those are the deployment path
# (`./deploy.sh up`), not the development one: `make up` exists so a developer
# can run the gateway from source with `make run-gateway` against real
# infrastructure. Starting them here would fail on an image nobody built, and
# would quietly shadow the source the developer is editing.
INFRA_SERVICES ?= postgres spire-server

.PHONY: up
up: ## Start infrastructure containers (postgres, SPIRE server)
	@# Only the delegating provider needs the socket; podman-compose does not.
	@case "$(COMPOSE)" in "podman compose"*) \
		systemctl --user start podman.socket 2>/dev/null \
		|| echo "warn: podman.socket unavailable — install podman-compose for a socket-free path";; \
	esac
	$(COMPOSE) up -d $(INFRA_SERVICES)
	@echo "waiting for postgres..."
	@until $(COMPOSE) exec -T postgres pg_isready -U uai >/dev/null 2>&1; do sleep 1; done
	@echo "ready"

.PHONY: down
down: spire-down ## Stop containers and the host SPIRE agent, keeping volumes
	$(COMPOSE) down

.PHONY: nuke
nuke: spire-down ## Stop containers and delete volumes
	$(COMPOSE) down -v
	@# The agent's state goes with the server's. An agent holding an SVID from
	@# a CA that no longer exists reports failures that look like the workload's
	@# fault.
	@rm -rf $(SPIRE_DIR)/data $(SPIRE_DIR)/public $(SPIRE_DIR)/svid \
		$(SPIRE_DIR)/bootstrap.pem $(SPIRE_DIR)/agent.log

## ---------- database ----------
.PHONY: migrate
migrate: ## Apply database migrations
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/migrations up

.PHONY: seed
seed: ## Load development bootstrap data (jurisdictions)
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/seed up

.PHONY: migrate-baseline
migrate-baseline: ## Record every migration as applied, for a database that predates the ledger
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/migrations baseline
	$(GO) run ./tools/uai-migrate -dsn "$(PG_DSN)" -dir db/seed baseline

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

## ---------- runtime attestation (SPIRE) ----------
# §9.1 says the registry must "verify SVID chain + verify SVID subject matches
# uai_id". These targets are what makes that possible locally: before them a
# binding recorded a runtime the agent described about itself.

.PHONY: spire-up
spire-up: spire-version-check ## Start the SPIRE agent on the host and bootstrap it against the server
	@$(COMPOSE) up -d spire-server
	@echo "waiting for the SPIRE server..."
	@for i in $$(seq 1 60); do \
		$(COMPOSE) exec -T spire-server /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1 \
			&& break; sleep 1; done
	@mkdir -p $(SPIRE_DIR)/bin $(SPIRE_DIR)/data $(SPIRE_DIR)/public $(SPIRE_DIR)/svid
	@# From the pinned image, not from a download. The agent decides which
	@# process may hold which identity; fetching that binary over the network at
	@# setup time would be the supply-chain hole this exists to close (T-07).
	@test -x $(SPIRE_DIR)/bin/spire-agent || { \
		echo "extracting spire-agent from $(SPIRE_AGENT_IMAGE)"; \
		cid=$$($(CONTAINER) create $(SPIRE_AGENT_IMAGE)) && \
		$(CONTAINER) cp "$$cid:/opt/spire/bin/spire-agent" $(SPIRE_DIR)/bin/spire-agent && \
		$(CONTAINER) rm "$$cid" >/dev/null && chmod +x $(SPIRE_DIR)/bin/spire-agent; }
	@# The CA bundle, out of band. Bootstrapping over an unauthenticated channel
	@# would make the first connection the one worth attacking.
	@$(COMPOSE) exec -T spire-server /opt/spire/bin/spire-server bundle show > $(SPIRE_DIR)/bootstrap.pem
	@test -s $(SPIRE_DIR)/bootstrap.pem || { echo "the SPIRE server returned no bundle"; exit 1; }
	@# Guard and start in ONE shell. Make runs each recipe line in its own, so
	@# an `exit 0` on the line above only ends that line -- the first version of
	@# this printed "already running" and then started a second agent beside the
	@# first, both answering the same socket.
	@# The pidfile, not pgrep. `pgrep -f 'spire-agent run'` matches the shell
	@# running the pgrep, because that string is in its own command line -- so
	@# the guard always fired, and a pkill written the same way killed the
	@# caller.
	@if [ -f $(SPIRE_DIR)/agent.pid ] && kill -0 $$(cat $(SPIRE_DIR)/agent.pid) 2>/dev/null; then \
		echo "the SPIRE agent is already running"; \
	else \
		token=$$($(COMPOSE) exec -T spire-server /opt/spire/bin/spire-server token generate \
			-spiffeID spiffe://$(SPIRE_TRUST_DOMAIN)/node/dev 2>/dev/null | sed 's/^Token: //'); \
		test -n "$$token" || { echo "no join token"; exit 1; }; \
		$(SPIRE_DIR)/bin/spire-agent run -config deploy/spire/conf/agent.conf \
			-joinToken "$$token" > $(SPIRE_DIR)/agent.log 2>&1 & \
		echo $$! > $(SPIRE_DIR)/agent.pid; \
	fi
	@for i in $$(seq 1 40); do test -S $(SPIRE_DIR)/public/api.sock && break; sleep 1; done
	@test -S $(SPIRE_DIR)/public/api.sock || { \
		echo "the SPIRE agent did not come up:"; tail -5 $(SPIRE_DIR)/agent.log; exit 1; }
	@echo "SPIRE agent attested as $$(grep -o 'spiffe://$(SPIRE_TRUST_DOMAIN)/spire/agent/[^\"]*' \
		$(SPIRE_DIR)/agent.log | head -1)"

.PHONY: spire-version-check
spire-version-check: ## Fail if the host agent and the stack's server are different versions
	@server=$$(echo "$(SPIRE_SERVER_IMAGE)" | sed 's/.*spire-server:\([^@]*\).*/\1/'); \
		agent=$$(echo "$(SPIRE_AGENT_IMAGE)" | sed 's/.*spire-agent:\([^@]*\).*/\1/'); \
		if [ "$$server" != "$$agent" ]; then \
			echo "SPIRE server is $$server and the host agent is $$agent."; \
			echo "A workload attestor a version away from its server fails in ways"; \
			echo "that look like the workload's fault. Pin both to the same release."; \
			exit 1; \
		fi; \
		echo "SPIRE server and agent are both $$server"

.PHONY: spire-down
spire-down: ## Stop the host SPIRE agent (the server stays with the stack)
	@test -f $(SPIRE_DIR)/agent.pid && kill $$(cat $(SPIRE_DIR)/agent.pid) 2>/dev/null || true
	@rm -f $(SPIRE_DIR)/agent.pid

.PHONY: spire-entry
spire-entry: ## Register a workload entry: make spire-entry ULID=01JY… [INSTANCE=dev]
	@test -n "$(ULID)" || { echo "usage: make spire-entry ULID=<26-char agent ULID>"; exit 1; }
	@parent=$$(grep -o 'spiffe://$(SPIRE_TRUST_DOMAIN)/spire/agent/join_token/[a-f0-9-]*' \
		$(SPIRE_DIR)/agent.log | head -1); \
		test -n "$$parent" || { echo "no attested agent; run make spire-up"; exit 1; }; \
		$(COMPOSE) exec -T spire-server /opt/spire/bin/spire-server entry create \
			-parentID "$$parent" \
			-spiffeID "spiffe://$(SPIRE_TRUST_DOMAIN)/agents/$(ULID)/i/$(or $(INSTANCE),dev)" \
			-selector "unix:uid:$$(id -u)" -x509SVIDTTL 3600

.PHONY: spire-svid
spire-svid: ## Fetch this process's SVID through the Workload API into .spire/svid/
	@$(SPIRE_DIR)/bin/spire-agent api fetch x509 \
		-socketPath $(SPIRE_DIR)/public/api.sock -write $(SPIRE_DIR)/svid

## ---------- runtime attestation, end to end ----------
ATT_PORT ?= 8090
ATT_DSN  ?= postgres://uai:uai@localhost:55468/uai?sslmode=disable
ATT_KEYS ?= $(SPIRE_DIR)/gateway

.PHONY: attested
attested: ## Prove a binding records a runtime SPIRE attested, and what that is worth
	@$(MAKE) --no-print-directory spire-up
	@$(MAKE) --no-print-directory attested-up
	@trap '$(MAKE) --no-print-directory attested-down' EXIT; \
		PG_DSN="$(ATT_DSN)" python3 demo/attested.py \
			--endpoint https://localhost:$(ATT_PORT) --dsn "$(ATT_DSN)" \
			--spire-dir $(SPIRE_DIR) --spire-container $(SPIRE_CONTAINER) \
			--container $(CONTAINER) --trust-domain $(SPIRE_TRUST_DOMAIN)

.PHONY: attested-up
attested-up:
	@$(CONTAINER) rm -f uai-pg-attested >/dev/null 2>&1 || true
	@$(CONTAINER) run -d --name uai-pg-attested -e POSTGRES_USER=uai -e POSTGRES_PASSWORD=uai \
		-e POSTGRES_DB=uai -p 127.0.0.1:55468:5432 $(PG_IMAGE) >/dev/null
	@for i in $$(seq 1 60); do \
		$(CONTAINER) exec uai-pg-attested psql -U uai -d uai -qtAc 'select 1' >/dev/null 2>&1 \
			&& break; sleep 1; done
	@for f in $$(ls db/migrations/*.up.sql db/seed/*.up.sql | sort); do \
		$(CONTAINER) exec -i uai-pg-attested psql -U uai -d uai -v ON_ERROR_STOP=1 -q < $$f || exit 1; \
	done
	@mkdir -p $(ATT_KEYS) && chmod 700 $(ATT_KEYS)
	@# The gateway's own TLS certificate is an SVID SPIRE minted for it, so the
	@# client verifies the server against the SAME bundle the server verifies
	@# clients against. One trust root, both directions -- which is the point of
	@# a trust domain, and would be lost by pasting in a self-signed cert.
	@# Written into /tmp, which already exists because the server's own API
	@# socket lives there: the image is distroless, so there is no mkdir and no
	@# shell to make a directory with.
	@$(COMPOSE) exec -T spire-server /opt/spire/bin/spire-server x509 mint \
		-spiffeID spiffe://$(SPIRE_TRUST_DOMAIN)/gateway -dns localhost -ttl 1h \
		-write /tmp >/dev/null
	@$(CONTAINER) cp $(SPIRE_CONTAINER):/tmp/svid.pem $(ATT_KEYS)/tls.pem
	@$(CONTAINER) cp $(SPIRE_CONTAINER):/tmp/key.pem $(ATT_KEYS)/tls.key
	@test -f $(ATT_KEYS)/issuer.jwk || \
		$(GO) run ./tools/uai-keygen -out $(ATT_KEYS)/issuer.jwk -did "$(ISSUER_DID)" >/dev/null
	@stale=$$(ss -ltnp 2>/dev/null | grep ":$(ATT_PORT) " | grep -oP 'pid=\K[0-9]+' | head -1); \
		if [ -n "$$stale" ]; then kill $$stale 2>/dev/null || true; sleep 1; fi
	@PG_DSN="$(ATT_DSN)" $(GO) run ./services/gateway -addr 127.0.0.1:$(ATT_PORT) \
		-scheme https -issuer-key $(ATT_KEYS)/issuer.jwk \
		-spire-bundle $(SPIRE_DIR)/bootstrap.pem -spire-trust-domain $(SPIRE_TRUST_DOMAIN) \
		-tls-cert $(ATT_KEYS)/tls.pem -tls-key $(ATT_KEYS)/tls.key \
		> $(ATT_KEYS)/gateway.log 2>&1 & \
		echo $$! > $(ATT_KEYS)/gateway.pid
	@for i in $$(seq 1 40); do \
		curl -sfk https://localhost:$(ATT_PORT)/v1/quarantines >/dev/null 2>&1 && break; sleep 1; done
	@curl -sfk https://localhost:$(ATT_PORT)/v1/quarantines >/dev/null 2>&1 || { \
		echo "the gateway did not come up:"; tail -8 $(ATT_KEYS)/gateway.log; exit 1; }

.PHONY: attested-down
attested-down:
	@test -f $(ATT_KEYS)/gateway.pid && kill $$(cat $(ATT_KEYS)/gateway.pid) 2>/dev/null || true
	@rm -f $(ATT_KEYS)/gateway.pid
	@$(CONTAINER) rm -f uai-pg-attested >/dev/null 2>&1 || true

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

.PHONY: manuals
manuals: ## Check that both manuals describe the same software
	$(GO) test ./test/docs/ -count=1

.PHONY: check
check: build lint test conformance vectors-check policy-verify threats manuals ## Everything that must pass before a commit

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
