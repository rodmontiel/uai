# 25 · Repository Structure

> Covers section **25**. Reflects the actual monorepo layout.

---

## 25.1 Layout

```text
uai/
├── docs/
│   ├── protocol/              # this specification (26 sections)
│   ├── integrators/           # integration guide, conformance, adapters
│   └── adr/                   # architecture decision records
├── spec/
│   ├── schemas/               # JSON Schema for every wire object
│   ├── contexts/              # JSON-LD contexts for credentials
│   ├── openapi/               # OpenAPI 3.1 definition
│   └── test-vectors/          # conformance vectors (normative)
├── proto/                     # protobuf for internal gRPC
├── pkg/                       # shared Go libraries
│   ├── uaiid/                 # ULID, UAI-ID, DID parsing
│   ├── uaicrypto/             # UAI-CS-1: signing, canonicalization, commitments
│   ├── uaivc/                 # verifiable credentials
│   ├── merkle/                # RFC 6962 tree, proofs, checkpoints
│   ├── attest/                # attestation build/verify + chain rules
│   ├── policy/                # OPA embedding, bundle verification
│   ├── ledger/                # contract bindings, anchor adapters
│   ├── spiffe/                # SVID helpers
│   ├── store/                 # repositories (sqlc-generated)
│   └── obs/                   # OpenTelemetry, logging with redaction
├── services/                  # one directory per service, each with main.go
│   ├── gateway/ identity/ registry/ credential/ passport/ action/
│   ├── policy/ harm-monitor/ quarantine/ governance/ voting/
│   └── evidence-vault/ transparency/ ledger-writer/ notification/ audit/
├── contracts/                 # Solidity (Foundry)
│   ├── src/  test/  script/
├── policy/                    # GASC bundles
│   └── gasc-2027.4/           # rego + data + manifest + signatures
├── db/
│   ├── migrations/            # golang-migrate SQL
│   └── seed/
├── web/                       # Next.js + TypeScript frontend
├── sdk/
│   ├── python/                # uai-sdk (PyPI)
│   ├── typescript/            # @uai/sdk (npm)
│   └── go/                    # client used by services
├── mcp/                       # uai-mcp server
├── deploy/
│   ├── compose/  k8s/  spire/  besu/
├── demo/                      # ACME end-to-end scenario
├── tools/
│   ├── uai-verify/            # standalone verification CLI (no UAI dependency)
│   └── uai-conformance/       # runs test vectors against any implementation
├── test/
│   ├── e2e/  integration/  invariants/    # INV-001..010 negative tests
├── Makefile
├── go.mod                     # single Go module (see 25.3)
└── CLAUDE.md
```

## 25.2 Conventions

| Area | Convention |
|---|---|
| Go | Standard layout, `internal/` inside each service for non-shared code, `pkg/` only for genuinely shared libraries |
| Errors | Typed errors mapping 1:1 to the `UAI_*` API codes; no string matching |
| Config | Environment variables with a typed loader; `.env.example` committed, `.env` never |
| Migrations | Forward-only in production, reviewed against INV-003/006 |
| Contracts | Foundry; invariant and fuzz tests required for anything touching governance |
| Frontend | App Router, server components by default, WCAG 2.2 AA, status never conveyed by color alone (§45 of the brief) |
| Commits | Conventional commits; one commit per milestone (§56 of the brief) |
| Tests | Co-located unit tests; `test/` for cross-service integration, e2e and invariants |

## 25.3 Why a single Go module

Sixteen Go services could be sixteen modules. For the MVP they are one, because cross-module
version bumps during rapid protocol iteration cost more than they buy, and the services share a
large surface (`pkg/uaicrypto`, `pkg/attest`) that is still changing. The split into separate
modules is a mechanical refactor once the protocol stabilizes, and the directory layout is
already shaped for it.

This is recorded as `docs/adr/0001-single-go-module.md` so the decision can be revisited with its
original reasoning intact.

## 25.4 What lives outside this repository

- **Witness operators' deployments** — by design, witnesses must be independent; a witness whose
  code and keys come from this repo provides no independent assurance.
- **Member country validator configuration** — sovereign infrastructure.
- **Real HSM material and production keys** — never in version control, and the CI secret scan
  enforces it.
