# 25 · Repository Structure

> Covers section **25**. Reflects the actual monorepo layout.

---

## 25.1 Layout

```text
uai/
├── .github/workflows/         # CI: every gate here blocks (26.1 phase 11)
├── docs/
│   ├── MANUAL.md  MANUAL.es.md  # user manual, English and Spanish, kept in step
│   ├── protocol/              # this specification (26 sections)
│   ├── integrators/           # integration guide, conformance, adapters
│   ├── security/              # pentest checklist
│   └── adr/                   # architecture decision records
├── spec/
│   ├── schemas/               # JSON Schema for every wire object
│   ├── contexts/              # JSON-LD contexts for credentials
│   ├── openapi/               # OpenAPI 3.1 definition
│   └── test-vectors/          # conformance vectors (normative)
├── proto/                     # protobuf for internal gRPC
├── pkg/                       # protocol core — NO external dependencies (see 25.2.1)
│   ├── uaiid/                 # ULID, UAI-ID, DID parsing
│   ├── uaicrypto/             # UAI-CS-1: signing, canonicalization, commitments
│   ├── uaivc/                 # verifiable credentials
│   ├── merkle/                # RFC 6962 tree, proofs, checkpoints
│   ├── attest/                # attestation build/verify + chain rules
│   ├── policy/                # OPA embedding, bundle verification
│   ├── ledger/                # contract bindings, anchor adapters
│   ├── spiffe/                # SVID helpers
│   ├── pop/                   # RFC 9421 proof of possession
│   ├── keys/                  # key history, rotation, validity at event time
│   └── receipt/               # checkpoints, transparency receipts, witnesses
├── internal/                  # server implementation — may take dependencies
│   ├── store/                 # PostgreSQL repositories
│   ├── api/                   # HTTP plumbing: problem+json, idempotency, PoP middleware
│   ├── conformance/           # the vector runner
│   ├── schemas/  openapi/     # spec checkers
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
├── web/                       # frontend: plain ES modules, no build step (ADR-0003)
├── sdk/
│   ├── python/                # uai-sdk (PyPI)
│   ├── typescript/            # @uai/sdk (npm)
│   └── go/                    # client used by services
├── mcp/                       # uai-mcp server
├── deploy/
│   ├── compose/  k8s/  spire/  besu/
├── demo/                      # ACME end-to-end scenario + the attestation gate
├── deploy/
│   ├── compose/  containers/  spire/   # stack, images, SPIRE server and agent config
├── tools/
│   ├── uai-verify/            # standalone verification CLI (no UAI dependency)
│   └── uai-conformance/       # runs test vectors against any implementation
├── test/
│   ├── invariants/            # INV-001..010 negative tests + the coverage gate
│   ├── attacks/               # the pentest, run against a live gateway
│   ├── threatmodel/           # 20 checked against the repository
│   ├── e2e/  integration/  onchain/  schemas/  openapi/  web/
├── deploy.sh                  # up / down / status: the platform as containers
├── Makefile
├── go.mod                     # single Go module (see 25.3)
└── CLAUDE.md
```

## 25.2 Conventions

| Area | Convention |
|---|---|
| Go | `pkg/` is the protocol core and takes no external dependencies; `internal/` is the server implementation and may. See 25.2.1 |
| Errors | Typed errors mapping 1:1 to the `UAI_*` API codes; no string matching |
| Config | Environment variables with a typed loader; `.env.example` committed, `.env` never |
| Migrations | Forward-only in production, reviewed against INV-003/006 |
| Contracts | Foundry; invariant and fuzz tests required for anything touching governance |
| Frontend | App Router, server components by default, WCAG 2.2 AA, status never conveyed by color alone (§45 of the brief) |
| Commits | Conventional commits; one commit per milestone (§56 of the brief) |
| Tests | Co-located unit tests; `test/` for cross-service integration, e2e and invariants |

### 25.2.1 The `pkg/` vs `internal/` boundary

`pkg/` is what a relying party runs to decide whether evidence is genuine: identifiers,
canonical bytes, signatures, Merkle proofs, proof of possession, key validity, receipts. It
takes **no external dependencies**, for two reasons that are not style preferences:

1. Every dependency on the verification path is supply-chain attack surface (threat T-07). An
   attacker who compromises a transitive library of the verifier does not need to forge
   anything — they change what "valid" means.
2. An auditor should be able to read the whole verification core without following a dependency
   tree, and a reimplementation in another language should have nothing to port but the spec.

`internal/` is the server: databases, HTTP, policy engines, schema validators. It may take
whatever dependencies it needs, because a compromised server is a failure UAI already models —
the log, the witnesses and the ledger exist precisely so that a lying server is detectable.

The rule is enforced by `test/deps`, not by discipline: a test runs `go list -deps` over `pkg/`
and fails on anything outside the standard library. That test itself once failed silently
because of a relative package pattern, so it also asserts that it actually inspected something.

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
