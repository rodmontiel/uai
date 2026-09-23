# Universal Agent Identity (UAI)

> **Every AI agent should be accountable.**
>
> A universal identity and accountability layer for autonomous artificial intelligence.

UAI is an **open protocol** (and a reference implementation) that gives autonomous AI agents a
portable, cryptographically verifiable identity, and gives everyone else a way to attribute
actions to that identity.

Four artifacts, named so that they explain themselves:

| Artifact | Analogy | What it is |
|---|---|---|
| **UAI-ID** | national ID number | Globally unique, time-sortable identifier, 1:1 with a W3C DID |
| **UAI Credential** | digital certificate | Verifiable Credential binding the identity to an owner, capabilities and metadata |
| **UAI Passport** | passport | Time-bounded authorization to act across jurisdictions |
| **UAI Action Attestation** | notarized receipt | Signed, hash-chained record of what an identity did, under which policy version |

## What UAI claims — and what it does not

UAI **does not** claim an agent is safe. No protocol can. It claims that an action is
attributable: *this identity, this declared owner, these enabled capabilities, this declared
purpose, this exact guardrail version, and this cryptographic evidence.*

UAI has **no global kill switch**, and says so in the specification, the API responses, the UI
and the demo. Revocation means participating organizations will no longer honor an identity's
credentials. Code on a disconnected machine keeps running. Designing around that limit is what
makes the rest credible.

> `identified` ≠ `safe`. Identity enables accountability. Accountability is what trust is built on.

## Specification

The protocol and architecture are defined in [`docs/protocol/`](docs/protocol/) — 26 sections,
written so a third party can build a conformant verifier **without running any code from this
repository**.

Start with [`docs/protocol/00-index.md`](docs/protocol/00-index.md). The two files a verifier
must implement are [identity](docs/protocol/03-identity.md) and
[cryptography](docs/protocol/04-cryptography.md).

## Repository status

Implementation is proceeding phase by phase (see
[roadmap](docs/protocol/19-roadmap.md)). What exists and runs today:

Phase numbering follows [the roadmap](docs/protocol/19-roadmap.md) exactly. A phase is ✅ only
when its own stated deliverable exists in this repository.

| Phase | Status | What |
|---|---|---|
| 0–1 Definition & architecture | ✅ | Protocol specification v0.1, 26 sections, Mermaid diagrams, threat model with accepted risks |
| 2 Protocol | ✅ | 10 JSON Schemas with 40 examples, 3 JSON-LD contexts, OpenAPI 3.1 (21 paths), 10 published vector sets, `uai-conformance` |
| 3 Data | ✅ | PostgreSQL schema, 34 tables, integrity guards, 35 executable invariant assertions |
| 4 Backend core | 🟡 | `internal/store` (chain-safe persistence), `internal/api` (problem+json, PoP and idempotency middleware, attestation and verification handlers), `services/gateway`. Registration, binding and credential issuance pending |
| 5 Cryptography | ✅ | `pkg/uaiid`, `pkg/uaicrypto`, `pkg/merkle`, `pkg/pop` (RFC 9421 PoP), `pkg/keys` (rotation, compromise, validity at event time), `pkg/receipt` (checkpoints, receipts, witness co-signing) |
| 6–12 | ⬜ | Policy engine, contracts, frontend, SDKs, demo, security, deployment |

Phase 5 ran ahead of Phase 2 because the backend needed canonical bytes and signatures before
anything else could be built. Phase 2 has since closed that gap: the crypto core is checked
against **committed vectors**, and an implementation in any language can be verified against the
same files without running this code.

The verification core is deliberately dependency-free — it is what a relying party runs to decide
whether evidence is genuine, and every dependency there is supply-chain surface. A test enforces
that rule rather than leaving it to discipline.

```bash
make conformance     # 125 checks: vectors, schemas, OpenAPI
make vectors-check   # fails if regenerating the vectors would change them
```

Every vector set and every schema carries negative cases. Passing only the positive ones would
not demonstrate domain separation, rejection of malformed identifiers, fork detection, or that a
vote without hardware user verification is refused.

```bash
make test        # Go unit tests (identifiers, crypto suite, Merkle log)
make up          # infrastructure containers
make migrate     # apply the schema
```

### Containers

The reference runtime is **rootless Podman**; Docker works on every target via
`make CONTAINER=docker <target>`. The runtime was fixed now, in Phase 4, rather than after the
last phase, because SPIRE derives workload identity from what the runtime can attest and its
selectors are runtime-specific — so in this system the runtime is the base of the workload trust
chain, not packaging. The reasoning and the measured comparison are in
[ADR-0001](docs/adr/0001-podman-rootless-runtime.md).

```bash
make runtime     # what was detected: runtime, compose provider, image tags
make image       # gateway image: FROM scratch, non-root, reproducible
```

The compose stack contains only services the code actually uses — today that is PostgreSQL
alone, pinned by manifest digest. Services join it in the phase that wires them.

### The invariant tests

The security model is executable, not aspirational. `test/invariants/invariants.sql` asserts
that **forbidden operations fail** — evidence cannot be edited, truncated or re-shredded; votes
cannot be altered; an automated process cannot cast a vote; a revoked identity keeps its
history; a guardrail decision cannot omit its policy version; a chain fork cannot be committed.

```bash
psql -v ON_ERROR_STOP=1 -f test/invariants/invariants.sql
```

### Ownership is proven, not declared

Registering an agent takes **two signatures that name the same subject** — one from the owner's
key, which UAI already holds, and one from the agent's key, which is introduced in the same
exchange. Neither party can register alone: an owner cannot claim an agent it does not control,
and an agent cannot attach itself to an owner that never vouched for it.

The asymmetry between the two halves is the whole argument. The agent's key arrives in the
request because it is being introduced. The owner's key is read from the registry and is
rejected if it arrives in the request — a key supplied by the caller would make ownership
self-asserted, which is the one thing the flow exists to prevent.

Registration is also the only write path in UAI without proof of possession, because
establishing the agent's key is what it does. That is safe because it mints nothing: an
unanswered registration leaves no identifier, no DID and no record any verifier can see.

### Credentials that do not depend on us

Registration issues an `AgentIdentityCredential` and an `AgentOwnershipCredential` in the same
transaction that mints the identity. Both are W3C Verifiable Credentials 2.0 with Data Integrity
proofs.

The ownership credential **embeds the two registration signatures verbatim**. A relying party
validates ownership from that document and the owner's public key alone — our signature on it
attests only that we witnessed the exchange and minted an identifier. A credential that only
means something while our API is reachable would be an API response with extra steps, and it
would put UAI's uptime and honesty back into the trust equation this protocol exists to take
them out of.

```bash
make issuer-key   # once per deployment; the gateway refuses to start without it
```

### You can leave, and leaving is not deletion

An agent binds and unbinds itself without asking an administrator. That is a stated principle
and also a security property: a protocol you cannot leave is one operators refuse to adopt.

Unbinding releases the runtime identities and stops participation. It deletes nothing — every
attestation ever made stays verifiable, and `UNBOUND` reads as *"this identity exists and its
history is intact, but it is not currently participating"*, never as a verdict about past
behaviour.

Rejoining requires **cryptographic continuity**: a proof signed by a key that was valid *at the
moment of unbinding*. The key is resolved as of that instant, not as of now, so a compromise
declared retroactively to before the unbind makes the proof fail. Without that rule, "unbind,
rotate the key, rebind" would be a laundering path for a stolen identity.

Registration, binds, unbinds, rebinds and actions are **one hash chain**. A verifier reading an
agent's history can see it was not participating between two actions, without consulting a
second source.

## Design priorities

In every trade-off, in this order:

**security > auditability > interoperability > simplicity > performance > visual polish**

## Standards this builds on

W3C DID · W3C Verifiable Credentials 2.0 · SPIFFE/SPIRE · RFC 8785 (JCS) · RFC 6962 (Merkle
transparency) · RFC 9421 (HTTP message signatures) · IETF SCITT · WebAuthn · Open Policy Agent ·
EVM smart contracts.

UAI does not replace any of them. It composes them and adds the missing layer.

## License

Reference implementation: [Apache-2.0](LICENSE). Specification: additionally CC-BY-4.0, so it
can be implemented and republished by anyone — including standards bodies.

Security policy and the list of accepted risks: [SECURITY.md](SECURITY.md).
