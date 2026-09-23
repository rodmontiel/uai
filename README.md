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

### Policy is data, and the data is signed

No jurisdiction rule, harm threshold or assurance floor is compiled into a binary. All of it
lives in `policy/gasc-2027.4/`, a bundle whose hash is approved by an M-of-N governance set.

The bundle is committed **with** its manifest and signatures; the private approval keys are not.
Editing a rule or a threshold therefore makes the build fail until somebody holding the
governance keys signs it again — policy cannot be changed by whoever has write access to the
source tree.

```bash
make policy-verify   # part of `make check`
```

Verifying a bundle and evaluating one are deliberately separate. Evaluation costs 33 third-party
modules and lives only in the PDP; verification — the manifest, the hash, the M-of-N signatures,
the version chain — is dependency-free, because **auditing a past decision must never require
the machinery that made it** ([ADR-0002](docs/adr/0002-opa-embedded-in-the-pdp.md)).

Every decision is recorded, including `ALLOW`, and every record names the exact policy version
and bundle hash that produced it. A guardrail that only logs denials cannot answer "what was
permitted and why", which is the question that matters after an incident.

### An administrator may submit a revocation, never decide one

`UAIRevocationRegistry.executeRevocation` checks every consequential parameter against delegate
signatures and a threshold read from the policy registry. A compromise of the application layer
— or of the admin account itself — cannot produce a revocation the contract accepts.

The quorum is not a constant in the contract. It is read from `UAIPolicyRegistry`, so governance
can change it by signing a new policy instead of redeploying the code that enforces it. And a
quorum drawn from one jurisdiction is refused: several countries must be represented, which is
what stops a single government, or one operator holding several delegates, from revoking alone.

```bash
make contracts        # compile, then export the ABIs to spec/contracts/
make contracts-test   # 31 tests, including 512-run fuzzing
```

**Nothing that could carry content can reach the chain.** `test/onchain` reads the committed
ABIs and rejects any parameter that is not `bytes32`, `uintN`, `intN`, `bool`, `address` or a
tuple of those. A `string` or a dynamic `bytes` could carry a prompt or an email address, and
the only reliable way to keep those off a chain is to make them unspellable — so INV-007/008 is
a build gate rather than a code-review habit.

### Evidence that survives its issuer

Every attested action is registered in a transparency log and comes back with a **receipt**: the
leaf index, an inclusion proof, a signed checkpoint and witness co-signatures. A relying party
holding the statement, the receipt and the trust anchors verifies all of it without calling us.

The log stores leaf hashes, never statements. A log that accumulated content would become the
single thing worth attacking, and its retention would stop being cheap and lawful the moment it
held anything about a person.

Witnesses co-sign a checkpoint only after checking it extends what they already signed. That
refusal is the mechanism: an operator showing two verifiers two histories must obtain witness
signatures for two inconsistent checkpoints, and an honest witness cannot provide the second.
The MVP runs two local witnesses, which provide **the mechanism but not the independence** —
split-view detection rests on witnesses being operated by parties who would not collude with the
log, and processes on one host are not that.

Checkpoints are anchored on the consortium ledger by `uai-ledger-writer`, a separate process
from the gateway because anchoring is a durability layer and not an admission gate: the gateway
must keep accepting attestations while the ledger is down.

The public anchor adapter ships as `noop-dev`, which **returns an error rather than a plausible
transaction hash**. A development build that invented an anchor would make receipts claim
durability nobody provided, and the claim would be indistinguishable from a real one until
somebody went looking for the transaction.

### A verify page that verifies

`web/` is plain ES modules and CSS. No framework, no build step, no dependencies — so what a
browser executes is what is in this repository, and a reader can compare the two.

That matters because of what the verify page does. It fetches public data and **checks the
proofs in the browser**: it recomputes the leaf, walks the inclusion proof, checks the
checkpoint signature and the witness co-signatures, and walks the event chain. The registry's
own answer is shown beside those checks, labelled as the registry's answer.

A page that asks our API "is this agent fine?" and renders the reply is our opinion with a nicer
font. A visitor has no more reason to believe it than to believe us directly.

Once the page is doing the verifying, every byte of JavaScript on it is code a visitor must
trust in order to learn whether to trust an agent — which is why there is none but ours.
[ADR-0003](docs/adr/0003-a-frontend-with-no-dependencies.md) records the reasoning and the
deviation from §25, which had said Next.js.

```bash
make run-web    # :8081, one origin, strict CSP, /v1 proxied to the gateway
make test-web   # runs the BROWSER code against spec/test-vectors/
```

The last one is the point: the frontend is held to the same standard as every other
implementation. If it verified proofs its own way, it would give visitors a confident answer to
a different question.

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
