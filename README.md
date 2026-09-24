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
| 2 Protocol | ✅ | 10 JSON Schemas with 41 examples, 3 JSON-LD contexts, OpenAPI 3.1 (28 paths), 13 published vector sets, `uai-conformance` |
| 3 Data | ✅ | PostgreSQL schema, 36 tables, integrity guards, 86 executable invariant assertions |
| 4 Backend core | ✅ | `internal/store`, `internal/api`, `services/gateway`. Register → bind → attest runs as a test, not a claim |
| 5 Cryptography | ✅ | `pkg/uaiid`, `pkg/uaicrypto`, `pkg/merkle`, `pkg/pop` (RFC 9421 PoP), `pkg/keys` (rotation, compromise, validity at event time), `pkg/receipt` |
| 6 Policy engine | ✅ | `pkg/policy` (dependency-free bundle verification), `internal/pdp` (embedded OPA), the 3-of-5 signed GASC bundle, signed decision records |
| 7 Blockchain | ✅ | 7 contracts with Foundry fuzzing, `internal/translog` (log, SCITT receipts, witness co-signing), `internal/chain`, `services/ledger-writer` |
| 8 Frontend | ✅ | Six surfaces in `web/`, one origin with a strict CSP, and a verify page that verifies in the browser rather than rendering our verdict |
| 9 SDK | ✅ | `sdk/go`, `sdk/python`, `sdk/typescript`, `mcp/` with the 8 tools of §22.9 |
| 10 Demo | ✅ | `make demo` runs the ACME scenario and fails unless all 21 MVP criteria are demonstrated; `tools/uai-verify` re-checks the history from public data alone |
| 11–12 | ⬜ | Security validation, deployment |

Phase 5 ran ahead of Phase 2 because the backend needed canonical bytes and signatures before
anything else could be built. Phase 2 has since closed that gap: the crypto core is checked
against **committed vectors**, and an implementation in any language can be verified against the
same files without running this code.

The verification core is deliberately dependency-free — it is what a relying party runs to decide
whether evidence is genuine, and every dependency there is supply-chain surface. A test enforces
that rule rather than leaving it to discipline.

```bash
make conformance     # 161 checks: vectors, schemas, OpenAPI
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

### The SDK cannot make an agent accountable

Everything else in UAI is built assuming the agent may be adversarial. The SDKs run *inside* the
agent's process, so they inherit none of that protection: an agent that does not want to be
accountable simply does not import them. That is not a gap to close — it is why the protocol puts
verification in the relying party.

What an SDK can do is make the accountable path the easy one. So the unit of work is a scope, not
two calls:

```python
with agent.action(capability="route.optimize", purpose="delivery_optimization",
                  jurisdiction=Jurisdiction(origin="AR", targets=("DE",),
                                            basis="resource_location"),
                  input=order) as act:
    act.output = optimize(order)
```

Three things follow from `with` that would not follow from `evaluate()` and `attest()`:

**The block does not run when the guardrail refuses.** `__enter__` evaluates first, and `DENY`,
`QUARANTINE` and `REQUIRE_HUMAN_APPROVAL` all raise. The last one is a refusal until a human
acts; treating it as a conditional yes is how a human-in-the-loop requirement becomes a log line.

**Something is attested on every way out** — return, exception, and refusal. An SDK that left the
second call to the integrator would produce a record of successes, because the failure paths are
the ones nobody writes it on. A record that contains only successes is an advertisement.

**Content never leaves the process.** Inputs and outputs are committed locally with a fresh
random salt; only `sha256:…` is sent. The salts come back to the caller, because a commitment
whose salt nobody kept can never be opened by anyone — which is the same as not having recorded
anything.

### No MCP tool grants capabilities

`uai-mcp` serves the eight tools of §22.9 under one agent identity. An MCP server holds that
identity's key, so a tool that could widen its privileges would be a confused-deputy generator
(T-11/T-13). `uai_request_capability` creates a **pending request**, and that rule is kept in
three places that would each have to fail together: no tool grants, no API route grants, and the
database refuses a grant whose grantor is the agent itself.

The only path to a grant is [`tools/uai-grant`](tools/uai-grant), which needs the owner's signing
key. It is deliberately not part of the API — a route that did this would be a route an agent
could reach.

### Three languages, one set of vectors

Each SDK reimplements RFC 8785 canonicalization and RFC 9421 message signatures in its own
language, because the alternative on this path is dependencies that can sign on the agent's
behalf ([ADR-0004](docs/adr/0004-sdk-dependency-posture.md)). The Python SDK has one dependency;
the TypeScript SDK has none and no build step; the Go SDK adds nothing to `pkg/`.

The cost of that is three implementations that can drift, and it is paid with tests rather than
accepted: all three reproduce the **same committed vectors**, byte for byte.

```bash
make test-sdk    # Python and TypeScript, against spec/test-vectors/
```

Writing them found two defects that reading the code had not. §10.4 says a signature covers
"jcs-canonicalize A minus signature", and the Go implementation was *blanking* the member instead
of removing it — emitting four empty strings into the signed bytes that no reader of the spec
would know to add. And `POST /v1/policy/evaluate` took the agent's passport **from the request
body**: sending `{"passport":{"state":"VALID","allowed_jurisdictions":["KP"]}}` turned a `DENY`
into an `ALLOW`. Both now have committed vectors or negative tests; the second has both.

### The demo shows what the system does not do

```bash
make demo        # the ACME scenario; fails unless all 21 MVP criteria are demonstrated
```

An agent is registered, bound, passported and working. It reaches for infrastructure it was
never authorized for. The guardrail denies it, a signed suspicion is filed, and **the policy —
not the script — decides** that the category warrants a preventive quarantine. A case opens.
Five delegates on three continents vote with hardware authenticators. Four say yes. An
administrator whose entire write surface is one button executes the decision; their only input
is a decision id, and everything else was fixed by the governance proof before they arrived.

Then the script runs the agent's business logic directly. **It still works.** Nothing stopped
the code from executing, because nothing in UAI can. What changed is that no participant will
honour its identity — and the demo says that at the moment it is least convenient to say it,
because a system that lets people believe otherwise has sold them a kill switch it does not
have.

### A decision does not close before everyone has spoken

The proposal used to authorize on the vote that first met the threshold. That refused every
delegate who had not answered yet — which in practice means refusing the dissent, since the
threshold is reached by the majority. The record then showed 4–0 where the council voted 4–1.

A decision whose record cannot show who objected is weaker, not stronger. So authorization
waits for the vote to actually finish, measured against the threshold **snapshotted when the
proposal opened** — a live count would let appointing a delegate mid-vote move the finish line.

Four YES votes from one country still fail: `min_countries` is a separate condition, because
M-of-N alone is satisfiable inside a single jurisdiction, and a revocation decided there is a
national decision wearing an international label.

### Criterion 21: verification without us

```bash
uai-verify -anchors anchors.json uai:agent:01JY8R9ZAF392N7QX2T81JH6KM
```

It fetches nothing but public data and trusts only the three anchors of
[§5.1](docs/protocol/02-actors-trust.md): the policy signing keys, the log and witness keys, and
the ledger validator set. Everything the registry returns is checked against them — including
the registry's own verdict, which the tool **recomputes rather than prints**.

For a revoked identity it rebuilds the tally and the governance proof from the signed
assertions. A decision whose stated outcome does not follow from its own votes is the only
forgery this design leaves room for, and that is the check that catches it.

If you let it fetch the anchors from the gateway it is auditing, it says so in the output:
that run proves internal consistency, not authenticity.

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
