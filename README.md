# Universal Agent Identity (UAI)

> **Every AI agent should be accountable.**
>
> An identity and accountability layer for autonomous artificial intelligence —
> open protocol, reference implementation, and a path to a federated network of
> independently operated registries.

![The identity card of a registered agent: identifier, DID, status, assurance level with the
reason it is not higher, the anchor of its event chain, and the credentials issued with
it](docs/img/agent-passport.png)

<sub>A real agent in a running stack, captured by `make screenshots`. Every value comes from the
API — including `UAI-AL0 — how strongly the identity was established, not how safe the agent
is`, which is the sentence this project exists to keep saying.</sub>

---

## Mission

**Make every action taken by an autonomous agent attributable to a named, responsible party —
and make that attribution checkable by anyone, without trusting the party that produced it.**

An AI agent sends an email, moves money, changes a firewall rule, reads a customer record. Today
the trace it leaves is, at best, a line in somebody's log saying `bot-27` — written by the same
system that took the action. A receipt that signed itself.

UAI replaces that with a chain of signed, independently verifiable evidence: *this identity, this
declared owner, these granted capabilities, this stated purpose, this exact version of the
rulebook, this outcome* — and the cryptographic material for a third party to check every link
without running our code.

## Vision

**One registry is a product. A network of them is infrastructure.**

The internet does not have a central authority deciding who may route packets. It has roughly
75,000 independently operated Autonomous Systems, each with its own number, each peering with
others bilaterally, each responsible for what it originates. That design is why the internet
scales across jurisdictions, competitors and political boundaries.

UAI is built toward the same shape for agent identity. An organization, a regulator, a cloud
provider or a country runs **its own registry** — a **UAI-AS** — with its own number, its own key
and its own operational policy. Registries peer with each other explicitly. Signed statements
about identities travel between peers, always attributable to the registry that originated them.
Nobody's database becomes anybody else's.

The long-term goal is **global auditability**: an action taken by an agent registered in Buenos
Aires can be verified by a counterparty in Frankfurt, against evidence neither of them had to
take on trust.

> **Where this actually is today:** the first three capabilities of that vision exist and run —
> a registry has its own identity, two registries peer explicitly, and one sends the other a
> signed statement about an identity it issued. Everything that makes it a *network* rather than
> a *link* — transit, path propagation, route selection, discovery — **does not exist yet** and
> is listed as such in [Federation](#federation-the-network-this-is-built-toward).

<sub><i>Long-term stretch goal: if Skynet ever does become self-aware and wake up 😂, at least the
audit trail will say which owner registered it, under which policy version it acted, whether its
passport had expired, and exactly which rule it fired on the way. We still will not have a kill
switch — but the incident report is going to be immaculate. 🤖</i></sub>

---

## What UAI claims — and what it does not

This goes first, not last, because it is the part most easily oversold.

UAI **does not** claim an agent is safe. No protocol can. It claims an action is *attributable*.

UAI has **no global kill switch**, and says so in the specification, the API responses, the UI and
the demo. Revoking an identity means participating organizations stop honoring its credentials —
**not** that the program stops. Code on a disconnected machine keeps running. The demo
demonstrates that limit on purpose rather than hiding it.

> `identified` ≠ `safe`. Identity enables accountability. Accountability is what trust is built on.

---

## The product, in four artifacts

| Artifact | What it answers | What it is |
|---|---|---|
| **UAI-ID** | *Who is this?* | A globally unique, time-sortable identifier, 1:1 with a W3C DID |
| **UAI Credential** | *Who answers for it, and what may it do?* | A Verifiable Credential binding the identity to an owner, an organization and its capabilities |
| **UAI Passport** | *Where, and until when?* | A time-bounded authorization to act across jurisdictions — never a grant of new capability |
| **UAI Action Attestation** | *What did it do?* | A signed, hash-chained record of each action, naming the exact policy version that allowed it |

The distinction between the last two is the one worth keeping:

- The **credential** says *"this agent may read customer records."* That is the **what**, and only
  the owner grants it.
- The **passport** says *"it may do so in Argentina and Germany, until 21 March."* That is the
  **where and until when**.

A passport can never add a capability the owner did not grant. That is what makes it safe for an
agent to request its own.

---

## The screens

Seven pages, one origin, a strict CSP, no build step and no external JavaScript.

The image at the top of this page is captured from a running stack by `make screenshots`, not
pasted by hand — a screenshot taken once goes stale silently, and a README showing a product that
no longer exists is a small lie that compounds. The panels below are sketched from the real page
code and real example documents in [`spec/schemas/examples/`](spec/schemas/examples/); where a
panel is a document rather than a page in `web/`, it says so.

### 1 · Identification — who is this, and how sure are we?

The card above is the answer to *who is this*. `verify.html` is the answer to *and should I
believe it* — the only screen in the system you are **not** asked to trust. It does not render our
verdict: the code that checks the signatures runs in your browser, has no dependencies, and can be
read in a few hundred lines. The page keeps the two halves apart and says so: *"this panel is the
registry's answer. The checks below are performed in your browser."*

Two things on it are the whole product argument.

**The assurance level says why it is not higher.** A bare `UAI-AL0` is indistinguishable from a
misconfiguration, so the registry reports the level *and* the dimension holding it down:

```
Assurance   UAI-AL0 — limited by runtime attestation
            no attested runtime; a binding the agent described itself is not attestation
```

The level is derived from evidence on every read — key protection, owner verification, runtime
attestation — and it is the **minimum** of the three. It is never stored: a saved copy would be a
cache with no invalidation path, and the evidence moves when a key rotates, a binding expires or
an owner is verified.

**And the chain check refuses to conclude.** An identity that has attested nothing gets
`not checked — no events yet` rather than a green tick, and one whose history cannot be tied back
to registration is reported as **failed**, not as passed-with-nothing-to-check. A verifier that
reported success for a walk it did not perform would be worse than no verifier at all.

### 2 · The AI Passport — where it may act, and until when

The passport is not a screen: it is a **signed credential** the holder can hand to a counterparty,
who validates it without calling us. This is a real one from
[`spec/schemas/examples/`](spec/schemas/examples/agent-passport-credential/valid/cross-border-passport.json):

```json
{
  "type": ["VerifiableCredential", "AgentPassportCredential"],
  "id": "urn:uai:passport:01JY8RB1Q4X7N2M8V0K3T5S9WE",
  "validFrom": "2026-09-22T00:00:00Z",
  "validUntil": "2027-03-21T00:00:00Z",
  "credentialSubject": {
    "id": "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
    "owner": "did:uai:owner:01JY8R9ZB00000000000000000",
    "allowedJurisdictions": ["AR", "BR", "DE", "ES"],
    "restrictedJurisdictions": ["KP", "IR"],
    "authorizedCapabilities": [
      { "capability": "cloud.securitygroup.update", "minAssurance": "UAI-AL3",
        "constraints": { "max_actions_per_hour": 20 } },
      { "capability": "crm.customer.read", "minAssurance": "UAI-AL2" }
    ],
    "assuranceLevel": "UAI-AL3",
    "policyVersion": "GASC-2027.4",
    "state": "VALID"
  },
  "proof": { "type": "DataIntegrityProof", "domain": "UAI-v1:credential", "…": "…" }
}
```

Note the floors. `cloud.securitygroup.update` requires **UAI-AL3**; holding this passport changes
nothing about whether the identity reaches it. If it does not, the guardrail refuses the action
with `assurance_below_floor` and names the rule that fired. A document that authorized something
the guardrail would deny is a document telling an operator they are covered when they are not.

And `validUntil` is not decoration: a passport expires, and an expired one authorizes nothing.
That is why it is safe for an agent to request its own — the worst case of a fraudulent passport
is **narrower** scope, never wider.

### 3 · The event chain — what it did, in order, with no gaps

Every action is a signed record naming the previous one. You cannot insert one, and you cannot
remove one without the numbering failing to close. `explorer.html` walks that chain:

```
Action explorer
  Identity  uai:agent:01JY8R9ZAF392N7QX2T81JH6KM      ● ACTIVE
  Genesis   sha256:f2d8c41d…32718f

  418 attested action(s)
  #     ACTION                   OUTCOME              LINKS TO       EVENT          ASSERTED AT
  ────────────────────────────────────────────────────────────────────────────────────────────
  418   infrastructure.modify    SUCCESS              aaaaaaaa…aa    3f91c02b…7d    14:02:04Z
  417   crm.customer.read        ABORTED_BY_POLICY    99c1e70b…13    aaaaaaaa…aa    13:58:41Z
```

An identity that has attested nothing gets a sentence rather than an empty table: *"That is not
evidence that it did nothing: an actor that never submits an event leaves no trace, which is a
limit this system states rather than hides."*

Each row is a signed document. This is a real one from
[`spec/schemas/examples/`](spec/schemas/examples/action-attestation/valid/):

```json
{
  "event_id": "01JY8RA3C7K2V9M0QW4T6Z8XPD",
  "agent_did": "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
  "runtime_identity": "spiffe://uai.world/agents/01JY8R9ZAF392N7QX2T81JH6KM/i/7f6a92",
  "action": { "type": "infrastructure.modify", "capability": "cloud.securitygroup.update",
              "resource": "urn:cloud:aws:eu-central-1:sg-0a1b2c3d", "risk_class": "CRITICAL" },
  "purpose": "incident_remediation",
  "jurisdiction": { "origin": "AR", "targets": ["DE"], "cross_border": true,
                    "basis": "resource_location" },
  "policy": { "version": "GASC-2027.4", "decision": "ALLOW_WITH_MONITORING",
              "decision_id": "01JY8RA3C0…", "rules_fired": ["gasc.infra.cross_border_change"] },
  "passport": { "required": true, "status_at_decision": "VALID", "credential_hash": "sha256:bb…" },
  "input_commitment": "sha256:aaaa…", "output_commitment": "sha256:bbbb…",
  "outcome": "SUCCESS",
  "previous_event_hash": "sha256:aaaa…", "sequence": 418,
  "signature": { "domain": "UAI-v1:attestation", "…": "…" }
}
```

Three things this record does that a log line cannot: it names **the exact policy version and the
rules that fired**, so the decision can be re-evaluated years later; it records **the passport's
state at decision time**, so that survives the passport's later expiry; and inputs and outputs
appear only as **salted commitments** — the text never leaves the agent, and the salts stay with
its owner, who decides who may open them and when.

Failures are attested too. `FAILURE`, `PARTIAL` and `ABORTED_BY_POLICY` are first-class outcomes,
and the SDK attests a thrown exception before re-throwing it. An accountability record containing
only successes is an advertisement.

### 4 · Governance — revoking an identity takes people, not an administrator

```
Governance
  PROPOSAL          SUBJECT                     KIND      STATE   THRESHOLD   YES/NO   COUNTRIES   CLOSES
  ────────────────────────────────────────────────────────────────────────────────────────────────────────
  01JY8RC4D2…       uai:agent:01JY8R9ZAF…       REVOKE    OPEN    4-of-5      4 / 1    4           in 19h

  How a vote is cast
    Each vote is a WebAuthn assertion with user verification: a human, on a hardware key,
    present at that moment. The challenge the key signs IS the digest of the vote, so an
    automated process cannot cast one — it may hold the delegate's credential and still not
    produce a valid vote. The registry refuses it with UAI_VOTE_NOT_USER_VERIFIED.
```

`COUNTRIES` is not decoration: the quorum must be drawn from at least three jurisdictions, which
is what stops a single government — or one operator holding several delegates — from revoking
alone. Every vote is permanently attributed; there is no anonymous governance here.

An administrator may *submit* a revocation. An administrator may never *decide* one:
`UAIRevocationRegistry.executeRevocation` re-verifies the delegate signatures and reads the
quorum from the policy registry, so a compromise of the application layer — or of the admin
account itself — cannot produce a revocation the contract accepts.

---

## Federation: the network this is built toward

### The idea

BGP works because no one owns it. Each Autonomous System has a number, decides for itself who to
peer with, and is accountable for the routes it originates. There is no global registry operator,
and that is precisely why it spans jurisdictions that agree on very little else.

Agent identity needs the same property. A single global registry of AI agents would be a single
point of political failure, a single subpoena target and a single outage. What the world needs
instead is **many registries that can recognize each other's statements without merging their
databases**.

In UAI, an installation with a number of its own is a **UAI-AS**:

| BGP | UAI |
|---|---|
| ASN — a number identifying an autonomous network | **UAI-ASN** — a number identifying an autonomous registry |
| `AS15169` | `did:uai-registry:1001` |
| Peering session between two ASes | Explicit, mutually configured peering between two registries |
| BGP OPEN | Signed `REGISTRY_HELLO` |
| UPDATE announcing a prefix | Signed `IDENTITY_ANNOUNCEMENT` about an identity |
| *"I originate this prefix"* | *"I issued this identity, and here is its state"* |

UAI-ASNs are independent of internet ASNs. An organization that already runs `AS64500` does not
inherit a UAI number, and never should: routing packets and vouching for an AI agent are different
authorities.

### What exists today

Running `make federation-demo` stands up **two registries with separate databases and separate
gateways** — because a process talking to itself proves nothing about autonomy — and exercises the
whole path:

```
==> step 1 — each registry says who it is
  A   UAI-AS 1001 · OMniLeads-UAI · did:uai-registry:1001 · ACTIVE
  B   UAI-AS 2001 · Partner-UAI   · did:uai-registry:2001 · ACTIVE

==> step 3 — handshake
  A   sent REGISTRY_HELLO from AS1001 · answered from AS2001 (Partner-UAI)
    ✓ PEER ACTIVE in both directions

==> step 5 — AS1001 announces an identity it issued
  A   announced  did:uai:1001:agent:01M3SGKV0D1MZV4C0DDWVESR45  →  ACCEPTED

==> step 7 — what AS2001 now holds
  B   AGENT DID                          ORIGIN   STATUS       SIGNATURE
  B   did:uai:1001:agent:01M3SGKV0D…     AS1001   REGISTERED   VERIFIED
  B   These belong to other registries. None of them is an agent of this one.

==> and what AS2001 refuses
    ✓ a replayed announcement: STALE_SEQUENCE
    ✓ AS2001 trying to revoke AS1001's identity: WRONG_AUTHORITY
    ✓ AS2001 has 0 local agents: a federated identity is not one
```

The rule the whole design rests on:

> ### PEER TRUST ≠ AGENT TRUST
>
> Configuring a peer means *"this registry may send me signed statements."* It never means
> *"I trust its agents."* A federated identity is a **claim by another registry**, recorded as
> such, and it is never an identity of yours.

That is enforced in the schema, not in a comment: federated identities live in their own table
with **no foreign key** to local agents, and a CHECK ties every DID to the ASN it was announced
under. And a valid signature is not authority — a registry can perfectly well sign a statement
about somebody else's agent, and it is refused with `WRONG_AUTHORITY`.

An announcement has seven fields, none of them free-form, and the decoder **rejects unknown
members**. That is how *"announcements must never carry prompts or PII"* stops being a rule in a
document.

### What does not exist yet

Named here so it cannot be mistaken for a roadmap that already shipped. None of the following is
implemented:

- **REGISTRY_PATH and transit** — an announcement travels one hop, between two directly
  configured peers. Nothing forwards it onward, and nothing records the path it took.
- **BGP-style route selection, multi-path, and tie-breaking** between competing statements.
- **Automatic peer discovery** — peering is manual and mutual, on purpose. Trust-on-first-use is
  offered for a lab and the tool says out loud that out-of-band is better.
- **An RPKI equivalent** — nothing outside the two registries certifies that a UAI-ASN belongs to
  who claims it.
- **Confederations, route reflectors, trust communities, import/export policy engines.**
- **Propagation of revocation or quarantine** between peers.
- **Passport federation** and cross-registry capability recognition.
- **A looking glass**, and federation consensus on a blockchain.

The interfaces were left extensible. Nothing above is scheduled, and nothing above is implied by
what runs today.

📖 Step by step, with real output: [`docs/Ejemplo_Practico_federation_es.md`](docs/Ejemplo_Practico_federation_es.md)

```
┌─ Federation — UAI ───────────────────────────────────────────────────────────┐
│  This registry                                                               │
│    UAI-AS              1001                                                  │
│    Registry            OMniLeads-UAI                                         │
│    Registry DID        did:uai-registry:1001            ● ACTIVE             │
│    Federation endpoint https://uai.omnileads.example                         │
│    Protocol            0.1                                                   │
│                                                                              │
│  Peers                                                                       │
│    UAI-AS  REGISTRY DID            STATUS   ENDPOINT               LAST SEEN │
│    2001    did:uai-registry:2001   ACTIVE   https://partner.exam…  16:49Z    │
│                                                                              │
│  Federated identities                                                        │
│    AGENT DID                      ORIGIN  REMOTE STATUS  SIGNATURE  SEQ      │
│    did:uai:2001:agent:01M3SGKV0D… AS2001  REGISTERED     VERIFIED   1042     │
│                                                                              │
│    These belong to other registries. None of them is an agent of this one.   │
└──────────────────────────────────────────────────────────────────────────────┘
```

Federation is **opt-in and off by default**. An installation nobody gave a number to answers
`404 UAI_FEDERATION_NOT_CONFIGURED`, which is the honest state for a registry that has not joined
anything.

---

## Run it

```bash
./deploy.sh up          # four containers; open http://localhost:8081
./deploy.sh status      # what is running, and whether runtime attestation is on
./deploy.sh down        # stop
```

To watch the whole protocol exercised end to end instead:

```bash
make demo               # throwaway stack, the ACME scenario,
                        # fails unless all 21 MVP criteria are demonstrated
make federation-demo    # two independent registries recognising each other
```

### Where to start reading

| If you are | Start here |
|---|---|
| Evaluating this as a product | This page, then [`docs/Ejemplo_Practico_es.md`](docs/Ejemplo_Practico_es.md) — twelve steps, every output real |
| New to the concepts | [`docs/MANUAL.md`](docs/MANUAL.md) — the whole system, component by component. Also in Spanish: [`docs/MANUAL.es.md`](docs/MANUAL.es.md) |
| Building a verifier | [`docs/protocol/00-index.md`](docs/protocol/00-index.md) — 26 sections, written so a third party can build a conformant verifier **without running any code from this repository**. The two files you must implement are [identity](docs/protocol/03-identity.md) and [cryptography](docs/protocol/04-cryptography.md) |
| Interested in federation | [`docs/Ejemplo_Practico_federation_es.md`](docs/Ejemplo_Practico_federation_es.md) |
| Assessing the risk | [`docs/protocol/13-threat-model.md`](docs/protocol/13-threat-model.md), and §20.5 in particular: the controls that **do not exist yet**, each with its consequence |

---

## Status

Phase numbering follows [the roadmap](docs/protocol/19-roadmap.md) exactly. A phase is ✅ only
when its own stated deliverable exists in this repository.

| Phase | Status | What |
|---|---|---|
| 0–1 Definition & architecture | ✅ | Protocol specification v0.1, 26 sections, Mermaid diagrams, threat model with accepted risks |
| 2 Protocol | ✅ | 10 JSON Schemas with 41 examples, 3 JSON-LD contexts, OpenAPI 3.1 (28 paths), 13 published vector sets, `uai-conformance` |
| 3 Data | ✅ | PostgreSQL schema, 45 tables, integrity guards, 94 executable invariant assertions |
| 4 Backend core | ✅ | `internal/store`, `internal/api`, `services/gateway`. Register → bind → attest runs as a test, not a claim |
| 5 Cryptography | ✅ | `pkg/uaiid`, `pkg/uaicrypto`, `pkg/merkle`, `pkg/pop` (RFC 9421 PoP), `pkg/keys` (rotation, compromise, validity at event time), `pkg/receipt` |
| 6 Policy engine | ✅ | `pkg/policy` (dependency-free bundle verification), `internal/pdp` (embedded OPA), the 3-of-5 signed GASC bundle, signed decision records |
| 7 Blockchain | ✅ | 7 contracts with Foundry fuzzing, `internal/translog` (log, SCITT receipts, witness co-signing), `internal/chain`, `services/ledger-writer` |
| 8 Frontend | ✅ | Seven pages in `web/`, one origin with a strict CSP, and a verify page that verifies in the browser rather than rendering our verdict |
| 9 SDK | ✅ | `sdk/go`, `sdk/python`, `sdk/typescript`, `mcp/` with the 8 tools of §22.9 |
| 10 Demo | ✅ | `make demo` runs the ACME scenario and fails unless all 21 MVP criteria are demonstrated; `tools/uai-verify` re-checks the history from public data alone |
| — Federation, step 1 | ✅ | Registry identity (UAI-AS), explicit peering, one signed identity announcement between two peers. **Not** transit, routing, discovery or propagation — see [Federation](#federation-the-network-this-is-built-toward) |
| 11–12 | ⬜ | Security validation, deployment |

Phase 5 ran ahead of Phase 2 because the backend needed canonical bytes and signatures before
anything else could be built. Phase 2 has since closed that gap: the crypto core is checked
against **committed vectors**, and an implementation in any language can be verified against the
same files without running this code.

```bash
make check           # build, vet, lint, unit tests, conformance, policy, docs gate
make conformance     # 161 checks: vectors, schemas, OpenAPI
make vectors-check   # fails if regenerating the vectors would change them
make integration     # throwaway PostgreSQL: store + API + 94 invariant assertions
make pentest         # 16 attacks across 10 threats, every one refused
```

Every vector set and every schema carries negative cases. Passing only the positive ones would
not demonstrate domain separation, rejection of malformed identifiers, fork detection, or that a
vote without hardware user verification is refused.

---

## How it holds up

The rest of this page is the engineering argument behind the claims above: why each guarantee is
enforced where it cannot be bypassed, and what each one deliberately does not promise.
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

---

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
make invariants   # through the runner, never through a pipe: `psql | grep` reports a
                  # failing invariant and exits 0, which is how this suite ran green
                  # for nine phases without ever having been enforced
```

---

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
