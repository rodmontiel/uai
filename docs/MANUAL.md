# Technical manual

> *Also available in Spanish: [`MANUAL.es.md`](MANUAL.es.md).*
>
> A reference for UAI's components: which standard each one implements, what it guarantees, where
> it lives in the repository, and how it fails. For the step-by-step walkthrough with real
> commands and real output, see [`Ejemplo_Practico_es.md`](Ejemplo_Practico_es.md).

---

## 1. The problem

An autonomous agent performed an action. **Who performed it, and who answers for it?**

The usual trace is a log line emitted by the same process that acted: unsigned, with no reference
to the policy in force when it decided, and with no way to detect that it was edited afterwards.
That is not evidence. It is an unverifiable assertion by the interested party.

For every action, UAI produces a signed record naming the identity, its declared owner, the
capability exercised, the purpose, the exact version of the rulebook that authorized it, and the
outcome — chained to the previous record and verifiable by a third party without running any code
from this repository.

### Declared limits

- **UAI does not evaluate whether an agent is safe.** It establishes attribution, not harmlessness.
- **UAI has no global kill switch.** Revoking an identity means participants stop honoring its
  credentials. The process does not stop: an agent on a disconnected machine keeps running.
  `make demo` demonstrates this explicitly.
- **An attestation proves an action was asserted, not that its effects occurred.** Proving effect
  requires the target system to counter-attest, and that is not implemented.

---

## 2. The four artifacts

| Artifact | Standard | Wire form | Answers |
|---|---|---|---|
| **UAI-ID** | ULID + W3C DID | `uai:agent:01M3QA6…` ↔ `did:uai:agent:01M3QA6…` | *who is this?* |
| **UAI Credential** | W3C VC 2.0 + Data Integrity | `AgentIdentityCredential`, `AgentOwnershipCredential` | *who answers for it, and what was it enabled to do?* |
| **UAI Passport** | W3C VC 2.0 | `AgentPassportCredential`, with `validUntil` | *where, and until when?* |
| **Action Attestation** | Signed JSON, hash-chained | `uai_version`, `sequence`, `previous_event_hash` | *what did it do?* |

The identifier is a ULID: 26 characters in Crockford base32, time-sortable, generated without
central coordination. The DID derives from it 1:1, so a verifier resolving the DID and one querying
the UAI-ID are talking about the same entity with no translation table in between.

**Credential and passport are not interchangeable.** The credential grants the capability
(`crm.customer.read`) and only the owner signs it. The passport bounds jurisdiction and validity
(`AR, DE`, until `2027-03-21`) and **cannot add a capability the owner did not grant**. That is why
an agent may request its own passport without it being a self-granted permission: the worst case of
a fraudulent passport is narrower scope, never wider.

Each capability also declares an **assurance floor** (`min_assurance`). A passport listing
`cloud.securitygroup.update` at floor `UAI-AL3` over an identity at `UAI-AL0` enables nothing: the
guardrail refuses the action with `assurance_below_floor` and names the rule that fired.

---

## 3. Components

### 3.1 Signatures — Ed25519

Ed25519 keys (RFC 8032). The private key never leaves the process holding it; in this repository it
lives in `.keys/`, which is gitignored and never committed.

What is signed is **the canonicalized document minus its signature member**. The member is
**removed**, not blanked: an implementation that blanked it would be signing four empty strings no
other signer adds, and its documents would verify only against itself.

Keys are resolved **as they were valid at event time**, not as they are now (`pkg/keys`). A
signature made before its key was revoked still verifies; one made after does not. Without that
rule, rotating a key would retroactively invalidate an entire history, and declaring a compromise
would invalidate nothing.

### 3.2 Canonicalization — JCS, RFC 8785

`{"a":1,"b":2}` and `{ "b":2, "a":1 }` are the same object and different bytes, so they produce
different signatures. JCS fixes member order, number encoding and string escaping so two
implementations produce the same bytes.

Implemented **three times** in this repository — Go, Python, TypeScript — and all three are tested
against the same vectors in `spec/test-vectors/jcs/`. The vectors are read, never regenerated in
tests: `make vectors-check` fails if regenerating them would change anything. Without that, three
implementations become three protocols.

### 3.3 Domain separation

What is hashed or signed is not the payload but `DOMAIN || 0x00 || payload`. Domains are constants
prefixed `UAI-v1:` — `attestation`, `credential`, `vote`, `quarantine`, `revocation`, `checkpoint`,
`commitment`, `passport`, `federation-hello`, and ten more in `pkg/uaicrypto/digest.go`.

Without separation, a signature produced to report a suspicion (`UAI-v1:suspicion`) could be
presented as the quarantine order that follows it (`UAI-v1:quarantine`), because the payload names
the same subject. Reusing an existing domain for a new purpose is a security bug, not a shortcut.

### 3.4 The event chain

Every event for an agent — registration, bind, unbind, rebind, action — carries the hash of the
previous one and a monotonic `sequence`. The hash covers the **signed** event, not just its
payload, so the chain binds the signature and not merely the content.

A gap in the numbering or a dangling link is visible to anyone walking the history. And a **forked**
chain — two different events declaring the same predecessor — has no innocent explanation: it is
the signal that the identity is running in two places at once.

### 3.5 Transparency log — Merkle, RFC 6962

Every attestation is entered into a Merkle tree and returns a **receipt**: leaf index, inclusion
proof, signed checkpoint and witness co-signatures. A third party holding the statement, the
receipt and the anchors verifies all of it without asking anyone.

The log stores **leaf hashes, never statements**. A log that accumulated content would become the
single thing worth attacking, and its retention would stop being cheap and lawful the moment it
held anything about a person.

### 3.6 Witnesses

The tree does not detect **split view**: an operator can show two consistent histories to two
different verifiers. The defence is organizational, not cryptographic.

A witness co-signs a checkpoint only after checking that it **extends** the one it already signed.
To sustain two histories, the operator would need witness signatures for two inconsistent
checkpoints, and an honest witness cannot produce the second.

> Today both witnesses run on the same machine. That provides **the mechanism but not the
> independence**: split-view detection rests on witnesses being operated by parties who would not
> collude with the log, and two processes on one host are not that. Declared, not hidden.

### 3.7 Chain anchoring

Periodically the checkpoint root is published to a consortium ledger (`uai-ledger-writer`, a
process separate from the gateway: anchoring is a durability layer, not an admission gate — the
gateway must keep accepting attestations while the ledger is down).

**No content reaches the chain, only salted commitments.** `test/onchain` reads the committed ABIs
and rejects any parameter that is not `bytes32`, `uintN`, `intN`, `bool`, `address` or a tuple of
those. A `string` or a dynamic `bytes` could carry a prompt or an email address, and the only
reliable way to keep those off a chain is to make them **unspellable** — which is why INV-007/008
is a build gate rather than a code-review habit.

The salt is mandatory: 32 bytes from `crypto/rand`, a fresh one per commitment. A bare hash of
low-entropy content — an email, an amount, a yes/no — is recoverable by dictionary attack, and a
commitment published on chain is a permanent privacy mistake. The salt stays with the owner: UAI
does not hold it and never will, which means a commitment whose salt was lost can never be opened.

The public anchor adapter ships as `noop-dev`, which **returns an error rather than a plausible
transaction hash**. A development build that invented an anchor would make receipts claim a
durability nobody provided.

### 3.8 Guardrail — OPA / Rego

Before acting, the agent asks the PDP, which evaluates a **signed policy bundle**
(`policy/gasc-2027.4/`). The bundle is committed with its manifest and signatures; the private
approval keys are not. Editing a rule or a threshold breaks startup until somebody holding the
governance keys signs again: policy is not changed by whoever has write access to the source tree.

**Verifying a bundle and evaluating one are deliberately separate.** Evaluation costs 33
third-party modules and lives only in the PDP; verification — manifest, hash, M-of-N signatures,
version chain — is dependency-free, because **auditing a past decision must never require the
machinery that made it** ([ADR-0002](adr/0002-opa-embedded-in-the-pdp.md)).

**Every** decision is recorded, `ALLOW` included, and every record names the exact bundle version
and hash. A guardrail that only logs denials cannot answer *"what was permitted, and why?"*, which
is the question that matters after an incident.

### 3.9 Governance — WebAuthn

Permanently revoking an identity requires **4 votes from 5 delegates, from at least 3 distinct
jurisdictions**.

The central design detail: **the challenge the hardware key signs IS the digest of the vote**. It
is not authenticate-then-vote; the authenticator signs exactly the content being voted on, with
`userVerification` required.

The consequence: **no automated process can vote.** It may hold the delegate's credential and still
not produce a valid vote, because the authenticator demands a verified human present. The registry
refuses it with `UAI_VOTE_NOT_USER_VERIFIED`.

The administrator is read-only by construction. The only thing it can do with a revocation is
**execute** one already decided, and `UAIRevocationRegistry.executeRevocation` re-verifies the
delegate signatures and the quorum against `UAIPolicyRegistry` before accepting it. A compromised
administrator revokes nobody. The quorum is not a constant in the contract: it is read from policy,
so governance changes it by signing rather than by redeploying the code that enforces it.

### 3.10 Runtime attestation — SPIFFE/SPIRE

A self-declared binding is the agent asserting where it runs, signed by the agent. It is worth the
same as nothing, and the system records it as `self-declared` so the two are distinguishable.

SPIRE observes the process from outside — operating-system selectors, today `unix:uid:N` — and
issues an **X509-SVID**: a certificate whose only URI SAN is a SPIFFE identity. The registry reads
the runtime **from the certificate, never from the request body**, and checks that the SVID names
*that* identity: a perfectly valid certificate belonging to another agent is refused with
`UAI_RUNTIME_IDENTITY_MISMATCH`.

The binding **expires with the SVID that proved it** (`expires_at` is the certificate's own
`NotAfter`, not a constant), and expired evidence does not count. The runtime dimension is not a
permanent achievement: it is a live state that has to be renewed.

> **What is still not recorded:** `runtime_identities.selectors` exists and is always empty. The
> registry stores the SPIFFE ID the attestor issued — a **name** — and not the evidence behind it,
> so nothing distinguishes an identity attested on `unix:uid` (any process of that user) from one
> attested on an image digest. It is in [§20.5](protocol/13-threat-model.md) with its consequence.

### 3.11 Assurance level

An identity's level (`UAI-AL0`…`UAI-AL3`) is the **minimum** of three dimensions:

| Dimension | AL1 | AL2 | AL3 |
|---|---|---|---|
| Key protection | software | TPM2, secure enclave, KMS, WebAuthn | HSM |
| Owner verification | domain control | verified organization credential | verified legal entity |
| Runtime attestation | attested SVID | SVID + attestor-supplied image digest | remote attestation of the environment |

It is **derived from evidence on every read, never stored**: a stored copy would be a cache with no
invalidation path, and the evidence changes when a key rotates, a binding expires or an owner is
verified. The registry also says **which dimension is the ceiling**, because a bare `UAI-AL0` is
indistinguishable from a misconfiguration.

> Owner verification is currently pinned at `SELF_ASSERTED`: nothing in the schema records domain
> control. That is why **every identity is at AL0**, even one with an HSM key and an attested
> runtime. The `did:web` control proof is listed as missing in §20.5.

### 3.12 SDKs

Three SDKs (Go, Python, TypeScript) and an MCP server with the 8 tools of §22.9.

The design starts from a limit that cannot be engineered away: **an SDK cannot make an agent
accountable**, because it runs inside the agent. The only thing available is to make the honest
path the shortest one:

```python
with agent.action("send the quote to the customer") as act:
    result = do_the_work()
```

Consulting policy, attesting the outcome and signing it happen on their own, **even if the work
raises**: `FAILURE` is attested and the exception re-thrown. A design where you had to call a
method at the end would be a design where the actions that go wrong do not get recorded — and an
accountability record containing only successes is an advertisement.

No MCP tool grants capabilities. `uai_request_capability` opens a request that **the owner**
approves out of band; the agent cannot approve anything for itself.

### 3.13 Federation — UAI-AS

An installation with a number of its own (`UAI_ASN`) is a **UAI-AS**: it has a registry DID
(`did:uai-registry:1001`), its own key — distinct from the issuer's — and answers *who is this
registry?*.

Two registries configure each other **by hand**, greet with a signed `REGISTRY_HELLO`, and exchange
an `IDENTITY_ANNOUNCEMENT` about an identity **the origin issued**.

> **PEER TRUST ≠ AGENT TRUST.** Configuring a peer means *"this registry may send me signed
> statements"*. It never means *"I trust its agents"*.

Held up by the schema, not by a comment: `federated_identities` has **no foreign key** to `agents`,
and a CHECK ties every DID to the ASN it is stored under. A valid signature is not authority — a
registry can perfectly well sign an announcement about another's agent, and it is refused with
`WRONG_AUTHORITY`.

An announcement has seven fields, none free-form, and the decoder **rejects unknown members**. That
is how *"announcements must never carry prompts or PII"* stops being a rule in a document.

What does **not** exist — transit, `REGISTRY_PATH`, routing, automatic discovery, revocation
propagation, passport federation — is enumerated in
[`Ejemplo_Practico_federation_es.md`](Ejemplo_Practico_federation_es.md). Federation is opt-in and
off by default: an installation with no number answers `404 UAI_FEDERATION_NOT_CONFIGURED`.
## 4. How do I try it

### What you need installed

- **Podman** (or Docker) — to run the database and SPIRE in containers.
- **Go 1.27** — to compile.
- **Python 3** with the `cryptography` library — for the demo and the SDK.
- **psql** — the PostgreSQL client.

> If `go` is installed but your shell says `Command 'go' not found`, it is not on your PATH. A
> common install puts it in `~/.local/go/bin`. Add it for this session with
> `export PATH="$PATH:$HOME/.local/go/bin"`, or permanently by putting that line in `~/.bashrc`.
> The `make` targets and `./deploy.sh` find it on their own; only commands you type yourself need
> this.

> A container is a program packaged with everything it needs, running isolated from the rest of the
> machine. *Rootless* means it runs without administrator privileges: if something goes wrong, the
> damage is bounded.

### The shortest path: one command

```bash
make demo
```

This stands everything up from scratch, runs the full scenario of a fictional company, and **fails
if any of the 21 MVP criteria is not demonstrated**. It cleans up everything it created afterwards.

It is not a narration: it is a test you can read. It shows registering an agent, binding it to a
runtime, requesting permissions, acting, the guardrail denying something, opening a case, voting a
revocation with five delegates, executing it, and verifying all of it from outside.

It ends like this:

```
21/21 criteria demonstrated
```

### Standing the platform up to use it

One command, everything in containers:

```bash
./deploy.sh up
```

The first time it builds the images and takes a few minutes; after that it is about 8 seconds. When
it finishes it shows what it started and on which ports.

```bash
./deploy.sh up       # build what is missing, start everything, apply the schema
./deploy.sh down     # stop, keeping the data
./deploy.sh nuke     # stop and delete the data (--keys: the keys too)
./deploy.sh status   # what is running, and on which ports
./deploy.sh env      # the exports the tools read: eval "$(./deploy.sh env)"
./deploy.sh logs uai-gateway   # follow one service's logs
```

Then, in the browser: **http://localhost:8081**

`podman ps` will show four containers:

```
uai_postgres_1       the database
uai_spire-server_1   the authority that certifies where each agent runs
uai_uai-gateway_1    the API
uai_uai-web_1        the web interface
```

> **The one thing that is not a container is the SPIRE agent**, and that is not an oversight. That
> component identifies a process by looking at it from outside, so it has to share a view with the
> processes it certifies — and the agents you will want certified run on your machine, not inside
> this stack. `make spire-up` starts it, and `./deploy.sh status` tells you whether it is on.

### If you would rather work on the code

For development it is better to run the API from source instead of from an image:

```bash
make dev          # infrastructure only (database + SPIRE)
make run-gateway  # the API, from source
make run-web      # the interface, from source
```

The difference: `./deploy.sh up` runs what was built, `make dev` + `make run-*` runs what you are
editing.

### Registering your first agent

An identity is not something UAI hands out. It is created by **two signatures naming the same
subject**: the owner's, saying "this agent is mine", and the agent's own, saying "this key is
mine". Neither alone proves anything, which is why there is no button for it.

`uai-register` performs that exchange.

**Step 1 — create an owner.** An owner is whoever answers for an agent. Creating one needs the
database rather than the API, and that is deliberate: a route anyone could call would make
"registered to an owner" mean "registered to a name somebody typed".

Set both addresses once. `owner` and `show` read the database directly; `agent` and `bind` go
through the gateway, and pick these up without being told:

```bash
export PG_DSN="postgres://uai:uai@localhost:5432/uai?sslmode=disable"
export UAI_ENDPOINT="https://localhost:8080"
export UAI_API_CA=".spire/bootstrap.pem"
```

The last two are for an **attested** stack, which serves TLS: an SVID is a client certificate, and
a plain connection has nowhere to put one. `.spire/bootstrap.pem` is the trust root the running
SPIRE issued — the same one the gateway verifies clients against, so both directions trust one
root. With attestation off the gateway serves plain HTTP: use `http://127.0.0.1:8080` and
`unset UAI_API_CA`. `./deploy.sh up` prints the right pair for the stack it just started, and
`./deploy.sh status` says which one you are on.

```bash
go run ./tools/uai-register owner -name "ACME Robotics" -org-did did:web:acme.example
```

```
  organization  did:web:acme.example
  owner         did:uai:owner:01M3D4QCXVCDNFT1GATPY98FDW
  key           .keys/owner.jwk
```

That key signs for every agent under it. It is the one file here whose loss cannot be undone by
re-running anything.

The command refuses to overwrite an existing `.keys/owner.jwk`, and after `./deploy.sh nuke` that
refusal is the thing people trip on: the database is gone, the key on disk is not. The key is still
yours — the registry simply no longer has a record of it. Register it again rather than deleting it:

```bash
go run ./tools/uai-register owner -reuse-key -name "ACME Robotics" -org-did did:web:acme.example
```

The owner gets a new identifier, because the old one existed only in the database that was deleted.
`-reuse-key` still refuses if some owner in *this* database already uses that key: one key behind
two owners means a signature no longer says which of them made the statement.

**Step 2 — register the agent.** Its key is generated on your machine and never leaves it; only
the public half is sent.

```bash
go run ./tools/uai-register agent -owner-did did:uai:owner:01M3D4QCXV… -name "RoutePlanner"
```

```
  uai-id     uai:agent:01M3D51K666A82R8VRG7EAC1PB
  status     REGISTERED
  key        .keys/routeplanner.jwk
```

**REGISTERED, not ACTIVE.** Registration is a claim; the binding that follows it is the proof. An
agent in this state cannot attest actions yet.

**Step 3 — bind a runtime.** This is what says *where* the agent runs, and it takes the identity to
ACTIVE.

```bash
go run ./tools/uai-register bind -uai-id uai:agent:01M3D51K66… -key .keys/routeplanner.jwk
```

If your stack has SPIRE on, that command is refused — correctly. A registry that verifies runtimes
will not accept one the agent describes about itself. Give SPIRE the agent's identifier first, then
present the certificate it issues:

```bash
make spire-entry ULID=01M3D51K666A82R8VRG7EAC1PB
make spire-svid
go run ./tools/uai-register bind -uai-id uai:agent:01M3D51K66… -key .keys/routeplanner.jwk -svid .spire/svid
```

```
  status     ACTIVE
  runtime    attested as spiffe://uai.test/agents/01M3D51K666A82R8VRG7EAC1PB/i/dev
```

> The order is not arbitrary. A SPIRE registration entry names the agent, so it cannot exist before
> the agent has an identifier — which is why binding is a separate step and not a flag.

**Step 4 — look at what you made.**

```bash
go run ./tools/uai-register show
```

And in the browser, paste the UAI-ID into `http://localhost:8081/verify.html`.

In a shell where you did not export them, the same two values go on the command line — `-endpoint`
and `-ca` override the environment:

```bash
go run ./tools/uai-register bind -uai-id uai:agent:01M3D51K66… -key .keys/routeplanner.jwk \
  -svid .spire/svid -endpoint https://localhost:8080 -ca .spire/bootstrap.pem
```

Against a TLS gateway, leaving the CA out is not a smaller version of the same command: the client
then has nothing to verify the gateway against, and the request fails before any of this is
reached. `-ca` is how you say which SPIRE you trust — not a switch that turns checking off.

### The surfaces

| Address | What it is | What to look at |
|---|---|---|
| `http://localhost:8081/` | Home | The overview, and what the system says about itself |
| `http://localhost:8081/verify.html` | **Verify** | The central screen: paste a UAI-ID and it says whether it is valid. This page **checks the proofs in your browser**; it does not display a verdict we handed it |
| `http://localhost:8081/explorer.html` | Explorer | The minute book: recorded actions and their proofs |
| `http://localhost:8081/quarantine.html` | Quarantines | Agents under preventive restriction, and what was suspended |
| `http://localhost:8081/governance.html` | Governance | Revocation proposals, who voted what, and under which threshold |
| `http://localhost:8081/agent.html?id=…` | Agent card | Everything public about one identity |
| `http://localhost:8081/federation.html` | Federation | This registry, its peers, and the identities others announced. `404 UAI_FEDERATION_NOT_CONFIGURED` when the installation has no number |

> The verify page is the only screen in the system you **do not have to take anyone's word for**. The
> code that checks the signatures runs in your browser and can be read: a few hundred lines with no
> external libraries, in [`web/app/verify.js`](../web/app/verify.js).

### Trying it from the command line

Asking the system about an identity that does not exist:

```bash
curl -s http://localhost:8080/v1/verify/uai:agent:01ZZZZZZZZZZZZZZZZZZZZZZZZ
```

```json
{
  "identity": "uai:agent:01ZZZZZZZZZZZZZZZZZZZZZZZZ",
  "verified": false,
  "status": "UAI_UNVERIFIED",
  "note": "No verifiable UAI identity exists for this identifier; this is not an assertion that the agent is malicious."
}
```

Look at the last line. **Silence is not an accusation.** A system not knowing an agent does not mean
that agent is malicious, and saying so explicitly stops anyone reading it the other way.

### The tests you can run

Each one fails if something is wrong. None of them is decorative.

```bash
make demo        # the full scenario: 21/21 criteria
make walkthrough # the same scenario, one criterion at a time, on your own stack
make attested    # that SPIRE certifies the runtime, not the agent itself: 7/7
make pentest     # 16 attacks from outside; fails if any of them works
make invariants  # 88 forbidden operations; fails if any is allowed
make check       # everything that has to pass before a commit
```

**`make walkthrough`** is `make demo` slowed down to reading speed. It stops at each of the 21
criteria, prints the call it just made as a command you could have typed yourself — a real `curl`,
a real `psql`, or the SDK when the call is signed — shows what came back, and tells you which page
to open before you press Enter. That is the difference that matters: `make demo` builds a
throwaway database and gateway and destroys both, so nothing it does is ever visible in the
browser. The walkthrough writes to the stack you are running, which is the one the pages read.

The price is that what it creates stays. UAI does not delete identities, so a walkthrough leaves
an organization, an owner and a revoked agent behind — and that is the guarantee working, not a
leak. Signed calls print as what the SDK sent rather than as a `curl` to paste: the signature
covers the method, the URL and the body, so a copy of it would not verify.

**`make pentest`** is the most illuminating for someone who wants to understand what the system
protects. It attacks a real API from outside, holding the only thing an attacker would have: a
legitimate identity of their own. It tries reusing signatures, replaying captured requests, binding
somebody else's identity, voting with a real credential but no human present. All 16 are refused,
and the report shows each one with the exact error.

**`make invariants`** is the other side: it asks what the **database** refuses to somebody who is
already inside it. For example, that an administrator with full access can neither edit a piece of
evidence nor delete a vote.

### Verifying from outside, without trusting us

This is the test that matters most, and the one that decides whether the project is worth anything:

```bash
go build -o uai-verify ./tools/uai-verify
./uai-verify uai:agent:01JY8R9ZAF392N7QX2T81JH6KM
```

That tool **trusts nothing** except three public keys. It fetches what is public, redoes the
arithmetic and **recomputes the verdict instead of printing it**. If the system said an identity was
revoked but the votes did not add up to 4 of 5, this tool would say so.

And when it finishes, it states what it checked and what it did not:

> *This says the record is internally consistent and signed by the keys it names — not that the
> actions described in it had the effects they claim.*

---

## 5. What is finished and what is not

Being clear here is part of the design: an identity project that overstates what it has loses its
credibility exactly once.

### Finished and tested

Identity, credentials, passports, action attestation, cryptography and reference vectors, the
guardrail with its signed rulebook, contracts and anchoring, the seven pages, three SDKs and an
MCP server, the 21-criteria demo, the security gates, runtime attestation with SPIRE, and the first
federation step (registry identity, explicit peering, and one signed announcement between peers).

### What is missing, and what that means

| Missing | What it implies today |
|---|---|
| **Domain-control proof** | When a company says it owns `company.com`, nobody checks. It is a claim |
| **Notifying the owner on registration** | If somebody registers an agent in your company's name, it is visible but nobody tells you |
| **Rate limits** | Nothing stops anyone registering a thousand agents or flooding the system with accusations |
| **Artifact signing (SBOM)** | We know which process is running, not what code it was built from |
| **Counter-attestation** | An agent that only records the flattering actions leaves visible gaps, but nobody looks at them |
| **Cross-installation clone detection** | Detectable in principle, and detected by nobody |

**The direct consequence:** since owner verification does not exist (§3.11), **every identity sits
at AL0**, even one with an HSM key and an attested runtime. The registry does not just state the
level: it states which dimension is the ceiling.

```json
"assurance_level":      "UAI-AL0",
"assurance_limited_by": "owner verification",
"assurance_detail":     "the owner is self-asserted; nothing has demonstrated control of its DID"
```

That is not a bug: it is the system refusing to assert something it cannot prove. A bare `UAI-AL0`
would be indistinguishable from a misconfiguration; with the reason beside it, whoever reads it
knows what would have to change, and the owner knows what to go and do.

### What is not real yet

The witnesses and the validators all run on the same machine, so **the independence that gives
witnesses their meaning does not exist yet**. The project's real test is not technical: it is that
*another organization* operates a validator and a witness on its own infrastructure. That is
Phase 13.

---

## 6. If something does not work

| Symptom | Cause and fix |
|---|---|
| `make dev` fails with `type "agent_status" already exists` | An old database with no migration ledger. `make migrate-baseline`, or `./deploy.sh nuke` to start clean (this deletes the data) |
| `./deploy.sh up` runs out of disk space | Old containers leave orphaned volumes behind. `podman volume prune` removes them; check the list first, in case one belongs to another project |
| The gateway exits with `permission denied` on `/keys/issuer.jwk` | The key is copied into a service-owned volume at startup. Running `./deploy.sh up` again redoes it |
| The gateway will not start and complains about the issuer key | The key is never generated at boot, on purpose: one that changed on every restart would issue credentials that later fail to verify. `make issuer-key` |
| The gateway warns `runtime attestation disabled` | Normal and fine. Without SPIRE configured it records self-declared runtimes; the warning exists so the difference is not invisible |
| `package slices is not in GOROOT (/usr/src/slices)` | The `go` being used is **gccgo**, which Ubuntu's `golang-go` and `gccgo-go` packages install at `/usr/bin/go`. It is a different compiler and cannot build this. `make check-go` says which toolchain the build will use; install an official one from <https://go.dev/dl/> and put it ahead of `/usr/bin` on PATH |
| `uai-register` refuses, saying it is running as root | You used `sudo`, and nothing here needs it: the database is reached over TCP and the keys go into your working tree. Run under sudo, the key is written as root and unreadable to you afterwards — which surfaces much later as a permission error on a file that looks fine |
| `uai-register agent` fails with `403 UAI_OWNER_NOT_ELIGIBLE` | The owner named by `-owner-did` is not in this database — usually because it was deleted by `./deploy.sh nuke` while the keys stayed on disk. `uai-register show` lists the owners that exist; register yours again with `-reuse-key` |
| `uai-register owner` says `.keys/owner.jwk already exists` | Correct, and it will not overwrite it: that key vouches for every agent under it. If the owner still exists the message names it — register an agent under that one. If nothing does, re-register the key with `-reuse-key` |
| `./deploy.sh status` says a SPIRE agent is running but the gateway started before it | A gateway takes its mode once, when it starts. Starting the agent afterwards attests nothing until `./deploy.sh up` restarts the gateway — which keeps the data |
| `make demo` says the port is in use | A previous run is still around. The target tries to clean it up; if not, `make demo DEMO_PORT=9999` |
| `./deploy.sh nuke` left the keys behind | On purpose: a deleted private key is gone, and the same file may still name an owner in another database. Register them again with `-reuse-key`, or delete them deliberately with `./deploy.sh nuke --keys`, which names every file it removes |
| `UAI_KEY_NOT_UNIQUE` | That key already names another identity. One key names one: two identities sharing a key make a signature unable to say which of them made the statement, and a revocation of one would leave the other operating under the same key |
| Everything is strange after poking at things | `make nuke && make dev` — deletes the volumes and starts clean |

---

## 7. Where to go next

- [`Ejemplo_Practico_es.md`](Ejemplo_Practico_es.md) — the same platform from the other end: one
  owner, one agent and one action, step by step, with every command and its real output.
  Written in Spanish
- [`README.md`](../README.md) — the project summary
- [`docs/protocol/`](protocol/) — the full specification, 26 sections
- [`docs/protocol/13-threat-model.md`](protocol/13-threat-model.md) — what can go wrong, what stops
  it, and which controls **do not exist yet**
- [`docs/security/pentest-checklist.md`](security/pentest-checklist.md) — what is attacked
  automatically and what needs a person
- [`SECURITY.md`](../SECURITY.md) — how to report a vulnerability

> If you find a way to break any of the ten rules in the threat model, that is exactly the report we
> most want.
