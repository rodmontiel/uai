# User manual

> *Also available in Spanish: [`MANUAL.es.md`](MANUAL.es.md).*
>
> This document explains UAI **from the ground up**, assuming nothing. It is written for someone
> who does not program. Technical terms do appear, but always with what they do and what they are
> like.

---

## 1. The problem, in one sentence

An artificial-intelligence program did something. **Who was it, and who answers for it?**

Today, in practice, there is no answer. An AI agent that sends an email, moves money or deletes a
file leaves behind, at best, a line in a log saying `bot-27`. That line was written by the same
system that took the action. It is a receipt that signed itself.

UAI exists so that question has an answer, and so the answer can be **checked without trusting us**.

### What UAI does NOT do

This comes first, not last, because it is the easiest thing to misread:

- **UAI does not say an agent is safe.** No protocol can. It says *who it is*, *who answers for
  it*, *what it was allowed to do* and *what it did*.
- **UAI has no global kill switch.** It does not exist and cannot exist. Revoking an identity means
  *everyone else stops accepting it* — not that the program stops. If the agent runs on a
  disconnected machine, it keeps running. The demo shows this on purpose.

> Analogy: if someone's passport is cancelled, they do not disintegrate. They simply stop being
> able to cross borders where it gets checked. UAI is the passport system, not the police.

---

## 2. The four things UAI gives an agent

| It is called | It is like | What it actually is |
|---|---|---|
| **UAI-ID** | A national ID number | A unique, unrepeatable identifier. It says nothing about the holder: it is the number everything else hangs off |
| **Credential** | A diploma or a licence | A signed document saying whose agent this is and what it was enabled to do |
| **Passport** | A passport | A permission with an expiry date to act in certain countries. It says **where**, never **what** |
| **Action attestation** | A notarized receipt | A signed record of each thing it did, chained to the previous one |

The distinction between credential and passport matters and is easy to lose:

- The **credential** says *"this agent may optimize delivery routes"*. That is the **what**, and
  the owner grants it.
- The **passport** says *"it may do so in Argentina and Germany, until 3 March"*. That is the
  **where and until when**.

A passport can never add a capability the owner did not grant. That is why an agent can request one
itself without that being a self-granted permission.

---

## 3. What it is made of, piece by piece

Each component below: the technology it uses, what that is for, and what it is like.

### 3.1 Digital signature — *the wax seal*

**Technology: public-key cryptography (Ed25519).**

Every agent generates **two mathematically paired keys**. One it keeps and never shows (the
*private* one). The other it publishes (the *public* one).

What makes the pair special is this: anything sealed with the private key can be checked by anyone
holding the public one — **but nobody can forge the seal without the private key.**

> Analogy: a wax seal only you own. Everyone recognizes your crest; nobody can carve an identical
> one.

UAI never generates an agent's keys. The agent makes its own, and **we never see the private one**.
That is deliberate: if we held it, we could sign in the agent's name, and a signature would stop
proving who acted.

### 3.2 Canonicalization — *agreeing how to write it down, before signing*

**Technology: JCS, RFC 8785.**

A boring and critical problem: `{"a":1,"b":2}` and `{ "b":2, "a":1 }` say the same thing, but they
are different text, so they produce different seals. If the signer and the verifier write the
document even slightly differently, the signature fails to validate — and it looks like fraud when
it was one extra space.

JCS is a rule that says exactly how to write the document before sealing it: what order the fields
go in, how many spaces, how numbers are written.

> Analogy: before signing a contract, both parties agree on the typeface, the paper size and the
> order of the clauses. It sounds bureaucratic. It is what makes two copies comparable.

It is implemented **three times** in this repository — in Go, in Python and in TypeScript — and all
three are tested against the **same reference examples**. That is what keeps three implementations
from becoming three different protocols.

### 3.3 Domain separation — *what this signature is for*

Every signature carries a label inside saying what it was made for: `UAI-v1:attestation`,
`UAI-v1:vote`, `UAI-v1:quarantine`.

> Analogy: signing a cheque and signing a travel consent form. Same hand, but you do not want
> anyone cutting your signature off one and pasting it onto the other.

Without that label, a signature made to report a suspicion could be reused as the quarantine order
that follows it.

### 3.4 The event chain — *the numbered pages of a notebook*

Every action an agent takes is stored with the **digest of the previous action** inside it.

> Analogy: a notebook where each page writes the summary of the previous page at the top. If
> someone tears a page out, the next one no longer adds up. Nothing can be deleted quietly.

If the same agent shows up running in two places at once, the chain forks — and a forked chain
**has no innocent explanation**. It is the signal that somebody cloned the identity.

### 3.5 The transparency log — *the public minute book*

**Technology: Merkle tree (RFC 6962), the same thing internet certificates use.**

Everything recorded goes into a structure that allows two remarkable things:

1. Proving that **something is inside**, without showing everything else.
2. Proving the book **only grew**, that no old page was ever rewritten.

> Analogy: a minute book where every page carries a number derived from all the pages before it.
> Changing one comma on page 3 changes the number on the last page, and everyone sees it.

**The log does not store the content.** It stores only a fingerprint. If somebody steals the log's
database, they get neither a prompt nor a piece of personal data.

### 3.6 Witnesses — *signing the same book from another office*

A minute book has a problem: what if whoever keeps it shows one version to you and a different one
to somebody else? That is called a *split view*, and cryptography alone does not catch it.

The answer is not technical but organizational: **other parties sign the same book**. For the log to
show two histories, it would have to get the witnesses to sign both.

> Analogy: two notaries from different firms sign the same minute. Forging it stops being one
> person's problem and becomes a conspiracy.

In this repository today the witnesses run on the same machine, and **that does not count as
independence**. It is written down as pending, not hidden.

### 3.7 Blockchain anchoring — *nailing the book up in the town square*

Every so often, the fingerprint of the minute book is published on a blockchain.

> Analogy: posting a note on the courthouse door saying "at 15:00 the minute book was on page 4,812
> and its fingerprint was this". If somebody later rewrites the book, the note on the door
> contradicts it.

**No content goes on the chain**, only salted fingerprints. That is guaranteed by an automated test
that rejects any contract declaring a parameter capable of carrying text.

> The "salted" part matters: the fingerprint of a guessable value (an email address, say) can be
> recovered by trying a dictionary. Adding a secret random value before computing it makes that
> infeasible.

### 3.8 The guardrail — *the rulebook, and whoever applies it*

**Technology: OPA / Rego, a policy engine.**

Before each action, the agent asks: *"may I do this?"*. What answers is a policy engine consulting a
**signed rulebook**.

The rulebook is not a file anyone can edit: it is signed by several independent custodians, and the
engine **refuses to load it** if the signatures do not check out. Editing a rule without re-signing
breaks startup.

> Analogy: a club's rulebook, signed by three board members. The doorman does not enforce it because
> it is printed: he enforces it because he recognizes the signatures.

And every decision it makes is recorded **with the exact version of the rulebook** used. Without
that, reviewing a decision from two years ago would be impossible: nobody would know which rules it
was taken against.

### 3.9 Governance — *revoking takes people, not software*

Permanently revoking an identity takes **4 votes out of 5 delegates, from at least 3 different
countries**.

**Technology: WebAuthn**, the same standard behind physical security keys and phone fingerprint
readers.

There is a design detail here that is the heart of the system: **the challenge the physical key
signs IS the digest of the vote**. It is not "log in and then vote". The device signs exactly *the
content of what is being voted on*.

> Analogy: instead of showing ID at the door and then signing whatever paper is inside, the pen only
> writes when you press your finger **on that specific sheet**.

The practical consequence: **no program can vote.** An automated process can hold a delegate's
credential and still cannot produce a valid vote, because the device demands verification of a
human who is present. The system refuses it with an error that says so in as many words.

> The system administrator is read-only by construction. The only thing they can do with a
> revocation is execute one that was already decided, and the contract re-verifies the delegates'
> signatures before accepting it. A compromised administrator cannot revoke anybody.

### 3.10 Runtime attestation — *the building issues the badge, not you*

**Technology: SPIFFE/SPIRE.**

Until recently, when an agent connected and said *"I am running in this place, as this program"*,
the system believed it. It was signed... **by the agent itself**. It is a form you fill in about
yourself.

SPIRE changes that. It is a service that looks at the process **from outside** — it asks the
operating system who is running it, from which file, as which user — and only then hands over a
short-lived certificate.

> Analogy: the difference between writing your name on a list as you walk into a building, and
> reception taking your photo, checking your ID and printing you a badge with an expiry time. You
> cannot forge the second one alone.

What this blocks, concretely: an agent holding a **perfectly valid** certificate can no longer use
it to pass as somebody else. The system checks that the certificate *names that identity*, and
refuses it otherwise.

### 3.11 The SDK — *the plug*

An SDK is the piece a developer drops into their program to talk to UAI. There are three (Python,
TypeScript, Go) and an MCP server for agents using that standard.

The design starts from an uncomfortable admission: **an SDK cannot force an agent to be
accountable**, because it runs inside the agent itself. The only thing you can do is make the
honest path the easy one. Hence this shape:

```python
with agent.action("send the quote to the customer") as act:
    result = do_the_work()
```

Consulting the policy, recording the outcome and signing it happen **on their own**, even if the
work fails. There is nothing to remember. A design where you had to call "record" at the end would
be a design where the actions that go wrong do not get recorded.

---

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
./deploy.sh nuke     # stop and delete the data
./deploy.sh status   # what is running, and on which ports
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

### The five surfaces

| Address | What it is | What to look at |
|---|---|---|
| `http://localhost:8081/` | Home | The overview, and what the system says about itself |
| `http://localhost:8081/verify.html` | **Verify** | The central screen: paste a UAI-ID and it says whether it is valid. This page **checks the proofs in your browser**; it does not display a verdict we handed it |
| `http://localhost:8081/explorer.html` | Explorer | The minute book: recorded actions and their proofs |
| `http://localhost:8081/quarantine.html` | Quarantines | Agents under preventive restriction, and what was suspended |
| `http://localhost:8081/governance.html` | Governance | Revocation proposals, who voted what, and under which threshold |
| `http://localhost:8081/agent.html?id=…` | Agent card | Everything public about one identity |

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
make attested    # that SPIRE certifies the runtime, not the agent itself: 7/7
make pentest     # 16 attacks from outside; fails if any of them works
make invariants  # 88 forbidden operations; fails if any is allowed
make check       # everything that has to pass before a commit
```

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
guardrail with its signed rulebook, contracts and anchoring, the five surfaces, three SDKs and an
MCP server, the 21-criteria demo, the security gates, and runtime attestation with SPIRE.

### What is missing, and what that means

| Missing | What it implies today |
|---|---|
| **Domain-control proof** | When a company says it owns `company.com`, nobody checks. It is a claim |
| **Notifying the owner on registration** | If somebody registers an agent in your company's name, it is visible but nobody tells you |
| **Rate limits** | Nothing stops anyone registering a thousand agents or flooding the system with accusations |
| **Artifact signing (SBOM)** | We know which process is running, not what code it was built from |
| **Counter-attestation** | An agent that only records the flattering actions leaves visible gaps, but nobody looks at them |
| **Cross-installation clone detection** | Detectable in principle, and detected by nobody |

**The direct, honest consequence:** the assurance level is the **minimum** across three dimensions —
how the key is held, how the owner was verified, and how the runtime was certified. Since owner
verification does not exist yet, **every identity sits at the lowest level (AL0)**, even one with a
hardware key and a certified runtime.

The system does not just state the level: it states **which dimension is holding it down**. Querying
a registered agent, the response carries these three fields:

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
| Everything is strange after poking at things | `make nuke && make dev` — deletes the volumes and starts clean |

---

## 7. Where to go next

- [`README.md`](../README.md) — the project summary
- [`docs/protocol/`](protocol/) — the full specification, 26 sections
- [`docs/protocol/13-threat-model.md`](protocol/13-threat-model.md) — what can go wrong, what stops
  it, and which controls **do not exist yet**
- [`docs/security/pentest-checklist.md`](security/pentest-checklist.md) — what is attacked
  automatically and what needs a person
- [`SECURITY.md`](../SECURITY.md) — how to report a vulnerability

> If you find a way to break any of the ten rules in the threat model, that is exactly the report we
> most want.
