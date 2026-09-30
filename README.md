# Universal Agent Identity (UAI)

> **Every AI agent should be accountable.**

**UAI is an open protocol for identity, authorization, and independently verifiable accountability of autonomous AI agents.**

Give an agent an identity.
Bind it to an accountable owner.
Define what it is allowed to do.
Record what it actually does.
Let others verify the evidence without trusting the registry that produced it.

![The identity card of a registered agent: identifier, DID, status, assurance level with the
reason it is not higher, the anchor of its event chain, and the credentials issued with
it](docs/img/agent-passport.png)

<sub>A real agent in a running stack, captured by <code>make screenshots</code>. Every value comes
from the API — including <code>UAI-AL0 — how strongly the identity was established, not how safe
the agent is</code>, which is the sentence this project exists to keep saying.</sub>

> **Identified ≠ safe.**
>
> UAI does not claim that an AI agent is safe. It provides a mechanism for making an agent's actions **attributable and independently verifiable**.

[![Status](https://img.shields.io/badge/status-prototype-orange)](#whats-implemented)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](#license)
[![Protocol](https://img.shields.io/badge/protocol-UAI--v0.1-purple)](#protocol-and-standards)
[![Documentation](https://img.shields.io/badge/docs-available-green)](#where-to-start)

---

## Why UAI?

AI agents are increasingly being given the ability to act on behalf of people and organizations.

They can:

* send emails
* access customer records
* call APIs
* modify infrastructure
* execute workflows
* move money
* make decisions within delegated authority
* interact with other autonomous agents

But when something goes wrong, the audit trail can still look like this:

```text
bot-27 changed firewall rule X
```

The system that performed the action is often also the system that wrote the log.

UAI explores a different model:

```text
IDENTITY
   ↓
OWNER
   ↓
CAPABILITIES
   ↓
AUTHORIZATION
   ↓
ACTION
   ↓
SIGNED ATTESTATION
   ↓
INDEPENDENT VERIFICATION
```

The goal is not to make an agent trustworthy by declaration.

The goal is to make its identity, authority, and actions **checkable evidence**.

> **"Who was this agent?"**
>
> **"Who was responsible for it?"**
>
> **"What was it allowed to do?"**
>
> **"What actually happened?"**
>
> **"Can I verify that independently?"**

UAI is an attempt to provide a protocol-level answer to those questions.

---

# What makes UAI different?

UAI is not only an identity registry.

It combines several layers that are usually treated separately:

```text
Agent Identity
      +
Owner / Responsibility
      +
Capabilities
      +
Time- and jurisdiction-bounded authorization
      +
Signed action attestations
      +
Transparency evidence
      +
Independent verification
      +
Federated registries
```

The central idea is:

> **Identity tells you who an agent is. Authorization tells you what it may do. Attestation records what it actually did. Verification lets a third party check the evidence.**

And an important distinction:

> **UAI does not attempt to create a single global authority that every agent must trust.**

The longer-term model is a network of independently operated registries that can exchange signed statements and verify each other's evidence.

---

# The four UAI artifacts

| Artifact                   | Question                         | Purpose                                                       |
| -------------------------- | -------------------------------- | ------------------------------------------------------------- |
| **UAI-ID**                 | Who is this agent?               | Globally unique agent identity                                |
| **UAI Credential**         | Who is responsible for it?       | Binds an agent to an owner, organization, and capabilities    |
| **UAI Passport**           | Where and until when may it act? | Time- and jurisdiction-bounded authorization                  |
| **UAI Action Attestation** | What did it actually do?         | Signed, hash-chained evidence of actions and policy decisions |

Think of them as four different questions:

```text
Credential
"This agent may read customer records."

Passport
"This agent may do so in Argentina and Germany until 2027-03-21."

Attestation
"This agent attempted to read customer record X
at time T, under policy version P,
and the decision was ALLOW / DENY."
```

A passport cannot grant a capability that the owner did not grant.

---

# See it in action

The repository contains a working reference implementation.

Clone it:

```bash
git clone https://github.com/rodmontiel/uai.git
cd uai
```

Start the local environment:

```bash
./deploy.sh up
```

Run the end-to-end demonstration:

```bash
make demo
```

The demo exercises the accountability path:

```text
register
   ↓
bind owner
   ↓
issue credentials
   ↓
issue passport
   ↓
execute agent action
   ↓
evaluate policy
   ↓
ALLOW / DENY / QUARANTINE
   ↓
attest outcome
   ↓
verify evidence
```

If you only have a few minutes, start here.

---

# Independent verification

One of the core design principles of UAI is:

> **Do not ask the registry whether its own evidence is valid. Verify it yourself.**

The browser verifier can validate evidence locally, including:

* signatures
* inclusion proofs
* checkpoints
* witness signatures
* event-chain continuity
* policy information

The verifier should not simply call an API such as:

```text
"is this agent valid?"
```

and render the answer.

That would merely move trust into a nicer interface.

The verification logic is intentionally small and dependency-conscious so that a relying party can inspect what is actually being verified.

An independent implementation should be able to verify UAI evidence without depending on the UAI reference implementation.

---

# A minimal accountable action

The SDK is designed to make the accountable path the natural programming model:

```python
with agent.action(
    capability="route.optimize",
    purpose="delivery_optimization",
    jurisdiction=Jurisdiction(
        origin="AR",
        targets=("DE",),
        basis="resource_location",
    ),
    input=order,
) as act:

    act.output = optimize(order)
```

The SDK evaluates the guardrail before entering the block.

If the action is denied, the business logic does not execute.

If the action succeeds, fails, throws an exception, or is refused by policy, the outcome can be attested.

Inputs and outputs can be represented as salted commitments rather than being sent to the registry as plaintext.

---

# Federation

## What if AI-agent identity worked more like Internet routing than a global database?

The long-term vision is not a single global registry containing every AI agent.

It is a **network of independently operated UAI registries**.

The model is inspired by Internet routing:

| Internet           | UAI                     |
| ------------------ | ----------------------- |
| Autonomous System  | UAI Registry            |
| ASN                | UAI-ASN                 |
| BGP peering        | Registry peering        |
| BGP OPEN           | `REGISTRY_HELLO`        |
| Route announcement | `IDENTITY_ANNOUNCEMENT` |

A registry can say:

> "I issued this identity."

Another registry can verify the signed statement without importing the first registry's entire database or treating the remote agent as one of its own.

The key principle is:

> **PEER TRUST ≠ AGENT TRUST**

Peering means:

> "This registry may send me signed statements."

It does **not** mean:

> "I trust every agent issued by this registry."

---

# Federation prototype

The repository contains a two-registry federation demonstration:

```bash
make federation-demo
```

It demonstrates:

* independent registry identities
* explicit mutual peering
* signed identity announcements
* sequence checking
* authority checking
* remote identity storage
* rejection of replayed announcements
* separation between local and federated identities

The current implementation is intentionally limited.

### Not implemented yet

The following are research / implementation areas rather than completed functionality:

* multi-hop transit
* route selection
* automatic peer discovery
* RPKI-like registry authority
* route reflectors / confederations
* cross-registry revocation propagation
* passport federation
* federation-wide discovery
* federation consensus

These are also potential contribution areas.

---

# What UAI claims — and what it does not

UAI is deliberately conservative about its claims.

### UAI provides mechanisms for:

* identifying an agent
* binding an agent to an accountable owner
* expressing capabilities
* expressing authorization constraints
* recording signed outcomes
* building verifiable evidence chains
* independently checking evidence
* federating registries

### UAI does **not** claim that:

* an identified agent is safe
* an owner cannot be compromised
* an agent cannot execute after revocation
* a registry is automatically trustworthy
* federated registries automatically trust each other's agents
* cryptographic proof guarantees correct software behavior
* the current federation prototype is production-ready

This distinction is fundamental:

```text
identified ≠ trustworthy
authorized ≠ safe
attested ≠ correct
revoked ≠ stopped
```

The protocol is intended to make these distinctions explicit rather than hiding them.

---

# What happens after revocation?

UAI is not a global kill switch.

Suppose an agent is revoked.

A participating relying party can refuse to honor:

```text
agent identity
credentials
passport
authorization
```

But code already running on a disconnected machine does not magically stop.

This is intentional.

UAI addresses **identity, authority, evidence, and verification**.

It does not claim to provide universal physical control over every execution environment.

---

# Failure is evidence too

A system that records only successful actions is an advertisement.

UAI treats failures and policy decisions as first-class outcomes.

Depending on the implementation, an attestation may represent:

```text
ALLOW
DENY
QUARANTINE
ERROR
EXCEPTION
```

The intent is to preserve an auditable account of what happened rather than recording only the happy path.

---

# Privacy by construction

Accountability does not require publishing the agent's private inputs and outputs.

Where appropriate, UAI can represent sensitive material using commitments, hashes, or other cryptographic evidence instead of sending plaintext payloads to the registry.

The goal is:

```text
verifiable evidence
        without
unnecessary disclosure
```

The exact privacy guarantees depend on the deployment and cryptographic primitives used.

UAI should not be treated as a complete privacy solution by itself.

---

# Architecture

At a high level:

```text
                    ┌────────────────────┐
                    │    AI Agent        │
                    └─────────┬──────────┘
                              │
                       UAI SDK / API
                              │
               ┌──────────────┴──────────────┐
               │                             │
               ▼                             ▼
        Policy Evaluation              Action Execution
               │                             │
               └──────────────┬──────────────┘
                              │
                              ▼
                     Action Attestation
                              │
                              ▼
                    Transparency Layer
                              │
                              ▼
                         UAI Registry
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
               Local Agent        Federated Registry
                                        │
                                        ▼
                                  Independent Verifier
```

The implementation includes protocol definitions, schemas, policy enforcement, cryptographic mechanisms, persistence, SDKs, verifier functionality, MCP tooling, and federation experiments.

See the protocol and architecture documentation for the detailed model.

---

# What's implemented?

UAI is a working reference implementation, not only a protocol document.

| Area                             | Status |
| -------------------------------- | ------ |
| Protocol specification           | ✅      |
| JSON schemas                     | ✅      |
| OpenAPI                          | ✅      |
| Cryptography                     | ✅      |
| Merkle / transparency mechanisms | ✅      |
| Policy engine                    | ✅      |
| Governance / revocation          | ✅      |
| Smart contracts                  | ✅      |
| Browser verifier                 | ✅      |
| Go SDK                           | ✅      |
| Python SDK                       | ✅      |
| TypeScript SDK                   | ✅      |
| MCP integration                  | ✅      |
| End-to-end demo                  | ✅      |
| Federation prototype             | ✅      |
| Security validation              | 🚧     |
| Production deployment            | 🚧     |
| Full federation                  | 🚧     |

The repository currently includes:

* protocol specifications
* JSON schemas
* example documents
* test vectors
* OpenAPI 3.1 definitions
* PostgreSQL persistence
* cryptographic primitives
* policy evaluation
* transparency receipts
* governance contracts
* browser verification
* Go, Python, and TypeScript SDKs
* MCP tooling
* end-to-end demonstrations
* federation experiments

See the repository documentation for the detailed implementation matrix.

---

# Design principles

UAI follows a few principles that shape the implementation:

```text
security
   >
auditability
   >
interoperability
   >
simplicity
   >
performance
   >
visual polish
```

### Evidence over assertions

Security properties should be enforced by code, schemas, signatures, and tests — not only by documentation.

### Verification over trust

A relying party should be able to verify evidence without depending on the issuer's API being honest.

### Accountability without surveillance

The system should make actions attributable without requiring the registry to receive the agent's plaintext inputs and outputs unnecessarily.

### Policy as signed data

Policies are versioned and represented as independently verifiable data.

### Explicit trust boundaries

Registry trust, agent trust, authorization, and execution control are different things.

UAI does not try to collapse them into a single concept.

---

# Protocol and standards

UAI builds on existing standards and technologies rather than attempting to replace them:

* W3C DID
* W3C Verifiable Credentials 2.0
* SPIFFE / SPIRE
* RFC 8785 — JSON Canonicalization Scheme
* RFC 6962 — Merkle transparency
* RFC 9421 — HTTP Message Signatures
* IETF SCITT
* WebAuthn
* Open Policy Agent
* EVM smart contracts

The goal is to compose established primitives into an accountability layer for autonomous agents.

---

# Related work and interoperability

Agent identity is an emerging area with several different approaches.

UAI is intentionally focused on the combination of:

```text
agent identity
+
owner binding
+
capabilities
+
authorization scope
+
action attestations
+
independent verification
+
federated registries
```

For example, other ecosystems are exploring universal identifiers for agents, verifiable credentials, workload identity, and decentralized identity.

UAI is not intended to replace those systems.

Where interoperability makes sense, the protocol should be able to consume or reference established identity and credential mechanisms rather than creating unnecessary parallel standards.

---

# Where to start

| I want to...                | Start with                               |
| --------------------------- | ---------------------------------------- |
| Understand the problem      | `docs/Ejemplo_Practico_es.md`            |
| Understand the architecture | `docs/MANUAL.md`                         |
| Read the protocol           | `docs/protocol/00-index.md`              |
| Understand the threat model | `docs/protocol/13-threat-model.md`       |
| Explore federation          | `docs/Ejemplo_Practico_federation_es.md` |
| Run the implementation      | `./deploy.sh up` + `make demo`           |
| Run checks                  | `make check`                             |
| Build an SDK integration    | SDK directories                          |
| Inspect verification        | verifier implementation                  |

Spanish documentation is also available in `docs/MANUAL.es.md`.

---

# Contributing

UAI is intentionally designed to be challenged.

You do **not** need to agree with the protocol.

In fact:

> **Finding where it breaks may be more valuable than adding another feature.**

Contributions are welcome in:

### 🔐 Security

Try to break the assumptions.

Look for:

* replay attacks
* identity confusion
* authority confusion
* signature misuse
* chain forks
* policy bypasses
* confused-deputy paths
* trust-boundary violations

### 🌐 Federation

Work on:

* multi-hop propagation
* route selection
* peer discovery
* revocation propagation
* cross-registry authorization
* federation observability

### 🧩 SDKs

Build integrations for additional languages, runtimes, or agent frameworks.

### 🔎 Independent verification

Build a verifier that does not depend on the UAI reference implementation.

### 📐 Protocol design

Challenge the specification itself.

A useful protocol issue should look something like:

```text
Problem
-------
What assumption or mechanism are you challenging?

Evidence
--------
Example, attack, interoperability problem, or alternative design.

Proposal
--------
What would you change?

Trade-offs
----------
What does the proposed change improve or make worse?
```

---

# Good first contributions

Some practical areas for contributors:

```text
good first issue
help wanted
security
protocol
federation
sdk
verifier
documentation
tests
examples
```

A small contribution is useful too:

* improve an example
* add a test vector
* document a threat
* port an SDK
* implement a verifier feature
* reproduce an edge case
* challenge a protocol assumption

You don't have to build the whole system.

---

# Repository quality

The repository is intended to be executable and inspectable, not merely illustrative.

Before opening a PR:

```bash
make check
```

Please include tests for protocol or implementation changes where applicable.

For security-sensitive changes, explain the security assumption and threat model being addressed.

---

# Explicit limitations

The following limitations are intentionally documented rather than hidden:

* An identity does not prove that the agent's software is safe.
* A credential does not prove that its owner is trustworthy.
* Authorization does not prove that the authorized action is beneficial.
* An attestation does not prove that the software behaved correctly internally.
* Revocation does not guarantee that already-running code has stopped.
* A federated registry is not automatically trusted merely because it is a peer.
* Cryptographic evidence does not eliminate operational compromise.
* The current federation implementation should be treated as experimental.
* Production-grade deployment requires additional security review, operational hardening, and independent validation.

---

# Security

Please see `SECURITY.md` before reporting security-sensitive issues.

For protocol-level security concerns, include enough technical detail to reproduce or reason about the issue without unnecessarily exposing sensitive information.

---

# License

Reference implementation: **Apache-2.0**

Specification: additionally **CC-BY-4.0**, allowing independent implementations and republication, including by standards organizations.

See the repository license files for the exact terms.

---

# Join the experiment

UAI is an attempt to answer a simple question:

> **When an autonomous AI agent acts on your behalf, how can somebody else independently determine who it was, who authorized it, what policy applied, and what actually happened?**

There are many possible answers.

This repository is one of them.

**Read it. Run it. Break it. Fork it.**

⭐ Star the repository if you want to follow the project.

🍴 Fork it if you want to experiment.

💬 Open an issue or discussion if you think the protocol is wrong.

🔐 Try to break its security assumptions.

🌐 Help explore federated agent identity.

🧑‍💻 Build an independent implementation.

The goal is not to prove that UAI is the final answer.

The goal is to make the problem concrete enough that other engineers can **test it, challenge it, and improve it**.

---

## About

Just a simple engineer thinking about Skynet 😂
