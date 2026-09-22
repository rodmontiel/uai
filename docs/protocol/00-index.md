# UAI — Architecture & Protocol Definition v0.1

| | |
|---|---|
| **Document** | UAI Architecture & Protocol Definition |
| **Version** | 0.1.0-draft |
| **Status** | Draft — normative intent, not yet ratified |
| **Date** | 2026-09-22 |
| **Protocol name** | Universal Agent Identity (UAI) |
| **Core artifacts** | `UAI-ID` · `UAI Credential` · `UAI Passport` · `UAI Action Attestation` |
| **License intent** | Specification: CC-BY-4.0 · Reference implementation: Apache-2.0 |

## What this document is

The normative definition of the UAI protocol and the architecture of its reference
implementation. It is written so that a third party — a cloud provider, a bank, a model
vendor, a regulator — can implement an interoperable verifier **without running any code
written by the UAI consortium**.

## What UAI claims, and what it does not

UAI **does not** claim that a registered agent is safe. It claims that an action can be
*attributed* to a cryptographically verifiable identity, with a declared owner, declared
capabilities, a declared purpose, and the exact policy version in force at the moment of
the decision.

UAI **has no global kill switch**. Revocation means: *participating organizations will no
longer accept this identity's credentials*. Code on a disconnected machine keeps running.
This limit is designed-in and stated in every layer — see [§26 Limitation](12-privacy.md)
and [Threat Model](13-threat-model.md).

## Section map

The 26 required sections are distributed across the files below. Each file states the
sections it covers in its header.

| § | Section | File |
|---|---|---|
| 1 | Executive Summary | [01-overview.md](01-overview.md) |
| 2 | Problem Statement | [01-overview.md](01-overview.md) |
| 3 | Design Principles | [01-overview.md](01-overview.md) |
| 4 | Actors | [02-actors-trust.md](02-actors-trust.md) |
| 5 | Trust Model | [02-actors-trust.md](02-actors-trust.md) |
| 6 | Identity Architecture | [03-identity.md](03-identity.md) |
| 7 | Cryptographic Architecture | [04-cryptography.md](04-cryptography.md) |
| 8 | Agent Registration Protocol | [05-registration-binding.md](05-registration-binding.md) |
| 9 | Agent Binding Protocol | [05-registration-binding.md](05-registration-binding.md) |
| 10 | Action Attestation Protocol | [06-action-attestation.md](06-action-attestation.md) |
| 11 | Passport Protocol | [07-passport.md](07-passport.md) |
| 12 | Guardrail Architecture | [08-guardrail.md](08-guardrail.md) |
| 13 | Quarantine Protocol | [09-quarantine-investigation.md](09-quarantine-investigation.md) |
| 14 | Harm Investigation Protocol | [09-quarantine-investigation.md](09-quarantine-investigation.md) |
| 15 | Human Governance Protocol | [10-governance-revocation.md](10-governance-revocation.md) |
| 16 | Revocation Protocol | [10-governance-revocation.md](10-governance-revocation.md) |
| 17 | Blockchain Architecture | [11-ledger-transparency.md](11-ledger-transparency.md) |
| 18 | Transparency Architecture | [11-ledger-transparency.md](11-ledger-transparency.md) |
| 19 | Privacy Model | [12-privacy.md](12-privacy.md) |
| 20 | Threat Model | [13-threat-model.md](13-threat-model.md) |
| 21 | Database Architecture | [14-database.md](14-database.md) |
| 22 | API Architecture | [15-api.md](15-api.md) |
| 23 | Deployment Architecture | [16-deployment.md](16-deployment.md) |
| 24 | MVP Scope | [17-mvp-scope.md](17-mvp-scope.md) |
| 25 | Repository Structure | [18-repository-structure.md](18-repository-structure.md) |
| 26 | Implementation Roadmap | [19-roadmap.md](19-roadmap.md) |

## Conventions

- **RFC 2119 / RFC 8174** keywords (MUST, SHOULD, MAY) are normative when capitalized.
- Identifiers in `did:uai:...` form are DIDs; `uai:agent:...` form are UAI-IDs. They are
  the same identifier with and without the DID scheme prefix — see [§6](03-identity.md).
- All byte strings are lowercase hex or `base64url` without padding, stated per field.
- JSON shown as `jcs(...)` means RFC 8785 JSON Canonicalization Scheme applied first.
- Priority order for every design trade-off in this document:
  **security > auditability > interoperability > simplicity > performance > visual polish.**

## Reading order for implementers

1. [01-overview.md](01-overview.md) — why and what.
2. [03-identity.md](03-identity.md) + [04-cryptography.md](04-cryptography.md) — the two files a verifier must implement.
3. [06-action-attestation.md](06-action-attestation.md) — the wire format that carries accountability.
4. [11-ledger-transparency.md](11-ledger-transparency.md) — how a claim becomes independently checkable.
5. [13-threat-model.md](13-threat-model.md) — what this does not protect against.
