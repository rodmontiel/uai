# Security Policy

## Reporting a vulnerability

Report privately to `security@uai.world` (PGP key at `https://uai.world/.well-known/pgp-key.txt`).
Do not open a public issue for a vulnerability affecting identity, governance, cryptography or
the transparency log.

We aim to acknowledge within 72 hours and to publish a fix or mitigation within 90 days.

## What we consider a vulnerability

Anything that breaks one of the security invariants in
[`docs/protocol/13-threat-model.md`](docs/protocol/13-threat-model.md):

| | |
|---|---|
| INV-001 | An identity is verified without cryptographic proof |
| INV-002 | An action is attributed by string ID alone |
| INV-003 | Evidence can be edited or deleted |
| INV-004 | A vote can be modified |
| INV-005 | A non-human path to permanent revocation exists |
| INV-006 | A revoked identity loses its history |
| INV-007 | A secret can reach the ledger |
| INV-008 | Full PII can reach the ledger |
| INV-009 | A guardrail decision omits its policy version |
| INV-010 | Revocation executes without valid human decision evidence |

A proof-of-concept that violates any of these is always in scope, including through
configuration, migrations, CI, or the frontend.

## Explicitly out of scope

These are documented accepted risks, not defects — see §20.2 of the threat model:

- Prompt injection causing an agent to take an authorized-but-undesirable action.
- Impersonation of an `UAI-AL0`/`UAI-AL1` identity whose software key was stolen.
- Collusion of a quorum of human delegates.
- A revoked agent's code continuing to run outside the UAI ecosystem. **UAI has no global kill
  switch and does not claim one.**
