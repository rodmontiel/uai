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

Each invariant has negative tests at two or more layers, and
[`test/invariants/coverage_test.go`](test/invariants/coverage_test.go) fails the build if one of
them stops. If you find a way past them, that is the report we most want.

## Before reporting, you can reproduce our own checks

```bash
make pentest             # attacks a live gateway from outside; fails if anything succeeds
make invariants          # what the database refuses, from inside
make invariant-coverage  # every INV-001..010 has a negative test, in two layers
make threats             # 20 of the threat model, checked against the repository
```

[`docs/security/pentest-checklist.md`](docs/security/pentest-checklist.md) lists what is
automated and what still needs a person, and
[§20.5](docs/protocol/13-threat-model.md#205-controls-named-in-201-that-do-not-exist-yet) lists
the controls named in the threat model that **do not exist yet** — rate limiting, `did:web`
domain-control proof, owner notification on registration, SBOM and artifact signing,
counter-attestation, and cross-instance fork observation. Reporting one of those is welcome but
it is not a finding; it is a roadmap item we have written down.

## Explicitly out of scope

These are documented accepted risks, not defects — see §20.2 of the threat model:

- Prompt injection causing an agent to take an authorized-but-undesirable action.
- Impersonation of an `UAI-AL0`/`UAI-AL1` identity whose software key was stolen.
- Collusion of a quorum of human delegates.
- A revoked agent's code continuing to run outside the UAI ecosystem. **UAI has no global kill
  switch and does not claim one.**
