# 20 · Threat Model

> Covers section **20**, implementing §30 and §52 of the product brief. Methodology: STRIDE per
> trust boundary ([§5.4](02-actors-trust.md)), plus abuse cases derived from the governance
> mechanisms themselves. Scored **before** listing controls, so that a control's absence is
> visible rather than implied.

Scale: likelihood and impact are `LOW · MODERATE · HIGH · CRITICAL`. Residual risk is what
remains **after** the listed controls are implemented as specified.

---

## 20.1 Threat register

### Identity and key threats

| ID | Threat | STRIDE | Likelihood | Impact | Controls | Residual |
|---|---|---|---|---|---|---|
| T-01 | **Identity theft** — attacker registers an agent claiming to be another party's | S | MODERATE | HIGH | Two-sided ownership proof ([§6.4.1](03-identity.md)); org credential verification; `did:web` domain control; all registrations logged and notified to the claimed owner | LOW |
| T-02 | **Private key theft** (software key) | S/T | **HIGH** | **CRITICAL** | Hardware backing mandatory at AL2+; short-lived SVIDs; fork detection ([§10.6](06-action-attestation.md)); `KeyCompromiseDeclared` with time-bounded invalidation; rotation without history loss | **MODERATE** — accepted: a stolen AL0/AL1 software key produces valid attestations until detected. This is the strongest argument for AL2+ and is stated to adopters |
| T-03 | **Cloned agent** — same identity running in two places | S | HIGH | HIGH | Per-agent hash chain ⇒ fork is detectable and has no benign cause; SVID workload attestation ties instance to image digest; automatic HIGH-confidence suspicion on fork | LOW |
| T-04 | **Sybil attack** — mass fake agents/owners | S | HIGH | MODERATE | Owner verification tiers; org credential requires legal-entity proof at AL2+; registration rate limits per owner; AL0/AL1 explicitly labeled weak to relying parties | MODERATE (by design: registration is open; assurance level is the differentiator) |
| T-05 | **Fake owner** — unverified entity claims to be a company | S | MODERATE | HIGH | `did:web` domain control proof; registrar verification of legal entity; `OrganizationCredential` issuance is itself logged and challengeable | LOW |
| T-06 | **Compromised corporation** — a legitimate member is taken over | S/E | LOW | HIGH | Blast radius limited to that org's agents; per-org key rotation; quarantine scoped to affected agents; other members unaffected | MODERATE |
| T-07 | **Supply-chain attack** on the agent binary or SDK | T | MODERATE | CRITICAL | SPIRE workload attestation on image digest; SBOM + artifact signing + provenance attestation in CI ([§50](16-deployment.md)); SDK releases signed and transparency-logged; image digest recorded in runtime binding | MODERATE |

### Protocol and message threats

| ID | Threat | STRIDE | Likelihood | Impact | Controls | Residual |
|---|---|---|---|---|---|---|
| T-08 | **Replay** of a signed request or attestation | S | HIGH | MODERATE | Nonce + replay cache; RFC 9421 `created` window; audience-bound challenges; `previous_event_hash` already consumed; domain separation | LOW |
| T-09 | **Forged action attestation** | S/R | MODERATE | HIGH | Signature over canonical bytes with domain separation; key must be valid at log time; decision reference required; runtime identity must match mTLS peer | LOW (reduces to T-02) |
| T-10 | **Cross-context signature reuse** | S | MODERATE | HIGH | Mandatory domain separation strings ([§7.2](04-cryptography.md)); verifier MUST reject domain mismatch | LOW |
| T-11 | **Confused deputy** — agent induced to use its authority for another party's goal | E | **HIGH** | HIGH | Purpose attestation on every action; capability scoping; per-action policy evaluation rather than session-level trust; counter-attestation by target systems | MODERATE — mitigated, not solved; the agent's intent is not observable |
| T-12 | **Prompt injection** leading to unauthorized action | E | **CRITICAL** | HIGH | **Out of UAI's scope to prevent.** UAI ensures the resulting action is attributed, policy-evaluated and recorded; capability floor and human-approval gates limit reachable damage | **HIGH — explicitly accepted.** Stated plainly: UAI is an accountability layer, not a prompt-injection defense |
| T-13 | **Malicious tool invocation** via MCP or plugin | E | HIGH | HIGH | MCP tools cannot grant capabilities they don't already hold ([§49](15-api.md)); every tool call is an attested action; `uai_request_capability` is a request, never a grant | MODERATE |
| T-14 | **Agent escaping quarantine** — continues acting after suspension | E | HIGH | MODERATE | Quarantine propagates to status lists, verify endpoint, on-chain event and push notifications; SVID entries revoked; relying parties reject. **Cannot stop execution outside the ecosystem (P3)** | MODERATE — accepted and documented |

### Log, ledger and infrastructure threats

| ID | Threat | STRIDE | Likelihood | Impact | Controls | Residual |
|---|---|---|---|---|---|---|
| T-15 | **Log deletion / rewriting** | T/R | MODERATE | CRITICAL | Append-only Merkle log; consistency proofs; witness co-signing; on-chain anchors; per-agent hash chains as independent corroboration | LOW |
| T-16 | **Split view** — log shows different histories to different verifiers | T | MODERATE | CRITICAL | Independent witness co-signatures; verifiers require ≥ W witnesses; gossip between verifiers; public anchor | LOW |
| T-17 | **Blockchain validator collusion** (> f) | T | LOW | CRITICAL | QBFT bound `3f+1`; validators are independent organizations/countries; periodic public-chain anchor makes consortium-wide rewriting externally visible | LOW |
| T-18 | **Denial of service** against UAI services | D | HIGH | MODERATE | Rate limits per identity; offline buffering in the SDK; degraded-mode policy evaluation with cached signed bundles; fail-closed only for HIGH/CRITICAL risk classes | MODERATE |
| T-19 | **Compromised evidence** — tampered or fabricated | T | MODERATE | HIGH | Append-only vault; commitments in log and chain; chain of custody with signed access records; DB grants revoke UPDATE/DELETE (INV-003) | LOW |
| T-20 | **Compromised AI provider** — a model vendor is breached | S/T | LOW | HIGH | Identity is provider-independent by construction; `vendor_model.pinned` allows an owner to require a specific version; a provider compromise does not yield agent private keys | LOW |

### Governance and human threats

| ID | Threat | STRIDE | Likelihood | Impact | Controls | Residual |
|---|---|---|---|---|---|---|
| T-21 | **Malicious administrator** | E/T | MODERATE | CRITICAL | Read-only role by construction; the single write path (`EXECUTE_AUTHORIZED_REVOCATION`) is verified on-chain against delegate signatures; no admin path to evidence, votes, policy or quarantine; every admin action signed and logged | **LOW** — the system is designed to survive this |
| T-22 | **Compromised country delegate** | S | LOW | HIGH | Hardware authenticator with user verification; threshold (4-of-5) means one delegate is insufficient; countries can rotate delegates; votes are individually attributable forever | LOW |
| T-23 | **Delegate collusion** (≥ threshold) | E | LOW | CRITICAL | Threshold configurable upward; delegates from independent jurisdictions; all votes public and permanently attributable; evidence digest binding means a collusive vote is a documented act | **MODERATE — accepted.** This is the human trust floor: a quorum of corrupt delegates can revoke an innocent agent. The mitigation is transparency and reversibility of the *record*, not prevention |
| T-24 | **False accusation** used to disable a competitor | D/R | **HIGH** | HIGH | Signed, attributable reporters (no anonymous accusations); rate limits; independent-corroboration requirement; quarantine auto-expiry; scoped restrictions; abuse recorded against the reporter | MODERATE |
| T-25 | **Policy manipulation** — malicious GASC bundle | T/E | LOW | CRITICAL | M-of-N signing by independent custodians; `previous_policy_hash` chain; on-chain registration; PDPs verify signatures and chain before loading; effective-date staging allows review | LOW |
| T-26 | **Vote manipulation via compromised frontend** | T | MODERATE | HIGH | WebAuthn challenge **is** the vote digest ([§15.3](10-governance-revocation.md)) — a malicious frontend cannot alter the voted content without invalidating the assertion; delegate can verify the digest independently | LOW |
| T-27 | **Quarantine-as-punishment** (process abuse without a case) | D | MODERATE | MODERATE | Mandatory `review_by` and `expires_at`; automatic release on expiry; extension requires a signed investigator act; all restrictions and releases on-chain | LOW |

## 20.2 Accepted risks

Listed separately because a threat model that claims everything is mitigated is not a threat
model. These four are the honest residual surface of UAI v0.1:

1. **T-12 Prompt injection (HIGH).** UAI does not prevent an agent from being manipulated. It
   ensures the resulting action is attributed, evaluated against policy and permanently recorded.
2. **T-02 Software key theft (MODERATE).** AL0/AL1 identities can be impersonated until detected.
   The protocol's answer is assurance levels: relying parties requiring strong attribution must
   require AL2+.
3. **T-23 Delegate collusion (MODERATE).** A corrupt quorum can revoke an innocent identity. No
   cryptography fixes a corrupt human quorum; what the design provides is that the act is
   permanent, public, individually attributable and reviewable.
4. **T-14 Post-revocation execution (MODERATE).** Code keeps running outside the ecosystem. This
   is P3, and it is a property of reality, not a gap in the implementation.

## 20.3 Security invariants and their enforcement points

Each invariant is enforced at more than one layer, so that a single compromised layer does not
break it.

| Invariant | Enforced at |
|---|---|
| **INV-001** An identity is never "verified" without cryptographic proof | Gateway PoP middleware; `verify` endpoint logic; status vocabulary forbids inferring verification from absence of evidence |
| **INV-002** An action is never attributed by string ID alone | Attestation schema requires a signature; action service rejects unsigned; DB constraint `signature IS NOT NULL`; verification algorithm step 4 |
| **INV-003** No administrator can edit evidence | No API path exists; Postgres grants revoke UPDATE/DELETE on `evidence_items`; trigger raises on modification; commitment in log + chain makes tampering externally detectable |
| **INV-004** No administrator can modify votes | Votes are WebAuthn assertions over the vote digest — unforgeable without the authenticator; tally recomputed from signatures; contract re-verifies on execution |
| **INV-005** No AI can execute a permanent revocation | Delegate credentials bound to hardware authenticators with user verification; contract verifies delegate signatures; no service key can satisfy the check |
| **INV-006** A revoked identity retains its history | `DELETE` revoked at the DB grant level for identity tables; status transition only; log and chain are append-only |
| **INV-007** No secrets on the blockchain | CI schema check on contract call parameters; code review gate; contracts accept only `bytes32` and enums |
| **INV-008** No full PII on the blockchain | Same as INV-007, plus salted-commitment requirement making low-entropy recovery infeasible ([§19.3](12-privacy.md)) |
| **INV-009** Every guardrail decision names its exact policy version | `policy.version` + `policy.bundle_hash` are required fields; action service rejects attestations referencing an unknown decision; bundles retained for replay |
| **INV-010** Permanent revocation requires valid human decision evidence | Governance proof verified in `UAIRevocationRegistry.executeRevocation`; application layer verification is secondary, not primary |

Each invariant has a corresponding **negative test** in the test suite — a test that asserts the
forbidden operation fails. Those tests are the executable form of this table
([§51](17-mvp-scope.md)).

## 20.4 Abuse cases (misuse of legitimate features)

| Abuse case | Feature abused | Mitigation |
|---|---|---|
| Accusation flooding to exhaust investigators | `HarmSuspicion` | Rate limits, deduplication, reporter accountability |
| Registering agents under a competitor's org name | Registration | Domain control proof, notification to the claimed org, challenge window |
| Using passports to legitimize an already-planned harmful action | Passport | Passport authorizes jurisdiction, never intent; per-action policy evaluation is independent of passport validity |
| "Unbind, rotate key, rebind" to launder a compromised identity | Self-binding | `continuity_proof` must be produced by a key valid at unbind time ([§9.3](05-registration-binding.md)) |
| Selective non-attestation (attest only the flattering actions) | Voluntary participation | Sequence gaps and dangling chain links are visible; counter-attestation by relying parties; gaps are a policy signal |
| Governance capture to eliminate competitors | Voting | Threshold from independent jurisdictions, permanent public attribution of every vote, published rationale |

## 20.5 Out of scope for v0.1

Declared, not omitted: model-weight provenance and evaluation attestation beyond a hash
reference; runtime behavioral analysis of agent internals; confidential-computing attestation
(TEE/SEV-SNP remote attestation is a roadmap item for AL4); side-channel resistance of agent
runtimes; anti-coercion for delegates; and detection of agents operating entirely outside UAI.
