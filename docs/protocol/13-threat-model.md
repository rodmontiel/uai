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

## 20.4 Control validation

§20.1 lists controls. This section says which of them **exist**, and names the artifact that
demonstrates each one — because a register that reads as though everything in the Controls column
were implemented is a more dangerous document than no register at all. The preamble hedges it
("residual risk is what remains *after* the listed controls are implemented as specified"); nobody
reads a table that way.

Status vocabulary:

| Status | Meaning |
|---|---|
| **ENFORCED** | The control exists and a named test asserts it. A regression fails the build |
| **PARTIAL** | Some of §20.1's controls exist and some do not. The missing ones are listed in [§20.5](#205-controls-named-in-201-that-do-not-exist-yet), and until they do, the residual risk is **higher** than §20.1 states |
| **ACCEPTED** | [§20.2](#202-accepted-risks) accepts this residual. The evidence shows the system behaving as described, not preventing it |
| **PLANNED** | None of the listed controls exists yet |

`make threats` checks this table against the repository: every threat in §20.1 needs a row, every
path named here has to exist, and every status has to come from the vocabulary above.

### Identity and key threats

| ID | Status | Evidence | What the evidence shows |
|---|---|---|---|
| T-01 | PARTIAL | `internal/api/registration.go`, `pkg/challenge/` | Registration issues a challenge that the agent's key and the owner's key must each answer. Domain-control proof for `did:web` and notification to the claimed owner do not exist |
| T-02 | ACCEPTED | `internal/store/store.go` (`ErrFork`), `internal/api/binding.go` | Rotation keeps history; key validity is time-bounded and checked at signing time, not at reading time. A stolen software key still produces valid attestations until it is declared |
| T-03 | PARTIAL | `pkg/spiffe/`, `internal/api/runtime.go`, `demo/attested.py` | The SPIFFE ID in a binding is now read off an SVID SPIRE issued to that process, so a clone cannot claim the original's runtime: `make attested` shows a genuine SVID refused for another agent. The image digest is still the agent's own claim, and cross-instance fork detection — the case that matters most — is an observation nothing performs yet |
| T-04 | PARTIAL | `internal/api/registration.go` | Assurance level is carried and published, so a relying party can refuse AL0. Per-owner registration rate limits do not exist |
| T-05 | PARTIAL | `internal/api/credentials.go` | Organization credentials are issued and logged. Legal-entity verification and `did:web` domain control are not implemented |
| T-06 | ENFORCED | `internal/api/escalate.go`, `test/invariants/invariants.sql` (QUAR) | A quarantine order names the agent and the capabilities it suspends; nothing in it reaches another organization's agents |
| T-07 | PARTIAL | `deploy/spire/conf/agent.conf`, `pkg/spiffe/spiffe.go` | A workload attestor derives identity from what the kernel reports about a process — facts it cannot assert about itself — and the registry refuses a binding whose SVID does not verify. SBOM, artifact signing and provenance attestation still do not exist, so what runs is attested and what it was BUILT from is not |

### Protocol and message threats

| ID | Status | Evidence | What the evidence shows |
|---|---|---|---|
| T-08 | ENFORCED | `internal/store/request.go` (`NonceCache`), `pkg/pop/`, `internal/api/middleware.go` | A nonce is recorded on first use and refused on the second; the `created` window bounds how long a captured request is worth replaying; attestation nonces are unique per agent |
| T-09 | ENFORCED | `pkg/attest/attest_test.go`, `test/invariants/invariants.sql` (INV-002) | An attestation without a signature is refused by the database, and one whose signature does not cover the canonical bytes is refused by the verifier |
| T-10 | ENFORCED | `pkg/uaicrypto/digest.go`, `spec/test-vectors/digest/`, `test/invariants/invariants.sql` | Every digest carries its domain string. A signature made for one purpose does not verify for another, and the database refuses an attestation relabelled into another domain |
| T-11 | PARTIAL | `internal/api/policy.go`, `pkg/attest/attest.go` | Every action carries a purpose and is evaluated individually rather than under a session grant. Counter-attestation by the target system does not exist |
| T-12 | ACCEPTED | `demo/demo.py`, `docs/protocol/17-mvp-scope.md` | Out of scope by design. The resulting action is attributed, evaluated and recorded; nothing here prevents the manipulation |
| T-13 | ENFORCED | `mcp/tools.go`, `mcp/mcp_test.go` (`TestNoToolGrantsCapabilities`), `db/migrations/0006_capability_requests.up.sql` | No MCP tool grants a capability, no API route grants one to its own caller, and the database refuses a grant whose grantor is the agent itself |
| T-14 | ACCEPTED | `demo/demo.py` (the step after revocation) | The agent's code keeps running after revocation. The demo shows it rather than implying otherwise |

### Log, ledger and infrastructure threats

| ID | Status | Evidence | What the evidence shows |
|---|---|---|---|
| T-15 | ENFORCED | `internal/translog/log.go`, `test/invariants/invariants.sql` (INV-003) | The log is append-only in the database and Merkle-structured above it; a rebuilt tree that disagrees with the last published checkpoint refuses to open rather than issuing confident proofs |
| T-16 | ENFORCED | `internal/translog/witness.go`, `tools/uai-verify/` | Checkpoints are co-signed, a checkpoint below the threshold is reported UNDERWITNESSED rather than silently downgraded, and `uai-verify` checks the co-signatures itself |
| T-17 | PLANNED | `contracts/` | The contracts exist and the consortium chain does not. `noop-dev` is the only anchor adapter, and it says so instead of fabricating a transaction |
| T-18 | PARTIAL | `internal/pdp/pdp.go` | Policy evaluation is fail-closed and works from a signed bundle held in memory, so a PDP outage does not become an allow. Rate limiting does not exist |
| T-19 | ENFORCED | `test/invariants/invariants.sql` (INV-003), `internal/api/invariant_test.go` | Evidence cannot be edited, deleted or truncated; crypto-shredding clears the content and keeps the commitment; and no API path or service statement writes to the evidence tables |
| T-20 | ENFORCED | `internal/api/registration.go` (`model_pinned`) | Identity does not depend on the provider. An owner can require a specific model version, and a provider breach yields no agent private key |

### Governance and human threats

| ID | Status | Evidence | What the evidence shows |
|---|---|---|---|
| T-21 | ENFORCED | `internal/api/governance_test.go` (`TestAnAdministratorCannotChooseAnything`), `contracts/test/Revocation.t.sol` | The administrator's only input to a revocation is a decision id. The contract verifies the delegates' signatures, so an administrator who reaches the chain still cannot decide anything |
| T-22 | ENFORCED | `pkg/webauthn/`, `db/migrations/0002_governance.up.sql` | A vote is a hardware assertion with user verification; one delegate is below every threshold the bundle allows |
| T-23 | ACCEPTED | `pkg/governance/governance.go` (`Proof`) | A colluding quorum can revoke an innocent agent. Every vote is individually attributable and permanently recorded; that is the mitigation, and it is not prevention |
| T-24 | PARTIAL | `db/migrations/0002_governance.up.sql` (`suspicion_reporter_identified`), `internal/api/capability.go` | Reports are signed and attributable, and repeated reports from one reporter do not manufacture corroboration. Rate limits and automatic abuse accounting against a reporter do not exist |
| T-25 | ENFORCED | `internal/pdp/pdp.go`, `tools/uai-policy/`, `policy/authority.json` | A bundle loads only if M-of-N independent signatures verify and the previous-hash chain holds. `make policy-verify` fails on an edited rule |
| T-26 | ENFORCED | `pkg/webauthn/webauthn.go`, `internal/api/governance.go` | The WebAuthn challenge **is** the vote digest, so a malicious frontend cannot alter what was voted without invalidating the assertion — and the tally rebuilds that digest from the statement rather than reading the value stored beside it |
| T-27 | ENFORCED | `db/migrations/0002_governance.up.sql` (quarantine CHECK), `test/invariants/invariants.sql` (QUAR) | A quarantine order without a review date and an expiry cannot be written, and a review date after the expiry is refused |

## 20.5 Controls named in §20.1 that do not exist yet

Extracted from the table above so they cannot be missed. Each one raises the residual risk of the
threats beside it above what §20.1 records:

| Missing control | Threats affected | Consequence today |
|---|---|---|
| Registration rate limits per owner | T-04, T-24 | Mass registration and accusation flooding are bounded by nothing but the database |
| `did:web` domain-control proof | T-01, T-05 | An organization DID is asserted, not demonstrated. A registrar check is the only thing between a claim and a fake company |
| Notification to the claimed owner on registration | T-01 | An identity registered in someone's name is discoverable but not announced |
| SBOM, artifact signing, provenance attestation | T-07 | A compromised build reaches production with a valid identity, because nothing ties the running image to a reviewed source |
| Counter-attestation by relying parties | T-11 | Selective non-attestation leaves gaps that are visible only to whoever goes looking |
| Cross-instance fork observation | T-03 | A cloned agent is detectable in principle and detected by nobody |
| An attestor-supplied image digest | T-03, T-07 | `image_digest` in a binding is the agent's claim about its own code. §6.8 wants the one the attestor observed, and until a selector supplies it the runtime dimension stops at AL1 |

None of these is hard in the sense of being unsolved. They are listed because a threat model that
describes intentions in the present tense is the specific failure mode this project has committed
to avoiding ([§26.4](19-roadmap.md) item 3).

## 20.6 Abuse cases (misuse of legitimate features)

| Abuse case | Feature abused | Mitigation |
|---|---|---|
| Accusation flooding to exhaust investigators | `HarmSuspicion` | Rate limits, deduplication, reporter accountability |
| Registering agents under a competitor's org name | Registration | Domain control proof, notification to the claimed org, challenge window |
| Using passports to legitimize an already-planned harmful action | Passport | Passport authorizes jurisdiction, never intent; per-action policy evaluation is independent of passport validity |
| "Unbind, rotate key, rebind" to launder a compromised identity | Self-binding | `continuity_proof` must be produced by a key valid at unbind time ([§9.3](05-registration-binding.md)) |
| Selective non-attestation (attest only the flattering actions) | Voluntary participation | Sequence gaps and dangling chain links are visible; counter-attestation by relying parties; gaps are a policy signal |
| Governance capture to eliminate competitors | Voting | Threshold from independent jurisdictions, permanent public attribution of every vote, published rationale |

## 20.7 Out of scope for v0.1

Declared, not omitted: model-weight provenance and evaluation attestation beyond a hash
reference; runtime behavioral analysis of agent internals; confidential-computing attestation
(TEE/SEV-SNP remote attestation is a roadmap item for AL4); side-channel resistance of agent
runtimes; anti-coercion for delegates; and detection of agents operating entirely outside UAI.
