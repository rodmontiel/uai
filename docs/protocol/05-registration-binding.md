# 8–9 · Agent Registration and Binding Protocols

> Covers sections **8** and **9**. Implements the self-binding principle (§9 of the product
> brief): an agent binds and unbinds itself without administrator intervention.

---

## §8 Agent Registration Protocol

### 8.1 Preconditions

| Requirement | Why |
|---|---|
| Owner holds a verified `OrganizationCredential` or an individual owner identity | Ownership must be attributable to a real party (§8 product brief) |
| Agent has generated a key pair it controls | Registration establishes possession, it does not distribute keys |
| Agent key is hardware-backed if target assurance ≥ AL2 | [§6.8](03-identity.md) |
| Idempotency key present | Registration is expensive and must be safely retryable ([§22](15-api.md)) |

UAI never generates an agent's private key. A registry that can generate your key can
impersonate you, which would void the entire attribution claim.

### 8.2 Flow

```mermaid
sequenceDiagram
    autonumber
    participant AG as Agent (SDK/Wallet)
    participant OW as Owner
    participant GW as uai-api-gateway
    participant REG as uai-agent-registry
    participant IDS as uai-identity-service
    participant CRED as uai-credential-service
    participant TL as uai-transparency-service
    participant LW as uai-ledger-writer

    OW->>GW: POST /agents {name, type, vendor, framework, owner_did, org_did, requested_capabilities}
    GW->>REG: create draft (idempotency-key)
    REG-->>OW: 202 {registration_id, challenge_owner, challenge_agent, expires_in: 300}
    OW->>GW: POST /agents/{rid}/prove (sig_owner over UAI-v1:challenge)
    AG->>GW: POST /agents/{rid}/prove (sig_agent over UAI-v1:challenge, public_jwk)
    GW->>REG: both proofs
    REG->>REG: verify both signatures reference the SAME (agent_pubkey, owner_did)
    REG->>IDS: mint ULID -> UAI-ID + DID
    IDS->>IDS: build DID Document v1 (agent key, controller=owner/org)
    IDS->>TL: append DID Document commitment
    TL-->>IDS: receipt {log_index, inclusion_proof, checkpoint}
    IDS->>CRED: issue AgentIdentityCredential + AgentOwnershipCredential
    CRED->>TL: append credential commitments
    CRED-->>REG: credentials
    REG->>LW: enqueue identity commitment
    LW->>LW: batch -> UAIIdentityRegistry.registerAgent(agentId, identityCommitment)
    REG-->>OW: 201 {uai_id, did, credentials, receipts, status: REGISTERED}
```

### 8.3 Registration record

The registry stores, and the transparency log commits to:

```json
{
  "uai_id": "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
  "did": "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
  "logical_name": "DeliveryOptimizer",
  "version": "1.4.2",
  "agent_type": "autonomous_task_agent",
  "org_did": "did:web:acme-robotics.example",
  "owner_did": "did:uai:owner:01JY8R9ZB0000000000000000",
  "vendor_model": { "vendor": "anthropic", "model_family": "claude", "pinned": false },
  "framework": "langgraph@0.2.x",
  "requested_capabilities": ["route.optimize", "crm.customer.read"],
  "assurance_level": "UAI-AL2",
  "primary_jurisdiction": "AR",
  "issued_at": "2026-09-22T14:02:01Z",
  "status": "REGISTERED",
  "identity_commitment": "sha256:…",
  "policy_version": "GASC-2027.4",
  "transparency": { "log_index": 184213, "checkpoint_size": 184300 }
}
```

`vendor_model.pinned = false` is meaningful: an agent's identity survives a model swap. Pinning
is available for agents whose assurance argument depends on a specific model version.

### 8.4 Status after registration

Registration yields `REGISTERED`, not `VERIFIED`. Promotion to `VERIFIED` requires the full
credential chain to validate (owner credential → org credential → issuer), and promotion to
`ACTIVE` additionally requires a runtime binding (§9). This staging is what makes
`UAI_REGISTERED` vs `UAI_VERIFIED` a meaningful distinction for relying parties
([§6.9](03-identity.md)).

### 8.5 Errors

| Condition | Code | HTTP |
|---|---|---|
| Owner proof and agent proof disagree on subject | `UAI_PROOF_MISMATCH` | 400 |
| Challenge expired or reused | `UAI_CHALLENGE_INVALID` | 401 |
| Owner credential revoked or suspended | `UAI_OWNER_NOT_ELIGIBLE` | 403 |
| Owner is `OWNER_RESTRICTED` and agent risk class is high | `UAI_OWNER_RESTRICTED` | 403 |
| Duplicate idempotency key, different body | `UAI_IDEMPOTENCY_CONFLICT` | 409 |
| Requested capability exceeds owner's own grant | `UAI_CAPABILITY_EXCEEDS_GRANT` | 403 |

Capabilities can never be self-elevated: an owner may only grant what it holds (§49 of the
product brief, restated here as a registry invariant).

## §9 Agent Binding Protocol

Binding is the act of associating a **runtime instance** with a **persistent identity**, and of
declaring participation in UAI. Three operations, all self-service, all requiring proof of
possession, all producing signed, logged, anchored events.

### 9.1 `BIND_AGENT`

```mermaid
sequenceDiagram
    autonumber
    participant W as UAI Agent Wallet
    participant SP as SPIRE Agent
    participant GW as uai-api-gateway
    participant REG as uai-agent-registry
    participant TL as uai-transparency-service

    W->>SP: fetch X509-SVID (workload attestation: k8s SA + image digest)
    SP-->>W: spiffe://uai.world/agents/01JY…/i/7f6a92 (TTL 1h)
    W->>GW: POST /agents/{id}/bind  (mTLS with SVID)
    GW-->>W: challenge (300s, audience=uai-agent-registry)
    W->>GW: sig_agent over jcs({challenge, "BIND_AGENT", uai_id, audience, svid_spiffe_id, svid_cert_hash})
    GW->>REG: verify PoP + verify SVID chain + verify SVID subject matches uai_id
    REG->>REG: state ACTIVE, create runtime_identities row
    REG->>TL: append BindEvent
    TL-->>REG: receipt
    REG-->>W: 200 {status: ACTIVE, binding_id, receipt}
```

The signature covers both the persistent-key challenge **and** the SVID identifiers. That is
what cryptographically ties "who I am" to "where I am running" — either alone would be
forgeable by an attacker holding the other.

### 9.2 `UNBIND_AGENT`

An agent may leave UAI at any time without asking anyone. This is a stated principle, and it is
also a security property: a protocol you cannot leave is a protocol operators will refuse to
adopt.

```text
ACTIVE ──UNBIND_AGENT──▶ UNBOUND
```

Requirements:

1. Proof of possession by the agent key (or by the owner key, for the case of a lost agent).
2. A signed `UnbindEvent` containing the reason code and the last event hash.
3. Transparency log entry + ledger commitment.
4. **History is retained in full.** Unbinding is not deletion (INV-006). Existing attestations
   remain verifiable forever.
5. Runtime SVID entries are removed from SPIRE; in-flight credentials are added to the status
   list as `suspended` with reason `unbound`.

Verifier semantics for `UNBOUND`: *"This identity exists and its history is intact, but it is
not currently participating."* It is not a negative signal about past behavior.

### 9.3 `REBIND_AGENT`

```text
UNBOUND ──REBIND_AGENT──▶ ACTIVE
```

Cryptographic continuity is mandatory:

```json
{
  "operation": "REBIND_AGENT",
  "uai_id": "uai:agent:01JY…",
  "previous_event_hash": "sha256:…",        // last event before unbinding
  "unbound_at_log_index": 184913,
  "rebound_key": "did:uai:agent:01JY…#key-2",
  "continuity_proof": "signature by a key that was valid at unbind time"
}
```

If the agent key rotated while unbound, the `continuity_proof` MUST be produced by a key that
was valid at the moment of unbinding, and the new key MUST be introduced through a normal,
logged DID Document version. Without this rule, "unbind, rotate, rebind" would be a laundering
path for a stolen identity.

### 9.4 Event chain across bind/unbind

```mermaid
flowchart LR
    E1["EVENT 001<br/>register"] --> E2["EVENT 002<br/>bind"]
    E2 --> E3["EVENT 003<br/>action"]
    E3 --> E4["EVENT 004<br/>unbind"]
    E4 -.->|"gap: no events while UNBOUND"| E5["EVENT 005<br/>rebind<br/>prev = hash(EVENT 004)"]
    E5 --> E6["EVENT 006<br/>action"]
```

The chain does not restart. A verifier walking backwards from any action reaches the
registration event through an unbroken hash path, regardless of how many bind cycles occurred.

### 9.5 Idempotency and concurrency

- All three operations require an `Idempotency-Key`. Replays return the original result.
- Concurrent bind attempts from two instances of the same agent are allowed (an agent may run
  replicated) — each produces its own `runtime_identities` row with a distinct SVID, but they
  share the persistent identity and append to a **single** event chain, serialized by the action
  service using a per-agent sequence with optimistic concurrency on `previous_event_hash`.
- A rejected append due to a stale `previous_event_hash` returns `409 UAI_CHAIN_CONFLICT` with
  the current head, and the SDK retries. Two *successful* appends claiming the same predecessor
  are impossible within one service; if they are ever observed across services, that is a fork
  and is treated as an incident ([§10.6](06-action-attestation.md)).
