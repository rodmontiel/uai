# 22 · API Architecture

> Covers section **22**, implementing §36–38 and §47–49 of the product brief.

---

## 22.1 Shape

| Surface | Protocol | Auth | Audience |
|---|---|---|---|
| Public API | REST + JSON, OpenAPI 3.1 | mTLS (SPIFFE SVID) + RFC 9421 message signatures | Agents, owners, integrators |
| Universal verify | REST, unauthenticated GET | none | Anyone |
| Internal service-to-service | gRPC + protobuf | SPIFFE mTLS, OPA authz per method | UAI services |
| Governance UI | REST + WebAuthn session | WebAuthn, hardware-backed | Delegates, admin |
| Events | NATS JetStream | SPIFFE mTLS | Internal + subscribed participants |
| Agent SDK | REST under the hood | as public API | Python, TypeScript, Go |
| MCP | stdio / HTTP | agent identity from the wallet | Agent frameworks |

REST externally because a protocol meant to be implemented by everyone must be implementable
with `curl`. gRPC internally where the call volume and schema discipline justify it.

## 22.2 Endpoints (v1)

```text
# Identity lifecycle
POST   /v1/agents                          register (returns challenges)
POST   /v1/agents/{id}/prove               submit owner/agent proof of possession
GET    /v1/agents/{id}                     identity card
GET    /v1/agents/{id}/credentials         credential set
POST   /v1/agents/{id}/bind                BIND_AGENT
POST   /v1/agents/{id}/unbind              UNBIND_AGENT
POST   /v1/agents/{id}/rebind              REBIND_AGENT
GET    /v1/agents/{id}/events              event chain (paginated, proofs included)

# Passports
POST   /v1/passports/request
GET    /v1/passports/{id}
POST   /v1/passports/{id}/suspend          owner-initiated

# Actions
POST   /v1/policy/evaluate                 PDP decision (pre-action)
POST   /v1/actions/attest                  submit signed attestation (post-action)
GET    /v1/actions/{event_id}              attestation + receipt + proof

# Harm and governance
POST   /v1/suspicions
GET    /v1/cases/{id}
POST   /v1/cases/{id}/evidence
GET    /v1/quarantines
POST   /v1/governance/cases/{id}/vote/prepare
POST   /v1/governance/cases/{id}/vote
POST   /v1/revocations/{decision_id}/execute

# Verification (public, unauthenticated)
GET    /v1/verify/{uai_id}
GET    /v1/status-lists/{list_id}
GET    /v1/log/checkpoint
GET    /v1/log/proof?index={i}&size={n}

# Discovery
GET    /.well-known/uai-configuration
GET    /1.0/identifiers/{did}              DID resolution
```

## 22.3 Universal verify endpoint

The simplest possible surface, because adoption depends on it being trivial:

```http
GET https://verify.uai.world/uai:agent:01JY8R9ZAF392N7QX2T81JH6KM
```

```json
{
  "identity": "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
  "did": "did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM",
  "verified": true,
  "status": "ACTIVE",
  "assurance_level": "UAI-AL2",
  "owner_verified": true,
  "organization": "ACME Robotics",
  "passport_status": "VALID",
  "credential_valid": true,
  "quarantined": false,
  "revoked": false,
  "capabilities": ["route.optimize", "crm.customer.read"],
  "primary_jurisdiction": "AR",
  "policy_version": "GASC-2027.4",
  "last_transparency_checkpoint": {
    "log_origin": "uai.world/log/1", "size": 184300,
    "root": "sha256:9f2c…", "timestamp": "2026-09-22T14:02:05Z"
  },
  "last_anchor": { "chain_id": 13370, "tx": "0x…", "block": 8829112 },
  "proof": "https://verify.uai.world/uai:agent:01JY…/proof",
  "as_of": "2026-09-22T14:03:00Z",
  "cache_max_age": 60
}
```

Rules:

- **No authentication**, aggressively cached, served from a read replica. It must survive being
  linked from a public page.
- Always returns `200` with an explicit status — including for unknown identities, which return
  `verified: false, status: "UAI_UNVERIFIED"` and the normative sentence:
  *"No verifiable UAI identity exists for this identifier; this is not an assertion that the
  agent is malicious."* (P2)
- `proof` links to the machine-verifiable bundle. A verifier that only reads this JSON is
  trusting UAI; a verifier that follows `proof` is not. Both are legitimate, and the difference
  is documented rather than hidden.

### 22.3.1 QR representation

QR encodes **only** `https://verify.uai.world/{uai_id}` — no credential, no key, no secret, no
personal data. Scanning reveals a public identity page and nothing else; the QR is a pointer, and
its compromise costs nothing.

## 22.4 Proof of possession on the wire

Covered in [§7.6](04-cryptography.md). Gateway middleware enforces, in order: mTLS peer SVID →
message signature verification → nonce replay check → identity status → rate limit → route.

Failures are distinguishable, because "your signature is wrong" and "your identity is revoked"
require different responses from the caller:

| Condition | Code |
|---|---|
| No signature present | `401 UAI_POP_REQUIRED` |
| Signature invalid | `401 UAI_POP_INVALID` |
| Nonce reused | `401 UAI_REPLAY_DETECTED` |
| Clock outside window | `401 UAI_TIMESTAMP_OUT_OF_WINDOW` |
| SVID does not match identity | `403 UAI_RUNTIME_MISMATCH` |
| Identity quarantined | `403 UAI_IDENTITY_QUARANTINED` |
| Identity revoked | `403 UAI_IDENTITY_REVOKED` |

## 22.5 Errors — RFC 9457 problem+json

```json
{
  "type": "https://uai.world/problems/capability-not-granted",
  "title": "UAI_CAPABILITY_NOT_GRANTED",
  "status": 403,
  "detail": "Capability 'cloud.securitygroup.update' is not present in any valid grant for this agent.",
  "instance": "/v1/policy/evaluate",
  "decision_id": "01JY8RA3C0000000000000000",
  "policy_version": "GASC-2027.4",
  "remediation": "Request the capability from the owner, or obtain a passport that authorizes it.",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
}
```

Errors carry `decision_id` and `policy_version` wherever a policy was involved, so a refusal is
auditable and reproducible rather than an opaque denial.

## 22.6 Idempotency

- `Idempotency-Key` header is **required** on `POST /agents`, `/bind`, `/unbind`, `/rebind`,
  `/passports/request`, `/actions/attest`, `/suspicions`, `/vote`, `/execute`.
- Key + request-body hash are stored; a replay with the same key and body returns the original
  response with `Idempotency-Replayed: true`; same key, different body returns
  `409 UAI_IDEMPOTENCY_CONFLICT`.
- Retention 24 h.

Attestation submission is idempotent on `event_id` in addition, which is what makes offline
buffer flushes safe to retry ([§10.5](06-action-attestation.md)).

### 22.6.1 A retry MUST be re-signed

Idempotency and proof of possession interact in a way that is easy to get wrong, so it is
stated normatively:

> A retry reuses the `Idempotency-Key` and the request body, and carries a **fresh signature
> with a fresh `UAI-Nonce`**.

Resending the byte-identical request reuses the nonce, and a nonce is single-use by
construction: the gateway answers `401 UAI_REPLAY_DETECTED`. That is correct behavior, not a
defect — a replay cache that made exceptions for requests carrying a familiar header would not
be a replay cache. The idempotency key still does its job, because it is matched on the key and
the body, neither of which changes when the request is re-signed.

The two mechanisms answer different questions and are deliberately not merged:

| | Answers | Scope |
|---|---|---|
| `UAI-Nonce` | "Have I seen this exact signed message before?" | One transmission |
| `Idempotency-Key` | "Have I already performed this logical operation?" | One logical request, across retries |

Order of enforcement at the gateway is body capture, then proof of possession, then the
idempotency claim. Claiming the key first would let an unauthenticated caller burn another
party's keys by guessing them.

## 22.7 Versioning and compatibility

- URL-versioned (`/v1/`) for the REST surface; the wire objects carry `uai_version` independently,
  because a v1 API may carry a v0.2 attestation.
- Additive changes only within a major version; unknown fields MUST be ignored by verifiers and
  MUST be preserved when re-transmitting signed objects (dropping an unknown field breaks the
  signature — a compatibility rule with teeth).
- Deprecation: 12 months' notice, `Sunset` header, both versions accepted during overlap.

## 22.8 Rate limiting

Per identity, per endpoint class, from policy rather than code:

| Class | Default |
|---|---|
| `verify` (public) | 1000 req/min per IP, cached |
| `policy/evaluate` | 600 req/min per agent |
| `actions/attest` | 2000 req/min per agent (batching above) |
| Registration | 10 agents/hour per owner |
| `suspicions` | 20/hour per reporter (T-24 control) |
| Governance | 60/min per delegate |

Limits are enforced at the gateway and are themselves published, so an integrator can design
against them.

## 22.9 MCP server (`uai-mcp`)

| Tool | Effect |
|---|---|
| `uai_register` | Start registration; returns challenges for the wallet to sign |
| `uai_verify_identity` | Verify any UAI-ID, returns the verify payload + proof link |
| `uai_get_status` | Current status of the calling agent |
| `uai_request_capability` | **Request** — creates a pending grant request for the owner |
| `uai_check_policy` | PDP evaluation without executing |
| `uai_attest_action` | Submit a signed attestation |
| `uai_verify_passport` | Passport validity for a jurisdiction set |
| `uai_report_incident` | File a `HarmSuspicion` |

**Hard rule:** no MCP tool grants capabilities. `uai_request_capability` creates a request that a
human owner approves out of band. An MCP server that could elevate its own caller's privileges
would be a confused-deputy generator (T-11/T-13), and this constraint is tested explicitly.

All MCP tool calls execute under the agent's identity from the wallet, are subject to the same
PoP requirements, and appear in the event chain like any other action.

## 22.10 Framework adapters

Thin adapters over the same SDK core, none of which UAI depends on structurally (§48 of the
product brief): OpenAI Agents, Anthropic (tool-use + MCP), Google AI, Microsoft Copilot,
AWS Bedrock Agents, LangChain, LangGraph, CrewAI, AutoGen, and custom agents via the raw SDK.

The interface each adapter implements is deliberately tiny:

```text
before_action(intent) -> decision        # policy evaluation
after_action(intent, result) -> receipt  # commitments + signature + attestation
```

If an adapter needs more than that, the abstraction is wrong.
