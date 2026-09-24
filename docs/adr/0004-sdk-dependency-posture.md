# ADR-0004 — The SDKs hold the signing key, so they take almost no dependencies

Status: accepted · 2026-09-23 · supersedes nothing · relates to
[ADR-0003](0003-a-frontend-with-no-dependencies.md)

## Context

Phase 9 ships three client libraries — Go, Python and TypeScript — plus an MCP
server. All four run **inside the agent's process** and hold, or can reach, the
agent's signing key.

That is a different position from anything else in this repository. The gateway,
the PDP, the transparency log and the contracts are all built assuming the agent
may be adversarial; they are protected from it. An SDK is not protected from
anything: it is code the agent already trusts completely, sitting next to the key
that produces attestations in the agent's name.

The threat model calls this T-07, supply chain. For the SDKs the consequence is
sharper than usual. A compromised transitive dependency of a web framework
exfiltrates data. A compromised transitive dependency here **signs**, and
everything it signs is indistinguishable from what the agent meant to sign,
forever, because the whole point of the protocol is that a signature is
attributable.

## Decision

Each SDK takes the minimum number of dependencies its language makes possible,
and that number is justified per language rather than per convenience.

| SDK | Runtime dependencies | Why |
|---|---|---|
| Go (`sdk/go`) | none beyond `pkg/` | The standard library has Ed25519, SHA-256 and HTTP. `pkg/` is already dependency-free (rule 3). |
| TypeScript (`sdk/typescript`) | **none** | Node ≥ 18 has Ed25519 and SHA-256 in `node:crypto` and a global `fetch`. |
| Python (`sdk/python`) | **one**: `cryptography` | Python has no asymmetric cryptography in its standard library. |
| MCP (`mcp/`) | none beyond `sdk/go` | JSON-RPC 2.0 over stdio is ~100 lines; an MCP library would be a dependency with a signing key behind it. |

**The Python exception is deliberate and bounded.** The alternative to
`cryptography` is a pure-Python Ed25519, which is a timing-attack surface wrapped
around the agent's private key — strictly worse than one audited dependency whose
field arithmetic runs in constant-time C. Everything else in the Python SDK,
including RFC 8785 canonicalization and the HTTP client, is standard library:
`urllib.request` rather than `requests` or `httpx`, because HTTP convenience is
not worth a second package on this path.

**The TypeScript SDK has no build step**, for the same reason
[ADR-0003](0003-a-frontend-with-no-dependencies.md) gave for the frontend: what
is published is what is in the repository, and a reader who wants to know what
signs on their behalf can read it. Type declarations are hand-written in
`src/index.d.ts` and committed.

## Consequences

**Good.** The complete signing path of all three SDKs is auditable in one sitting.
A `npm install @uai/sdk` pulls exactly one package. A `pip install uai-sdk` pulls
two. No SDK can be compromised through a dependency it does not have.

**The cost, stated plainly.** Three RFC 8785 implementations and three RFC 9421
implementations now exist in this repository, and they can drift. That is the real
price of this decision, and it is paid with tests rather than accepted: each SDK
reproduces `spec/test-vectors/` — the *same committed vectors*, read and never
regenerated. A drift of one byte in a signature base or one key in a canonical
form fails the build in whichever SDK drifted. This is the same standard the
browser verification code is held to.

**The hand-written `.d.ts` can drift from the implementation.**
`test/types.test.mjs` asserts export parity in both directions, which catches a
missing, renamed or orphaned export. It does **not** catch a changed signature.
That limit is real; the declarations are kept small so the surface where it
matters stays small. If they grow, the answer is to generate them — and to accept
a build step then, rather than pretend the check is stronger than it is.

## Alternatives considered

**`requests`/`httpx` in Python, `undici` or `axios` in TypeScript.** Rejected:
these are the largest dependency trees in either ecosystem, and they buy
ergonomics on a path where the failure mode is a forged attestation.

**A pure-Python Ed25519, for zero dependencies everywhere.** Rejected: constant
time matters more than dependency count when the secret is a signing key. The
count is not the goal; the attack surface is.

**An MCP server SDK.** Rejected: the protocol surface this server needs is
`initialize`, `tools/list` and `tools/call` over newline-delimited JSON. Taking a
dependency to avoid writing that would put a library between a model and a key.

**Publishing compiled TypeScript.** Rejected on the same grounds as ADR-0003, and
for one more: a compiled artifact would let the published package differ from the
reviewed source with nobody able to tell by looking.
