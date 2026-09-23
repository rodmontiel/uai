# ADR-0003 · A frontend with no dependencies, and a verify page that verifies

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** 8 (frontend)
- **Deviates from:** [§25 Repository structure](../protocol/18-repository-structure.md), which says `web/` is Next.js + TypeScript

---

## 1 · The question

§25 names Next.js. Nothing in building the backend contradicted that, so this is a deliberate
change of mind rather than a discovery, and it needs a reason good enough to justify deviating
from a written specification.

The reason is what the verify page is **for**.

## 2 · Decision

1. `web/` is plain ES modules and CSS, served as static files. **No build step, no npm runtime
   dependencies.**
2. The verify page **performs verification in the browser** — inclusion proof, checkpoint
   signature, witness co-signatures, chain links — rather than displaying a verdict computed by
   the server.
3. `services/web` serves the files and proxies `/v1/*` to the gateway, so the page runs on one
   origin under a strict Content-Security-Policy with no CORS.

## 3 · Rationale

### 3.1 A verify page that shows our answer verifies nothing

This is the whole argument.

§18.1's design goal is evidence that survives the disappearance of its issuer: a relying party
holding a statement and a receipt needs no UAI service at all. A web page that asks our API
"is this agent fine?" and renders the reply is not an instance of that. It is our opinion with
a nicer font, and a visitor has no more reason to believe it than to believe us directly.

A page that fetches the public data and checks the proofs itself is a different artifact. It is
criterion 21's `uai-verify` CLI, in a browser, for people who will never run a CLI. What it
displays is not "UAI says this is valid" but "these are the proofs, and they hold".

### 3.2 Which makes every dependency on that page load-bearing

Once the page is doing the verifying, every byte of JavaScript on it is code a visitor must
trust in order to learn whether to trust an agent. A framework, its runtime, and its transitive
tree are all in that position.

That is the same argument as [ADR-0002](0002-opa-embedded-in-the-pdp.md) §3.1, one layer up:
**auditing must not require the machinery being audited.** There it kept OPA out of `pkg/`; here
it keeps a framework out of the page whose job is to check proofs.

### 3.3 No build step means what you audit is what runs

With no bundler and no transpiler there is nothing between the source in this repository and the
bytes a browser executes. A reader can compare the served file to the committed file and be done.

For most products that property is not worth the ergonomics it costs. For the page that tells
people whether an autonomous agent is accountable, it is.

### 3.4 And the priority list already said so

`security > auditability > interoperability > simplicity > performance > visual polish`. Visual
polish is last, explicitly. A framework bought for developer ergonomics and richer interaction
is spending the last item to pay for costs in the first two.

## 4 · What this costs

- Hand-written DOM code. There is no component model, no reactive state, no router. The five
  surfaces are read-mostly tables and detail views, so this is a real but small cost — and it
  would grow if the product grew interactive.
- No server-side rendering, so the pages need JavaScript. Acceptable: the page's purpose is to
  run cryptographic checks, which server-side rendering could not do on the visitor's behalf
  anyway without becoming the thing §3.1 rejects.
- Deviation from §25, which is updated to record this rather than left to contradict the code.

## 5 · What would change this decision

If the frontend grows genuinely interactive — governance workflows with live state, an evidence
workbench, dashboards — the hand-written cost stops being small and a framework becomes the
right call for those surfaces.

The verify page should stay as it is regardless, and can, because it shares nothing with them
but CSS.

## 6 · Consequences, verified

| Property | How it is proven |
|---|---|
| Verification happens in the browser | `web/app/verify.js` recomputes the leaf, walks the inclusion proof and checks the signatures; the API's own verdict is displayed beside it, not instead of it |
| No dependencies | `web/` contains no `package.json`, and a test asserts it |
| Served under a strict CSP | `services/web` sets `default-src 'self'` with no `unsafe-inline`, and a test asserts the header |
| Revocation is never described as a kill switch | a test greps every served file for the claim (project rule 2) |
