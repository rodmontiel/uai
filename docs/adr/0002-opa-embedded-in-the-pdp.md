# ADR-0002 · OPA embedded in the PDP, and what stays out of it

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** 6 (policy engine)
- **Related:** [ADR-0001](0001-podman-rootless-runtime.md), [§12 Guardrail](../protocol/08-guardrail.md), project rule 3

---

## 1 · The question

The specification commits to Rego over signed GASC bundles, so the evaluator is settled. What
was not settled is **where it runs**, and that turned out to matter more than expected once the
cost was measured.

Adding `github.com/open-policy-agent/opa` grows the module graph from **18 to 204 modules**. The
module graph is not what ships, though, so the number that matters is what a program actually
links:

```text
go list -deps github.com/open-policy-agent/opa/v1/rego
  174 packages, from 33 distinct third-party modules
```

Thirty-three modules — including a JWT library, a GraphQL parser and a logging framework — in a
binary that decides authorization. That is a real cost against threat **T-07**, and it deserved
a decision rather than an import.

## 2 · Decision

1. **The evaluator is embedded, in `internal/pdp`.** Not a sidecar.
2. **`pkg/policy` verifies bundles and takes no dependencies at all.** Manifest validation, the
   bundle hash, M-of-N approval signatures and the `previous_policy_hash` chain are implemented
   there, in the dependency-free verification core.
3. `pkg/` keeps its no-external-dependency rule, and `test/deps` still enforces it.

## 3 · Rationale

### 3.1 The split follows what a relying party actually has to do

This is the whole argument, and it is narrower than "embedded vs sidecar".

**A relying party never re-runs Rego.** Handed an attestation that cites a decision, what it has
to check is: does the decision record name a policy version and a bundle hash, is it signed, and
was the bundle with that hash approved by the governance process? None of that needs an
evaluator. All of it needs to run in the verification path, where every dependency is
supply-chain surface.

**A PDP does run Rego**, because it is producing a fresh authorization rather than checking an
old one. That is a different job with a different threat profile, and it is the only place the
33 modules live.

So the boundary is not "heavy code over there, light code over here". It is: *auditing a past
decision must never require the machinery that made it.*

### 3.2 Why not a sidecar

A sidecar would keep the 33 modules out of our binary entirely, which is genuinely attractive.
It loses on two counts that matter more:

- **§12.4's fail mode is stateful.** "Guardrail bundle unreachable ⇒ use the last signed cached
  bundle, mark `degraded: true`" requires the PDP to hold and control that bundle. With a
  sidecar, the cached policy lives in a process whose state we do not own, and `degraded` becomes
  a guess about somebody else's cache.
- **§12.6 requires replay.** An auditor must fetch a bundle by hash, replay the input and get the
  same decision. Embedding makes "which evaluator produced this" a property of our own build,
  recorded with our own version. With a separately-versioned sidecar it is a second moving part
  that the decision record does not capture.

### 3.3 Why not write our own evaluator

It would remove every dependency and it is the wrong trade. A bespoke policy language means
other implementers cannot read the bundle, which defeats the reason the policy is a signed
artifact in the first place, and it means the default-deny semantics that carry the whole
guardrail would rest on code nobody else has reviewed.

## 4 · What this costs, stated plainly

- 33 third-party modules in the PDP's dependency tree, pinned by version and reviewed on upgrade.
- The gateway currently hosts the PDP, so those modules are in the edge binary today. §23.1 makes
  `uai-policy-service` a separate service; until that split lands, this is a real and
  acknowledged widening of the edge's supply-chain surface.
- The verification path is unaffected, and a test enforces that rather than leaving it to
  discipline.

## 5 · Consequences, verified

| Property | How it is proven |
|---|---|
| `pkg/` still has no external dependencies | `test/deps` fails the build otherwise |
| The committed bundle is the one that was approved | `make policy-verify`, and `TestCommittedBundleVerifies` |
| Editing policy without the governance keys breaks the build | a changed `.rego` or threshold no longer hashes to the manifest |
| One signer cannot satisfy a 3-of-5 | `TestBundleRefusesTamperedContent` |
| A PDP with no policy permits nothing | `TestNoBundleFailsClosed` returns 503, not an allow |
| Every decision names its policy | `TestEveryDecisionNamesItsPolicy`, both for ALLOW and DENY |

## 6 · A note on the committed bundle

`policy/gasc-2027.4/` ships **with** its manifest and signatures; the private approval keys do
not. Editing a rule or a threshold therefore makes verification fail until somebody holding the
governance keys signs it again.

That is not friction to work around. It is §12.1 made true in this repository: policy cannot be
changed by whoever has write access to the source tree.
