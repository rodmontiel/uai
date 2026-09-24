# @uai/sdk

The TypeScript/JavaScript SDK for [Universal Agent Identity](../../README.md).

```bash
npm install @uai/sdk     # Node 18 or newer
```

## The scoped call

```ts
import { Agent, PolicyRefused } from '@uai/sdk';

const agent = await Agent.fromEnv();   // UAI_ENDPOINT, UAI_AGENT_ID, UAI_AGENT_KEY

try {
  const record = await agent.act({
    capability: 'cloud.securitygroup.update',
    purpose: 'close an unrestricted ingress rule',
    jurisdiction: { origin: 'AR', targets: ['DE'], basis: 'resource_location' },
    input: { securityGroup: 'sg-0a1b2c3d' },
    riskClass: 'HIGH',
  }, () => updateSecurityGroup('sg-0a1b2c3d'));

  console.log(record.eventId, record.sequence, record.transparency);
} catch (error) {
  if (error instanceof PolicyRefused) {
    console.log(error.decision.reason, error.decision.decisionId);
  }
}
```

Three things happen that are worth knowing about:

**The callback does not run if the guardrail refuses.** The policy is evaluated
first. `DENY`, `QUARANTINE` and `REQUIRE_HUMAN_APPROVAL` all throw
`PolicyRefused` — the last one is a refusal until a human acts, not a
conditional yes.

**Something is attested on every way out.** Return, throw, or refusal. An SDK
that exposed `evaluate()` and `attest()` separately would produce a record of
successes only, because the failure paths are the ones nobody writes the second
call on.

**The content never leaves your process.** `input` and the callback's return
value are committed locally with a fresh random salt, and only `sha256:…` is
sent. Keep `record.inputSalt` and `record.outputSalt`: UAI does not have them and
never will, so a commitment whose salt was discarded can never be opened by
anyone.

## When the record is missing

`record.attestError` is set when the action ran but could not be recorded — the
work already happened, so throwing afterwards would not undo it. Pass
`strict: true` to throw `NotAttested` instead, when running unattested is worse
for you than failing.

## The rest of the surface

```ts
await agent.verify('uai:agent:01JY8R9ZAF392N7QX2T81JH6KM');   // public, no key needed
await agent.status();
await agent.events({ limit: 50 });
await agent.checkPassport({ capability: 'crm.customer.read', targets: ['DE'] });
await agent.requestCapability({ capability: 'payments.transfer', justification: 'issue refunds' });
await agent.reportHarm({ subject: 'uai:agent:01J…', harm_categories: [/* … */], confidence: 0.8 });
```

`requestCapability` creates a **pending request**. It does not grant anything and
cannot be made to: approval is an act by the human owner, out of band, and no
method here, no API route and no database path turns one into a grant.

## What this SDK cannot do

It cannot make an agent accountable. An agent that does not want to be does not
import it. What it does is make the accountable path the easy one; verification
lives in the relying party, which is where it survives an adversarial agent.

It does not hold or generate keys. `Signer` is supplied by you, from a JWK file
or anything else that can produce Ed25519 signatures.

## No dependencies, no build step

The package ships the files in this repository. Node supplies Ed25519, SHA-256
and `fetch`, so there is nothing to install — and this package holds your signing
key, which makes every dependency a dependency that could sign on your behalf.

Types are hand-written in [`src/index.d.ts`](src/index.d.ts) and committed
alongside the code, for the same reason: a generated artifact is a build step,
and a build step means what is published is not what you can read here. The cost
is that a declaration can drift from its implementation, so `test/types.test.mjs`
asserts that every runtime export has a declaration and every declaration has a
runtime export. It does not catch a changed signature; that is the honest limit
of the trade.

## Tests

```bash
cd sdk/typescript && npm test
```

They run against `spec/test-vectors/`, the same committed vectors the Go and
Python implementations reproduce. The vectors are read, never regenerated: a test
that writes its own expectations proves only that the code agrees with itself.
