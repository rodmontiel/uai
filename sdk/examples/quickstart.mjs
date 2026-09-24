#!/usr/bin/env node
// The same example in TypeScript/JavaScript, against a running gateway.
//
//     export UAI_ENDPOINT=http://127.0.0.1:8080
//     export UAI_AGENT_ID=uai:agent:01...
//     export UAI_AGENT_KEY=.keys/agent.jwk
//     node sdk/examples/quickstart.mjs
//
// Run sdk/examples/bootstrap.py first if you have no identity yet.

import { Agent, PolicyRefused } from '../typescript/src/index.js';

/** Stand-in for the work the agent actually does. */
function optimize(order) {
  return { route: ['depot', order.destination], etaMinutes: 42 };
}

const agent = await Agent.fromEnv();
console.log(`acting as ${agent.uaiId}`);
console.log(`status: ${(await agent.status()).status}\n`);

const order = { orderId: 'ORD-4471', destination: 'Berlin', customer: 'customer@example.com' };

// ── an action the guardrail permits ─────────────────────────────────────────
const record = await agent.act({
  capability: 'route.optimize',
  purpose: 'delivery_optimization',
  jurisdiction: { origin: 'AR', targets: ['DE'], basis: 'resource_location' },
  input: order,
}, () => optimize(order));

console.log(`decision : ${record.decision.effect} under ${record.decision.policyVersion}`);
console.log(`outcome  : ${record.outcome}`);
console.log(`event    : ${record.eventId} at sequence ${record.sequence}`);
console.log(`log      : ${record.transparency}`);
if (record.attestError) {
  // The work ran and the evidence is missing. Printing the empty event id
  // without this line would read as success.
  console.log(`NOT RECORDED: ${record.attestError}`);
}
// The salts are the only way this record can ever be opened. UAI does not have
// them: store them wherever the customer data itself is stored.
console.log(`salts    : input=${Buffer.from(record.inputSalt).toString('hex').slice(0, 16)}…\n`);

// ── an action it refuses ────────────────────────────────────────────────────
try {
  await agent.act({
    capability: 'payments.transfer',
    purpose: 'refund the customer',
    jurisdiction: { origin: 'AR', basis: 'owner_jurisdiction' },
  }, () => { throw new Error('this line must never run'); });
} catch (error) {
  if (!(error instanceof PolicyRefused)) throw error;
  console.log(`refused  : ${error.decision.effect} — ${error.decision.reason}\n`);
}

// ── the failure path is recorded too ────────────────────────────────────────
try {
  await agent.act({
    capability: 'route.optimize',
    purpose: 'delivery_optimization',
    jurisdiction: { origin: 'AR', basis: 'owner_jurisdiction' },
    input: order,
  }, () => { throw new Error('the routing service timed out'); });
} catch (error) {
  console.log(`failed   : ${error.message}`);
}

// ── asking for something the owner has not granted ──────────────────────────
try {
  const pending = await agent.requestCapability({
    capability: 'payments.transfer',
    justification: 'issue refunds without a human in the loop',
  });
  console.log(`requested: ${pending.capability} → ${pending.state} (granted=${pending.granted})`);
  console.log(`           ${pending.note}\n`);
} catch (error) {
  // One open request per capability: asking again does not make approval more
  // likely, and repeated asking is itself a signal.
  if (error.code !== 'UAI_CAPABILITY_REQUEST_OPEN') throw error;
  console.log(`requested: already pending — ${error.detail}\n`);
}

// ── the chain, walked back ──────────────────────────────────────────────────
const chain = await agent.events({ limit: 10 });
console.log('chain:');
for (const event of chain.events) {
  const outcome = event.outcome || '—';
  console.log(`  ${String(event.sequence).padStart(3)}  ${outcome.padEnd(18)} ${event.event_hash.slice(0, 23)}…`);
}
