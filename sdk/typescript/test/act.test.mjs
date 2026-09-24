// The act() contract.
//
// These are the assertions that make an SDK-owned call worth having over two
// separate ones: the work does not run when policy refuses, and something is
// attested on every way out of it -- return, throw, and refusal.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';

import { Agent, PolicyRefused, Problem, NotAttested, jurisdiction } from '../src/index.js';
import { Signer, commitObject, formatDigest } from '../src/crypto.js';

const UAI_ID = 'uai:agent:01JY8R9ZAF392N7QX2T81JH6KM';

/** A stub gateway that answers the three calls an action makes. */
function gateway(options = {}) {
  const state = {
    decision: options.decision ?? 'ALLOW',
    reason: options.reason ?? '',
    attestStatus: options.attestStatus ?? 201,
    attested: [],
    evaluated: 0,
  };
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
      const json = (status, payload) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      if (req.url === '/v1/policy/evaluate') {
        state.evaluated += 1;
        return json(200, {
          decision_id: '01JD', decision: state.decision, reason: state.reason,
          policy: { version: 'GASC-2027.4', bundle_hash: 'sha256:aa' },
          rules_fired: ['capability_envelope'],
        });
      }
      if (req.url === '/v1/actions/attest') {
        state.attested.push(body);
        if (state.attestStatus !== 201) {
          return json(state.attestStatus, {
            title: 'UAI_IDENTITY_NOT_ACTIVE', status: state.attestStatus,
            detail: 'no runtime bound',
          });
        }
        return json(201, {
          event_id: 'evt-1', event_hash: 'sha256:cc', sequence: 2, transparency: 'LOGGED',
        });
      }
      return json(200, { events: [], head: { hash: 'sha256:bb', sequence: 1 } });
    });
  });
  return { server, state };
}

async function withAgent(options, run) {
  const { server, state } = gateway(options);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const { privateKey } = generateKeyPairSync('ed25519');
  const agent = new Agent({
    endpoint: `http://127.0.0.1:${port}`, uaiId: UAI_ID,
    signer: new Signer(privateKey, `did:${UAI_ID}#key-1`),
    ownerDid: 'did:uai:owner:01JY8R9ZB0',
  });
  try {
    await run(agent, state);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const intent = (extra = {}) => ({
  capability: 'route.optimize', purpose: 'delivery_optimization',
  jurisdiction: { origin: 'AR', basis: 'owner_jurisdiction' },
  ...extra,
});

test('a success is attested', async () => {
  await withAgent({}, async (agent, state) => {
    const record = await agent.act(intent(), () => ({ routes: 3 }));
    assert.equal(record.outcome, 'SUCCESS');
    assert.equal(record.eventId, 'evt-1');
    assert.equal(record.transparency, 'LOGGED');
    assert.equal(record.attestError, null);
    assert.deepEqual(record.result, { routes: 3 });
    assert.equal(state.attested.length, 1);
    assert.equal(state.attested[0].outcome, 'SUCCESS');
  });
});

// The reason the SDK owns the call rather than exposing attest(). An integrator
// who has to remember a second call writes it on the happy path, and a record
// that contains only successes is an advertisement.
test('a thrown error is attested as FAILURE and re-thrown', async () => {
  await withAgent({}, async (agent, state) => {
    await assert.rejects(
      agent.act(intent(), () => { throw new Error('the routing service refused'); }),
      /the routing service refused/);
    assert.equal(state.attested.length, 1);
    assert.equal(state.attested[0].outcome, 'FAILURE');
  });
});

test('a rejected promise is attested as FAILURE', async () => {
  await withAgent({}, async (agent, state) => {
    await assert.rejects(agent.act(intent(), async () => { throw new Error('timeout'); }), /timeout/);
    assert.equal(state.attested[0].outcome, 'FAILURE');
  });
});

test('a denial stops the work and is recorded', async () => {
  await withAgent({ decision: 'DENY', reason: 'capability_not_granted' }, async (agent, state) => {
    let ran = false;
    await assert.rejects(
      agent.act(intent(), () => { ran = true; }),
      (err) => {
        assert.ok(err instanceof PolicyRefused);
        assert.equal(err.decision.reason, 'capability_not_granted');
        return true;
      });
    assert.equal(ran, false, 'the work ran after a DENY');
    // A refusal nobody wrote down is indistinguishable from a request nobody
    // made, so it appears in the agent's own chain, not only in our table.
    assert.equal(state.attested.length, 1);
    assert.equal(state.attested[0].outcome, 'ABORTED_BY_POLICY');
  });
});

test('REQUIRE_HUMAN_APPROVAL is not an allow', async () => {
  for (const effect of ['REQUIRE_HUMAN_APPROVAL', 'QUARANTINE', 'DENY']) {
    await withAgent({ decision: effect }, async (agent) => {
      let ran = false;
      await assert.rejects(agent.act(intent(), () => { ran = true; }), PolicyRefused);
      assert.equal(ran, false, `${effect} ran the work`);
    });
  }
});

// "We could not ask" must never read as "no objection" (12.4).
test('an unreachable guardrail fails closed', async () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const offline = new Agent({
    endpoint: 'http://127.0.0.1:1', uaiId: UAI_ID,
    signer: new Signer(privateKey, `did:${UAI_ID}#key-1`), timeoutMs: 500,
  });
  let ran = false;
  await assert.rejects(offline.act(intent(), () => { ran = true; }));
  assert.equal(ran, false, 'the work ran while the guardrail was unreachable');
});

test('content never leaves the process', async () => {
  await withAgent({}, async (agent, state) => {
    const secret = { email: 'customer@example.com' };
    const record = await agent.act(intent({ input: secret }), () => ({ records: 1 }));
    const sent = JSON.stringify(state.attested[0]);
    assert.ok(!sent.includes('customer@example.com'), 'the content was transmitted');
    assert.ok(state.attested[0].input_commitment.startsWith('sha256:'));
    assert.equal(record.inputSalt.length, 32);
    // The salt the caller kept must actually open the commitment. If it did
    // not, the record would be permanently unopenable and nobody would find out
    // until the day it mattered.
    assert.equal(formatDigest(commitObject(record.inputSalt, secret)),
      state.attested[0].input_commitment);
  });
});

test('a salt is never reused', async () => {
  await withAgent({}, async (agent, state) => {
    await agent.act(intent({ input: 'YES' }), () => 'NO');
    await agent.act(intent({ input: 'YES' }), () => 'NO');
    assert.notEqual(state.attested[0].input_commitment, state.attested[1].input_commitment,
      'identical content produced identical commitments');
  });
});

test('an unrecorded action says so', async () => {
  await withAgent({ attestStatus: 403 }, async (agent) => {
    const record = await agent.act(intent(), () => 'done');
    assert.ok(record.attestError instanceof Problem);
    assert.equal(record.attestError.code, 'UAI_IDENTITY_NOT_ACTIVE');
    assert.equal(record.eventHash, '', 'an event hash was reported for a refused attestation');
  });
});

test('strict throws when the action was not recorded', async () => {
  await withAgent({ attestStatus: 403 }, async (agent) => {
    await assert.rejects(agent.act(intent({ strict: true }), () => 'done'), NotAttested);
  });
});

test('the chain is tracked, not guessed', async () => {
  await withAgent({}, async (agent, state) => {
    await agent.act(intent(), () => null);
    await agent.act(intent(), () => null);
    assert.equal(state.attested[0].previous_event_hash, 'sha256:bb');
    assert.equal(state.attested[1].previous_event_hash, 'sha256:cc');
    assert.equal(state.attested[1].sequence, 3);
  });
});

test('the guardrail is consulted once per action', async () => {
  await withAgent({}, async (agent, state) => {
    await agent.act(intent(), () => null);
    assert.equal(state.evaluated, 1);
  });
});

// Under-declaring jurisdiction is the failure mode with real-world consequences.
test('cross_border is derived, not declared', () => {
  assert.equal(jurisdiction({ origin: 'AR', targets: ['AR'] }).cross_border, false);
  assert.equal(jurisdiction({ origin: 'AR', targets: ['DE'] }).cross_border, true);
  assert.equal(jurisdiction({ origin: 'AR' }).cross_border, false);
});

// A design assertion: nothing turns a refusal into execution.
test('there is no force option', async () => {
  await withAgent({ decision: 'DENY' }, async (agent) => {
    for (const forbidden of ['force', 'skipPolicy', 'ignoreDecision', 'bypass']) {
      await assert.rejects(
        agent.act(intent({ [forbidden]: true }), () => 'ran'), PolicyRefused,
        `${forbidden} let a refused action run`);
    }
  });
});
