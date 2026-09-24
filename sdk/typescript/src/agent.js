/**
 * The scoped-callback API: `await agent.act(intent, work)`.
 *
 * # Why a callback and not an attest() call
 *
 * An SDK that exposed `evaluate()` and `attest()` and trusted the integrator to
 * call both, in order, on every path, would produce an accountability log of
 * successes. Not because integrators are careless, but because the failure
 * paths are the ones nobody writes the second call on: the early return, the
 * thrown exception, the branch added six months later.
 *
 * JavaScript has no `with` statement worth using, so the equivalent is a
 * callback the SDK owns: `try/finally` around it makes the attestation happen
 * on every path, with the outcome that actually occurred. A record that
 * contains only successes is an advertisement.
 *
 * # What this cannot do
 *
 * The agent's process is the one place UAI cannot constrain. An agent that does
 * not want to be accountable does not import this module. This SDK makes the
 * accountable path the easy one; the protocol puts verification in the relying
 * party, which is where it survives an adversarial agent.
 *
 * @module
 */

import { randomBytes } from 'node:crypto';

import { canonicalizeWithout } from './canonical.js';
import { Transport } from './client.js';
import { Domain, Signer, commitObject, formatDigest, salt } from './crypto.js';
import { NotAttested, PolicyRefused, Problem } from './errors.js';
import { nonce } from './pop.js';

const UAI_VERSION = '0.1';

/**
 * The jurisdictional context of an action (11.2).
 *
 * `crossBorder` is derived, never declared: under-declaring jurisdiction is the
 * failure mode with real-world consequences, and a flag the caller sets by hand
 * is a flag the caller forgets.
 *
 * @param {{origin: string, targets?: string[], basis?: string}} j
 * @returns {{origin: string, targets: string[], cross_border: boolean, basis: string}}
 */
export function jurisdiction(j) {
  const targets = j.targets ?? [];
  return {
    origin: j.origin,
    targets,
    cross_border: targets.some((t) => t && t !== j.origin),
    basis: j.basis ?? '',
  };
}

/**
 * Whether a decision permits the action to run.
 *
 * REQUIRE_HUMAN_APPROVAL is not an allow. It is a refusal until a human acts,
 * and treating it as a conditional yes is how a human-in-the-loop requirement
 * quietly becomes a log line.
 *
 * @param {Decision} decision @returns {boolean}
 */
export function allows(decision) {
  return decision.effect === 'ALLOW' || decision.effect === 'ALLOW_WITH_MONITORING';
}

/**
 * @typedef {{decisionId: string, effect: string, reason: string,
 *            policyVersion: string, bundleHash: string, rulesFired: string[],
 *            conditions: Record<string, unknown>, raw: Record<string, unknown>}} Decision
 */

/** @param {Record<string, any>} payload @returns {Decision} */
function toDecision(payload) {
  const policy = payload.policy ?? {};
  return {
    decisionId: payload.decision_id ?? '',
    effect: payload.decision ?? 'DENY',
    reason: payload.reason ?? '',
    policyVersion: policy.version ?? '',
    bundleHash: policy.bundle_hash ?? '',
    rulesFired: payload.rules_fired ?? [],
    conditions: payload.conditions ?? {},
    raw: payload,
  };
}

/** A UAI identity, and everything it can do. */
export class Agent {
  /**
   * One identity per instance. An object that could sign as several agents
   * would make "which identity performed this" a parameter at the call site,
   * and the first mistake in passing it would be a misattributed action.
   *
   * @param {{endpoint: string, uaiId: string, signer: Signer, ownerDid?: string,
   *          timeoutMs?: number}} options
   */
  constructor(options) {
    if (!options.uaiId) throw new Error("uai: the agent's UAI-ID is required");
    if (!options.signer) throw new Error('uai: a signer is required; this package does not create keys');
    this.transport = new Transport(options);
    this.uaiId = options.uaiId;
    this.signer = options.signer;
    this.did = options.signer.did;
    this.ownerDid = options.ownerDid ?? '';
    /** @type {{hash: string, sequence: number} | null} */
    this.head = null;
  }

  /**
   * Build an agent from `UAI_ENDPOINT`, `UAI_AGENT_ID`, `UAI_AGENT_KEY`.
   *
   * Nothing is generated when a variable is missing. A key created at startup
   * would sign credentials that stop verifying at the next restart, and the
   * operator would find out from verification failures rather than from a
   * startup error.
   *
   * @param {NodeJS.ProcessEnv} [env] @returns {Promise<Agent>}
   */
  static async fromEnv(env = process.env) {
    const uaiId = env.UAI_AGENT_ID ?? '';
    const keyPath = env.UAI_AGENT_KEY ?? '';
    if (!uaiId || !keyPath) {
      throw new Error(
        'uai: set UAI_AGENT_ID and UAI_AGENT_KEY. This SDK signs as exactly one ' +
        'registered identity and will not invent one.');
    }
    return new Agent({
      endpoint: env.UAI_ENDPOINT ?? 'http://127.0.0.1:8080',
      uaiId,
      signer: await Signer.fromFile(keyPath, `did:${uaiId}#key-1`),
      ownerDid: env.UAI_OWNER_DID ?? '',
    });
  }

  /**
   * Run one action under UAI: evaluate, execute, attest.
   *
   * In order:
   *   1. The guardrail is consulted BEFORE `work` runs. A refusal means `work`
   *      is never called, and `PolicyRefused` is thrown.
   *   2. Whatever happens to `work` -- a value or a thrown error -- an
   *      attestation is submitted on the way out, with SUCCESS, FAILURE or
   *      ABORTED_BY_POLICY.
   *   3. The error from `work` is re-thrown after the attestation is submitted,
   *      so the agent's own error handling is unchanged by having been observed.
   *
   * @template T
   * @param {Intent} intent
   * @param {() => T | Promise<T>} work
   * @returns {Promise<ActionRecord & {result?: T}>}
   */
  async act(intent, work) {
    if (!intent.capability || !intent.purpose) {
      throw new Error('uai: an action needs a capability and a purpose');
    }
    /** @type {ActionRecord & {result?: any}} */
    const record = {
      outcome: '', eventId: '', eventHash: '', sequence: 0, transparency: '',
      receipt: null, inputSalt: null, outputSalt: null, attestError: null,
      decision: toDecision({}),
    };

    let decision;
    try {
      decision = await this.evaluate(intent);
    } catch (cause) {
      // The guardrail was unreachable or refused to answer. Fail closed: 12.4 is
      // explicit that "we could not ask" must never read as "no objection", and
      // a client that ran the work anyway would be where that is lost.
      throw new Error(
        `uai: policy could not be evaluated, so the action was not run: ${cause}`,
        { cause });
    }
    record.decision = decision;

    if (!allows(decision)) {
      record.outcome = 'ABORTED_BY_POLICY';
      await this.#attest(record, intent, undefined);
      throw new PolicyRefused(decision);
    }

    let output;
    let failure;
    try {
      output = await work();
      record.outcome = 'SUCCESS';
      record.result = output;
    } catch (thrown) {
      record.outcome = 'FAILURE';
      failure = thrown;
    }
    await this.#attest(record, intent, output);
    if (failure !== undefined) throw failure;
    if (record.attestError && intent.strict) {
      throw new NotAttested(
        `the action ran but was not recorded: ${record.attestError}`, record.attestError);
    }
    return record;
  }

  /**
   * Ask the guardrail whether an action may proceed, without running it.
   *
   * @param {Intent} intent @returns {Promise<Decision>}
   */
  async evaluate(intent) {
    const body = {
      action: {
        capability: intent.capability, purpose: intent.purpose,
        resource: intent.resource ?? '',
      },
      jurisdiction: jurisdiction(intent.jurisdiction ?? { origin: '' }),
    };
    return toDecision(await this.transport.post('/v1/policy/evaluate', Domain.DECISION, body) ?? {});
  }

  /**
   * Build, sign and submit the attestation.
   *
   * It never throws: the action already happened, and the caller's error is the
   * work's error. A failure to record is reported in `record.attestError`
   * instead of masking what the work did.
   *
   * @param {ActionRecord} record @param {Intent} intent @param {unknown} output
   */
  async #attest(record, intent, output) {
    try {
      await this.#submit(record, intent, output);
    } catch (error) {
      if (error instanceof Problem && error.code === 'UAI_CHAIN_CONFLICT' && error.chainHead) {
        // The refusal carries the real head, so the retry is not a guess:
        // another writer appended between the read and the write, which is
        // ordinary concurrency. Anything else is reported as it is -- retrying
        // a policy refusal would be the SDK arguing with the guardrail.
        this.head = error.chainHead;
        try {
          await this.#submit(record, intent, output);
          return;
        } catch (retry) {
          record.attestError = retry;
          return;
        }
      }
      record.attestError = error;
    }
  }

  /** @param {ActionRecord} record @param {Intent} intent @param {unknown} output */
  async #submit(record, intent, output) {
    const [inputCommitment, inputSalt] = commitValue(intent.input);
    const [outputCommitment, outputSalt] = commitValue(output);
    record.inputSalt = inputSalt;
    record.outputSalt = outputSalt;

    const head = await this.chainHead();
    /** @type {Record<string, any>} */
    const attestation = {
      uai_version: UAI_VERSION,
      event_id: 'evt-' + nonce(),
      agent_did: this.did,
      owner_did: this.ownerDid,
      timestamp: new Date().toISOString(),
      nonce: nonce(),
      action: {
        type: intent.type || intent.capability,
        capability: intent.capability,
        ...(intent.resource ? { resource: intent.resource } : {}),
        ...(intent.riskClass ? { risk_class: intent.riskClass } : {}),
      },
      purpose: intent.purpose,
      jurisdiction: jurisdiction(intent.jurisdiction ?? { origin: '' }),
      policy: {
        version: record.decision.policyVersion,
        bundle_hash: record.decision.bundleHash,
        decision_id: record.decision.decisionId,
        decision: record.decision.effect,
        rules_fired: record.decision.rulesFired,
      },
      outcome: record.outcome,
      previous_event_hash: head.hash,
      sequence: head.sequence + 1,
    };
    if (intent.runtimeIdentity) attestation.runtime_identity = intent.runtimeIdentity;
    if (inputCommitment) attestation.input_commitment = inputCommitment;
    if (outputCommitment) attestation.output_commitment = outputCommitment;

    // 10.4: the signature covers the attestation MINUS its signature member.
    attestation.signature = this.signer.sign(
      Domain.ATTESTATION, canonicalizeWithout(attestation, 'signature'));

    const response = await this.transport.post(
      '/v1/actions/attest', Domain.ATTESTATION, attestation) ?? {};
    record.eventId = response.event_id ?? '';
    record.eventHash = response.event_hash ?? '';
    record.sequence = response.sequence ?? 0;
    record.transparency = response.transparency ?? '';
    record.receipt = response.receipt ?? null;
    this.head = { hash: record.eventHash, sequence: record.sequence };
  }

  /**
   * The tip of this agent's event chain, fetched once and then tracked.
   *
   * @returns {Promise<{hash: string, sequence: number}>}
   */
  async chainHead() {
    if (this.head === null) {
      const response = await this.transport.get(`/v1/agents/${this.uaiId}/events?limit=1`) ?? {};
      this.head = response.head ?? { hash: '', sequence: 0 };
    }
    return /** @type {{hash: string, sequence: number}} */ (this.head);
  }

  /** Verify any UAI-ID. Needs no signature and no account.
   * @param {string} uaiId @returns {Promise<Record<string, any>>} */
  verify(uaiId) {
    return this.transport.get(`/v1/verify/${uaiId}`);
  }

  /** This agent's identity card. @returns {Promise<Record<string, any>>} */
  status() {
    return this.transport.get(`/v1/agents/${this.uaiId}`);
  }

  /** An agent's event chain.
   * @param {{uaiId?: string, limit?: number}} [options] @returns {Promise<Record<string, any>>} */
  events(options = {}) {
    let path = `/v1/agents/${options.uaiId ?? this.uaiId}/events`;
    if (options.limit) path += `?limit=${options.limit}`;
    return this.transport.get(path);
  }

  /**
   * Ask the owner for a capability this agent does not hold.
   *
   * This creates a PENDING request and nothing else. Approval is an act by the
   * human owner, out of band; no method here, no endpoint, and no database path
   * turns one into a grant (22.9, T-11/T-13).
   *
   * @param {{capability: string, justification: string, purpose?: string}} request
   * @returns {Promise<Record<string, any>>}
   */
  requestCapability(request) {
    return this.transport.post('/v1/capability-requests', Domain.CAPABILITY_REQUEST, {
      capability: request.capability,
      justification: request.justification,
      purpose: request.purpose ?? '',
    });
  }

  /**
   * Run the 11.6 checklist for a capability and a set of jurisdictions.
   *
   * A GET, and unsigned: the check changes nothing, and the party who needs the
   * answer is whoever is dealing with the agent -- not the agent.
   *
   * @param {{capability: string, targets: string[], subject?: string, riskClass?: string}} check
   * @returns {Promise<Record<string, any>>}
   */
  checkPassport(check) {
    const query = new URLSearchParams({
      subject: check.subject ?? this.uaiId,
      capability: check.capability,
      targets: check.targets.join(','),
    });
    if (check.riskClass) query.set('risk_class', check.riskClass);
    return this.transport.get(`/v1/passports/check?${query}`);
  }

  /**
   * File a signed suspicion about another identity.
   *
   * The document produced here is the `HarmSuspicion` of
   * `spec/schemas/harm-suspicion.schema.json`, field for field. A third party
   * implementing against the committed schema and a caller using this SDK must
   * produce the same document, or the two are not the same protocol.
   *
   * Each category is `{category, severity}` with severity 0-4. There is
   * deliberately nowhere to record a finding: 14 is explicit that a suspicion is
   * a claim warranting examination, never guilt.
   *
   * The report carries its own signature, separate from the one on the HTTP
   * call, because the row outlives the request: an accusation that cannot be
   * re-attributed months later is one nobody has to answer for (14.1).
   *
   * @param {{subject: {agent_did: string, owner_did: string},
   *          harmCategories: {category: string, severity: number}[],
   *          confidence: number, relatedEvents?: string[], reporterType?: string,
   *          guardrail?: {rule?: string, policy_version?: string, bundle_hash?: string},
   *          evidenceCommitments?: string[], affectedJurisdictions?: string[]}} report
   * @returns {Promise<Record<string, any>>}
   */
  reportHarm(report) {
    /** @type {Record<string, any>} */
    const body = {
      suspicion_id: ulid(),
      reported_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
      reporter: { did: this.did, type: report.reporterType ?? 'AUTOMATED_GUARDRAIL' },
      subject: report.subject,
      harm_categories: report.harmCategories,
      confidence: report.confidence,
    };
    if (report.relatedEvents?.length) body.related_events = report.relatedEvents;
    if (report.guardrail) body.guardrail = report.guardrail;
    if (report.evidenceCommitments?.length) body.evidence_commitments = report.evidenceCommitments;
    if (report.affectedJurisdictions?.length) {
      body.affected_jurisdictions = report.affectedJurisdictions;
    }
    body.signature = this.signer.sign(
      Domain.SUSPICION, canonicalizeWithout(body, 'signature'));
    return this.transport.post('/v1/suspicions', Domain.SUSPICION, body);
  }
}

/**
 * A Crockford base32 ULID: 48 bits of time, 80 of randomness.
 *
 * Written here rather than taken as a dependency: it is fifteen lines, and this
 * package's dependency budget is zero (ADR-0004).
 *
 * @returns {string}
 */
function ulid() {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let value = (BigInt(Date.now()) << 80n) |
    BigInt('0x' + Buffer.from(randomBytes(10)).toString('hex'));
  let out = '';
  for (let i = 0; i < 26; i++) {
    out = alphabet[Number(value & 0x1fn)] + out;
    value >>= 5n;
  }
  return out;
}

/**
 * Commit locally, with a fresh salt per commitment.
 *
 * Never a per-agent or per-session salt: commitments are published, and two
 * commitments under one salt let anyone who opens the first test guesses
 * against the second.
 *
 * @param {unknown} value @returns {[string, Uint8Array | null]}
 */
function commitValue(value) {
  if (value === undefined || value === null) return ['', null];
  const saltBytes = salt();
  return [formatDigest(commitObject(saltBytes, value)), saltBytes];
}

/**
 * @typedef {{capability: string, purpose: string, type?: string, resource?: string,
 *            riskClass?: string, jurisdiction?: {origin: string, targets?: string[], basis?: string},
 *            input?: unknown, runtimeIdentity?: string, strict?: boolean}} Intent
 *
 * @typedef {{decision: Decision, outcome: string, eventId: string, eventHash: string,
 *            sequence: number, transparency: string, receipt: unknown,
 *            inputSalt: Uint8Array | null, outputSalt: Uint8Array | null,
 *            attestError: unknown}} ActionRecord
 */
