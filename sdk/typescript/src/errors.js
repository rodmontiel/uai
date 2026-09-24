/**
 * Typed errors that map one-to-one to the `UAI_*` API codes.
 *
 * They are classes rather than messages so that a caller never has to match on
 * a string. A refusal an integrator can only detect by reading prose is a
 * refusal an integrator will eventually mishandle.
 *
 * @module
 */

/** Base class for everything this SDK throws. */
export class UAIError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'UAIError';
  }
}

/** An RFC 9457 problem document returned by the gateway. */
export class Problem extends UAIError {
  /** @param {number} status @param {Record<string, any>} document */
  constructor(status, document) {
    const code = document.title || 'UAI_UNKNOWN_ERROR';
    let message = `${code} [${status}]`;
    if (document.detail) message += `: ${document.detail}`;
    if (document.remediation) message += ` (${document.remediation})`;
    super(message);
    this.name = 'Problem';
    this.status = status;
    this.document = document;
    this.code = code;
    this.detail = document.detail ?? '';
    this.remediation = document.remediation ?? '';
    this.decisionId = document.decision_id ?? '';
    this.policyVersion = document.policy_version ?? '';
    this.chainHead = document.chain_head ?? null;
  }
}

/**
 * The guardrail refused the action, so the work did not run.
 *
 * It carries the decision rather than only a message: the caller needs the
 * decision id to look the refusal up, and the reason to decide whether to ask a
 * human, change the request, or stop.
 */
export class PolicyRefused extends UAIError {
  /** @param {import('./agent.js').Decision} decision */
  constructor(decision) {
    super(`policy refused ${decision.effect}: ${decision.reason} ` +
      `(${decision.policyVersion}, decision ${decision.decisionId})`);
    this.name = 'PolicyRefused';
    this.decision = decision;
  }
}

/**
 * The action ran but could not be recorded.
 *
 * Thrown only when the caller asked for it (`strict: true`). By default the
 * failure is reported on the action instead, because the work has already
 * happened and throwing afterwards would not undo it -- but a caller that has
 * not looked at `action.attestError` is running unattested without knowing.
 */
export class NotAttested extends UAIError {
  /** @param {string} message @param {unknown} [cause] */
  constructor(message, cause) {
    super(message);
    this.name = 'NotAttested';
    this.cause = cause;
  }
}
