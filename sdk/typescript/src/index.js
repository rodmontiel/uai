/**
 * @uai/sdk - Universal Agent Identity for TypeScript and JavaScript.
 *
 * ```js
 * import { Agent } from '@uai/sdk';
 *
 * const agent = await Agent.fromEnv();
 *
 * const record = await agent.act({
 *   capability: 'route.optimize',
 *   purpose: 'delivery_optimization',
 *   jurisdiction: { origin: 'AR', targets: ['DE'], basis: 'resource_location' },
 *   input: order,
 * }, () => optimize(order));
 *
 * console.log(record.eventId, record.transparency);
 * ```
 *
 * The callback runs only if the guardrail permits it, and something is attested
 * on the way out whatever happens inside -- including a thrown error. See
 * {@link module:agent} for why the SDK owns the call rather than exposing
 * `evaluate()` and `attest()` separately.
 *
 * @module
 */

export { Agent, allows, jurisdiction } from './agent.js';
export { Transport } from './client.js';
export {
  Domain, SALT_LEN, Signer, b64url, b64urlDecode, commit, commitObject,
  digest, digestObject, formatDigest, jwkThumbprint, salt, signingInput, thumbprintInput,
  verify, verifyCommitment,
} from './crypto.js';
export {
  canonicalize, canonicalizeJSON, canonicalString, canonicalizeWithout,
} from './canonical.js';
export { NotAttested, PolicyRefused, Problem, UAIError } from './errors.js';
export {
  DEFAULT_COMPONENTS, contentDigest, nonce, serializeParams, signRequest, signatureBase,
} from './pop.js';

export const VERSION = '0.1.0';
