/**
 * RFC 9421 HTTP message signatures: proof of possession for the UAI API.
 *
 * The rule this module exists to enforce: `agent_id` in a JSON body proves
 * nothing. Any process that can write the body can write the identifier. A
 * state-changing call carries a signature from a key the caller demonstrably
 * controls (INV-002).
 *
 * Domain separation works differently here than everywhere else in UAI, and the
 * difference is deliberate. RFC 9421 already carries the context inside the
 * signature, as the `tag` parameter of `@signature-params`, which is itself a
 * signed component. Prefixing the base with the UAI domain as well would add no
 * security property and would stop a standard RFC 9421 verifier from
 * interoperating.
 *
 * @module
 */

import { createHash, randomBytes } from 'node:crypto';

export const HEADER_SIGNATURE_INPUT = 'Signature-Input';
export const HEADER_SIGNATURE = 'Signature';
export const HEADER_CONTENT_DIGEST = 'Content-Digest';
export const HEADER_AGENT_ID = 'UAI-Agent-Id';
export const HEADER_NONCE = 'UAI-Nonce';

export const LABEL = 'uai';

/**
 * The components UAI requires on a state-changing call.
 *
 * Content-Digest is covered so the body cannot be swapped; UAI-Agent-Id and
 * UAI-Nonce are covered so that neither the claimed identity nor the replay
 * token can be altered without invalidating the signature.
 */
export const DEFAULT_COMPONENTS = Object.freeze([
  '@method', '@target-uri', 'content-digest', 'uai-agent-id', 'uai-nonce',
]);

/** @returns {string} A fresh 128-bit replay nonce. */
export function nonce() {
  return randomBytes(16).toString('hex');
}

/**
 * An RFC 9530 `Content-Digest` field value.
 *
 * @param {Uint8Array | string} body @returns {string}
 */
export function contentDigest(body) {
  const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
  return 'sha-256=:' + createHash('sha256').update(bytes).digest('base64') + ':';
}

/**
 * Render RFC 9421 signature parameters as an RFC 8941 inner list.
 *
 * This exact string is both the `Signature-Input` value and the last line of
 * the signature base. Building it twice, in two places, is how implementations
 * end up signing something other than what they send.
 *
 * @param {{components?: readonly string[], created?: number, expires?: number,
 *          keyId: string, alg?: string, nonce?: string, tag: string}} params
 * @returns {string}
 */
export function serializeParams(params) {
  const components = params.components ?? DEFAULT_COMPONENTS;
  let out = '(' + components.map((c) => quote(c.toLowerCase())).join(' ') + ')';
  if (params.created) out += `;created=${params.created}`;
  if (params.expires) out += `;expires=${params.expires}`;
  if (params.keyId) out += `;keyid=${quote(params.keyId)}`;
  if (params.alg) out += `;alg=${quote(params.alg)}`;
  if (params.nonce) out += `;nonce=${quote(params.nonce)}`;
  if (params.tag) out += `;tag=${quote(params.tag)}`;
  return out;
}

/** @param {string} value @returns {string} */
function quote(value) {
  return JSON.stringify(value);
}

/**
 * Build the RFC 9421 signature base.
 *
 * One line per covered component, then the `@signature-params` line with no
 * trailing newline. The absence of that final newline is not a detail: it is
 * where implementations most often diverge, and a base with one extra byte
 * verifies against nothing.
 *
 * @param {{method: string, url: string, headers: Record<string, string>}} message
 * @param {{components?: readonly string[], created?: number, expires?: number,
 *          keyId: string, alg?: string, nonce?: string, tag: string}} params
 * @returns {Uint8Array}
 */
export function signatureBase(message, params) {
  const components = params.components ?? DEFAULT_COMPONENTS;
  const seen = new Set();
  const lines = [];
  for (const raw of components) {
    const name = raw.toLowerCase();
    if (seen.has(name)) throw new Error(`uai: component "${name}" listed twice`);
    seen.add(name);
    lines.push(`${quote(name)}: ${componentValue(message, name)}`);
  }
  lines.push(`${quote('@signature-params')}: ${serializeParams(params)}`);
  return new TextEncoder().encode(lines.join('\n'));
}

/**
 * @param {{method: string, url: string, headers: Record<string, string>}} message
 * @param {string} name @returns {string}
 */
function componentValue(message, name) {
  if (name.startsWith('@')) {
    const url = new URL(message.url);
    switch (name) {
      case '@method': return message.method.toUpperCase();
      case '@target-uri': return message.url;
      case '@authority': return url.host.toLowerCase();
      case '@scheme': return url.protocol.replace(':', '').toLowerCase();
      case '@path': return url.pathname || '/';
      case '@query': return '?' + url.search.replace(/^\?/, '');
      default: throw new Error(`uai: unsupported derived component ${name}`);
    }
  }
  for (const [key, value] of Object.entries(message.headers)) {
    if (key.toLowerCase() === name) return String(value).trim().replace(/\s+/g, ' ');
  }
  throw new Error(`uai: covered component missing from the message: ${name}`);
}

/**
 * Sign an outgoing request, returning the headers to send.
 *
 * `body` is required because the digest is a covered component: signing without
 * covering the body would leave it swappable, which is the whole point of proof
 * of possession on a state-changing call.
 *
 * @param {import('./crypto.js').Signer} signer
 * @param {{method: string, url: string, headers?: Record<string, string>,
 *          body: Uint8Array | string, domain: string, agentId: string,
 *          replayNonce?: string, created?: number}} request
 * @returns {Record<string, string>}
 */
export function signRequest(signer, request) {
  if (!request.agentId) throw new Error('uai: an agent id is required');
  const url = new URL(request.url); // throws on a relative target
  if (!url.protocol || !url.host) {
    // A relative target would make the signature cover a resource the caller
    // never addressed, and it would verify against nothing at the gateway.
    throw new Error(`uai: the target URI must be absolute, got ${request.url}`);
  }
  const headers = { ...(request.headers ?? {}) };
  headers[HEADER_CONTENT_DIGEST] = contentDigest(request.body);
  headers[HEADER_AGENT_ID] = request.agentId;
  headers[HEADER_NONCE] = request.replayNonce ?? nonce();

  const params = {
    keyId: signer.kid, tag: request.domain,
    created: request.created ?? Math.floor(Date.now() / 1000),
    alg: /** @type {typeof import('./crypto.js').Signer} */ (signer.constructor).HTTP_ALG,
    components: DEFAULT_COMPONENTS,
  };
  const base = signatureBase({ method: request.method, url: request.url, headers }, params);
  const raw = signer.signRaw(base);
  headers[HEADER_SIGNATURE_INPUT] = `${LABEL}=${serializeParams(params)}`;
  headers[HEADER_SIGNATURE] = `${LABEL}=:${Buffer.from(raw).toString('base64')}:`;
  return headers;
}
