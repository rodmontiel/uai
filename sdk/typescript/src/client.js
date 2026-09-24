/**
 * The HTTP surface, over the platform.
 *
 * `fetch` and `node:crypto`, nothing else. This package holds the agent's
 * signing key, so every dependency here is a dependency that could sign on the
 * agent's behalf (T-07) -- and Node supplies everything this needs.
 *
 * @module
 */

import { Problem, UAIError } from './errors.js';
import { nonce, signRequest } from './pop.js';

/**
 * Cap on a response body. A client that read an unbounded body would let a
 * compromised or confused gateway exhaust the agent's memory.
 */
export const MAX_RESPONSE = 4 << 20;

/** Signed and unsigned calls to one gateway, as one identity. */
export class Transport {
  /** @param {{endpoint: string, uaiId: string, signer: import('./crypto.js').Signer,
   *           timeoutMs?: number, fetch?: typeof globalThis.fetch}} options */
  constructor(options) {
    this.endpoint = options.endpoint.replace(/\/+$/, '');
    this.uaiId = options.uaiId;
    this.signer = options.signer;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.fetch = options.fetch ?? globalThis.fetch;
    if (typeof this.fetch !== 'function') {
      throw new Error('uai: no fetch available; Node 18 or newer is required');
    }
  }

  /** @param {string} path @returns {Promise<any>} */
  get(path) {
    return this.#send('GET', this.#url(path), undefined, {});
  }

  /**
   * An unsigned call to a public endpoint.
   *
   * Separate from {@link post} so that reaching a public surface never silently
   * requires a key: a relying party checking somebody else's passport is not a
   * UAI participant, and an SDK that made them sign to ask would have put an
   * account in front of verification.
   *
   * @param {string} path @param {unknown} body @returns {Promise<any>}
   */
  postPublic(path, body) {
    const raw = new TextEncoder().encode(JSON.stringify(body));
    return this.#send('POST', this.#url(path), raw, {
      'Content-Type': 'application/json',
      'Idempotency-Key': 'sdk-' + nonce(),
    });
  }

  /**
   * A signed, state-changing call.
   *
   * `domain` is carried as the RFC 9421 tag, and it is an argument rather than
   * a constant because a signature valid for one endpoint must not be
   * replayable against another.
   *
   * @param {string} path @param {string} domain @param {unknown} body
   * @returns {Promise<any>}
   */
  post(path, domain, body) {
    const raw = new TextEncoder().encode(JSON.stringify(body));
    const url = this.#url(path);
    const headers = signRequest(this.signer, {
      method: 'POST', url, body: raw, domain, agentId: this.uaiId,
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'sdk-' + nonce() },
    });
    return this.#send('POST', url, raw, headers);
  }

  /** @param {string} path @returns {string} */
  #url(path) {
    return this.endpoint + path;
  }

  /**
   * @param {string} method @param {string} url @param {Uint8Array | undefined} body
   * @param {Record<string, string>} headers @returns {Promise<any>}
   */
  async #send(method, url, body, headers) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await this.fetch(url, {
        method, headers, body, signal: controller.signal,
      });
    } catch (cause) {
      throw new UAIError(`uai: ${method} ${url}: ${cause}`, { cause });
    } finally {
      clearTimeout(timer);
    }

    const text = await response.text();
    if (text.length > MAX_RESPONSE) {
      throw new UAIError('uai: response body exceeds the client limit');
    }
    let payload = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = null;
      }
    }
    if (!response.ok) {
      // A non-JSON error body is reported as what it is rather than parsed into
      // a plausible-looking problem: a proxy's HTML error page must not read as
      // a verdict from the gateway.
      const document = payload && typeof payload === 'object' && 'title' in payload
        ? payload
        : { title: 'UAI_UNKNOWN_ERROR', detail: text.trim() };
      throw new Problem(response.status, document);
    }
    return payload;
  }
}
