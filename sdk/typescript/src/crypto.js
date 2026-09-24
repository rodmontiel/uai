/**
 * UAI-CS-1: domain separation, salted commitments and Ed25519 signatures.
 *
 * Zero dependencies. Node has Ed25519 and SHA-256 in `node:crypto`, so nothing
 * here needs a library -- and this package holds the agent's signing key, which
 * makes every dependency a dependency that could sign on the agent's behalf
 * (T-07).
 *
 * @module
 */

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, randomBytes } from 'node:crypto';
import { canonicalize } from './canonical.js';

export const SALT_LEN = 32;

/**
 * The domain registry of 7.2.
 *
 * Every digest and every signature covers `DOMAIN || 0x00 || payload`, so a
 * signature made in one context can never be replayed as valid in another.
 * Reusing one of these for a new purpose is a security bug, not a shortcut.
 */
export const Domain = Object.freeze({
  ATTESTATION: 'UAI-v1:attestation',
  CREDENTIAL: 'UAI-v1:credential',
  DID_DOCUMENT: 'UAI-v1:did-document',
  REGISTRATION: 'UAI-v1:registration',
  CHALLENGE: 'UAI-v1:challenge',
  VOTE: 'UAI-v1:vote',
  DECISION: 'UAI-v1:decision',
  POLICY_BUNDLE: 'UAI-v1:policy-bundle',
  QUARANTINE: 'UAI-v1:quarantine',
  REVOCATION: 'UAI-v1:revocation',
  CHECKPOINT: 'UAI-v1:checkpoint',
  COMMITMENT: 'UAI-v1:commitment',
  AUDIT: 'UAI-v1:audit',
  CAPABILITY_REQUEST: 'UAI-v1:capability-request',
  SUSPICION: 'UAI-v1:suspicion',
  PASSPORT: 'UAI-v1:passport',
});

const KNOWN = new Set(Object.values(Domain));

/**
 * Return `DOMAIN || 0x00 || payload`, the exact bytes that are signed.
 *
 * An unknown domain is refused rather than accepted permissively: an
 * unrecognised context is exactly the situation in which a cross-context replay
 * would succeed.
 *
 * @param {string} domain @param {Uint8Array} payload @returns {Uint8Array}
 */
export function signingInput(domain, payload) {
  if (!KNOWN.has(domain)) {
    throw new Error(`uai: unknown domain separation string: ${domain}`);
  }
  const prefix = new TextEncoder().encode(domain);
  const out = new Uint8Array(prefix.length + 1 + payload.length);
  out.set(prefix, 0);
  out[prefix.length] = 0x00;
  out.set(payload, prefix.length + 1);
  return out;
}

/** @param {string} domain @param {Uint8Array} payload @returns {Uint8Array} */
export function digest(domain, payload) {
  return new Uint8Array(createHash('sha256').update(signingInput(domain, payload)).digest());
}

/** @param {string} domain @param {unknown} value @returns {Uint8Array} */
export function digestObject(domain, value) {
  return digest(domain, canonicalize(value));
}

/** @returns {Uint8Array} A fresh 32-byte commitment salt. */
export function salt() {
  return new Uint8Array(randomBytes(SALT_LEN));
}

/**
 * Return `SHA-256("UAI-v1:commitment" || 0x00 || salt || content)`.
 *
 * The salt is mandatory. A bare hash of low-entropy content -- an email, an
 * amount, a customer id, a yes/no answer -- is recoverable by dictionary
 * attack, and commitments are published on-chain where that leak is permanent.
 *
 * @param {Uint8Array} saltBytes @param {Uint8Array} content @returns {Uint8Array}
 */
export function commit(saltBytes, content) {
  if (saltBytes.length < SALT_LEN) {
    throw new Error(`uai: salt must be at least ${SALT_LEN} bytes, got ${saltBytes.length}`);
  }
  const payload = new Uint8Array(saltBytes.length + content.length);
  payload.set(saltBytes, 0);
  payload.set(content, saltBytes.length);
  return digest(Domain.COMMITMENT, payload);
}

/** @param {Uint8Array} saltBytes @param {unknown} value @returns {Uint8Array} */
export function commitObject(saltBytes, value) {
  return commit(saltBytes, canonicalize(value));
}

/**
 * Report whether `(salt, content)` opens a commitment.
 *
 * This is the disclosure path: an authorized party is shown the salt and the
 * content and checks the match itself, rather than trusting an assertion that
 * it matched.
 *
 * @param {Uint8Array} commitment @param {Uint8Array} saltBytes @param {Uint8Array} content
 * @returns {boolean}
 */
export function verifyCommitment(commitment, saltBytes, content) {
  try {
    const computed = commit(saltBytes, content);
    if (computed.length !== commitment.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i++) diff |= computed[i] ^ commitment[i];
    return diff === 0;
  } catch {
    return false;
  }
}

/**
 * Return the exact bytes RFC 7638 hashes, or '' for an unsupported key.
 *
 * RFC 7638 fixes the member set and their order per key type, so this is built
 * by hand rather than with `JSON.stringify` over the whole object: a serializer
 * that emitted its own field order would produce a different thumbprint for the
 * same key, and the registration proof that names it would stop composing.
 *
 * @param {Record<string, unknown>} jwk @returns {string}
 */
export function thumbprintInput(jwk) {
  let members;
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    members = ['crv', 'kty', 'x'];
  } else if (jwk.kty === 'EC') {
    members = ['crv', 'kty', 'x', 'y'];
  } else {
    return '';
  }
  if (members.some((m) => typeof jwk[m] !== 'string')) return '';
  return '{' + members.map((m) => `"${m}":${JSON.stringify(jwk[m])}`).join(',') + '}';
}

/**
 * Return the RFC 7638 thumbprint in the UAI wire form `sha256:<hex>`.
 *
 * This is the subject identifier of a registration proof (8.2): both the owner
 * and the agent sign it, so an owner vouching for a thumbprint the agent
 * computed differently vouches for a key that was never presented.
 *
 * It is the one digest in UAI that is NOT domain-separated, because RFC 7638
 * fixes its input exactly and a prefix would make it a different function under
 * the same name.
 *
 * @param {Record<string, unknown>} jwk @returns {string}
 */
export function jwkThumbprint(jwk) {
  const canonical = thumbprintInput(jwk);
  if (!canonical) {
    throw new Error(`uai: unsupported key type for a thumbprint: ${jwk.kty}/${jwk.crv}`);
  }
  return formatDigest(new Uint8Array(createHash('sha256').update(canonical, 'utf8').digest()));
}

/** @param {Uint8Array} raw @returns {string} The `sha256:<hex>` wire form. */
export function formatDigest(raw) {
  return 'sha256:' + Buffer.from(raw).toString('hex');
}

/** @param {Uint8Array} raw @returns {string} base64url without padding. */
export function b64url(raw) {
  return Buffer.from(raw).toString('base64url');
}

/** @param {string} text @returns {Uint8Array} */
export function b64urlDecode(text) {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

/**
 * An Ed25519 signing key with the DID URL that names it.
 *
 * The key is supplied, never generated here on the fly: an SDK that created a
 * key when it found none would hand out credentials that stop verifying at the
 * next restart, and the operator would learn about it from verification
 * failures rather than from a startup error.
 */
export class Signer {
  static ALG = 'EdDSA';
  static HTTP_ALG = 'ed25519';

  /** @param {import('node:crypto').KeyObject} privateKey @param {string} kid */
  constructor(privateKey, kid) {
    if (privateKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('uai: only Ed25519 keys are supported by this SDK');
    }
    this.key = privateKey;
    this.kid = kid;
  }

  /**
   * Load a signer from an RFC 8037 Ed25519 JWK.
   *
   * @param {{kty?: string, crv?: string, d?: string}} jwk @param {string} kid
   * @returns {Signer}
   */
  static fromJWK(jwk, kid) {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
      throw new Error('uai: only Ed25519 OKP keys are supported by this SDK');
    }
    if (!jwk.d) throw new Error('uai: the JWK carries no private key');
    return new Signer(createPrivateKey({ key: jwk, format: 'jwk' }), kid);
  }

  /**
   * Load a signer from a JWK file, refusing one any other user can read.
   *
   * @param {string} path @param {string} kid @returns {Promise<Signer>}
   */
  static async fromFile(path, kid) {
    const fs = await import('node:fs/promises');
    const stat = await fs.stat(path);
    if (stat.mode & 0o077) {
      throw new Error(
        `uai: ${path} is readable by group or other (mode ${(stat.mode & 0o777).toString(8)}); ` +
        'a signing key that others can read is not a signing key');
    }
    return Signer.fromJWK(JSON.parse(await fs.readFile(path, 'utf8')), kid);
  }

  /** @returns {string} The DID this key belongs to: the kid without its fragment. */
  get did() {
    return this.kid.split('#')[0];
  }

  /** @returns {{kty: string, crv: string, x: string}} */
  publicJWK() {
    const jwk = createPublicKey(this.key).export({ format: 'jwk' });
    return { kty: 'OKP', crv: 'Ed25519', x: /** @type {string} */ (jwk.x) };
  }

  /**
   * Sign exact bytes, with no domain prefix.
   *
   * Used only for RFC 9421 signature bases, where the domain is carried inside
   * the signed base as the `tag` parameter. Everything else goes through
   * {@link sign}.
   *
   * @param {Uint8Array} message @returns {Uint8Array}
   */
  signRaw(message) {
    return new Uint8Array(nodeSign(null, message, this.key));
  }

  /**
   * Sign a domain-separated payload.
   *
   * @param {string} domain @param {Uint8Array} payload
   * @returns {{alg: string, kid: string, domain: string, value: string}}
   */
  sign(domain, payload) {
    const raw = nodeSign(null, signingInput(domain, payload), this.key);
    return { alg: Signer.ALG, kid: this.kid, domain, value: Buffer.from(raw).toString('base64url') };
  }

  /**
   * Canonicalize and sign.
   *
   * @param {string} domain @param {unknown} value
   * @returns {{alg: string, kid: string, domain: string, value: string}}
   */
  signObject(domain, value) {
    return this.sign(domain, canonicalize(value));
  }
}

/**
 * Raise unless a signature is valid in exactly this domain.
 *
 * @param {import('node:crypto').KeyObject} publicKey @param {string} domain
 * @param {Uint8Array} payload
 * @param {{domain: string, value: string}} signature
 */
export function verify(publicKey, domain, payload, signature) {
  if (signature.domain !== domain) {
    throw new Error(`uai: signed for ${signature.domain}, verifying as ${domain}`);
  }
  const ok = nodeVerify(null, signingInput(domain, payload), publicKey, b64urlDecode(signature.value));
  if (!ok) throw new Error('uai: signature does not verify');
}
