// The TypeScript SDK against the committed vectors.
//
// Same standard as the Go and Python implementations: the vectors are read,
// never regenerated here. A test that wrote its own expectations would prove
// only that this SDK agrees with itself, and two implementations that agree on
// the cryptography but disagree on a newline cannot verify each other -- the
// disagreement stays invisible until it matters.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { canonicalizeJSON, canonicalizeWithout } from '../src/canonical.js';
import {
  Signer, digest, formatDigest, jwkThumbprint, signingInput, thumbprintInput,
  verifyCommitment,
} from '../src/crypto.js';
import { contentDigest, serializeParams, signatureBase } from '../src/pop.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(HERE, '..', '..', '..', 'spec', 'test-vectors');

const load = (...parts) => JSON.parse(readFileSync(join(VECTORS, ...parts), 'utf8'));
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));

test('every canonicalization case reproduces byte for byte', () => {
  const { cases } = load('jcs', 'canonicalization.json');
  assert.ok(cases.length > 0);
  for (const c of cases) {
    const got = canonicalizeJSON(c.input_json);
    assert.equal(new TextDecoder().decode(got), c.canonical, c.name);
    assert.equal(createHash('sha256').update(got).digest('hex'), c.canonical_sha256, c.name);
  }
});

test('every domain reproduces its digest', () => {
  const { cases } = load('digest', 'domain-separation.json');
  for (const c of cases) {
    assert.equal(formatDigest(digest(c.domain, utf8(c.payload_utf8))), c.digest, c.domain);
  }
  // The property the domains exist for, asserted rather than assumed.
  assert.equal(new Set(cases.map((c) => c.digest)).size, cases.length,
    'two domains produced the same digest for the same payload');
});

test('commitments open only for the right content', () => {
  const { cases } = load('commitment', 'salted-commitment.json');
  for (const c of cases) {
    const opened = verifyCommitment(
      hex(c.commitment.split(':')[1]), hex(c.salt_hex), utf8(c.content_utf8));
    assert.equal(opened, c.opens, c.name);
  }
});

// What a signature over a self-signed object covers. 10.4 says "jcs-canonicalize
// A minus signature"; the alternative reading -- blank the member, keep the key
// -- is what a struct-based implementation produces by accident, and it signs
// something nobody else can verify.
test('the signing payload is the document minus its signature', () => {
  const { cases } = load('attestation', 'signing-payload.json');
  assert.ok(cases.length > 0);
  for (const c of cases) {
    const got = canonicalizeWithout(c.document, 'signature');
    const text = new TextDecoder().decode(got);
    if (c.must_verify) {
      assert.equal(text, c.signing_payload, c.name);
      assert.equal(createHash('sha256').update(got).digest('hex'), c.signing_payload_sha256, c.name);
    } else {
      // The negative vector pins the payload we must NOT produce.
      assert.notEqual(text, c.signing_payload, c.name);
    }
    const publicKey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(c.public_key_hex, 'hex').toString('base64url') },
      format: 'jwk',
    });
    const message = signingInput(c.domain, utf8(c.signing_payload));
    const verified = nodeVerify(null, message, publicKey, Buffer.from(c.signature_b64url, 'base64url'));
    assert.equal(verified, c.must_verify, c.name);
  }
});

// The subject identifier of a registration proof (8.2). Both halves of the
// proof sign it, so an implementation that computes it differently does not
// produce a proof -- it produces two statements about two different keys that
// happen to look like one.
test('every JWK thumbprint reproduces, input and digest', () => {
  const { cases } = load('keys', 'jwk-thumbprint.json');
  assert.ok(cases.length > 0);
  for (const c of cases) {
    // The bytes hashed are checked too: agreeing on the digest while
    // disagreeing on the input means agreeing by accident.
    assert.equal(thumbprintInput(c.jwk), c.canonical_json, c.name);
    assert.equal(jwkThumbprint(c.jwk), c.thumbprint, c.name);
  }
  const byName = Object.fromEntries(cases.map((c) => [c.name, c]));
  assert.equal(byName['Ed25519'].thumbprint,
    byName['Ed25519 with extra members that are not hashed'].thumbprint,
    'members outside the RFC 7638 set changed the thumbprint');
});

test('an unsupported key type is refused', () => {
  assert.throws(() => jwkThumbprint({ kty: 'RSA', n: 'abc', e: 'AQAB' }));
});

// RFC 9421, including the exact signature base string. The base is pinned
// because that is where implementations diverge: a stray newline, an unquoted
// component name or a lowercased method all yield a base that verifies against
// nothing.
test('the RFC 9421 signature base is exact', () => {
  for (const c of load('pop', 'rfc9421.json').cases) {
    // The verifier sees the tag as presented, which for the cross-domain case
    // is not the tag that was signed.
    const verifyTag = c.verify_tag || c.tag;
    if (verifyTag !== c.tag || !c.must_verify) continue;
    const params = { keyId: c.keyid, tag: verifyTag, created: c.created, alg: c.alg,
      components: c.components };
    assert.equal(serializeParams(params), c.signature_input.slice(c.signature_input.indexOf('=') + 1), c.name);
    const base = signatureBase({ method: c.method, url: c.target_uri, headers: c.headers }, params);
    assert.equal(new TextDecoder().decode(base), c.signature_base, c.name);
    assert.equal(contentDigest(c.body_utf8), c.content_digest, c.name);
  }
});

test('acceptance matches the vector, including the rejections', () => {
  for (const c of load('pop', 'rfc9421.json').cases) {
    const verifyTag = c.verify_tag || c.tag;
    const params = { keyId: c.keyid, tag: verifyTag, created: c.created, alg: c.alg,
      components: c.components };
    const base = signatureBase({ method: c.method, url: c.target_uri, headers: c.headers }, params);
    const publicKey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(c.public_key_hex, 'hex').toString('base64url') },
      format: 'jwk',
    });
    const digestOk = contentDigest(c.body_utf8) === c.content_digest;
    const signatureOk = nodeVerify(null, base, publicKey, Buffer.from(c.signature_b64, 'base64'));
    assert.equal(digestOk && signatureOk, c.must_verify,
      c.failure_reason ?? `${c.name}: unexpected verification outcome`);
  }
});

// Ed25519 is deterministic, so a correct signer reproduces the committed
// signature. This is the check that would catch a signer that signs something
// other than the base -- the failure a verify-only test cannot see.
test('signing reproduces the committed signature', () => {
  for (const c of load('pop', 'rfc9421.json').cases) {
    if (!c.must_verify) continue;
    const params = { keyId: c.keyid, tag: c.tag, created: c.created, alg: c.alg,
      components: c.components };
    const base = signatureBase({ method: c.method, url: c.target_uri, headers: c.headers }, params);
    const signer = Signer.fromJWK({
      kty: 'OKP', crv: 'Ed25519',
      d: Buffer.from(c.seed_hex, 'hex').toString('base64url'),
      x: Buffer.from(c.public_key_hex, 'hex').toString('base64url'),
    }, c.keyid);
    assert.equal(Buffer.from(signer.signRaw(base)).toString('base64'), c.signature_b64, c.name);
  }
});
