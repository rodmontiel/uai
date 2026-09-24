// Runs the BROWSER verification code against the committed test vectors.
//
// This is the same discipline the Go implementation is held to: the vectors in
// spec/test-vectors/ are the protocol, and any implementation that claims to
// verify UAI evidence has to reproduce them. A frontend that verified proofs
// its own way would give visitors a confident answer to a different question.
//
// Run with: make test-web
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  leafHash, rootFromInclusionProof, canonicalize, checkpointBody, hexToBytes, bytesToHex,
  checkReceipt,
} from '../../web/app/verify.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = (name) => JSON.parse(readFileSync(join(here, '../../spec/test-vectors', name), 'utf8'));
const enc = new TextEncoder();

test('leaf hashing matches the committed vectors', async () => {
  const set = vectors('merkle/hashing.json');
  for (const c of set.cases) {
    if (c.kind !== 'leaf') continue;
    const got = bytesToHex(await leafHash(enc.encode(c.data_utf8 || '')));
    assert.equal(got, c.hash_hex, `leaf of ${JSON.stringify(c.data_utf8 || '')}`);
  }
});

test('inclusion proofs rebuild the committed roots', async () => {
  const set = vectors('merkle/tree-proofs.json');
  let checked = 0;
  for (const c of set.cases) {
    for (const inc of c.inclusion || []) {
      const leaf = hexToBytes(inc.leaf_hash_hex);
      const proof = (inc.proof_hex || []).map(hexToBytes);
      const root = await rootFromInclusionProof(inc.index, c.size, leaf, proof);
      assert.equal(bytesToHex(root), c.root_hex,
        `index ${inc.index} of a tree of ${c.size}`);
      checked++;
    }
  }
  // A loop that checked nothing would pass just as happily.
  assert.ok(checked >= 10, `only ${checked} inclusion proofs were exercised`);
});

test('a tampered inclusion proof does not rebuild the root', async () => {
  const set = vectors('merkle/tree-proofs.json');
  const c = set.cases.find((x) => x.size >= 4);
  const inc = c.inclusion.find((i) => (i.proof_hex || []).length > 0);
  const proof = inc.proof_hex.map(hexToBytes);
  proof[0] = new Uint8Array(32); // one sibling replaced with zeros
  const root = await rootFromInclusionProof(inc.index, c.size, hexToBytes(inc.leaf_hash_hex), proof);
  assert.notEqual(bytesToHex(root), c.root_hex);
});

test('a proof of the wrong length is refused rather than guessed at', async () => {
  const set = vectors('merkle/tree-proofs.json');
  const c = set.cases.find((x) => x.size >= 4);
  const inc = c.inclusion.find((i) => (i.proof_hex || []).length > 0);
  await assert.rejects(
    () => rootFromInclusionProof(inc.index, c.size, hexToBytes(inc.leaf_hash_hex), []),
    /needs/,
  );
});

test('canonical JSON matches the committed vectors', () => {
  const set = vectors('jcs/canonicalization.json');
  let checked = 0;
  for (const c of set.cases) {
    if (!c.canonical) continue;
    assert.equal(canonicalize(JSON.parse(c.input_json)), c.canonical, c.name);
    checked++;
  }
  assert.ok(checked >= 5, `only ${checked} canonicalization cases were exercised`);
});

test('the checkpoint body keeps its trailing newline', () => {
  // The newline is part of what the log and its witnesses signed. Dropping it
  // makes every co-signature fail for a reason that looks like a key problem.
  const body = new TextDecoder().decode(
    checkpointBody({ origin: 'uai.world/log/1', size: 42, root_b64: 'AAA=' }));
  assert.equal(body, 'uai.world/log/1\n42\nAAA=\n');
});

// ── INV-001 · an identity is never "verified" without cryptographic proof ────
//
// The browser is where this invariant is most easily lost. A page that renders
// the API's verdict has checked nothing, and the visitor cannot tell the
// difference -- which is why checkReceipt reports three states and not two:
// true, false, and null for a question it is not equipped to answer.
//
// null must never be rendered, counted or summarized as a pass. These tests
// hold the distinction that everything above them depends on.

/** A receipt for a one-entry log, where the root IS the leaf and the proof is empty. */
async function receiptFor(statement) {
  const leaf = await leafHash(enc.encode(canonicalize(statement)));
  return {
    leaf_hash: `sha256:${bytesToHex(leaf)}`,
    log_index: 0,
    inclusion_proof: [],
    checkpoint: {
      origin: 'uai.test/log', size: 1, root: `sha256:${bytesToHex(leaf)}`,
      issued_at: '2027-06-01T00:00:00Z',
    },
    log_signature: { alg: 'EdDSA', kid: 'did:web:log.uai.test#key-1', value: 'AAAA' },
    witness_signatures: [],
  };
}

test('INV-001: a check that cannot be performed is not a pass', async () => {
  const statement = { uai: 'test' };
  // No anchors: the visitor holds no trusted key, so the signature question
  // has no answer here -- and "no answer" must not round up.
  const checks = await checkReceipt(await receiptFor(statement), statement, {});

  const signed = checks.find((x) => x.name === 'The log signed this checkpoint');
  assert.ok(signed, 'the signature check must appear even when it cannot be answered');
  assert.equal(signed.ok, null,
    `a checkpoint whose signer is not trusted reported ok=${signed.ok}; unanswerable is not verified`);

  const witnessed = checks.find((x) => x.name === 'Independent witnesses saw the same history');
  assert.equal(witnessed.ok, null, 'unchecked co-signatures reported as checked');

  // And the distinction has to survive the summary a page would compute.
  assert.ok(checks.filter((x) => x.ok === null).length >= 2,
    'the three-state result collapsed to two; INV-001 lives in the third');
  assert.equal(checks.every((x) => x.ok !== false), true,
    'nothing here is actually wrong; the point is that nothing is proven either');
});

test('INV-001: a statement that is not the one the receipt covers verifies nothing', async () => {
  // The receipt is genuine; the statement shown beside it is not the one it
  // covers. This is the substitution a compromised page would make, and the
  // one a visitor could never notice by reading the rendered verdict.
  const receipt = await receiptFor({ uai: 'test' });
  const checks = await checkReceipt(receipt, { uai: 'something else entirely' }, {});

  assert.equal(checks[0].ok, false, 'a substituted statement was accepted');
  assert.equal(checks.length, 1,
    'verification continued past a failed binding; nothing after it means anything');
});
