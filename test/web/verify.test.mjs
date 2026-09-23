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
