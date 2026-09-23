// Client-side verification.
//
// This module exists so the verify page checks proofs instead of displaying a
// verdict computed on our side. A page that asks the API "is this fine?" and
// renders the reply is our opinion with a nicer font; a visitor has no more
// reason to believe it than to believe us directly.
//
// Everything here mirrors pkg/merkle and pkg/receipt. When the two disagree,
// the Go implementation and spec/test-vectors are authoritative and this file
// is wrong.

const enc = new TextEncoder();

/** SHA-256 over concatenated byte arrays. */
async function sha256(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { buf.set(p, off); off += p.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}

/** RFC 6962 leaf hash: SHA-256(0x00 || entry). */
export async function leafHash(entry) {
  return sha256(new Uint8Array([0x00]), entry);
}

/** RFC 6962 node hash: SHA-256(0x01 || left || right). */
async function nodeHash(left, right) {
  return sha256(new Uint8Array([0x01]), left, right);
}

export function hexToBytes(hex) {
  const clean = hex.startsWith('sha256:') ? hex.slice(7) : hex;
  if (clean.length % 2 !== 0) throw new Error(`not a digest: ${hex}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export function b64urlToBytes(s) {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function equal(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Rebuild the tree root from an inclusion proof, exactly as RFC 6962 specifies.
 * Mirrors merkle.RootFromInclusionProof in pkg/merkle.
 */
export async function rootFromInclusionProof(index, size, leaf, proof) {
  if (index >= size) throw new Error(`index ${index} is outside a tree of ${size}`);
  let inner = 0;
  let idx = index;
  let sz = size - 1;
  while (sz > 0) { if (idx === sz) break; inner++; idx >>= 1; sz >>= 1; }
  let border = 0;
  let i = index >> inner;
  while (i > 0) { if (i & 1) border++; i >>= 1; }
  if (proof.length !== inner + border) {
    throw new Error(`proof has ${proof.length} hashes, the tree shape needs ${inner + border}`);
  }
  let seed = leaf;
  let at = index;
  for (let k = 0; k < inner; k++) {
    seed = (at & 1) ? await nodeHash(proof[k], seed) : await nodeHash(seed, proof[k]);
    at >>= 1;
  }
  for (let k = inner; k < proof.length; k++) seed = await nodeHash(proof[k], seed);
  return seed;
}

/** RFC 8785 canonical JSON, enough of it for UAI's documents. */
export function canonicalize(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: numbers must be finite');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    // RFC 8785 orders members by their UTF-16 code units, which is what
    // JavaScript's default sort already does on strings.
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  throw new Error(`JCS: cannot canonicalize ${typeof value}`);
}

/** The checkpoint body the log and its witnesses sign. Mirrors receipt.Checkpoint.Body. */
export function checkpointBody(cp) {
  const rootB64 = cp.root_b64 || cp.rootB64 || '';
  // The trailing newline is part of the signed bytes (C2SP tlog-checkpoint).
  return enc.encode(`${cp.origin}\n${cp.size}\n${rootB64}\n`);
}

/** Domain-separated signing input: DOMAIN || 0x00 || payload. */
function signingInput(domain, payload) {
  const d = enc.encode(domain);
  const out = new Uint8Array(d.length + 1 + payload.length);
  out.set(d, 0);
  out[d.length] = 0x00;
  out.set(payload, d.length + 1);
  return out;
}

/** Whether this browser can check the signatures at all. */
export async function ed25519Available() {
  try {
    await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'Ed25519' }, false, ['verify']);
    return true;
  } catch {
    return false;
  }
}

/** Verify one Ed25519 signature over a domain-separated payload. */
export async function verifyEd25519(publicKeyRaw, domain, payload, signature) {
  const key = await crypto.subtle.importKey('raw', publicKeyRaw, { name: 'Ed25519' }, false, ['verify']);
  return crypto.subtle.verify({ name: 'Ed25519' }, key, signature, signingInput(domain, payload));
}

/**
 * Check a transparency receipt against the statement it claims to cover.
 *
 * Returns a list of checks, each with its own outcome. A single boolean would
 * hide which part held and which did not, and "it failed" is not an answer
 * anybody can act on.
 */
export async function checkReceipt(receipt, statement, anchors = {}) {
  const checks = [];
  const add = (name, ok, detail) => checks.push({ name, ok, detail });

  let leaf;
  try {
    leaf = await leafHash(enc.encode(canonicalize(statement)));
    const claimed = hexToBytes(receipt.leaf_hash);
    add('The statement is the one the receipt covers', equal(leaf, claimed),
      equal(leaf, claimed)
        ? `leaf ${receipt.leaf_hash.slice(0, 17)}…`
        : `the statement hashes to sha256:${bytesToHex(leaf)}, the receipt says ${receipt.leaf_hash}`);
    if (!equal(leaf, claimed)) return checks;
  } catch (e) {
    add('The statement is the one the receipt covers', false, e.message);
    return checks;
  }

  try {
    const proof = (receipt.inclusion_proof || []).map(hexToBytes);
    const root = await rootFromInclusionProof(receipt.log_index, receipt.checkpoint.size, leaf, proof);
    const claimedRoot = receipt.checkpoint.root_b64
      ? b64urlToBytes(receipt.checkpoint.root_b64.replace(/\+/g, '-').replace(/\//g, '_'))
      : hexToBytes(receipt.checkpoint.root || '');
    const ok = equal(root, claimedRoot);
    add('The entry is in the log at the index it claims', ok,
      ok ? `index ${receipt.log_index} of ${receipt.checkpoint.size}`
         : 'the audit path does not rebuild the checkpoint root');
    if (!ok) return checks;
  } catch (e) {
    add('The entry is in the log at the index it claims', false, e.message);
    return checks;
  }

  const body = checkpointBody(receipt.checkpoint);
  const logKey = anchors.logKeys && anchors.logKeys[receipt.log_signature.kid];
  if (!logKey) {
    // Not a failure of the receipt: a verifier that does not hold the log's key
    // simply cannot answer this question, and saying so is the honest result.
    add('The log signed this checkpoint', null,
      `no trusted key for ${receipt.log_signature.kid}; supply one to check this`);
  } else {
    try {
      const ok = await verifyEd25519(logKey, 'UAI-v1:checkpoint', body,
        b64urlToBytes(receipt.log_signature.value));
      add('The log signed this checkpoint', ok, ok ? receipt.log_signature.kid : 'signature does not verify');
    } catch (e) {
      add('The log signed this checkpoint', false, e.message);
    }
  }

  const sigs = receipt.witness_signatures || [];
  const known = anchors.witnessKeys || {};
  let counted = 0;
  for (const w of sigs) {
    if (!known[w.witness]) continue;
    try {
      if (await verifyEd25519(known[w.witness], 'UAI-v1:checkpoint', body, b64urlToBytes(w.value))) counted++;
    } catch { /* an unverifiable co-signature simply does not count */ }
  }
  const min = anchors.minWitnesses || 0;
  if (min > 0) {
    add('Independent witnesses saw the same history', counted >= min,
      `${counted} of ${min} required co-signatures verified`);
  } else {
    add('Independent witnesses saw the same history', null,
      `${sigs.length} co-signature(s) present; supply witness keys to check them`);
  }

  add('The history is pinned where the operator cannot rewrite it', receipt.anchor ? true : null,
    receipt.anchor
      ? `chain ${receipt.anchor.chain_id}, tx ${receipt.anchor.tx}`
      : 'not anchored yet — the strongest truthful answer between an event and its next anchor');

  return checks;
}

/**
 * Walk an agent's event chain and report the first broken link.
 *
 * This is the check that catches a deleted or never-submitted event: the log
 * proves what is there, and the chain is what shows that nothing is missing
 * between two things that are.
 */
export function checkChain(events, genesisHash) {
  const checks = [];
  if (!events.length) {
    checks.push({ name: 'The chain starts at registration', ok: null, detail: 'no events yet' });
    return checks;
  }
  let expected = genesisHash;
  let broken = null;
  for (const ev of events) {
    const prev = ev.previous_event_hash || '';
    if (expected && prev !== expected) { broken = { at: ev.sequence, prev, expected }; break; }
    expected = ev.event_hash;
  }
  checks.push({
    name: 'Every event links to the one before it',
    ok: broken === null,
    detail: broken
      ? `sequence ${broken.at} references ${broken.prev || '(nothing)'}, expected ${broken.expected}`
      : `${events.length} event(s), unbroken back to registration`,
  });
  return checks;
}
