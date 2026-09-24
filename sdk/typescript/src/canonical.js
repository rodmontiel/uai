/**
 * RFC 8785 JSON Canonicalization.
 *
 * Every hash and every signature in UAI is computed over this representation,
 * so this file is on the verification path: if it disagrees with the Go
 * implementation by one byte, nothing this SDK signs will verify anywhere. It
 * is tested against `spec/test-vectors/jcs/canonicalization.json` -- the same
 * committed vectors the Go and Python implementations reproduce -- rather than
 * against itself.
 *
 * @module
 */

/** @typedef {null | boolean | number | string | JSONValue[] | { [k: string]: JSONValue }} JSONValue */

/**
 * Return the RFC 8785 canonical UTF-8 encoding of a value.
 *
 * @param {unknown} value
 * @returns {Uint8Array}
 */
export function canonicalize(value) {
  return new TextEncoder().encode(canonicalString(value));
}

/**
 * Return the canonical form as a string.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalString(value) {
  return write(value);
}

/**
 * Canonicalize an existing JSON document.
 *
 * @param {string} raw
 * @returns {Uint8Array}
 */
export function canonicalizeJSON(raw) {
  return canonicalize(JSON.parse(raw));
}

/**
 * Canonicalize an object with the named top-level members REMOVED.
 *
 * This is how every self-signed object in UAI is signed: 10.4 says
 * "jcs-canonicalize A minus signature". Removed, not blanked -- blanking the
 * member leaves `{"alg":"","domain":"","kid":"","value":""}` in the signed
 * bytes, which is what a struct-based implementation produces by accident and
 * what no reader of the spec would think to add.
 *
 * @param {Record<string, unknown>} value @param {...string} members
 * @returns {Uint8Array}
 */
export function canonicalizeWithout(value, ...members) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('uai: only objects have members to remove');
  }
  const kept = Object.fromEntries(
    Object.entries(value).filter(([k]) => !members.includes(k)));
  return canonicalize(kept);
}

/** @param {unknown} value @returns {string} */
function write(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return formatNumber(value);
    case 'string':
      return writeString(value);
    case 'undefined':
      // JSON has no undefined. Emitting null would change the document rather
      // than canonicalize it, and the difference would be invisible until a
      // signature failed to verify somewhere else.
      throw new TypeError('uai: undefined cannot be canonicalized');
    default:
      break;
  }
  if (Array.isArray(value)) {
    return '[' + value.map(write).join(',') + ']';
  }
  if (typeof value === 'object') {
    const entries = Object.entries(/** @type {Record<string, unknown>} */ (value))
      .filter(([, v]) => v !== undefined)
      .sort((a, b) => compareUTF16(a[0], b[0]));
    return '{' + entries.map(([k, v]) => writeString(k) + ':' + write(v)).join(',') + '}';
  }
  throw new TypeError(`uai: unsupported type ${typeof value}`);
}

/**
 * Order two strings by their UTF-16 code units, which is what RFC 8785
 * requires.
 *
 * JavaScript's `<` on strings already compares code units, so this exists to be
 * explicit about WHY the default is correct here: a future change to
 * `localeCompare` or a sort with a different collation would be a silent
 * protocol break.
 *
 * @param {string} a @param {string} b @returns {number}
 */
function compareUTF16(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

const SHORT_ESCAPES = {
  '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f',
  '\n': '\\n', '\r': '\\r', '\t': '\\t',
};

/** @param {string} s @returns {string} */
function writeString(s) {
  let out = '"';
  for (const ch of s) {
    const short = /** @type {Record<string, string>} */ (SHORT_ESCAPES)[ch];
    if (short !== undefined) {
      out += short;
    } else if (ch < ' ') {
      out += '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0');
    } else {
      out += ch;
    }
  }
  return out + '"';
}

/**
 * Serialize a double the way ECMAScript `Number::toString` does, which is what
 * RFC 8785 delegates number formatting to.
 *
 * `String(n)` already IS that algorithm, so the work here is only the two
 * places JCS differs from what a JSON serializer would otherwise emit: negative
 * zero renders as "0", and NaN and the infinities are refused rather than
 * turned into null.
 *
 * @param {number} n @returns {string}
 */
function formatNumber(n) {
  if (!Number.isFinite(n)) {
    throw new TypeError(`uai: ${n} is not representable in JSON`);
  }
  if (n === 0) return '0';
  return String(n);
}
