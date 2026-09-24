"""RFC 8785 JSON Canonicalization, in the standard library only.

Every hash and every signature in UAI is computed over this representation, so
this file is on the verification path: if it disagrees with the Go
implementation by one byte, nothing this SDK signs will verify anywhere.  It is
therefore written against ``spec/test-vectors/jcs/canonicalization.json`` and
tested against the same committed vectors the Go and browser implementations
reproduce, rather than against itself.
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = ["canonicalize", "canonicalize_json", "canonicalize_without", "NotCanonicalizable"]


class NotCanonicalizable(ValueError):
    """A value JSON cannot represent canonically, such as NaN or an infinity."""


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value``."""
    return _write(value).encode("utf-8")


def canonicalize_json(raw: bytes | str) -> bytes:
    """Return the canonical form of an existing JSON document."""
    return canonicalize(json.loads(raw, parse_float=float, parse_int=int))


def canonicalize_without(value: Any, *members: str) -> bytes:
    """Canonicalize a mapping with the named top-level members REMOVED.

    This is how every self-signed object in UAI is signed: 10.4 says
    "jcs-canonicalize A minus signature".  Removed, not blanked -- blanking the
    member leaves ``{"alg":"","domain":"","kid":"","value":""}`` in the signed
    bytes, which is what a struct-based implementation produces by accident and
    what no reader of the spec would think to add.
    """
    if not isinstance(value, dict):
        raise NotCanonicalizable("only objects have members to remove")
    return canonicalize({k: v for k, v in value.items() if k not in members})


def _write(value: Any) -> str:
    if value is None:
        return "null"
    # bool before int: in Python True is an int, and emitting "1" for true would
    # change the document rather than canonicalize it.
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int):
        return _number(float(value)) if abs(value) > 2**53 else str(value)
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_write(v) for v in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_string(k) + ":" + _write(v) for k, v in members) + "}"
    raise NotCanonicalizable(f"unsupported type {type(value).__name__}")


def _utf16_key(name: Any) -> bytes:
    """Sort key ordering by UTF-16 code units, which is what RFC 8785 requires.

    Python compares strings by code point, which differs from code-unit order
    for characters outside the Basic Multilingual Plane.  Encoding to UTF-16
    big-endian makes a byte-wise comparison equal a code-unit comparison.
    """
    if not isinstance(name, str):
        raise NotCanonicalizable("object member names must be strings")
    return name.encode("utf-16-be", errors="surrogatepass")


_SHORT_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        short = _SHORT_ESCAPES.get(ch)
        if short is not None:
            out.append(short)
        elif ch < "\x20":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(f: float) -> str:
    """Serialize a double the way ECMAScript ``Number::toString`` does.

    RFC 8785 delegates number formatting to that algorithm, so this follows
    ECMA-262 6.1.6.1.20 directly: the shortest digit string that round-trips,
    placed in plain notation inside [1e-6, 1e21) and in exponential notation
    outside it, with no zero padding on the exponent.
    """
    if math.isnan(f) or math.isinf(f):
        raise NotCanonicalizable(f"{f} is not representable in JSON")
    if f == 0:
        return "0"  # including negative zero, which JCS renders as "0"

    sign = "-" if f < 0 else ""
    digits, n = _digits_and_exponent(abs(f))
    k = len(digits)

    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    exponent = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{sign}{mantissa}e{'+' if exponent >= 0 else '-'}{abs(exponent)}"


def _digits_and_exponent(f: float) -> tuple[str, int]:
    """Return (digits, n) with ``0.digits * 10**n == f`` and digits minimal.

    ``repr`` already gives the shortest string that round-trips, which is the
    property the algorithm needs; the work here is only re-deriving the decimal
    point position from it.
    """
    text = repr(f)
    if "e" in text or "E" in text:
        mantissa, _, exp_text = text.replace("E", "e").partition("e")
        exponent = int(exp_text)
    else:
        mantissa, exponent = text, 0
    integer, _, fraction = mantissa.partition(".")
    raw = integer + fraction
    stripped = raw.lstrip("0")
    leading_zeros = len(raw) - len(stripped)
    n = len(integer) + exponent - leading_zeros
    return stripped.rstrip("0") or "0", n
