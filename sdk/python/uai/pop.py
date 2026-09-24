"""RFC 9421 HTTP message signatures: proof of possession for the UAI API.

The rule this module exists to enforce: ``agent_id`` in a JSON body proves
nothing.  Any process that can write the body can write the identifier.  A
state-changing call carries a signature from a key the caller demonstrably
controls (INV-002).

Domain separation works differently here than everywhere else in UAI, and the
difference is deliberate.  RFC 9421 already carries the context inside the
signature, as the ``tag`` parameter of ``@signature-params``, which is itself a
signed component.  Prefixing the base with the UAI domain as well would add no
security property and would stop a standard RFC 9421 verifier from
interoperating.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from .crypto import Signer

__all__ = ["Params", "signature_base", "content_digest", "sign_request", "nonce"]

HEADER_SIGNATURE_INPUT = "Signature-Input"
HEADER_SIGNATURE = "Signature"
HEADER_CONTENT_DIGEST = "Content-Digest"
HEADER_AGENT_ID = "UAI-Agent-Id"
HEADER_NONCE = "UAI-Nonce"

LABEL = "uai"

#: The components UAI requires on a state-changing call.
#:
#: Content-Digest is covered so the body cannot be swapped; UAI-Agent-Id and
#: UAI-Nonce are covered so that neither the claimed identity nor the replay
#: token can be altered without invalidating the signature.
DEFAULT_COMPONENTS = ("@method", "@target-uri", "content-digest", "uai-agent-id", "uai-nonce")


def nonce() -> str:
    """A fresh 128-bit replay nonce."""
    return secrets.token_hex(16)


def content_digest(body: bytes) -> str:
    """An RFC 9530 ``Content-Digest`` field value."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode("ascii") + ":"


@dataclass
class Params:
    """RFC 9421 signature parameters.  ``tag`` carries the UAI domain."""

    key_id: str
    tag: str
    created: int
    alg: str = "ed25519"
    components: tuple[str, ...] = DEFAULT_COMPONENTS
    expires: int = 0
    nonce: str = ""

    def serialize(self) -> str:
        """Render as an RFC 8941 inner list.

        This exact string is both the ``Signature-Input`` value and the last
        line of the signature base.  Building it twice, in two places, is how
        implementations end up signing something other than what they send.
        """
        inner = " ".join(_quote(c.lower()) for c in self.components)
        out = f"({inner})"
        if self.created:
            out += f";created={self.created}"
        if self.expires:
            out += f";expires={self.expires}"
        if self.key_id:
            out += f";keyid={_quote(self.key_id)}"
        if self.alg:
            out += f";alg={_quote(self.alg)}"
        if self.nonce:
            out += f";nonce={_quote(self.nonce)}"
        if self.tag:
            out += f";tag={_quote(self.tag)}"
        return out


def _quote(value: str) -> str:
    """Quote a string the way Go's strconv.Quote and RFC 8941 both do."""
    return json.dumps(value, ensure_ascii=False)


@dataclass
class Message:
    """The subset of an HTTP request a signature covers."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)


def signature_base(message: Message, params: Params) -> bytes:
    """Build the RFC 9421 signature base.

    One line per covered component, then the ``@signature-params`` line with no
    trailing newline.  The absence of that final newline is not a detail: it is
    where implementations most often diverge, and a base with one extra byte
    verifies against nothing.
    """
    lines: list[str] = []
    seen: set[str] = set()
    for raw in params.components:
        name = raw.lower()
        if name in seen:
            raise ValueError(f"component {name!r} listed twice")
        seen.add(name)
        lines.append(f"{_quote(name)}: {_component_value(message, name)}")
    lines.append(f'{_quote("@signature-params")}: {params.serialize()}')
    return "\n".join(lines).encode("utf-8")


def _component_value(message: Message, name: str) -> str:
    if name.startswith("@"):
        parts = urlsplit(message.url)
        if name == "@method":
            return message.method.upper()
        if name == "@target-uri":
            return message.url
        if name == "@authority":
            return parts.netloc.lower()
        if name == "@scheme":
            return parts.scheme.lower()
        if name == "@path":
            return parts.path or "/"
        if name == "@query":
            return "?" + parts.query
        raise ValueError(f"unsupported derived component {name!r}")
    for key, value in message.headers.items():
        if key.lower() == name:
            return " ".join(value.split())
    raise ValueError(f"covered component missing from the message: {name}")


def sign_request(signer: Signer, method: str, url: str, headers: dict[str, str],
                 body: bytes, domain: str, agent_id: str,
                 replay_nonce: str | None = None, created: int | None = None) -> dict[str, str]:
    """Sign an outgoing request, returning the headers to send.

    ``body`` is required because the digest is a covered component: signing
    without covering the body would leave it swappable, which is the whole point
    of proof of possession on a state-changing call.
    """
    if not agent_id:
        raise ValueError("an agent id is required")
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        # A relative target would make the signature cover a resource the caller
        # never addressed, and it would verify against nothing at the gateway.
        raise ValueError(f"the target URI must be absolute, got {url!r}")

    out = dict(headers)
    out[HEADER_CONTENT_DIGEST] = content_digest(body)
    out[HEADER_AGENT_ID] = agent_id
    out[HEADER_NONCE] = replay_nonce or nonce()

    params = Params(
        key_id=signer.kid, tag=domain,
        created=created if created is not None else int(time.time()),
        alg=signer.HTTP_ALG,
    )
    base = signature_base(Message(method, url, out), params)
    raw = signer.sign_raw(base)
    out[HEADER_SIGNATURE_INPUT] = f"{LABEL}={params.serialize()}"
    out[HEADER_SIGNATURE] = f"{LABEL}=:{base64.b64encode(raw).decode('ascii')}:"
    return out


def normalize_url(base: str, path: str) -> str:
    """Join a base URL and a path into an absolute target URI."""
    parts = urlsplit(base)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"base url must be absolute, got {base!r}")
    prefix = parts.path.rstrip("/")
    target, _, query = path.partition("?")
    return urlunsplit((parts.scheme, parts.netloc, prefix + target, query, ""))
