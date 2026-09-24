"""UAI-CS-1 in Python: domain separation, commitments and Ed25519 signatures.

The one external dependency of this SDK lives here.  Python has no asymmetric
cryptography in its standard library, and the alternative -- a pure-Python
Ed25519 -- would be a timing-attack surface wrapped around the agent's signing
key.  ``cryptography`` (PyCA) is the de-facto standard, is audited, and does the
arithmetic in a constant-time C implementation.  Everything else in this SDK,
including canonicalization and HTTP, is the standard library.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize

__all__ = [
    "Domain", "Signature", "Signer", "digest", "digest_object", "commit",
    "commit_object", "verify_commitment", "salt", "format_digest", "SALT_LEN",
    "jwk_thumbprint", "thumbprint_input",
]

SALT_LEN = 32


class Domain:
    """The domain registry of 7.2.

    Every digest and every signature covers ``DOMAIN || 0x00 || payload``, so a
    signature made in one context can never be replayed as valid in another.
    Reusing one of these for a new purpose is a security bug, not a shortcut.
    """

    ATTESTATION = "UAI-v1:attestation"
    CREDENTIAL = "UAI-v1:credential"
    DID_DOCUMENT = "UAI-v1:did-document"
    REGISTRATION = "UAI-v1:registration"
    CHALLENGE = "UAI-v1:challenge"
    VOTE = "UAI-v1:vote"
    DECISION = "UAI-v1:decision"
    POLICY_BUNDLE = "UAI-v1:policy-bundle"
    QUARANTINE = "UAI-v1:quarantine"
    REVOCATION = "UAI-v1:revocation"
    CHECKPOINT = "UAI-v1:checkpoint"
    COMMITMENT = "UAI-v1:commitment"
    AUDIT = "UAI-v1:audit"
    CAPABILITY_REQUEST = "UAI-v1:capability-request"
    SUSPICION = "UAI-v1:suspicion"
    PASSPORT = "UAI-v1:passport"

    ALL = frozenset({
        ATTESTATION, CREDENTIAL, DID_DOCUMENT, REGISTRATION, CHALLENGE, VOTE,
        DECISION, POLICY_BUNDLE, QUARANTINE, REVOCATION, CHECKPOINT, COMMITMENT,
        AUDIT, CAPABILITY_REQUEST, SUSPICION, PASSPORT,
    })


class UnknownDomain(ValueError):
    """A domain outside the registry.

    Rejected rather than accepted permissively: an unrecognised context is
    exactly the situation in which a cross-context replay would succeed.
    """


def signing_input(domain: str, payload: bytes) -> bytes:
    """Return ``DOMAIN || 0x00 || payload``, the exact bytes that are signed."""
    if domain not in Domain.ALL:
        raise UnknownDomain(f"unknown domain separation string: {domain!r}")
    return domain.encode("ascii") + b"\x00" + payload


def digest(domain: str, payload: bytes) -> bytes:
    """SHA-256 over the domain-separated payload."""
    return hashlib.sha256(signing_input(domain, payload)).digest()


def digest_object(domain: str, value: Any) -> bytes:
    """Canonicalize ``value`` per RFC 8785 and return its domain-separated digest."""
    return digest(domain, canonicalize(value))


def salt() -> bytes:
    """A fresh 32-byte commitment salt."""
    return os.urandom(SALT_LEN)


def commit(salt_bytes: bytes, content: bytes) -> bytes:
    """Return ``SHA-256("UAI-v1:commitment" || 0x00 || salt || content)``.

    The salt is mandatory.  A bare hash of low-entropy content -- an email, an
    amount, a customer id, a yes/no answer -- is recoverable by dictionary
    attack, and commitments are published on-chain where that leak is permanent.
    """
    if len(salt_bytes) < SALT_LEN:
        raise ValueError(f"salt must be at least {SALT_LEN} bytes, got {len(salt_bytes)}")
    return digest(Domain.COMMITMENT, salt_bytes + content)


def commit_object(salt_bytes: bytes, value: Any) -> bytes:
    """Commit to the canonical form of ``value``."""
    return commit(salt_bytes, canonicalize(value))


def verify_commitment(commitment: bytes, salt_bytes: bytes, content: bytes) -> bool:
    """Report whether ``(salt, content)`` opens the commitment.

    This is the disclosure path: an authorized party is shown the salt and the
    content and checks the match itself, rather than trusting an assertion that
    it matched.
    """
    try:
        return commit(salt_bytes, content) == commitment
    except (ValueError, UnknownDomain):
        return False


def thumbprint_input(jwk: dict[str, Any]) -> str:
    """Return the exact bytes RFC 7638 hashes, or "" for an unsupported key.

    RFC 7638 fixes the member set and their order per key type, so this is
    built by hand rather than by a JSON serializer: a serializer that emitted
    its own field order would produce a different thumbprint for the same key,
    and the registration proof that names it would stop composing.
    """
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        members = ("crv", "kty", "x")
    elif kty == "EC":
        members = ("crv", "kty", "x", "y")
    else:
        return ""
    if any(not isinstance(jwk.get(m), str) for m in members):
        return ""
    return "{" + ",".join(f'"{m}":{json.dumps(jwk[m])}' for m in members) + "}"


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Return the RFC 7638 thumbprint in the UAI wire form ``sha256:<hex>``.

    This is the subject identifier of a registration proof (8.2): both the
    owner and the agent sign it, so an owner vouching for a thumbprint the
    agent computed differently vouches for a key that was never presented.

    It is the one digest in UAI that is NOT domain-separated, because RFC 7638
    fixes its input exactly and a prefix would make it a different function
    under the same name.
    """
    canonical = thumbprint_input(jwk)
    if not canonical:
        raise ValueError(f"unsupported key type for a thumbprint: {jwk.get('kty')}/{jwk.get('crv')}")
    return format_digest(hashlib.sha256(canonical.encode("utf-8")).digest())


def format_digest(raw: bytes) -> str:
    """Render a digest in the UAI wire form: ``sha256:`` and lowercase hex."""
    return "sha256:" + raw.hex()


def b64url(raw: bytes) -> str:
    """base64url without padding, the encoding used throughout UAI."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class Signature:
    """A detached UAI signature envelope."""

    alg: str
    kid: str
    domain: str
    value: str

    def as_dict(self) -> dict[str, str]:
        return {"alg": self.alg, "kid": self.kid, "domain": self.domain, "value": self.value}


class Signer:
    """An Ed25519 signing key with the DID URL that names it.

    The key is supplied, never generated here on the fly: an SDK that created a
    key when it found none would hand out credentials that stop verifying at the
    next restart, and the operator would learn about it from verification
    failures rather than from a startup error.
    """

    ALG = "EdDSA"
    HTTP_ALG = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey, kid: str) -> None:
        self._key = private_key
        self.kid = kid

    @classmethod
    def from_file(cls, path: str, kid: str) -> "Signer":
        """Load a key from a JWK file, refusing one any other user can read."""
        mode = os.stat(path).st_mode
        if mode & 0o077:
            raise PermissionError(
                f"{path} is readable by group or other (mode {mode & 0o777:o}); "
                "a signing key that others can read is not a signing key"
            )
        with open(path, "rb") as handle:
            jwk = json.load(handle)
        return cls.from_jwk(jwk, kid)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any], kid: str) -> "Signer":
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError("only Ed25519 OKP keys are supported by this SDK")
        if "d" not in jwk:
            raise ValueError("the JWK carries no private key")
        return cls(Ed25519PrivateKey.from_private_bytes(b64url_decode(jwk["d"])), kid)

    @property
    def did(self) -> str:
        """The DID this key belongs to: the kid without its fragment."""
        return self.kid.split("#", 1)[0]

    def public_jwk(self) -> dict[str, str]:
        raw = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}

    def sign_raw(self, message: bytes) -> bytes:
        """Sign exact bytes, with no domain prefix.

        Used only for RFC 9421 signature bases, where the domain is carried
        inside the signed base as the ``tag`` parameter.  Everything else goes
        through :meth:`sign`.
        """
        return self._key.sign(message)

    def sign(self, domain: str, payload: bytes) -> Signature:
        """Sign a domain-separated payload."""
        raw = self._key.sign(signing_input(domain, payload))
        return Signature(alg=self.ALG, kid=self.kid, domain=domain, value=b64url(raw))

    def sign_object(self, domain: str, value: Any) -> Signature:
        """Canonicalize and sign."""
        return self.sign(domain, canonicalize(value))


def verify(public_key: Ed25519PublicKey, domain: str, payload: bytes, signature: Signature) -> None:
    """Raise unless the signature is valid in exactly this domain."""
    if signature.domain != domain:
        raise ValueError(f"signed for {signature.domain!r}, verifying as {domain!r}")
    public_key.verify(b64url_decode(signature.value), signing_input(domain, payload))
