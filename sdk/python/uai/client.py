"""The HTTP surface, over the standard library.

``urllib.request`` rather than ``requests`` or ``httpx``: this SDK holds the
agent's signing key, so every dependency here is a dependency that could sign on
the agent's behalf (T-07).  One dependency, for the cryptography, is a cost worth
paying; a second one, for convenience over HTTP, is not.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .crypto import Signer
from .errors import Problem, UAIError
from .pop import nonce, normalize_url, sign_request

__all__ = ["Transport"]

#: Cap on a response body.  A client that read an unbounded body would let a
#: compromised or confused gateway exhaust the agent's memory.
MAX_RESPONSE = 4 << 20


class Transport:
    """Signed and unsigned calls to one gateway, as one identity."""

    def __init__(self, endpoint: str, uai_id: str, signer: Signer, timeout: float = 30.0) -> None:
        if not uai_id:
            raise ValueError("the agent's UAI-ID is required")
        self.endpoint = endpoint.rstrip("/")
        self.uai_id = uai_id
        self.signer = signer
        self.timeout = timeout

    def get(self, path: str) -> Any:
        return self._send("GET", path, None, {})

    def post_public(self, path: str, body: Any) -> Any:
        """An unsigned call to a public endpoint.

        Separate from :meth:`post` so that reaching a public surface never
        silently requires a key: a relying party checking somebody else's
        passport is not a UAI participant, and an SDK that made them sign to ask
        would have put an account in front of verification.
        """
        raw = json.dumps(body).encode("utf-8")
        return self._send("POST", path, raw, {
            "Content-Type": "application/json",
            "Idempotency-Key": "sdk-" + nonce(),
        })

    def post(self, path: str, domain: str, body: Any) -> Any:
        """A signed, state-changing call.

        ``domain`` is carried as the RFC 9421 tag, and it is an argument rather
        than a constant because a signature valid for one endpoint must not be
        replayable against another.
        """
        raw = json.dumps(body).encode("utf-8")
        url = normalize_url(self.endpoint, path)
        headers = sign_request(
            self.signer, "POST", url,
            {"Content-Type": "application/json", "Idempotency-Key": "sdk-" + nonce()},
            raw, domain, self.uai_id,
        )
        return self._send("POST", path, raw, headers, url=url)

    def _send(self, method: str, path: str, body: bytes | None,
              headers: dict[str, str], url: str | None = None) -> Any:
        target = url or normalize_url(self.endpoint, path)
        request = urllib.request.Request(target, data=body, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return _decode(response.read(MAX_RESPONSE + 1))
        except urllib.error.HTTPError as exc:
            payload = exc.read(MAX_RESPONSE + 1)
            document = _decode(payload)
            if not isinstance(document, dict) or "title" not in document:
                # A non-JSON error body is reported as what it is rather than
                # parsed into a plausible-looking problem: a proxy's HTML error
                # page must not read as a verdict from the gateway.
                document = {"title": "UAI_UNKNOWN_ERROR",
                            "detail": payload.decode("utf-8", "replace").strip()}
            raise Problem(exc.code, document) from None
        except urllib.error.URLError as exc:
            raise UAIError(f"{method} {path}: {exc.reason}") from None


def _decode(raw: bytes) -> Any:
    if not raw:
        return None
    if len(raw) > MAX_RESPONSE:
        raise UAIError("response body exceeds the client limit")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}
