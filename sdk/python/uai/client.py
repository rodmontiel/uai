"""The HTTP surface, over the standard library.

``urllib.request`` rather than ``requests`` or ``httpx``: this SDK holds the
agent's signing key, so every dependency here is a dependency that could sign on
the agent's behalf (T-07).  One dependency, for the cryptography, is a cost worth
paying; a second one, for convenience over HTTP, is not.
"""

from __future__ import annotations

import json
import ssl
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

    def __init__(self, endpoint: str, uai_id: str, signer: Signer, timeout: float = 30.0,
                 ca: str = "", svid: str = "", svid_key: str = "") -> None:
        if not uai_id:
            raise ValueError("the agent's UAI-ID is required")
        self.endpoint = endpoint.rstrip("/")
        self.uai_id = uai_id
        self.signer = signer
        self.timeout = timeout
        # A gateway that verifies runtime identity serves TLS, because an SVID is
        # presented as a client certificate and a plain connection has nowhere to
        # put one.  Its certificate is issued by the deployment's own CA, which no
        # public trust store knows, so without this the SDK could only reach a
        # gateway that verifies nothing.
        #
        # A path, never a "skip verification" switch: an SDK that could be told to
        # trust any certificate would let anything on the path read an agent's
        # traffic and answer for the registry.  If you do not have the CA, that is
        # the problem to fix.
        self.context = ssl.create_default_context(cafile=ca) if ca else None
        # The agent's X509-SVID, presented as a client certificate. A registry
        # that verifies runtimes reads WHERE an agent runs off this certificate
        # and never off the request body, so an agent with no SVID to present
        # cannot bind there at all -- which is the point of §9.1, not a gap.
        if svid:
            if self.context is None:
                raise ValueError(
                    "an SVID is presented over TLS, so a CA is needed to verify the "
                    "gateway in return: pass ca= as well")
            self.context.load_cert_chain(svid, svid_key or svid)

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
            with urllib.request.urlopen(request, timeout=self.timeout,
                                        context=self.context) as response:
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
            hint = ""
            if isinstance(exc.reason, ssl.SSLCertVerificationError) and self.context is None:
                # The one failure whose cause is invisible in its message: the
                # gateway is fine, the certificate is fine, and nothing here was
                # told which CA issued it.
                hint = ("\n  This gateway serves TLS and no CA was given. Pass ca= to "
                        "Transport/Agent, or set UAI_API_CA.")
            raise UAIError(f"{method} {path}: {exc.reason}{hint}") from None


def _decode(raw: bytes) -> Any:
    if not raw:
        return None
    if len(raw) > MAX_RESPONSE:
        raise UAIError("response body exceeds the client limit")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}
