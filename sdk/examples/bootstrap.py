#!/usr/bin/env python3
"""Bring one agent into existence, for local development.

This is the OWNER's side of the flow, and it is a separate script on purpose.
Registration needs two signatures from two keys held by two parties (8.2), and
an example that quietly held both would teach the wrong shape: the whole point
is that an agent cannot register itself.

Here, for development, one process holds both keys. In a real deployment the
owner key lives with the owner -- in a wallet, an HSM, a hardware token -- and
never touches the machine the agent runs on.

    python3 sdk/examples/bootstrap.py --owner-did did:uai:owner:01... \\
        --owner-key .keys/owner.jwk --name DeliveryOptimizer

It prints the environment the agent-side examples read.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from uai.client import Transport  # noqa: E402
from uai.crypto import Domain, Signer, b64url, jwk_thumbprint  # noqa: E402
from uai.pop import nonce  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("UAI_ENDPOINT", "http://127.0.0.1:8080"))
    parser.add_argument("--owner-did", required=True)
    parser.add_argument("--owner-key", required=True, help="the owner's JWK; held by the owner, not the agent")
    parser.add_argument("--agent-key", default=".keys/agent.jwk")
    parser.add_argument("--name", default="DeliveryOptimizer")
    parser.add_argument("--agent-type", default="autonomous_task_agent")
    parser.add_argument("--jurisdiction", default="AR")
    parser.add_argument("--spiffe-id", default="")
    args = parser.parse_args()

    owner = Signer.from_file(args.owner_key, args.owner_did + "#key-1")

    # ── 1. the agent generates its own key ──────────────────────────────────
    # UAI never generates it, and neither does the owner: whoever can generate
    # your key can impersonate you.
    if os.path.exists(args.agent_key):
        print(f"{args.agent_key} already exists; delete it deliberately to re-register", file=sys.stderr)
        return 1
    agent_private = Ed25519PrivateKey.generate()
    agent_jwk = {
        "kty": "OKP", "crv": "Ed25519",
        "x": b64url(agent_private.public_key().public_bytes_raw()),
        "d": b64url(agent_private.private_bytes_raw()),
    }
    os.makedirs(os.path.dirname(args.agent_key) or ".", exist_ok=True)
    fd = os.open(args.agent_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(agent_jwk, handle)
    public_jwk = {k: agent_jwk[k] for k in ("kty", "crv", "x")}
    tp = jwk_thumbprint(public_jwk)

    # ── 2. open the registration ────────────────────────────────────────────
    def post(path: str, body: dict, headers: dict | None = None) -> dict:
        raw = json.dumps(body).encode()
        request = urllib.request.Request(args.endpoint + path, data=raw, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Idempotency-Key", "boot-" + nonce())
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            print(f"{path} -> {exc.code}: {exc.read().decode()}", file=sys.stderr)
            raise SystemExit(1) from None

    opened = post("/v1/agents", {
        "logical_name": args.name, "agent_type": args.agent_type,
        "owner_did": args.owner_did, "primary_jurisdiction": args.jurisdiction,
    })
    registration_id = opened["registration_id"]
    print(f"registration {registration_id} opened")

    # ── 3. two signatures naming the same subject ───────────────────────────
    def ownership(role: str, challenge: str) -> dict:
        return {
            "challenge": challenge, "registration_id": registration_id, "role": role,
            "agent_key_thumbprint": tp, "owner_did": args.owner_did,
        }

    owner_statement = ownership("owner", opened["challenge_owner"])
    post(f"/v1/agents/{registration_id}/prove", {
        "role": "owner", "challenge": owner_statement["challenge"],
        "agent_key_thumbprint": tp,
        "signature": owner.sign_object(Domain.CHALLENGE, owner_statement).as_dict(),
    })
    print("owner proof accepted")

    agent = Signer(agent_private, "did:key:pending#key-1")
    agent_statement = ownership("agent", opened["challenge_agent"])
    minted = post(f"/v1/agents/{registration_id}/prove", {
        "role": "agent", "challenge": agent_statement["challenge"],
        "agent_key_thumbprint": tp, "public_jwk": public_jwk,
        "signature": agent.sign_object(Domain.CHALLENGE, agent_statement).as_dict(),
    })
    uai_id = minted["uai_id"]
    print(f"minted {uai_id} ({minted['status']})")

    # ── 4. bind a runtime ───────────────────────────────────────────────────
    # An identity with no bound runtime cannot attest: an attestation that
    # claims something ran, while naming nothing that could have run it, would
    # make runtime assurance optional in practice (6.10).
    bound_agent = Signer(agent_private, f"did:{uai_id}#key-1")
    transport = Transport(args.endpoint, uai_id, bound_agent)
    challenge = transport.post(f"/v1/agents/{uai_id}/bind", Domain.CHALLENGE, {})
    spiffe_id = args.spiffe_id or f"spiffe://uai.world/agents/{uai_id}/i/{secrets.token_hex(4)}"
    statement = {
        "challenge": challenge["challenge"], "operation": "BIND_AGENT", "uai_id": uai_id,
        "audience": challenge["audience"], "svid_spiffe_id": spiffe_id,
        "svid_cert_hash": "sha256:" + secrets.token_hex(32),
    }
    result = transport.post(f"/v1/agents/{uai_id}/bind", Domain.CHALLENGE, {
        "challenge": statement["challenge"], "svid_spiffe_id": statement["svid_spiffe_id"],
        "svid_cert_hash": statement["svid_cert_hash"],
        "signature": bound_agent.sign_object(Domain.CHALLENGE, statement).as_dict(),
    })
    print(f"bound: {result['status']} at sequence {result['sequence']}")

    print("\n# the agent-side examples read these:")
    print(f"export UAI_ENDPOINT={args.endpoint}")
    print(f"export UAI_AGENT_ID={uai_id}")
    print(f"export UAI_AGENT_KEY={args.agent_key}")
    print(f"export UAI_OWNER_DID={args.owner_did}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
