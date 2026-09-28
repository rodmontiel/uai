#!/usr/bin/env python3
"""Runtime attestation, end to end, against a real SPIRE.

Phase 12's gate. It proves three things and refuses to pass without all of them:

  1. A binding can record a runtime SPIRE ATTESTED, not one the agent declared.
     The SVID is fetched through the Workload API, so the identity comes from
     what the kernel told the attestor about the process -- uid, binary path,
     binary digest -- and not from anything the process said about itself.
  2. A genuine SVID cannot bind a different agent (§9.1 step 6). This is the
     case proof of possession cannot see: the right agent key, the wrong runtime.
  3. Attestation alone does not raise the assurance level, and /verify says
     which dimension holds it down (§6.8).

Run with:  make attested
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from uai.crypto import Domain, Signer, b64url, jwk_thumbprint  # noqa: E402
from uai.pop import nonce, sign_request  # noqa: E402

# Shared with demo/demo.py: see demo/spire.py for why picking svid.0.pem is the
# mistake this replaces.
from spire import spiffe_id_of as read_spiffe_id  # noqa: E402
from spire import svid_count as count_svids  # noqa: E402
from spire import fetch_svid  # noqa: E402

BOLD, DIM, RED, GREEN, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[0m"

checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, ok, detail))
    mark = f"{GREEN}ok{RESET}  " if ok else f"{RED}FAIL{RESET}"
    print(f"  {mark}  {name}  {DIM}{detail}{RESET}")


def run(cmd: list[str], *, quiet: bool = False) -> str:
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0 and not quiet:
        raise SystemExit(f"{' '.join(cmd[:3])}… failed:\n{out.stderr.strip()}")
    return out.stdout


def request(url: str, ctx: ssl.SSLContext, *, method: str = "GET",
            body: dict | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    raw = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=raw, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if raw is not None and "Content-Type" not in (headers or {}):
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            return exc.code, json.loads(payload or b"{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": payload[:300].decode("utf-8", "replace")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--spire-dir", default=".spire")
    ap.add_argument("--spire-container", default="uai_spire-server_1")
    ap.add_argument("--container", default="podman")
    ap.add_argument("--trust-domain", default="uai.test")
    args = ap.parse_args()
    endpoint = args.endpoint.rstrip("/")
    bundle_path = os.path.join(args.spire_dir, "bootstrap.pem")

    server = [args.container, "exec", "-i", args.spire_container,
              "/opt/spire/bin/spire-server"]
    agent_bin = os.path.join(args.spire_dir, "bin", "spire-agent")
    socket = os.path.join(args.spire_dir, "public", "api.sock")

    print(f"{BOLD}Runtime attestation{RESET}  {DIM}docs/protocol/05-registration-binding.md §9.1{RESET}")

    # The gateway serves TLS with an SVID SPIRE minted for it, so the client
    # verifies the server against the same bundle the server verifies clients
    # against. One trust root, both directions.
    plain = ssl.create_default_context(cafile=bundle_path)

    def psql(sql: str) -> str:
        return run(["psql", args.dsn, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", sql]).strip()

    owner_did = "did:uai:owner:01M3ATTESTED00000000000000"
    keys = os.path.join(args.spire_dir, "demo")
    os.makedirs(keys, mode=0o700, exist_ok=True)
    owner_key = os.path.join(keys, "owner.jwk")
    if not os.path.exists(owner_key):
        priv = Ed25519PrivateKey.generate()
        fd = os.open(owner_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"kty": "OKP", "crv": "Ed25519",
                       "x": b64url(priv.public_key().public_bytes_raw()),
                       "d": b64url(priv.private_bytes_raw())}, fh)
    owner = Signer.from_file(owner_key, owner_did + "#key-1")
    psql(f"""
        INSERT INTO organizations (id, did, legal_name, jurisdiction)
        VALUES ('org-att', 'did:web:attested.example', 'Attested Ltd', 'AR')
        ON CONFLICT (did) DO NOTHING;
        INSERT INTO owners (id, uai_id, did, organization_id, display_name, jurisdiction)
        VALUES ('own-att', 'uai:owner:01M3ATTESTED00000000000000', '{owner_did}',
                'org-att', 'Attested Ops', 'AR') ON CONFLICT (did) DO NOTHING;
        INSERT INTO owner_keys (id, owner_id, key_id, alg, public_jwk, protection, valid_from)
        VALUES ('ok-att', 'own-att', 'key-1', 'EdDSA',
                '{json.dumps(owner.public_jwk())}'::jsonb, 'SOFTWARE', now() - interval '1 hour')
        ON CONFLICT (id) DO NOTHING;""")

    def register(label: str) -> tuple[str, Signer]:
        priv = Ed25519PrivateKey.generate()
        pub = {"kty": "OKP", "crv": "Ed25519",
               "x": b64url(priv.public_key().public_bytes_raw())}
        thumb = jwk_thumbprint(pub)
        code, opened = request(f"{endpoint}/v1/agents", plain, method="POST", body={
            "logical_name": label, "agent_type": "autonomous_task_agent",
            "owner_did": owner_did, "primary_jurisdiction": "AR", "version": "1.0.0",
        }, headers={"Idempotency-Key": "att-" + nonce()})
        if code >= 300:
            raise SystemExit(f"registration: {code} {opened}")
        reg = opened["registration_id"]

        def stmt(role: str, challenge: str) -> dict:
            return {"challenge": challenge, "registration_id": reg, "role": role,
                    "agent_key_thumbprint": thumb, "owner_did": owner_did}

        st = stmt("owner", opened["challenge_owner"])
        request(f"{endpoint}/v1/agents/{reg}/prove", plain, method="POST", body={
            "role": "owner", "challenge": st["challenge"], "agent_key_thumbprint": thumb,
            "signature": owner.sign_object(Domain.CHALLENGE, st).as_dict(),
        }, headers={"Idempotency-Key": "att-" + nonce()})
        st = stmt("agent", opened["challenge_agent"])
        code, minted = request(f"{endpoint}/v1/agents/{reg}/prove", plain, method="POST", body={
            "role": "agent", "challenge": st["challenge"], "agent_key_thumbprint": thumb,
            "public_jwk": pub,
            "signature": Signer(priv, "did:key:pending#key-1").sign_object(
                Domain.CHALLENGE, st).as_dict(),
        }, headers={"Idempotency-Key": "att-" + nonce()})
        if code >= 300:
            raise SystemExit(f"minting: {code} {minted}")
        return minted["uai_id"], Signer(priv, minted["did"] + "#key-1")

    print(f"\n{BOLD}Two identities, and an SVID for the first{RESET}")
    subject_id, subject_key = register("AttestedAgent")
    other_id, other_key = register("OtherAgent")
    ulid = subject_id.rsplit(":", 1)[-1]
    print(f"  subject {subject_id}\n  other   {other_id}")

    # The registration entry is the operator's decision about which process may
    # hold which identity. The agent then enforces it from what it observes.
    run(server + ["entry", "create",
                  "-parentID", parent_of(args), "-spiffeID",
                  f"spiffe://{args.trust_domain}/agents/{ulid}/i/dev",
                  "-selector", f"unix:uid:{os.getuid()}", "-x509SVIDTTL", "3600"], quiet=True)
    svid_dir = os.path.join(args.spire_dir, "svid")
    # A workload holds every SVID whose registration entry matches it, and a
    # selector like unix:uid matches more than one. Picking svid.0 got the SVID
    # of whichever entry SPIRE happened to return first -- a bug that would have
    # shipped as "attestation works" while binding the wrong identity. An agent
    # has to choose the SVID that names IT, and wait for it to exist.
    svid_pem = fetch_svid(agent_bin, socket, svid_dir, ulid)
    check("the Workload API issued an SVID for this agent", bool(svid_pem),
          read_spiffe_id(svid_pem) if svid_pem else f"none of the {count_svids(svid_dir)} "
          f"SVIDs this workload holds names {ulid}")
    if not svid_pem:
        return report()

    mtls = ssl.create_default_context(cafile=bundle_path)
    mtls.load_cert_chain(svid_pem, svid_pem[:-len(".pem")] + ".key")

    print(f"\n{BOLD}Binding{RESET}")
    code, out = bind(endpoint, subject_id, subject_key, mtls, svid_pem)
    check("a bind presenting the attested SVID succeeds", code == 200 and out.get("status") == "ACTIVE",
          f"{code} {out.get('status') or out.get('title')}")

    attestor = psql(f"""SELECT attestor FROM runtime_identities r
        JOIN agents a ON a.id = r.agent_id WHERE a.uai_id = '{subject_id}'
        ORDER BY bound_at DESC LIMIT 1""")
    check("the runtime is recorded as attested, not self-declared",
          attestor == f"spiffe://{args.trust_domain}", attestor or "(none)")

    print(f"\n{BOLD}What it refuses{RESET}")
    code, out = bind(endpoint, other_id, other_key, mtls, svid_pem)
    check("a genuine SVID cannot bind a different agent",
          code == 403 and out.get("title") == "UAI_RUNTIME_IDENTITY_MISMATCH",
          f"{code} {out.get('title')}")

    code, out = bind(endpoint, other_id, other_key, plain, svid_pem, forge=True)
    check("a declared svid_spiffe_id with no certificate is refused",
          code == 401 and out.get("title") == "UAI_RUNTIME_ATTESTATION_REQUIRED",
          f"{code} {out.get('title')}")

    print(f"\n{BOLD}What it is worth{RESET}")
    code, verdict = request(f"{endpoint}/v1/verify/{subject_id}", plain)
    check("attestation alone does not raise the assurance level",
          verdict.get("assurance_level") == "UAI-AL0",
          f"{verdict.get('assurance_level')}")
    check("/verify names the dimension holding it down",
          verdict.get("assurance_limited_by") == "owner verification",
          f"{verdict.get('assurance_limited_by')}: {verdict.get('assurance_detail')}")
    return report()


def parent_of(args) -> str:
    """The attested node identity, read from the agent's own log."""
    import re
    log = os.path.join(args.spire_dir, "agent.log")
    with open(log, encoding="utf-8") as fh:
        m = re.search(rf"spiffe://{re.escape(args.trust_domain)}/spire/agent/join_token/[a-f0-9-]+",
                      fh.read())
    if not m:
        raise SystemExit("the SPIRE agent has not attested; run make spire-up")
    return m.group(0)




def bind(endpoint: str, uai_id: str, signer: Signer, ctx: ssl.SSLContext,
         svid_pem: str, *, forge: bool = False) -> tuple[int, dict]:
    """The two-call exchange of §9.1.1, over the given TLS context."""
    def send(payload: dict) -> tuple[int, dict]:
        raw = json.dumps(payload).encode()
        url = f"{endpoint}/v1/agents/{uai_id}/bind"
        headers = sign_request(signer, "POST", url, {"Content-Type": "application/json"},
                               raw, Domain.CHALLENGE, uai_id)
        headers["Idempotency-Key"] = "att-" + nonce()
        return request(url, ctx, method="POST", body=payload, headers=headers)

    code, opened = send({})
    if code != 202:
        return code, opened
    spiffe_id = read_spiffe_id(svid_pem)
    cert_hash = sha256_of(svid_pem)
    if forge:
        # The shape of the old attack: name a runtime in the signed statement
        # and present nothing that proves it.
        spiffe_id = spiffe_id.rsplit("/i/", 1)[0] + "/i/invented"
    statement = {
        "challenge": opened["challenge"], "operation": "BIND_AGENT", "uai_id": uai_id,
        "audience": opened["audience"], "svid_spiffe_id": spiffe_id,
        "svid_cert_hash": cert_hash,
    }
    return send({
        "challenge": opened["challenge"], "svid_spiffe_id": spiffe_id,
        "svid_cert_hash": cert_hash,
        "signature": signer.sign_object(Domain.CHALLENGE, statement).as_dict(),
    })


def sha256_of(pem_path: str) -> str:
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    with open(pem_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    return "sha256:" + hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def report() -> int:
    failed = [c for c in checks if not c[1]]
    print()
    if failed:
        print(f"{RED}{BOLD}{len(failed)} of {len(checks)} checks failed{RESET}")
        return 1
    print(f"{BOLD}{len(checks)}/{len(checks)} checks — the runtime is attested, "
          f"and the level says what that is worth{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
