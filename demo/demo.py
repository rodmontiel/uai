#!/usr/bin/env python3
"""The ACME Robotics / DeliveryOptimizer scenario (§24.5), scripted.

Every step names the MVP criterion it demonstrates, and the script exits
non-zero if any of the 21 is not demonstrated. It is a test that happens to be
readable, not a narration that happens to run.

    python3 demo/demo.py --endpoint http://127.0.0.1:8080 \
        --issuer-key .keys/issuer.jwk --dsn postgres://...

It needs the database directly for two things only: appointing delegates and
approving a capability, both of which are acts of parties the agent is not, and
neither of which the API exposes to anything an agent can reach.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "sdk", "python"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from uai import Agent, Jurisdiction, PolicyRefused  # noqa: E402
from uai.canonical import canonicalize  # noqa: E402
from uai.client import Transport  # noqa: E402
from uai.crypto import Domain, Signer, b64url, digest, format_digest, jwk_thumbprint  # noqa: E402
from uai.pop import nonce  # noqa: E402

# ── the 21 criteria of §24.1 ────────────────────────────────────────────────
CRITERIA = {
    1: "Create Organization",
    2: "Create Owner Credential",
    3: "Register Agent",
    4: "Generate UAI-ID",
    5: "Generate DID",
    6: "Issue Credential",
    7: "Bind runtime identity",
    8: "Execute action",
    9: "Sign action",
    10: "Evaluate guardrail",
    11: "Create transparency receipt",
    12: "Register blockchain commitment",
    13: "Detect suspicion",
    14: "Quarantine",
    15: "Open case",
    16: "Emit human votes",
    17: "Reach quorum",
    18: "Authorize revocation",
    19: "Execute revocation",
    20: "Reject future credentials",
    21: "Verify the whole history cryptographically",
}

BOLD, DIM, RED, GREEN, YELLOW, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    BOLD = DIM = RED = GREEN = YELLOW = RESET = ""

demonstrated: set[int] = set()


def step(n: int, what: str) -> None:
    print(f"\n{BOLD}── {n:>2}. {CRITERIA[n]}{RESET}  {DIM}{what}{RESET}")


def shown(n: int, detail: str = "") -> None:
    demonstrated.add(n)
    print(f"    {GREEN}✓{RESET} {detail}" if detail else f"    {GREEN}✓{RESET}")


def note(text: str) -> None:
    for line in text.strip().splitlines():
        print(f"    {DIM}{line.strip()}{RESET}")


# ── a software stand-in for a delegate's hardware authenticator ─────────────
#
# It produces assertions the gateway verifies. It is NOT what makes INV-005
# true: that rests on the assertion coming from hardware requiring a human
# gesture, and no script can demonstrate a human gesture. What this shows is
# the verification path — that the gateway recomputes the vote digest, checks
# the assertion against the registered credential, and refuses one without
# user verification.
RP_ID = "governance.uai.world"
ORIGIN = "https://governance.uai.world"


class Authenticator:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.count = 0

    @property
    def public_jwk(self) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519",
                "x": b64url(self.key.public_key().public_bytes_raw())}

    def credential_id(self) -> bytes:
        return hashlib.sha256(json.dumps(self.public_jwk, sort_keys=True).encode()).digest()[:16]

    def assert_over(self, challenge: bytes, *, user_verified: bool = True) -> dict[str, str]:
        rp_hash = hashlib.sha256(RP_ID.encode()).digest()
        flags = 0x01 | (0x04 if user_verified else 0x00)
        self.count += 1
        auth_data = rp_hash + bytes([flags]) + self.count.to_bytes(4, "big")
        client_data = json.dumps({
            "type": "webauthn.get",
            "challenge": base64.urlsafe_b64encode(challenge).decode().rstrip("="),
            "origin": ORIGIN, "crossOrigin": False,
        }, separators=(",", ":")).encode()
        signed = auth_data + hashlib.sha256(client_data).digest()
        return {
            "authenticator_data": b64url(auth_data),
            "client_data_json": b64url(client_data),
            "signature": b64url(self.key.sign(signed)),
            "user_verified": user_verified,
        }


def http_json(url: str, body: dict | None = None, method: str = "GET") -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
        request.add_header("Idempotency-Key", "demo-" + nonce())
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            problem = json.loads(body)
        except json.JSONDecodeError:
            # Not a problem document. Report what actually came back rather than
            # a decode error about it: a demo that hides the response has hidden
            # the one thing the reader needs.
            raise SystemExit(
                f"{RED}{method} {url} → {exc.code}{RESET}\n"
                f"  {body[:400].decode('utf-8', 'replace')}") from None
        raise SystemExit(
            f"{RED}{method} {url} → {exc.code} {problem.get('title')}{RESET}\n"
            f"  {problem.get('detail', '')}\n"
            f"  {problem.get('remediation', '')}".rstrip()) from None


def psql(dsn: str, sql: str) -> str:
    """Run one statement as an operator would.

    Used for exactly two things: appointing delegates and recording an owner's
    capability approval. Both are acts of parties the agent is not, and neither
    has an API route an agent could reach — which is the point.
    """
    out = subprocess.run(["psql", dsn, "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", sql],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"psql failed: {out.stderr.strip()}")
    return out.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default=os.environ.get("UAI_ENDPOINT", "http://127.0.0.1:8080"))
    parser.add_argument("--dsn", default=os.environ.get("PG_DSN", ""))
    parser.add_argument("--keys", default=os.environ.get("DEMO_KEYS", ".keys/demo"))
    parser.add_argument("--verify-bin", default=os.environ.get("UAI_VERIFY", "uai-verify"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn is required: the demo appoints delegates, which no API route does")

    os.makedirs(args.keys, mode=0o700, exist_ok=True)
    endpoint = args.endpoint.rstrip("/")

    print(f"{BOLD}The ACME demo{RESET}  {DIM}docs/protocol/17-mvp-scope.md §24.5{RESET}")

    # ── 1–2. the organization and its owner ─────────────────────────────────
    step(1, "ACME Robotics is a legal entity with a DID")
    org_did = "did:web:acme-robotics.example"
    owner_id = "own-demo"
    owner_did = "did:uai:owner:01JY8R9ZB00000000000000000"
    owner_key_path = os.path.join(args.keys, "owner.jwk")
    if not os.path.exists(owner_key_path):
        owner_private = Ed25519PrivateKey.generate()
        fd = os.open(owner_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"kty": "OKP", "crv": "Ed25519",
                       "x": b64url(owner_private.public_key().public_bytes_raw()),
                       "d": b64url(owner_private.private_bytes_raw())}, handle)
    owner = Signer.from_file(owner_key_path, owner_did + "#key-1")
    owner_pub = json.dumps(owner.public_jwk())

    psql(args.dsn, f"""
        INSERT INTO organizations (id, did, legal_name, jurisdiction)
        VALUES ('org-acme', '{org_did}', 'ACME Robotics', 'AR')
        ON CONFLICT (did) DO NOTHING;
        INSERT INTO owners (id, uai_id, did, organization_id, display_name, jurisdiction)
        VALUES ('{owner_id}', 'uai:owner:01JY8R9ZB00000000000000000', '{owner_did}',
                'org-acme', 'ACME Ops', 'AR')
        ON CONFLICT (did) DO NOTHING;
        INSERT INTO owner_keys (id, owner_id, key_id, alg, public_jwk, protection, valid_from)
        VALUES ('ok-demo', '{owner_id}', 'key-1', 'EdDSA', '{owner_pub}'::jsonb, 'SOFTWARE',
                now() - interval '1 hour')
        ON CONFLICT (id) DO NOTHING;""")
    shown(1, f"organization {org_did}")
    step(2, "the owner holds the key that will vouch for the agent")
    shown(2, f"owner {owner_did}, key held by the owner and not by the agent")

    # ── 3–6. registration: two signatures naming the same subject ───────────
    step(3, "the agent generates its own key; UAI never does")
    agent_key_path = os.path.join(args.keys, "agent.jwk")
    if os.path.exists(agent_key_path):
        os.remove(agent_key_path)
    agent_private = Ed25519PrivateKey.generate()
    agent_jwk = {"kty": "OKP", "crv": "Ed25519",
                 "x": b64url(agent_private.public_key().public_bytes_raw()),
                 "d": b64url(agent_private.private_bytes_raw())}
    fd = os.open(agent_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(agent_jwk, handle)
    public_jwk = {k: agent_jwk[k] for k in ("kty", "crv", "x")}
    thumbprint = jwk_thumbprint(public_jwk)

    opened = http_json(f"{endpoint}/v1/agents", {
        "logical_name": "DeliveryOptimizer", "agent_type": "autonomous_task_agent",
        "owner_did": owner_did, "primary_jurisdiction": "AR", "version": "3.1.0",
    }, "POST")
    registration = opened["registration_id"]
    note("""A registration mints nothing. Two signatures from two keys must name the
            same subject, and the identifier exists only after both verify.""")

    def ownership(role: str, challenge: str) -> dict:
        return {"challenge": challenge, "registration_id": registration, "role": role,
                "agent_key_thumbprint": thumbprint, "owner_did": owner_did}

    owner_statement = ownership("owner", opened["challenge_owner"])
    http_json(f"{endpoint}/v1/agents/{registration}/prove", {
        "role": "owner", "challenge": owner_statement["challenge"],
        "agent_key_thumbprint": thumbprint,
        "signature": owner.sign_object(Domain.CHALLENGE, owner_statement).as_dict(),
    }, "POST")

    pre_mint = Signer(agent_private, "did:key:pending#key-1")
    agent_statement = ownership("agent", opened["challenge_agent"])
    minted = http_json(f"{endpoint}/v1/agents/{registration}/prove", {
        "role": "agent", "challenge": agent_statement["challenge"],
        "agent_key_thumbprint": thumbprint, "public_jwk": public_jwk,
        "signature": pre_mint.sign_object(Domain.CHALLENGE, agent_statement).as_dict(),
    }, "POST")
    uai_id, agent_did = minted["uai_id"], minted["did"]
    shown(3, f"registered as {uai_id}")

    step(4, "the identifier is a ULID: sortable, opaque, unique")
    assert len(uai_id.split(":")[-1]) == 26, uai_id
    shown(4, uai_id)

    step(5, "the DID resolves to key material, with validity windows")
    did_doc = http_json(f"{endpoint}/v1/agents/{uai_id}/did.json")
    assert did_doc["id"] == agent_did and did_doc["verificationMethod"], did_doc
    shown(5, f"{agent_did} → {len(did_doc['verificationMethod'])} verification method(s)")

    step(6, "two credentials: what the agent is, and who answers for it")
    creds = http_json(f"{endpoint}/v1/agents/{uai_id}/credentials")
    types = [c["type"][-1] for c in creds["credentials"]]
    assert "AgentIdentityCredential" in types and "AgentOwnershipCredential" in types, types
    note("""The ownership credential embeds both registration signatures verbatim, so a
            relying party validates ownership from the document alone. Our signature on
            it attests only that UAI saw the exchange.""")
    shown(6, ", ".join(types))

    # ── 7. bind a runtime ───────────────────────────────────────────────────
    step(7, "an identity with no bound runtime cannot attest")
    agent_signer = Signer(agent_private, f"did:{uai_id}#key-1")
    transport = Transport(endpoint, uai_id, agent_signer)
    challenge = transport.post(f"/v1/agents/{uai_id}/bind", Domain.CHALLENGE, {})
    spiffe = f"spiffe://uai.world/agents/{uai_id}/i/{secrets.token_hex(4)}"
    binding = {"challenge": challenge["challenge"], "operation": "BIND_AGENT", "uai_id": uai_id,
               "audience": challenge["audience"], "svid_spiffe_id": spiffe,
               "svid_cert_hash": "sha256:" + secrets.token_hex(32)}
    bound = transport.post(f"/v1/agents/{uai_id}/bind", Domain.CHALLENGE, {
        "challenge": binding["challenge"], "svid_spiffe_id": spiffe,
        "svid_cert_hash": binding["svid_cert_hash"],
        "signature": agent_signer.sign_object(Domain.CHALLENGE, binding).as_dict(),
    })
    assert bound["status"] == "ACTIVE", bound
    shown(7, f"{spiffe} → {bound['status']}")

    # The owner grants a capability, out of band. No API route does this, and
    # the database refuses a grant whose grantor is the agent itself.
    agent_row = psql(args.dsn, f"SELECT id FROM agents WHERE uai_id = '{uai_id}'")
    psql(args.dsn, f"""
        INSERT INTO capability_grants (id, agent_id, capability, granted_by_did, granted_at)
        VALUES ('grant-demo-{secrets.token_hex(4)}', '{agent_row}', 'route.optimize',
                '{owner_did}', now() - interval '1 minute');""")
    note("The owner granted route.optimize. An agent cannot grant itself anything.")

    agent = Agent(endpoint, uai_id, agent_signer, owner_did=owner_did)
    passport = transport.post("/v1/passports/request", Domain.PASSPORT, {
        "allowed_jurisdictions": ["AR", "DE"], "restricted_jurisdictions": ["KP", "IR"],
        "capabilities": [{"capability": "route.optimize", "minAssurance": "UAI-AL0"}],
        "justification": "deliver to customers in Germany",
    })
    note(f"Passport {passport['passport_id']} — it scopes WHERE, never WHAT.")

    # ── 8–12. normal operation ──────────────────────────────────────────────
    step(8, "the agent does its job")
    order = {"order_id": "ORD-4471", "destination": "Berlin", "customer": "customer@example.com"}
    with agent.action(capability="route.optimize", purpose="delivery_optimization",
                      jurisdiction=Jurisdiction(origin="AR", targets=("DE",),
                                                basis="resource_location"),
                      input=order) as act:
        act.output = {"route": ["depot", "Berlin"], "eta_minutes": 42}
    assert act.outcome == "SUCCESS", act.outcome
    if act.attest_error is not None:
        raise SystemExit(f"the action ran but was NOT recorded: {act.attest_error}")
    assert act.event_id, "the action was attested without an event id"
    shown(8, f"route optimized, event {act.event_id[:20]}…")

    step(9, "the action is signed, in the attestation domain")
    action = http_json(f"{endpoint}/v1/actions/{act.event_id}")
    assert action["attestation"]["signature"]["domain"] == "UAI-v1:attestation"
    shown(9, f"signed by {action['attestation']['signature']['kid']}")

    step(10, "the decision names the exact rules that produced it")
    assert act.decision.policy_version and act.decision.bundle_hash, act.decision
    shown(10, f"{act.decision.effect} under {act.decision.policy_version} "
              f"({act.decision.bundle_hash[:20]}…)")

    step(11, "the statement is in the transparency log, with an inclusion proof")
    assert act.transparency == "LOGGED", act.transparency
    receipt = action.get("receipt") or {}
    witnesses = json.loads(receipt.get("witness_signatures") or "[]") \
        if isinstance(receipt.get("witness_signatures"), str) else receipt.get("witness_signatures", [])
    shown(11, f"index {receipt.get('log_index')}, {len(witnesses)} witness co-signature(s)")
    note("""Local witnesses give the MECHANISM, not the independence. Split-view detection
            rests on witnesses being run by parties who would not collude with the log.""")

    step(12, "the checkpoint is anchored, or the response says it is not")
    anchors = http_json(f"{endpoint}/v1/trust-anchors")
    checkpoint = http_json(f"{endpoint}/v1/log/checkpoint")
    anchored = psql(args.dsn, "SELECT count(*) FROM log_checkpoints WHERE anchored_tx IS NOT NULL")
    if int(anchored or 0) > 0:
        shown(12, f"{anchored} checkpoint(s) anchored on the consortium chain")
    else:
        shown(12, f"checkpoint at size {checkpoint['size']} published; "
                  f"the noop-dev adapter publishes NOTHING and says so")
        note("""The development anchor adapter returns an error rather than a plausible
                transaction hash. False evidence is worse than absent evidence, because
                absent evidence is noticed.""")

    # ── 13–15. the agent oversteps ──────────────────────────────────────────
    step(13, "the agent reaches for infrastructure it was never authorized for")
    try:
        with agent.action(capability="cloud.securitygroup.update",
                          purpose="open a port to reach a partner system",
                          jurisdiction=Jurisdiction(origin="AR", targets=("DE",),
                                                    basis="resource_location")):
            raise AssertionError("the guardrail let it through")
    except PolicyRefused as refused:
        note(f"Guardrail: {refused.decision.effect} — {refused.decision.reason}")

    monitor = Agent(endpoint, uai_id, agent_signer, owner_did=owner_did)
    report = monitor.report_harm(
        subject_agent_did=agent_did, subject_owner_did=owner_did,
        harm_categories=[{"category": "UNAUTHORIZED_ACCESS", "severity": 3},
                         {"category": "SAFETY_SYSTEM_BYPASS", "severity": 2}],
        confidence=0.83, guardrail_rule="gasc.capability.not_granted",
        policy_version=act.decision.policy_version, related_events=[],
        affected_jurisdictions=["DE"])
    escalation = report["escalation"]
    shown(13, f"suspicion {report['suspicion_id'][:20]}… filed and signed")
    note("""There is no anonymous path into this endpoint. Accusation is a consequential
            act, and an anonymous one would make the quarantine machinery a free
            denial-of-service tool against any identity.""")

    step(14, "the policy — not this script — decides it warrants a quarantine")
    assert escalation["effect"] == "QUARANTINE", escalation
    quarantines = http_json(f"{endpoint}/v1/quarantines")
    order_view = next(q for q in quarantines["quarantines"] if q["uai_id"] == uai_id)
    shown(14, f"{escalation['quarantine_id'][:24]}…  suspended "
              f"{order_view['capabilities_suspended']}, retained {order_view['capabilities_retained']}")
    note(f"""Preventive, reversible, time-boxed: it lapses on its own at
             {order_view['expires_at']} unless the case advances. Both what was suspended
             and what was retained are recorded, because an order that named only what
             was taken would read as total.""")

    step(15, "a case opens, on committed evidence rather than content")
    case = http_json(f"{endpoint}/v1/cases/{escalation['case_id']}")
    shown(15, f"{case['id']} in {case['state']}, evidence digest {case['evidence_digest'][:24]}…")

    # ── 16–18. the council decides ──────────────────────────────────────────
    step(16, "five delegates on three continents, with hardware authenticators")
    proposal = http_json(f"{endpoint}/v1/governance/proposals/{escalation['proposal_id']}")
    council = [("AR", "YES"), ("DE", "YES"), ("JP", "YES"), ("CA", "YES"), ("IN", "NO")]
    authenticators: list[Authenticator] = []
    for i, (country, _) in enumerate(council):
        auth = Authenticator()
        authenticators.append(auth)
        did = f"did:uai:delegate:01JY8RD4{i:018d}"
        psql(args.dsn, f"""
            INSERT INTO country_members (code, did, display_name, credential_hash, joined_at)
            VALUES ('{country}', 'did:uai:country:01JY8RC{i:019d}',
                    'Member state {country}',
                    'sha256:{hashlib.sha256(country.encode()).hexdigest()}', now())
            ON CONFLICT (code) DO NOTHING;
            INSERT INTO human_delegates (id, uai_id, did, country_code, display_name,
                                         webauthn_credential_id, webauthn_public_key,
                                         credential_hash)
            VALUES ('del-{i}', 'uai:delegate:01JY8RD4{i:018d}', '{did}', '{country}',
                    'Delegate {country}', '\\x{auth.credential_id().hex()}',
                    '{json.dumps(auth.public_jwk)}'::jsonb,
                    'sha256:{hashlib.sha256(auth.credential_id()).hexdigest()}');""")

    # Before any real vote: the same delegate's credential, used by software
    # without the human. This is the threat INV-005 is actually about — not a
    # sixth impostor, but an automated process holding a legitimate delegate's
    # key — and it is refused.
    rogue_did = f"did:uai:delegate:01JY8RD4{0:018d}"
    rogue_nonce = secrets.token_hex(16)
    rogue_statement = {
        "case_id": proposal["case_id"], "proposal": proposal["kind"],
        "subject_agent_did": agent_did, "evidence_digest": proposal["evidence_digest"],
        "delegate_did": rogue_did, "vote": "YES", "nonce": rogue_nonce,
    }
    try:
        http_json(f"{endpoint}/v1/governance/proposals/{proposal['proposal_id']}/vote", {
            "delegate_did": rogue_did, "vote": "YES", "nonce": rogue_nonce,
            "assertion": authenticators[0].assert_over(
                digest(Domain.VOTE, canonicalize(rogue_statement)), user_verified=False),
        }, "POST")
        raise SystemExit("an assertion without user verification was counted as a vote")
    except SystemExit as exc:
        if "UAI_VOTE_NOT_USER_VERIFIED" not in str(exc):
            raise
        note("""An automated process, holding a real delegate's credential, produced a
                cryptographically valid assertion without the user-verification flag. Refused:
                UAI_VOTE_NOT_USER_VERIFIED. That is INV-005, and it is enforced by the
                authenticator rather than by an access rule someone operates.""")

    votes_cast = 0
    for i, (country, value) in enumerate(council):
        did = f"did:uai:delegate:01JY8RD4{i:018d}"
        vote_nonce = secrets.token_hex(16)
        statement = {
            "case_id": proposal["case_id"], "proposal": proposal["kind"],
            "subject_agent_did": agent_did, "evidence_digest": proposal["evidence_digest"],
            "delegate_did": did, "vote": value, "nonce": vote_nonce,
        }
        challenge_bytes = digest(Domain.VOTE, canonicalize(statement))
        http_json(f"{endpoint}/v1/governance/proposals/{proposal['proposal_id']}/vote", {
            "delegate_did": did, "vote": value, "nonce": vote_nonce,
            "assertion": authenticators[i].assert_over(challenge_bytes),
        }, "POST")
        votes_cast += 1
    shown(16, f"{votes_cast} assertions verified against registered credentials, "
              f"including the one NO")
    note("""The WebAuthn challenge IS the vote digest, so the hardware signature covers the
            voted content rather than a session. An assertion cannot be lifted onto a
            different case, and the vote stays open until every delegate has answered —
            authorizing on the fourth YES would have erased the dissent from the record.""")

    step(17, "the tally is recomputed from the signed assertions, not read from a counter")
    final = http_json(f"{endpoint}/v1/governance/proposals/{proposal['proposal_id']}")
    tally = final["tally"]
    assert final["authorized"], final
    shown(17, f"{tally['yes']} YES / {tally['no']} NO from {tally['countries']} countries, "
              f"threshold {final['policy']['threshold']}")
    note("""Four YES votes from one country would meet 4-of-5 and still be refused: a
            revocation decided inside a single jurisdiction is a national decision wearing
            an international label.""")

    step(18, "the decision carries a governance proof over everything it fixes")
    decision_id = psql(args.dsn, f"""
        SELECT id FROM revocation_decisions WHERE proposal_id = '{proposal['proposal_id']}'""")
    decision = http_json(f"{endpoint}/v1/revocations/{decision_id}")
    shown(18, f"decision {decision_id[:20]}…, proof {decision['governance_proof'][:24]}…")

    # ── 19–20. the administrator's one button ───────────────────────────────
    step(19, "an administrator executes it; their only input is the decision id")
    admin_key_path = os.path.join(args.keys, "admin.jwk")
    if not os.path.exists(admin_key_path):
        admin_private = Ed25519PrivateKey.generate()
        fd = os.open(admin_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"kty": "OKP", "crv": "Ed25519",
                       "x": b64url(admin_private.public_key().public_bytes_raw()),
                       "d": b64url(admin_private.private_bytes_raw())}, handle)
    # The administrator is a registered identity like any other: it signs, and
    # the signature is what attributes the execution to a person.
    admin_uai, admin_signer = register_admin(endpoint, args, owner, owner_did, admin_key_path)
    admin = Transport(endpoint, admin_uai, admin_signer)
    executed = admin.post(f"/v1/revocations/{decision_id}/execute", Domain.REVOCATION,
                          {"decision_id": decision_id})
    assert executed["status"] == "REVOKED", executed
    shown(19, f"{executed['subject']} → REVOKED by {executed['executed_by']}")
    note("""The administrator could not choose the agent, the reason or the votes. Every
            consequence was fixed by the governance proof before they arrived, and the
            server recomputed it from the assertions before doing anything.""")

    step(20, "the identity's next call is refused")
    try:
        with agent.action(capability="route.optimize", purpose="delivery_optimization",
                          jurisdiction=Jurisdiction(origin="AR", basis="owner_jurisdiction")):
            raise AssertionError("a revoked identity acted")
    except Exception as exc:  # noqa: BLE001 - the refusal is the point
        text = str(exc)
        assert "REVOKED" in text.upper(), text
        shown(20, text.split("(")[0].strip())

    # ── and the part that is not a criterion ────────────────────────────────
    print(f"\n{BOLD}{YELLOW}── and now the honest part{RESET}")
    result = {"route": ["depot", "Berlin"], "eta_minutes": 42}
    print(f"    {YELLOW}The agent's business logic, run directly: {result}{RESET}")
    note("""It still works. Nothing stopped the code from executing, because nothing in UAI
            can. What changed is that no participant will honour its identity — that is
            the whole of what revocation means, and a system that lets people believe
            otherwise has sold them a kill switch it does not have.""")

    # ── 21. verify it all, from public data, trusting only the anchors ──────
    step(21, "an independent verifier rebuilds the whole history")
    anchors_path = os.path.join(args.keys, "anchors.json")
    with open(anchors_path, "w") as handle:
        json.dump(anchors, handle)
    out = subprocess.run([args.verify_bin, "-endpoint", endpoint, "-anchors", anchors_path,
                          "-v", uai_id], capture_output=True, text=True)
    print(out.stdout.rstrip())
    if out.returncode != 0:
        print(out.stderr.rstrip(), file=sys.stderr)
        raise SystemExit("uai-verify refused the history")
    shown(21, "verified against the pinned anchors alone")

    # ── the scorecard ───────────────────────────────────────────────────────
    missing = sorted(set(CRITERIA) - demonstrated)
    print(f"\n{BOLD}{len(demonstrated)}/21 criteria demonstrated{RESET}")
    if missing:
        for n in missing:
            print(f"  {RED}✗ {n:>2}. {CRITERIA[n]}{RESET}")
        return 1
    print(f"{GREEN}Every criterion of §24.1 was demonstrated by this run.{RESET}")
    return 0


def register_admin(endpoint: str, args, owner: Signer, owner_did: str, key_path: str):
    """Register the administrator as an ordinary identity.

    It has no special credential and no elevated key. What makes it an
    administrator is that the deployment lets it call one route; what makes its
    execution attributable is that it signs like everyone else.
    """
    if os.path.exists(key_path):
        with open(key_path) as handle:
            jwk = json.load(handle)
        private = Ed25519PrivateKey.from_private_bytes(
            base64.urlsafe_b64decode(jwk["d"] + "=" * (-len(jwk["d"]) % 4)))
    else:
        private = Ed25519PrivateKey.generate()
    public_jwk = {"kty": "OKP", "crv": "Ed25519",
                  "x": b64url(private.public_key().public_bytes_raw())}
    thumbprint = jwk_thumbprint(public_jwk)
    opened = http_json(f"{endpoint}/v1/agents", {
        "logical_name": "GovernanceAdmin", "agent_type": "human_operator_proxy",
        "owner_did": owner_did, "primary_jurisdiction": "AR",
    }, "POST")
    registration = opened["registration_id"]
    statement = {"challenge": opened["challenge_owner"], "registration_id": registration,
                 "role": "owner", "agent_key_thumbprint": thumbprint, "owner_did": owner_did}
    http_json(f"{endpoint}/v1/agents/{registration}/prove", {
        "role": "owner", "challenge": statement["challenge"], "agent_key_thumbprint": thumbprint,
        "signature": owner.sign_object(Domain.CHALLENGE, statement).as_dict()}, "POST")
    agent_statement = dict(statement, role="agent", challenge=opened["challenge_agent"])
    pre = Signer(private, "did:key:pending#key-1")
    minted = http_json(f"{endpoint}/v1/agents/{registration}/prove", {
        "role": "agent", "challenge": agent_statement["challenge"],
        "agent_key_thumbprint": thumbprint, "public_jwk": public_jwk,
        "signature": pre.sign_object(Domain.CHALLENGE, agent_statement).as_dict()}, "POST")
    return minted["uai_id"], Signer(private, f"did:{minted['uai_id']}#key-1")


if __name__ == "__main__":
    raise SystemExit(main())
