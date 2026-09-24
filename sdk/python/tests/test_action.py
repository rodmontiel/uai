"""The context-manager contract.

These are the assertions that make ``with`` worth having over two calls: the
block does not run when policy refuses, and something is attested on every way
out of it -- return, exception, and refusal.
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from uai import Agent, Jurisdiction, PolicyRefused, Problem
from uai.crypto import Signer, commit_object, format_digest
from uai.errors import NotAttested

UAI_ID = "uai:agent:01JY8R9ZAF392N7QX2T81JH6KM"


class Gateway(BaseHTTPRequestHandler):
    """A stub that answers the three calls an action makes."""

    decision = "ALLOW"
    reason = ""
    attest_status = 201
    attested: list[dict] = []
    evaluated = 0

    def log_message(self, *args) -> None:  # noqa: D102 - silence the test server
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's interface
        self._json(200, {"events": [], "head": {"hash": "sha256:bb", "sequence": 1}})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/v1/policy/evaluate":
            Gateway.evaluated += 1
            self._json(200, {
                "decision_id": "01JD", "decision": Gateway.decision, "reason": Gateway.reason,
                "policy": {"version": "GASC-2027.4", "bundle_hash": "sha256:aa"},
                "rules_fired": ["capability_envelope"],
            })
            return
        if self.path == "/v1/actions/attest":
            Gateway.attested.append(body)
            if Gateway.attest_status != 201:
                self._json(Gateway.attest_status, {
                    "title": "UAI_IDENTITY_NOT_ACTIVE", "status": Gateway.attest_status,
                    "detail": "no runtime bound"})
                return
            self._json(201, {"event_id": "evt-1", "event_hash": "sha256:cc",
                             "sequence": 2, "transparency": "LOGGED"})
            return
        self._json(404, {"title": "UAI_NOT_FOUND"})

    def _json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ActionTest(unittest.TestCase):
    def setUp(self) -> None:
        Gateway.decision, Gateway.reason = "ALLOW", ""
        Gateway.attest_status, Gateway.attested, Gateway.evaluated = 201, [], 0
        self.server = HTTPServer(("127.0.0.1", 0), Gateway)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        signer = Signer(Ed25519PrivateKey.generate(), f"did:{UAI_ID}#key-1")
        host, port = self.server.server_address
        self.agent = Agent(f"http://{host}:{port}", UAI_ID, signer,
                           owner_did="did:uai:owner:01JY8R9ZB0")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def action(self, **kwargs):
        defaults = dict(capability="route.optimize", purpose="delivery_optimization",
                        jurisdiction=Jurisdiction(origin="AR", basis="owner_jurisdiction"))
        defaults.update(kwargs)
        return self.agent.action(**defaults)

    # ── the contract ────────────────────────────────────────────────────────

    def test_success_is_attested(self) -> None:
        with self.action() as act:
            act.output = {"routes": 3}
        self.assertEqual(act.outcome, "SUCCESS")
        self.assertEqual(act.event_id, "evt-1")
        self.assertEqual(act.transparency, "LOGGED")
        self.assertIsNone(act.attest_error)
        self.assertEqual(len(Gateway.attested), 1)
        self.assertEqual(Gateway.attested[0]["outcome"], "SUCCESS")

    def test_an_exception_is_attested_as_failure_and_propagates(self) -> None:
        """The reason the SDK owns the block rather than exposing attest().

        An integrator who has to remember a second call writes it on the happy
        path.  A record that contains only successes is an advertisement.
        """
        class Boom(RuntimeError):
            pass

        act = self.action()
        with self.assertRaises(Boom):
            with act:
                raise Boom("the routing service refused")
        self.assertEqual(act.outcome, "FAILURE")
        self.assertEqual(len(Gateway.attested), 1)
        self.assertEqual(Gateway.attested[0]["outcome"], "FAILURE")

    def test_a_denial_stops_the_block_and_is_recorded(self) -> None:
        Gateway.decision, Gateway.reason = "DENY", "capability_not_granted"
        ran = False
        act = self.action()
        with self.assertRaises(PolicyRefused) as caught:
            with act:
                ran = True
        self.assertFalse(ran, "the block ran after a DENY")
        self.assertEqual(caught.exception.decision.reason, "capability_not_granted")
        self.assertEqual(act.outcome, "ABORTED_BY_POLICY")
        # A refusal nobody wrote down is indistinguishable from a request nobody
        # made, so it appears in the agent's own chain, not only in our table.
        self.assertEqual(len(Gateway.attested), 1)
        self.assertEqual(Gateway.attested[0]["outcome"], "ABORTED_BY_POLICY")

    def test_require_human_approval_is_not_an_allow(self) -> None:
        for effect in ("REQUIRE_HUMAN_APPROVAL", "QUARANTINE", "DENY"):
            with self.subTest(effect):
                Gateway.decision, Gateway.attested = effect, []
                ran = False
                with self.assertRaises(PolicyRefused):
                    with self.action():
                        ran = True
                self.assertFalse(ran, f"{effect} ran the block")

    def test_an_unreachable_guardrail_fails_closed(self) -> None:
        """'We could not ask' must never read as 'no objection' (12.4)."""
        signer = Signer(Ed25519PrivateKey.generate(), f"did:{UAI_ID}#key-1")
        offline = Agent("http://127.0.0.1:1", UAI_ID, signer)
        ran = False
        with self.assertRaises(Exception):
            with offline.action(capability="route.optimize", purpose="p",
                                jurisdiction=Jurisdiction(origin="AR")):
                ran = True
        self.assertFalse(ran, "the block ran while the guardrail was unreachable")

    # ── privacy ─────────────────────────────────────────────────────────────

    def test_content_never_leaves_the_process(self) -> None:
        secret = {"email": "customer@example.com"}
        with self.action(input=secret) as act:
            act.output = {"records": 1}
        sent = json.dumps(Gateway.attested[0])
        self.assertNotIn("customer@example.com", sent)
        self.assertTrue(Gateway.attested[0]["input_commitment"].startswith("sha256:"))
        # The salt the caller kept must actually open the commitment.  If it did
        # not, the record would be permanently unopenable and nobody would find
        # out until the day it mattered.
        self.assertEqual(len(act.input_salt), 32)
        self.assertEqual(
            format_digest(commit_object(act.input_salt, secret)),
            Gateway.attested[0]["input_commitment"])

    def test_a_salt_is_never_reused(self) -> None:
        for _ in range(2):
            with self.action(input="YES") as act:
                act.output = "NO"
        self.assertNotEqual(Gateway.attested[0]["input_commitment"],
                            Gateway.attested[1]["input_commitment"],
                            "identical content produced identical commitments")

    # ── honesty about failure ───────────────────────────────────────────────

    def test_an_unrecorded_action_says_so(self) -> None:
        Gateway.attest_status = 403
        with self.action() as act:
            act.output = "done"
        self.assertIsInstance(act.attest_error, Problem)
        self.assertEqual(act.attest_error.code, "UAI_IDENTITY_NOT_ACTIVE")
        self.assertEqual(act.event_hash, "", "an event hash was reported for a refused attestation")

    def test_strict_raises_when_the_action_was_not_recorded(self) -> None:
        Gateway.attest_status = 403
        with self.assertRaises(NotAttested):
            with self.action(strict=True) as act:
                act.output = "done"

    def test_the_chain_is_tracked_not_guessed(self) -> None:
        for _ in range(2):
            with self.action():
                pass
        self.assertEqual(Gateway.attested[0]["previous_event_hash"], "sha256:bb")
        self.assertEqual(Gateway.attested[1]["previous_event_hash"], "sha256:cc")
        self.assertEqual(Gateway.attested[1]["sequence"], 3)

    def test_the_guardrail_is_consulted_once_per_action(self) -> None:
        with self.action():
            pass
        self.assertEqual(Gateway.evaluated, 1)

    def test_cross_border_is_derived_not_declared(self) -> None:
        """Under-declaring jurisdiction is the failure mode with consequences."""
        domestic = Jurisdiction(origin="AR", targets=("AR",))
        crossing = Jurisdiction(origin="AR", targets=("DE",))
        self.assertFalse(domestic.cross_border)
        self.assertTrue(crossing.cross_border)

    def test_no_force_option(self) -> None:
        """A design assertion: nothing turns a refusal into execution."""
        import inspect
        signature = inspect.signature(Agent.action)
        for forbidden in ("force", "skip_policy", "ignore_decision", "bypass"):
            self.assertNotIn(forbidden, signature.parameters)


if __name__ == "__main__":
    unittest.main()
