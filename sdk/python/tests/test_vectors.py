"""The Python SDK against the committed vectors.

Same standard as the Go implementation and the browser code: the vectors are
read, never regenerated here.  A test that wrote its own expectations would
prove only that this SDK agrees with itself, and two implementations that agree
on the cryptography but disagree on a newline cannot verify each other -- the
disagreement stays invisible until it matters.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from uai.canonical import canonicalize_json, canonicalize_without
from uai.crypto import (
    Signer, digest, format_digest, jwk_thumbprint, thumbprint_input, verify_commitment,
)
from uai.pop import Message, Params, content_digest, signature_base

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "spec" / "test-vectors"


def load(*parts: str) -> dict:
    with open(VECTORS.joinpath(*parts), encoding="utf-8") as handle:
        return json.load(handle)


class TestCanonicalization(unittest.TestCase):
    def test_every_case_reproduces_byte_for_byte(self) -> None:
        cases = load("jcs", "canonicalization.json")["cases"]
        self.assertGreater(len(cases), 0)
        for case in cases:
            with self.subTest(case["name"]):
                got = canonicalize_json(case["input_json"])
                self.assertEqual(got.decode("utf-8"), case["canonical"])
                self.assertEqual(hashlib.sha256(got).hexdigest(), case["canonical_sha256"])


class TestDomainSeparation(unittest.TestCase):
    def test_every_domain_reproduces(self) -> None:
        cases = load("digest", "domain-separation.json")["cases"]
        for case in cases:
            with self.subTest(case["domain"]):
                got = format_digest(digest(case["domain"], case["payload_utf8"].encode("utf-8")))
                self.assertEqual(got, case["digest"])

    def test_the_same_payload_differs_across_domains(self) -> None:
        """The property the domains exist for, asserted rather than assumed."""
        cases = load("digest", "domain-separation.json")["cases"]
        digests = {case["digest"] for case in cases}
        self.assertEqual(len(digests), len(cases),
                         "two domains produced the same digest for the same payload")


class TestCommitments(unittest.TestCase):
    def test_openings_and_refusals(self) -> None:
        for case in load("commitment", "salted-commitment.json")["cases"]:
            with self.subTest(case["name"]):
                commitment = bytes.fromhex(case["commitment"].split(":", 1)[1])
                opened = verify_commitment(
                    commitment, bytes.fromhex(case["salt_hex"]),
                    case["content_utf8"].encode("utf-8"))
                self.assertEqual(opened, case["opens"])


class TestSigningPayload(unittest.TestCase):
    """What a signature over a self-signed object covers.

    10.4 says "jcs-canonicalize A minus signature".  The alternative reading --
    blank the member, keep the key -- is what a struct-based implementation
    produces by accident, and an implementation can be byte-correct on every
    other vector while signing something nobody else can verify.
    """

    def cases(self) -> list[dict]:
        return load("attestation", "signing-payload.json")["cases"]

    def test_the_payload_is_the_document_minus_its_signature(self) -> None:
        for case in self.cases():
            if not case["must_verify"]:
                continue
            with self.subTest(case["name"]):
                got = canonicalize_without(case["document"], "signature")
                self.assertEqual(got.decode("utf-8"), case["signing_payload"])
                self.assertEqual(hashlib.sha256(got).hexdigest(),
                                 case["signing_payload_sha256"])

    def test_the_blanked_form_is_not_what_we_produce(self) -> None:
        """The negative vector: the payload we must NOT produce."""
        for case in self.cases():
            if case["must_verify"]:
                continue
            with self.subTest(case["name"]):
                got = canonicalize_without(case["document"], "signature")
                self.assertNotEqual(got.decode("utf-8"), case["signing_payload"])

    def test_the_signature_verifies_over_the_payload(self) -> None:
        from uai.crypto import Domain, signing_input
        for case in self.cases():
            with self.subTest(case["name"]):
                public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(case["public_key_hex"]))
                message = signing_input(case["domain"], case["signing_payload"].encode("utf-8"))
                signature = base64.urlsafe_b64decode(
                    case["signature_b64url"] + "=" * (-len(case["signature_b64url"]) % 4))
                try:
                    public.verify(signature, message)
                    verified = True
                except InvalidSignature:
                    verified = False
                self.assertEqual(verified, case["must_verify"])
                self.assertIn(case["domain"], Domain.ALL)


class TestJWKThumbprints(unittest.TestCase):
    """The subject identifier of a registration proof (8.2).

    Both halves of the proof sign it, so an implementation that computes it
    differently does not produce a proof -- it produces two statements about
    two different keys that happen to look like one.
    """

    def test_every_key_type_reproduces(self) -> None:
        cases = load("keys", "jwk-thumbprint.json")["cases"]
        self.assertGreater(len(cases), 0)
        for case in cases:
            with self.subTest(case["name"]):
                # The bytes hashed are checked too: agreeing on the digest while
                # disagreeing on the input means agreeing by accident.
                self.assertEqual(thumbprint_input(case["jwk"]), case["canonical_json"])
                self.assertEqual(jwk_thumbprint(case["jwk"]), case["thumbprint"])

    def test_members_outside_the_set_are_not_hashed(self) -> None:
        cases = {c["name"]: c for c in load("keys", "jwk-thumbprint.json")["cases"]}
        plain = cases["Ed25519"]
        decorated = cases["Ed25519 with extra members that are not hashed"]
        self.assertEqual(plain["thumbprint"], decorated["thumbprint"])

    def test_an_unsupported_key_type_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            jwk_thumbprint({"kty": "RSA", "n": "abc", "e": "AQAB"})


class TestProofOfPossession(unittest.TestCase):
    """RFC 9421, including the exact signature base string.

    The base is pinned because that is where implementations diverge: a stray
    newline, an unquoted component name or a lowercased method all yield a base
    that verifies against nothing.
    """

    def cases(self) -> list[dict]:
        return load("pop", "rfc9421.json")["cases"]

    def test_signature_base_is_exact(self) -> None:
        for case in self.cases():
            # The verifier sees the tag as presented, which for the cross-domain
            # case is not the tag that was signed.
            verify_tag = case.get("verify_tag") or case["tag"]
            untampered = verify_tag == case["tag"] and case["must_verify"]
            if not untampered:
                continue
            with self.subTest(case["name"]):
                params = Params(key_id=case["keyid"], tag=verify_tag, created=case["created"],
                                alg=case["alg"], components=tuple(case["components"]))
                self.assertEqual(params.serialize(), case["signature_input"].split("=", 1)[1])
                base = signature_base(
                    Message(case["method"], case["target_uri"], case["headers"]), params)
                self.assertEqual(base.decode("utf-8"), case["signature_base"])

    def test_acceptance_matches_the_vector(self) -> None:
        for case in self.cases():
            with self.subTest(case["name"]):
                verify_tag = case.get("verify_tag") or case["tag"]
                params = Params(key_id=case["keyid"], tag=verify_tag, created=case["created"],
                                alg=case["alg"], components=tuple(case["components"]))
                base = signature_base(
                    Message(case["method"], case["target_uri"], case["headers"]), params)
                public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(case["public_key_hex"]))
                digest_ok = content_digest(case["body_utf8"].encode("utf-8")) == case["content_digest"]
                try:
                    public.verify(base64.b64decode(case["signature_b64"]), base)
                    signature_ok = True
                except InvalidSignature:
                    signature_ok = False
                accepted = digest_ok and signature_ok
                self.assertEqual(accepted, case["must_verify"],
                                 case.get("failure_reason", "unexpected verification outcome"))

    def test_signing_reproduces_the_committed_signature(self) -> None:
        """Ed25519 is deterministic, so a correct signer reproduces the vector.

        This is the check that would catch a signer that signs something other
        than the base -- the failure a verify-only test cannot see.
        """
        for case in self.cases():
            if not case["must_verify"]:
                continue
            with self.subTest(case["name"]):
                params = Params(key_id=case["keyid"], tag=case["tag"], created=case["created"],
                                alg=case["alg"], components=tuple(case["components"]))
                base = signature_base(
                    Message(case["method"], case["target_uri"], case["headers"]), params)
                signer = Signer(
                    Ed25519PrivateKey.from_private_bytes(bytes.fromhex(case["seed_hex"])),
                    case["keyid"])
                self.assertEqual(
                    base64.b64encode(signer.sign_raw(base)).decode("ascii"),
                    case["signature_b64"])


if __name__ == "__main__":
    unittest.main()
