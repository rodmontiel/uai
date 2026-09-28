"""The context-manager API: ``with agent.action(...) as act``.

# Why a context manager and not an ``attest()`` call

An SDK that exposed ``evaluate()`` and ``attest()`` and trusted the integrator to
call both, in order, on every path, would produce an accountability log of
successes.  Not because integrators are careless, but because the failure paths
are the ones nobody writes the second call on: the early return, the raised
exception, the branch added six months later.

``with`` moves that from discipline to language.  ``__exit__`` runs whether the
block returned, raised, or was left by ``break``; so the attestation happens on
every path, with the outcome that actually occurred.  A record that contains only
successes is an advertisement.

# What this cannot do

The agent's process is the one place UAI cannot constrain.  An agent that does
not want to be accountable does not import this module.  This SDK makes the
accountable path the easy one; the protocol puts verification in the relying
party, which is where it survives an adversarial agent.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable

from .canonical import canonicalize_without
from .client import Transport
from .crypto import Domain, Signer, commit_object, format_digest, salt
from .errors import NotAttested, PolicyRefused, Problem
from .pop import nonce

__all__ = ["Agent", "Action", "Decision", "Jurisdiction"]

UAI_VERSION = "0.1"


@dataclass(frozen=True)
class Jurisdiction:
    """The jurisdictional context of an action (11.2).

    ``basis`` records WHY the system concluded what it concluded, which is the
    first thing an auditor asks.  It is not decoration: without it, a
    cross-border finding is an assertion with no derivation.
    """

    origin: str
    targets: tuple[str, ...] = ()
    basis: str = ""

    @property
    def cross_border(self) -> bool:
        """True when any target differs from the origin.

        Derived rather than declared.  Under-declaring jurisdiction is the
        failure mode with real-world consequences (11.2), and a flag the caller
        sets by hand is a flag the caller forgets.
        """
        return any(t and t != self.origin for t in self.targets)

    def as_dict(self) -> dict[str, Any]:
        return {"origin": self.origin, "targets": list(self.targets),
                "cross_border": self.cross_border, "basis": self.basis}


@dataclass(frozen=True)
class Decision:
    """A signed policy decision record (12.3.1)."""

    decision_id: str
    effect: str
    reason: str
    policy_version: str
    bundle_hash: str
    rules_fired: tuple[str, ...] = ()
    conditions: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def allows(self) -> bool:
        """Whether the action may run.

        REQUIRE_HUMAN_APPROVAL is not an allow.  It is a refusal until a human
        acts, and treating it as a conditional yes is how a human-in-the-loop
        requirement quietly becomes a log line.
        """
        return self.effect in ("ALLOW", "ALLOW_WITH_MONITORING")

    @classmethod
    def from_response(cls, payload: dict[str, Any]) -> "Decision":
        policy = payload.get("policy") or {}
        return cls(
            decision_id=payload.get("decision_id", ""),
            effect=payload.get("decision", "DENY"),
            reason=payload.get("reason", ""),
            policy_version=policy.get("version", ""),
            bundle_hash=policy.get("bundle_hash", ""),
            rules_fired=tuple(payload.get("rules_fired") or ()),
            conditions=payload.get("conditions") or {},
            raw=payload,
        )


class Action:
    """One action, from the policy check to the attestation.

    Obtained from :meth:`Agent.action` and used as a context manager.  Set
    :attr:`output` inside the block to commit to the result; the content itself
    never leaves the process.
    """

    def __init__(self, agent: "Agent", *, capability: str, purpose: str,
                 jurisdiction: Jurisdiction, action_type: str = "", resource: str = "",
                 risk_class: str = "", input: Any = None, strict: bool = False,
                 runtime_identity: str = "") -> None:
        if not capability or not purpose:
            raise ValueError("an action needs a capability and a purpose")
        self._agent = agent
        self.capability = capability
        self.purpose = purpose
        self.action_type = action_type or capability
        self.resource = resource
        self.risk_class = risk_class
        self.jurisdiction = jurisdiction
        self.runtime_identity = runtime_identity
        self.input = input
        self.output: Any = None
        self.strict = strict

        self.decision: Decision | None = None
        self.outcome: str = ""
        self.event_id: str = ""
        self.event_hash: str = ""
        self.sequence: int = 0
        self.transparency: str = ""
        self.receipt: dict[str, Any] | None = None
        #: The salts open the commitments.  Keep them: UAI does not have them and
        #: never will, so a commitment whose salt was discarded can never be
        #: opened by anyone -- which is the same as not having recorded anything.
        self.input_salt: bytes | None = None
        self.output_salt: bytes | None = None
        #: Set when the action ran but could not be recorded.  A caller that
        #: ignores this is running unattested without knowing it.
        self.attest_error: Exception | None = None

    # ── context manager ─────────────────────────────────────────────────────

    def __enter__(self) -> "Action":
        self.decision = self._agent.evaluate(self)
        if not self.decision.allows:
            # The refusal is attested before it is raised.  A refusal nobody
            # wrote down is indistinguishable from a request nobody made, and
            # recording it only in UAI's decision table would leave the agent's
            # own chain silent about a request it made.
            self.outcome = "ABORTED_BY_POLICY"
            self._attest()
            raise PolicyRefused(self.decision)
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if self.outcome == "ABORTED_BY_POLICY":
            return False  # __enter__ raised; nothing ran
        self.outcome = "SUCCESS" if exc_type is None else "FAILURE"
        self._attest()
        if self.attest_error is not None and self.strict and exc_type is None:
            raise NotAttested(
                "the action ran but was not recorded: " + str(self.attest_error)
            ) from self.attest_error
        # Never suppress.  An SDK that swallowed the exception would change what
        # the agent does, and observing something must not alter it.
        return False

    # ── attestation ─────────────────────────────────────────────────────────

    def _attest(self) -> None:
        try:
            self._submit()
        except Problem as exc:
            if exc.code == "UAI_CHAIN_CONFLICT" and exc.chain_head:
                # The refusal carries the real head, so the retry is not a
                # guess: another writer appended between the read and the write,
                # which is ordinary concurrency.  Anything else is reported as
                # it is -- retrying a policy refusal would be the SDK arguing
                # with the guardrail.
                self._agent._head = exc.chain_head
                try:
                    self._submit()
                    return
                except Exception as retry:  # noqa: BLE001 - reported, not raised
                    self.attest_error = retry
                    return
            self.attest_error = exc
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            self.attest_error = exc

    def _submit(self) -> None:
        input_commitment, self.input_salt = _commit(self.input)
        output_commitment, self.output_salt = _commit(self.output)
        head = self._agent.head()
        decision = self.decision or Decision("", "DENY", "", "", "")

        attestation: dict[str, Any] = {
            "uai_version": UAI_VERSION,
            "event_id": "evt-" + nonce(),
            "agent_did": self._agent.did,
            "owner_did": self._agent.owner_did,
            "timestamp": _now(),
            "nonce": nonce(),
            "action": {
                "type": self.action_type, "capability": self.capability,
                **({"resource": self.resource} if self.resource else {}),
                **({"risk_class": self.risk_class} if self.risk_class else {}),
            },
            "purpose": self.purpose,
            "jurisdiction": self.jurisdiction.as_dict(),
            "policy": {
                "version": decision.policy_version, "bundle_hash": decision.bundle_hash,
                "decision_id": decision.decision_id, "decision": decision.effect,
                "rules_fired": list(decision.rules_fired),
            },
            "outcome": self.outcome,
            "previous_event_hash": head.get("hash", ""),
            "sequence": int(head.get("sequence", 0)) + 1,
        }
        if self.runtime_identity:
            attestation["runtime_identity"] = self.runtime_identity
        if input_commitment:
            attestation["input_commitment"] = input_commitment
        if output_commitment:
            attestation["output_commitment"] = output_commitment

        # 10.4: the signature covers the attestation MINUS its signature member.
        signature = self._agent.signer.sign(
            Domain.ATTESTATION, canonicalize_without(attestation, "signature"))
        attestation["signature"] = signature.as_dict()

        response = self._agent.transport.post(
            "/v1/actions/attest", Domain.ATTESTATION, attestation) or {}
        self.event_id = response.get("event_id", "")
        self.event_hash = response.get("event_hash", "")
        self.sequence = int(response.get("sequence", 0))
        self.transparency = response.get("transparency", "")
        self.receipt = response.get("receipt")
        self._agent._head = {"hash": self.event_hash, "sequence": self.sequence}


def _commit(value: Any) -> tuple[str, bytes | None]:
    """Commit locally, with a fresh salt per commitment.

    Never a per-agent or per-session salt: commitments are published, and two
    commitments under one salt let anyone who opens the first test guesses
    against the second.
    """
    if value is None:
        return "", None
    salt_bytes = salt()
    return format_digest(commit_object(salt_bytes, value)), salt_bytes


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Agent:
    """A UAI identity, and everything it can do.

    One identity per instance.  An object that could sign as several agents
    would make "which identity performed this" a parameter at the call site, and
    the first mistake in passing it would be a misattributed action.
    """

    def __init__(self, endpoint: str, uai_id: str, signer: Signer,
                 owner_did: str = "", timeout: float = 30.0, ca: str = "") -> None:
        self.transport = Transport(endpoint, uai_id, signer, timeout=timeout, ca=ca)
        self.uai_id = uai_id
        self.signer = signer
        self.did = signer.did
        self.owner_did = owner_did
        self._head: dict[str, Any] | None = None

    @classmethod
    def from_env(cls) -> "Agent":
        """Build an agent from ``UAI_ENDPOINT``, ``UAI_AGENT_ID``, ``UAI_AGENT_KEY``.

        ``UAI_API_CA`` names the CA to verify a TLS gateway with, and is read
        here so that moving from a plain stack to an attested one is a change of
        environment rather than a change of code.

        Nothing is generated when a variable is missing.  A key created at
        startup would sign credentials that stop verifying at the next restart,
        and the operator would find out from verification failures rather than
        from a startup error.
        """
        endpoint = os.environ.get("UAI_ENDPOINT", "http://127.0.0.1:8080")
        uai_id = os.environ.get("UAI_AGENT_ID", "")
        key_path = os.environ.get("UAI_AGENT_KEY", "")
        if not uai_id or not key_path:
            raise ValueError(
                "set UAI_AGENT_ID and UAI_AGENT_KEY. This SDK signs as exactly one "
                "registered identity and will not invent one."
            )
        signer = Signer.from_file(key_path, f"did:{uai_id}#key-1")
        return cls(endpoint, uai_id, signer, owner_did=os.environ.get("UAI_OWNER_DID", ""),
                   ca=os.environ.get("UAI_API_CA", ""))

    # ── the context-manager API ─────────────────────────────────────────────

    def action(self, capability: str, purpose: str, *,
               jurisdiction: Jurisdiction | None = None, origin: str = "",
               targets: Iterable[str] = (), basis: str = "",
               action_type: str = "", resource: str = "", risk_class: str = "",
               input: Any = None, strict: bool = False,
               runtime_identity: str = "") -> Action:
        """Return an action to use with ``with``.

        Entering evaluates policy and raises :class:`PolicyRefused` if the
        guardrail refuses, so the block never runs.  Leaving attests, whatever
        happened inside.
        """
        if jurisdiction is None:
            jurisdiction = Jurisdiction(origin=origin, targets=tuple(targets), basis=basis)
        return Action(self, capability=capability, purpose=purpose,
                      jurisdiction=jurisdiction, action_type=action_type,
                      resource=resource, risk_class=risk_class, input=input,
                      strict=strict, runtime_identity=runtime_identity)

    # ── individual calls ────────────────────────────────────────────────────

    def evaluate(self, action: Action) -> Decision:
        """Ask the guardrail whether an action may proceed, without running it."""
        body = {
            "action": {"capability": action.capability, "purpose": action.purpose,
                       "resource": action.resource},
            "jurisdiction": action.jurisdiction.as_dict(),
        }
        return Decision.from_response(
            self.transport.post("/v1/policy/evaluate", Domain.DECISION, body) or {})

    def head(self) -> dict[str, Any]:
        """The tip of this agent's event chain, fetched once and then tracked."""
        if self._head is None:
            response = self.transport.get(f"/v1/agents/{self.uai_id}/events?limit=1") or {}
            self._head = response.get("head") or {"hash": "", "sequence": 0}
        return self._head

    def verify(self, uai_id: str) -> dict[str, Any]:
        """Verify any UAI-ID.  Needs no signature and no account."""
        return self.transport.get(f"/v1/verify/{uai_id}")

    def status(self) -> dict[str, Any]:
        """This agent's identity card."""
        return self.transport.get(f"/v1/agents/{self.uai_id}")

    def events(self, uai_id: str = "", limit: int = 0) -> dict[str, Any]:
        """An agent's event chain."""
        path = f"/v1/agents/{uai_id or self.uai_id}/events"
        if limit:
            path += f"?limit={limit}"
        return self.transport.get(path)

    def request_capability(self, capability: str, justification: str,
                           purpose: str = "") -> dict[str, Any]:
        """Ask the owner for a capability this agent does not hold.

        This creates a PENDING request and nothing else.  Approval is an act by
        the human owner, out of band; no method here, no endpoint, and no
        database path turns one into a grant (22.9, T-11/T-13).
        """
        return self.transport.post("/v1/capability-requests", Domain.CAPABILITY_REQUEST, {
            "capability": capability, "justification": justification, "purpose": purpose,
        })

    def check_passport(self, capability: str, targets: Iterable[str],
                       subject: str = "", risk_class: str = "") -> dict[str, Any]:
        """Run the 11.6 checklist for a capability and a set of jurisdictions.

        A GET, and unsigned: the check changes nothing, and the party who needs
        the answer is whoever is dealing with the agent -- not the agent.
        """
        from urllib.parse import urlencode
        query = {"subject": subject or self.uai_id, "capability": capability,
                 "targets": ",".join(targets)}
        if risk_class:
            query["risk_class"] = risk_class
        return self.transport.get("/v1/passports/check?" + urlencode(query))

    def report_harm(self, subject_agent_did: str, subject_owner_did: str,
                    harm_categories: list[dict[str, Any]], confidence: float, *,
                    related_events: Iterable[str] = (), guardrail_rule: str = "",
                    policy_version: str = "", bundle_hash: str = "",
                    reporter_type: str = "AUTOMATED_GUARDRAIL",
                    evidence_commitments: Iterable[str] = (),
                    affected_jurisdictions: Iterable[str] = ()) -> dict[str, Any]:
        """File a signed suspicion about another identity.

        The document produced here is the ``HarmSuspicion`` of
        ``spec/schemas/harm-suspicion.schema.json``, field for field.  A third
        party implementing against the committed schema and a caller using this
        SDK must produce the same document, or the two are not the same protocol.

        Each category is ``{"category": ..., "severity": 0..4}``.  There is
        deliberately nowhere to record a finding: 14 is explicit that a
        suspicion is a claim warranting examination, never guilt.

        The report carries its own signature, separate from the one on the HTTP
        call, because the row outlives the request: an accusation that cannot be
        re-attributed months later is one nobody has to answer for (14.1).
        """
        from datetime import datetime, timezone
        report: dict[str, Any] = {
            "suspicion_id": _ulid(),
            "reported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reporter": {"did": self.did, "type": reporter_type},
            "subject": {"agent_did": subject_agent_did, "owner_did": subject_owner_did},
            "harm_categories": harm_categories,
            "confidence": confidence,
        }
        if related_events:
            report["related_events"] = list(related_events)
        if guardrail_rule or policy_version or bundle_hash:
            guardrail = {}
            if guardrail_rule:
                guardrail["rule"] = guardrail_rule
            if policy_version:
                guardrail["policy_version"] = policy_version
            if bundle_hash:
                guardrail["bundle_hash"] = bundle_hash
            report["guardrail"] = guardrail
        if evidence_commitments:
            report["evidence_commitments"] = list(evidence_commitments)
        if affected_jurisdictions:
            report["affected_jurisdictions"] = list(affected_jurisdictions)
        report["signature"] = self.signer.sign(
            Domain.SUSPICION, canonicalize_without(report, "signature")).as_dict()
        return self.transport.post("/v1/suspicions", Domain.SUSPICION, report)


def _ulid() -> str:
    """A Crockford base32 ULID: 48 bits of time, 80 of randomness.

    Written here rather than taken as a dependency: it is twenty lines, and this
    package's dependency budget is spent on the one thing Python cannot supply
    (ADR-0004).
    """
    import os
    import time
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    out = []
    for _ in range(26):
        out.append(alphabet[value & 0x1F])
        value >>= 5
    return "".join(reversed(out))
