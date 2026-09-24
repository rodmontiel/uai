#!/usr/bin/env python3
"""The context-manager example, against a running gateway.

    export UAI_ENDPOINT=http://127.0.0.1:8080
    export UAI_AGENT_ID=uai:agent:01...
    export UAI_AGENT_KEY=.keys/agent.jwk
    python3 sdk/examples/quickstart.py

Run sdk/examples/bootstrap.py first if you have no identity yet.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from uai import Agent, Jurisdiction, PolicyRefused  # noqa: E402


def optimize(order: dict) -> dict:
    """Stand-in for the work the agent actually does."""
    return {"route": ["depot", order["destination"]], "eta_minutes": 42}


def main() -> int:
    agent = Agent.from_env()
    print(f"acting as {agent.uai_id}")
    print(f"status: {agent.status()['status']}\n")

    order = {"order_id": "ORD-4471", "destination": "Berlin", "customer": "customer@example.com"}

    # ── an action the guardrail permits ─────────────────────────────────────
    with agent.action(
        capability="route.optimize",
        purpose="delivery_optimization",
        jurisdiction=Jurisdiction(origin="AR", targets=("DE",), basis="resource_location"),
        input=order,
    ) as act:
        act.output = optimize(order)

    print(f"decision : {act.decision.effect} under {act.decision.policy_version}")
    print(f"outcome  : {act.outcome}")
    print(f"event    : {act.event_id} at sequence {act.sequence}")
    print(f"log      : {act.transparency}")
    if act.attest_error is not None:
        # The work ran and the evidence is missing. Printing the empty event id
        # without this line would read as success.
        print(f"NOT RECORDED: {act.attest_error}")
    # The salts are the only way this record can ever be opened. UAI does not
    # have them: store them wherever the customer data itself is stored.
    print(f"salts    : input={act.input_salt.hex()[:16]}… output={act.output_salt.hex()[:16]}…\n")

    # ── an action it refuses ────────────────────────────────────────────────
    # The action is built first and entered second, because __enter__ is what
    # raises: `with agent.action(...) as refused` would leave `refused` unbound
    # on the refusal path, and the refusal is exactly what we want to look at.
    refused = agent.action(
        capability="payments.transfer",
        purpose="refund the customer",
        jurisdiction=Jurisdiction(origin="AR", basis="owner_jurisdiction"),
    )
    try:
        with refused:
            raise AssertionError("this line must never run")
    except PolicyRefused as error:
        print(f"refused  : {error.decision.effect} — {error.decision.reason}")
        print(f"recorded : {refused.outcome} at {refused.event_id}\n")

    # ── the failure path is recorded too ────────────────────────────────────
    failing = agent.action(
        capability="route.optimize", purpose="delivery_optimization",
        jurisdiction=Jurisdiction(origin="AR", basis="owner_jurisdiction"), input=order)
    try:
        with failing:
            raise RuntimeError("the routing service timed out")
    except RuntimeError as error:
        print(f"failed   : {error}")
        print(f"recorded : {failing.outcome} at {failing.event_id}\n")

    # ── asking for something the owner has not granted ──────────────────────
    pending = agent.request_capability(
        "payments.transfer", justification="issue refunds without a human in the loop")
    print(f"requested: {pending['capability']} → {pending['state']} (granted={pending['granted']})")
    print(f"           {pending['note']}\n")

    # ── the chain, walked back ──────────────────────────────────────────────
    chain = agent.events(limit=10)
    print("chain:")
    for event in chain["events"]:
        print(f"  {event['sequence']:>3}  {event['outcome'] or '—':<18} {event['event_hash'][:23]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
