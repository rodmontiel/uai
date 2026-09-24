"""uai - the Python SDK for Universal Agent Identity.

    from uai import Agent, Jurisdiction

    agent = Agent.from_env()

    with agent.action(
        capability="route.optimize",
        purpose="delivery_optimization",
        jurisdiction=Jurisdiction(origin="AR", targets=("DE",), basis="resource_location"),
        input=order,
    ) as act:
        act.output = optimize(order)

    print(act.event_id, act.transparency)

The block runs only if the guardrail permits it, and something is attested on
the way out whatever happens inside -- including an exception.  See
:mod:`uai.agent` for why that is a context manager rather than two calls.
"""

from .agent import Action, Agent, Decision, Jurisdiction
from .canonical import canonicalize, canonicalize_json, canonicalize_without
from .crypto import (
    Domain, Signature, Signer, commit, commit_object, jwk_thumbprint, verify_commitment,
)
from .errors import NotAttested, PolicyRefused, Problem, UAIError

__version__ = "0.1.0"

__all__ = [
    "Action", "Agent", "Decision", "Jurisdiction",
    "Domain", "Signature", "Signer",
    "canonicalize", "canonicalize_json", "canonicalize_without",
    "commit", "commit_object", "jwk_thumbprint", "verify_commitment",
    "NotAttested", "PolicyRefused", "Problem", "UAIError",
    "__version__",
]
