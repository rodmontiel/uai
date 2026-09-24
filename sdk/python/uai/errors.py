"""Typed errors that map one-to-one to the ``UAI_*`` API codes.

They are types rather than messages so that a caller never has to match on a
string.  A refusal an integrator can only detect by reading prose is a refusal
an integrator will eventually mishandle.
"""

from __future__ import annotations

from typing import Any

__all__ = ["UAIError", "Problem", "PolicyRefused", "NotAttested"]


class UAIError(Exception):
    """Base class for everything this SDK raises."""


class Problem(UAIError):
    """An RFC 9457 problem document returned by the gateway."""

    def __init__(self, status: int, document: dict[str, Any]) -> None:
        self.status = status
        self.document = document
        self.code: str = document.get("title") or "UAI_UNKNOWN_ERROR"
        self.detail: str = document.get("detail", "")
        self.remediation: str = document.get("remediation", "")
        self.decision_id: str = document.get("decision_id", "")
        self.policy_version: str = document.get("policy_version", "")
        self.chain_head: dict[str, Any] | None = document.get("chain_head")
        message = f"{self.code} [{status}]"
        if self.detail:
            message += f": {self.detail}"
        if self.remediation:
            message += f" ({self.remediation})"
        super().__init__(message)


class PolicyRefused(UAIError):
    """The guardrail refused the action, so the work did not run.

    It carries the decision rather than only a message: the caller needs the
    decision id to look the refusal up, and the reason to decide whether to ask
    a human, change the request, or stop.
    """

    def __init__(self, decision: Any) -> None:
        self.decision = decision
        super().__init__(
            f"policy refused {decision.effect}: {decision.reason} "
            f"({decision.policy_version}, decision {decision.decision_id})"
        )


class NotAttested(UAIError):
    """The action ran but could not be recorded.

    Raised only when the caller asked for it (``strict=True``).  By default the
    failure is reported on the action instead, because the work has already
    happened and raising afterwards would not undo it -- but a caller that has
    not looked at ``action.attest_error`` is running unattested without knowing.
    """
