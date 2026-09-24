# uai-sdk

The Python SDK for [Universal Agent Identity](../../README.md).

```bash
pip install uai-sdk
```

## The context manager

```python
from uai import Agent, Jurisdiction, PolicyRefused

agent = Agent.from_env()          # UAI_ENDPOINT, UAI_AGENT_ID, UAI_AGENT_KEY

try:
    with agent.action(
        capability="cloud.securitygroup.update",
        purpose="close an unrestricted ingress rule",
        jurisdiction=Jurisdiction(origin="AR", targets=("DE",), basis="resource_location"),
        input={"security_group": "sg-0a1b2c3d"},
        risk_class="HIGH",
    ) as act:
        act.output = update_security_group("sg-0a1b2c3d")
except PolicyRefused as refused:
    print(refused.decision.reason, refused.decision.decision_id)
else:
    print(act.event_id, act.sequence, act.transparency)
```

Three things happen that are worth knowing about:

**The block does not run if the guardrail refuses.** `__enter__` evaluates the
policy first. A `DENY`, a `QUARANTINE` and a `REQUIRE_HUMAN_APPROVAL` all raise
`PolicyRefused` — the last one is a refusal until a human acts, not a
conditional yes.

**Something is attested on every way out.** Return, exception, or refusal. An
SDK that exposed `evaluate()` and `attest()` separately would produce a record of
successes only, because the failure paths are the ones nobody writes the second
call on.

**The content never leaves your process.** `input` and `act.output` are committed
locally with a fresh random salt, and only `sha256:…` is sent. Keep
`act.input_salt` and `act.output_salt`: UAI does not have them and never will,
so a commitment whose salt was discarded can never be opened by anyone.

## When the record is missing

`act.attest_error` is set when the action ran but could not be recorded — the
work already happened, so raising afterwards would not undo it. Pass
`strict=True` to raise `NotAttested` instead, when running unattested is worse
for you than failing.

```python
with agent.action(..., strict=True) as act:
    act.output = do_the_work()
```

## The rest of the surface

```python
agent.verify("uai:agent:01JY8R9ZAF392N7QX2T81JH6KM")   # public, no key needed
agent.status()
agent.events(limit=50)
agent.check_passport("crm.customer.read", targets=["DE"])
agent.request_capability("payments.transfer", justification="issue refunds")
agent.report_harm(subject="uai:agent:01J…", harm_categories=[…], confidence=0.8)
```

`request_capability` creates a **pending request**. It does not grant anything
and cannot be made to: approval is an act by the human owner, out of band, and
no method here, no API route and no database path turns one into a grant.

## What this SDK cannot do

It cannot make an agent accountable. An agent that does not want to be does not
import it. What it does is make the accountable path the easy one; verification
lives in the relying party, which is where it survives an adversarial agent.

It does not hold or generate keys. `Signer` is supplied by you and may be backed
by a file, an HSM or a remote KMS.

## Dependencies

One: `cryptography`. Python has no asymmetric cryptography in its standard
library, and a pure-Python Ed25519 would be a timing-attack surface wrapped
around your signing key. Canonicalization (RFC 8785), HTTP message signatures
(RFC 9421) and the HTTP client itself are standard library.

## Tests

```bash
cd sdk/python && python -m unittest discover -s tests -t .
```

They run against `spec/test-vectors/`, the same committed vectors the Go
implementation and the browser verification code reproduce. The vectors are read,
never regenerated: a test that writes its own expectations proves only that the
code agrees with itself.
