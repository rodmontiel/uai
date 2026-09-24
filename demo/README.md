# The ACME demo

The scenario from §24.5, end to end, against a real stack. It exists to
demonstrate the 21 MVP criteria of §24.1 — and one thing that is not a
criterion at all.

```bash
make demo
```

## What happens

ACME Robotics registers an owner and an agent called DeliveryOptimizer. The
agent binds a runtime, gets a passport for Germany, and works: it optimizes
routes, and every action is evaluated, signed, chained and logged.

Then it tries to reach infrastructure it was never authorized for. The guardrail
denies it, a harm suspicion is filed and signed, and the policy — not this
script — decides that the category warrants a preventive quarantine. A case
opens. Five delegates on three continents look at the same evidence digest and
vote with hardware authenticators. Four say yes.

An administrator whose entire write surface is one button executes the decision.
They cannot choose the agent, the reason or the votes: their only input is a
decision id, and everything else was fixed by the governance proof before they
arrived.

The agent's next call is refused.

## And then the part that is not a criterion

After the revocation, the script runs DeliveryOptimizer's business logic
directly against the target stub. **It still works.** Nothing stopped the code
from executing, because nothing in UAI can.

What changed is that no participant will honour its identity. That is the whole
of what revocation means, and the demo says it out loud at the moment it is
least convenient to say it — because a system that lets people believe otherwise
has sold them a kill switch it does not have.

## Reading the output

Each step prints the criterion it demonstrates. `make demo` fails if any
criterion is not demonstrated, so this is a test that happens to be readable
rather than a narration that happens to run.

The last step runs `uai-verify`, which re-checks the entire history from public
data using only the three trust anchors — including the revocation, whose tally
and governance proof it rebuilds from the signed assertions rather than reading
the outcome we recorded.
