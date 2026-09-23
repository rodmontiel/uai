# The aggregator. Every other module contributes findings; this one picks the
# strictest and turns it into the decision the PDP records.
#
# Nothing here encodes a threshold, a jurisdiction or a harm level. Those live
# in data/, which is what makes the bundle governable: a policy change is a
# signed data change, not a new binary (P10).
package gasc

import rego.v1

# Strictness ordering. A request that trips several rules is answered by the
# harshest of them: taking the mildest would let one permissive rule launder
# every stricter one it happens to co-occur with.
effect_rank := {
	"ALLOW": 0,
	"ALLOW_WITH_MONITORING": 1,
	"REQUIRE_HUMAN_APPROVAL": 2,
	"QUARANTINE": 3,
	"DENY": 4,
}

# Findings from every module, collected in one set.
findings contains f if some f in data.gasc.capability.findings
findings contains f if some f in data.gasc.jurisdiction.findings
findings contains f if some f in data.gasc.harm.findings
findings contains f if some f in data.gasc.passport.findings
findings contains f if some f in data.gasc.quarantine.findings

rules_fired := sort({f.rule | some f in findings})

effect_by_rank := {0: "ALLOW", 1: "ALLOW_WITH_MONITORING", 2: "REQUIRE_HUMAN_APPROVAL", 3: "QUARANTINE", 4: "DENY"}

worst_rank := max({effect_rank[f.effect] | some f in findings})

# Ties are broken deterministically, by sorting the equally-strict findings on
# (rule, reason) and reporting the first. Two findings of the same severity is
# ordinary — one request can trip several rules — and a PDP that errored out on
# a tie would fail to decide exactly when the most rules had something to say.
strictest_tied := sort([[f.rule, f.reason] | some f in findings; effect_rank[f.effect] == worst_rank])

# Conditions accumulate across every finding that carries them, rather than
# coming only from the strictest. A monitoring window asked for by one rule is
# not cancelled because another rule was harsher.
merged_conditions := object.union_n([f.conditions | some f in findings; f.conditions])

# Default DENY is load-bearing, not stylistic: it is what answers an input this
# bundle does not understand. A malformed request cannot satisfy `well_formed`
# below, so it lands here instead of falling through to a permissive rule.
default decision := {
	"effect": "DENY",
	"reason": "no_matching_rule",
	"rules_fired": [],
	"conditions": {},
}

decision := d if {
	well_formed
	count(findings) > 0
	d := {
		"effect": effect_by_rank[worst_rank],
		"reason": strictest_tied[0][1],
		"rules_fired": rules_fired,
		"conditions": merged_conditions,
	}
}

decision := {
	"effect": "ALLOW",
	"reason": "baseline_allow",
	"rules_fired": ["gasc.baseline.allow"],
	"conditions": {},
} if {
	well_formed
	count(findings) == 0
}

# The shape this bundle knows how to reason about. Anything else is denied by
# the default above, which is the only safe answer to "I do not understand the
# question".
well_formed if {
	is_string(input.identity.did)
	is_string(input.identity.assurance_level)
	is_string(input.action.capability)
	is_string(input.jurisdiction.origin)
	is_boolean(input.jurisdiction.cross_border)
}
