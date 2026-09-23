# Passport eligibility for the action being decided.
package gasc.passport

import rego.v1

# Fail closed (§12.4): a cross-border action with no valid passport is denied,
# including when the passport field is simply absent. "We could not tell" and
# "it was fine" must not produce the same answer.
findings contains {
	"effect": "DENY",
	"reason": "passport_required",
	"rule": "gasc.passport.required",
} if {
	input.jurisdiction.cross_border
	object.get(input, ["passport", "state"], "ABSENT") != "VALID"
}

findings contains {
	"effect": "DENY",
	"reason": "passport_does_not_cover_target",
	"rule": "gasc.passport.jurisdiction_scope",
} if {
	input.jurisdiction.cross_border
	input.passport.state == "VALID"
	some t in input.jurisdiction.targets
	not t in {j | some j in input.passport.allowed_jurisdictions}
}

findings contains {
	"effect": "DENY",
	"reason": "passport_does_not_cover_capability",
	"rule": "gasc.passport.capability_scope",
} if {
	input.jurisdiction.cross_border
	input.passport.state == "VALID"
	not input.action.capability in {c | some c in input.passport.authorized_capabilities}
}

# Autonomous cross-border action at the highest assurance level only.
authorizes_autonomous if {
	input.passport.state == "VALID"
	input.action.capability in {c | some c in input.passport.authorized_capabilities}
	input.identity.assurance_level == "UAI-AL3"
	every t in input.jurisdiction.targets {
		t in {j | some j in input.passport.allowed_jurisdictions}
	}
}
