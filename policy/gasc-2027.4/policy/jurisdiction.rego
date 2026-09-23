# Cross-border rules.
package gasc.jurisdiction

import rego.v1

# A cross-border action that names no target cannot be audited against passport
# scope, so it is refused before any of the finer rules run.
findings contains {
	"effect": "DENY",
	"reason": "cross_border_without_target",
	"rule": "gasc.jurisdiction.no_target",
} if {
	input.jurisdiction.cross_border
	count(object.get(input.jurisdiction, "targets", [])) == 0
}

# Restricted regions come from data/jurisdictions.json, never from a constant
# here: which places are restricted is a governance decision with a signature
# behind it, and a rule that hard-coded a country would put that decision in a
# binary nobody voted on.
findings contains {
	"effect": "REQUIRE_HUMAN_APPROVAL",
	"reason": "restricted_target_jurisdiction",
	"rule": "gasc.jurisdiction.restricted_target",
} if {
	some t in input.jurisdiction.targets
	t in {j | some j in data.jurisdictions.restricted}
}

# §12.5: critical infrastructure across a border needs a human, unless a
# passport authorizes autonomous action there.
findings contains {
	"effect": "REQUIRE_HUMAN_APPROVAL",
	"reason": "cross_border_critical_infrastructure",
	"rule": "gasc.infra.cross_border_change",
} if {
	cross_border_critical
	not data.gasc.passport.authorizes_autonomous
}

findings contains {
	"effect": "ALLOW_WITH_MONITORING",
	"reason": "cross_border_critical_infrastructure_with_passport",
	"rule": "gasc.infra.cross_border_change",
	"conditions": {"monitor_window_seconds": 3600, "attest_output": true},
} if {
	cross_border_critical
	data.gasc.passport.authorizes_autonomous
}

cross_border_critical if {
	input.jurisdiction.cross_border
	entry := data.capabilities.registry[input.action.capability]
	entry.risk_class == "CRITICAL"
}
