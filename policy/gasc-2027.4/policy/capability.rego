# Capability and assurance floor.
#
# Absence of a grant is not a grant (§12.4): every rule here is written so that
# missing input produces a finding, never silence.
package gasc.capability

import rego.v1

findings contains {
	"effect": "DENY",
	"reason": "capability_not_granted",
	"rule": "gasc.capability.not_granted",
} if {
	not granted
}

granted if input.action.capability in {c | some c in input.capabilities.granted}

# Every capability carries a risk class and a minimum assurance level, both from
# data/capabilities.json. An unregistered capability has no floor to check, so
# it is refused rather than waved through.
findings contains {
	"effect": "DENY",
	"reason": "capability_not_registered",
	"rule": "gasc.capability.unregistered",
} if {
	granted
	not data.capabilities.registry[input.action.capability]
}

# Only for capabilities the agent actually holds. Reporting a floor breach for a
# capability that was never granted would bury the more useful answer under a
# second one that is true but beside the point.
findings contains {
	"effect": "DENY",
	"reason": "assurance_below_floor",
	"rule": "gasc.capability.assurance_floor",
} if {
	granted
	entry := data.capabilities.registry[input.action.capability]
	assurance_rank[input.identity.assurance_level] < assurance_rank[entry.min_assurance]
}

assurance_rank := {"UAI-AL0": 0, "UAI-AL1": 1, "UAI-AL2": 2, "UAI-AL3": 3}

# Runtime assurance is the point of AL2 and above (§12.4): at those levels an
# action with no bound runtime names nothing that could have performed it.
findings contains {
	"effect": "DENY",
	"reason": "runtime_not_bound",
	"rule": "gasc.capability.runtime_required",
} if {
	assurance_rank[input.identity.assurance_level] >= 2
	not input.runtime.bound
}
