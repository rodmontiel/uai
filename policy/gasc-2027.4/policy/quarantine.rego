# Suspicion thresholds.
package gasc.quarantine

import rego.v1

# An agent already under quarantine may still perform low-risk work (§12.3.2):
# quarantine is preventive, and stopping everything would make a reversible
# measure indistinguishable from a sanction.
findings contains {
	"effect": "DENY",
	"reason": "quarantined_above_low_risk",
	"rule": "gasc.quarantine.risk_ceiling",
} if {
	input.identity.status == "QUARANTINED"
	entry := data.capabilities.registry[input.action.capability]
	risk_rank[entry.risk_class] > risk_rank[data.taxonomy.quarantine.max_risk_class]
}

risk_rank := {"INFORMATIONAL": 0, "LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}
