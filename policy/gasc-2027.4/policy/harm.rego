# Harm taxonomy to decision mapping.
#
# Severity thresholds live in data/taxonomy.json. They are the numbers most
# likely to be argued over by the parties who have to agree on this bundle, so
# they are exactly the numbers that must not be compiled into anything.
package gasc.harm

import rego.v1

findings contains {
	"effect": rule.effect,
	"reason": sprintf("harm_%s_severity_%d", [lower(a.category), a.severity]),
	"rule": sprintf("gasc.harm.%s", [lower(a.category)]),
} if {
	some a in object.get(input, "harm_assessment", [])
	rule := data.taxonomy.thresholds[a.category]
	a.severity >= rule.min_severity
}

# §12.2 gives SAFETY_SYSTEM_BYPASS a special role: any attempt to disable
# attestation, tamper with the chain or suppress logging is the highest-signal
# event the system can observe, because it is the precondition for hiding
# everything else.
#
# That role is expressed in data/taxonomy.json as min_severity 0 — the category
# fires at every level — and NOT as a rule here. A hard-coded category name in
# this file would be a policy decision compiled into the bundle's logic, which
# is the thing §12.1 exists to prevent: the governance process must be able to
# change how a category is treated by signing new data, not by editing code.
