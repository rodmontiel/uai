# Quorum and delegate eligibility.
#
# Not consulted by the action PDP: it answers the governance service (§16). It
# ships in the same bundle because a quorum size is a policy parameter with the
# same signatures behind it as a harm threshold, and splitting them would let
# the two versions drift.
package gasc.governance

import rego.v1

# A revocation vote counts only from a delegate that is eligible at the time of
# the vote.
eligible(delegate) if {
	delegate.status == "ACTIVE"
	delegate.user_verified
	delegate.country in {c | some c in data.jurisdictions.member_countries}
}

quorum_met(proposal) if {
	votes := [v | some v in proposal.votes; eligible(v.delegate); v.value == "YES"]
	count(votes) >= data.taxonomy.governance.revocation_quorum
	count({v.delegate.country | some v in votes}) >= data.taxonomy.governance.min_countries
}

# The threshold as a string, so a service reads it from the bundle rather than
# composing "4-of-5" from two numbers. Two places that build the same string are
# two places that can disagree about it, and this one ends up inside a
# governance proof that a contract checks.
threshold := data.taxonomy.governance.revocation_threshold

min_countries := data.taxonomy.governance.min_countries
