BEGIN;
DROP TABLE IF EXISTS nonces, idempotency_keys, audit_events, revocations, revocation_decisions,
    votes, governance_proposals, human_delegates, country_members, quarantine_orders,
    evidence_access_log, evidence_items, harm_cases, harm_suspicions, ledger_commitments,
    transparency_receipts, action_attestations, action_events, policy_decisions,
    policy_rules, policy_versions, policies CASCADE;
DROP FUNCTION IF EXISTS uai_reject_mutation, uai_reject_delete, uai_votes_only_supersede CASCADE;
COMMIT;
