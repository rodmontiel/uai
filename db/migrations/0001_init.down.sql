BEGIN;
DROP TABLE IF EXISTS passport_capabilities, passports, capability_grants, capabilities,
    credentials, runtime_identities, agent_bindings, agent_keys, agents, owners,
    organizations, jurisdictions CASCADE;
DROP DOMAIN IF EXISTS iso_country, uai_did, uai_id, sha256_digest CASCADE;
DROP TYPE IF EXISTS proposal_state, proposal_kind, action_outcome, vote_value, evidence_kind,
    reporter_type, passport_state, case_state, harm_category, policy_decision_effect,
    risk_class, key_protection, signature_alg, binding_operation, credential_state,
    credential_type, entity_status, assurance_level, agent_status CASCADE;
COMMIT;
