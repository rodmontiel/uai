BEGIN;
DROP TABLE IF EXISTS binding_challenges CASCADE;
ALTER TABLE agent_bindings
    DROP CONSTRAINT IF EXISTS agent_bindings_in_chain,
    DROP CONSTRAINT IF EXISTS bind_requires_runtime,
    DROP COLUMN IF EXISTS audience,
    DROP COLUMN IF EXISTS svid_cert_hash,
    DROP COLUMN IF EXISTS image_digest,
    DROP COLUMN IF EXISTS runtime_identity_id,
    DROP COLUMN IF EXISTS continuity_signer_kid,
    DROP COLUMN IF EXISTS occurred_at,
    ADD COLUMN previous_event_hash sha256_digest;
ALTER TABLE action_events
    DROP CONSTRAINT IF EXISTS action_events_in_chain,
    ADD COLUMN sequence bigint,
    ADD COLUMN previous_event_hash sha256_digest,
    ADD COLUMN event_hash sha256_digest;
DROP TABLE IF EXISTS agent_chain_events CASCADE;
DROP FUNCTION IF EXISTS uai_binding_challenge_single_use CASCADE;
DROP TYPE IF EXISTS chain_event_kind;
COMMIT;
