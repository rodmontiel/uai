DROP TRIGGER IF EXISTS agent_keys_one_identity ON agent_keys;
DROP TRIGGER IF EXISTS owner_keys_one_identity ON owner_keys;
DROP FUNCTION IF EXISTS uai_reject_shared_agent_key();
DROP FUNCTION IF EXISTS uai_reject_shared_owner_key();
DROP INDEX IF EXISTS agent_keys_thumbprint_idx;
DROP INDEX IF EXISTS owner_keys_thumbprint_idx;
ALTER TABLE agent_keys DROP COLUMN IF EXISTS thumbprint;
ALTER TABLE owner_keys DROP COLUMN IF EXISTS thumbprint;
DROP FUNCTION IF EXISTS uai_jwk_thumbprint(jsonb);
