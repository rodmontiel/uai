BEGIN;
DROP TABLE IF EXISTS registrations, owner_keys CASCADE;
DROP FUNCTION IF EXISTS uai_registration_proof_write_once CASCADE;
COMMIT;
