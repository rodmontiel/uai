BEGIN;
DROP TRIGGER IF EXISTS capability_grants_by_another_party ON capability_grants;
DROP FUNCTION IF EXISTS uai_grant_by_another_party CASCADE;
DROP TABLE IF EXISTS capability_requests CASCADE;
DROP TYPE IF EXISTS capability_request_state;
COMMIT;
