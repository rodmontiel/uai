DROP TRIGGER IF EXISTS federated_identities_forward_only ON federated_identities;
DROP FUNCTION IF EXISTS uai_reject_stale_federation_sequence();
DROP TABLE IF EXISTS federated_identities;
DROP TABLE IF EXISTS federation_peers;
DROP TABLE IF EXISTS federation_registry;
DROP TYPE IF EXISTS federation_signature_status;
DROP TYPE IF EXISTS peer_status;
DROP DOMAIN IF EXISTS uai_registry_did;
