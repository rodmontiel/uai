BEGIN;
DROP TABLE IF EXISTS log_checkpoints, log_entries CASCADE;
DROP FUNCTION IF EXISTS uai_checkpoint_only_anchor CASCADE;
COMMIT;
