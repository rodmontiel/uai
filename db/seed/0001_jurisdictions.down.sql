BEGIN;
DELETE FROM jurisdictions WHERE source_bundle = 'bootstrap';
COMMIT;
