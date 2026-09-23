-- 0005 · Transparency log (docs/protocol/11-ledger-transparency.md §18)
--
-- The log stores leaf hashes and checkpoints. It does NOT store statements:
-- a leaf is SHA-256(0x00 || jcs(signed_statement)), and the statement itself
-- lives with whoever made it. That is project rule 5 applied to the log rather
-- than only to the chain — a log that accumulated content would become the
-- single place worth attacking, and its retention would stop being cheap and
-- lawful the moment it held anything about a person.

BEGIN;

CREATE TABLE log_entries (
    log_origin      text NOT NULL,
    log_index       bigint NOT NULL,
    leaf_hash       sha256_digest NOT NULL,
    subject_kind    text NOT NULL,      -- attestation | decision | vote | credential | ...
    subject_id      text NOT NULL,
    appended_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (log_origin, log_index),
    -- One statement, one entry. Appending the same leaf twice would put the
    -- same evidence at two indices, and an inclusion proof for either would
    -- then be ambiguous about which entry it proved.
    UNIQUE (log_origin, leaf_hash)
);

CREATE INDEX log_entries_subject_idx ON log_entries (subject_kind, subject_id);

CREATE TABLE log_checkpoints (
    log_origin      text NOT NULL,
    size            bigint NOT NULL,
    root            sha256_digest NOT NULL,
    log_signature   text NOT NULL,
    signer_kid      text NOT NULL,
    witness_signatures jsonb NOT NULL DEFAULT '[]'::jsonb,
    witness_count   integer NOT NULL DEFAULT 0,
    issued_at       timestamptz NOT NULL,
    anchored_tx     text,
    anchored_at     timestamptz,
    PRIMARY KEY (log_origin, size),
    -- One size, one root. Two roots at one size IS a split view: the operator
    -- showing two verifiers different histories. The database refuses to be the
    -- place that happened.
    UNIQUE (log_origin, root),
    CONSTRAINT checkpoint_anchor_complete
        CHECK ((anchored_tx IS NULL) = (anchored_at IS NULL))
);

CREATE INDEX log_checkpoints_unanchored_idx ON log_checkpoints (log_origin, size)
    WHERE anchored_tx IS NULL;

-- The log is append-only, like everything else that records what happened. The
-- one permitted update is recording an anchor, which adds information about an
-- existing checkpoint and never changes what it said.
CREATE TRIGGER log_entries_append_only BEFORE UPDATE OR DELETE ON log_entries
    FOR EACH ROW EXECUTE FUNCTION uai_reject_mutation();
CREATE TRIGGER log_entries_no_write_stmt BEFORE UPDATE OR DELETE ON log_entries
    FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation();
CREATE TRIGGER log_entries_no_truncate BEFORE TRUNCATE ON log_entries
    FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation();

CREATE OR REPLACE FUNCTION uai_checkpoint_only_anchor() RETURNS trigger AS $fn$
BEGIN
    IF OLD.anchored_tx IS NOT NULL THEN
        RAISE EXCEPTION 'UAI_ALREADY_ANCHORED: checkpoint %/% is anchored at %',
            OLD.log_origin, OLD.size, OLD.anchored_tx
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.root IS DISTINCT FROM OLD.root
    OR NEW.log_signature IS DISTINCT FROM OLD.log_signature
    OR NEW.signer_kid IS DISTINCT FROM OLD.signer_kid
    OR NEW.size IS DISTINCT FROM OLD.size
    OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
    OR NEW.witness_signatures IS DISTINCT FROM OLD.witness_signatures
    OR NEW.witness_count IS DISTINCT FROM OLD.witness_count THEN
        RAISE EXCEPTION 'UAI_CHECKPOINT_IMMUTABLE: only the anchor may be added to checkpoint %/%',
            OLD.log_origin, OLD.size
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

CREATE TRIGGER log_checkpoints_only_anchor BEFORE UPDATE ON log_checkpoints
    FOR EACH ROW EXECUTE FUNCTION uai_checkpoint_only_anchor();
CREATE TRIGGER log_checkpoints_no_delete BEFORE DELETE ON log_checkpoints
    FOR EACH ROW EXECUTE FUNCTION uai_reject_mutation();
CREATE TRIGGER log_checkpoints_no_delete_stmt BEFORE DELETE ON log_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation();
CREATE TRIGGER log_checkpoints_no_truncate BEFORE TRUNCATE ON log_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation();

COMMIT;
