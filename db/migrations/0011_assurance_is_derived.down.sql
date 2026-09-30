-- Restores the column with the default it always held. It comes back as the
-- registration-time constant it was, because the evidence it should have
-- reflected was never written here and cannot be recovered from this table.
ALTER TABLE agents ADD COLUMN assurance_level assurance_level NOT NULL DEFAULT 'UAI-AL0';
