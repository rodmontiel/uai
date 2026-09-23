-- 0004 · Agent binding (docs/protocol/05-registration-binding.md §9)
--
-- The centrepiece of this migration is not the binding tables: it is that the
-- event chain becomes ONE chain.
--
-- §9.4 draws registration, binds, actions, unbinds and rebinds as a single
-- hash-linked sequence, and until now only actions were in it. That gap is an
-- auditability hole, not a cosmetic one: with bindings outside the chain, a
-- verifier reading an agent's history cannot see that it was UNBOUND between
-- two actions. The state at event time would have to come from a second source,
-- and reconciling two sources is exactly the work a hash chain exists to avoid.

BEGIN;

CREATE TYPE chain_event_kind AS ENUM ('REGISTER', 'BIND', 'UNBIND', 'REBIND', 'ACTION');

-- The single authoritative chain. Everything that happens to an identity links
-- here, and the uniqueness rules that make a fork impossible live in one place
-- rather than being restated per table.
CREATE TABLE agent_chain_events (
    id                  text PRIMARY KEY,           -- ULID; also the wire event_id
    agent_id            text NOT NULL REFERENCES agents(id),
    sequence            bigint NOT NULL,
    kind                chain_event_kind NOT NULL,
    previous_event_hash sha256_digest,
    event_hash          sha256_digest NOT NULL,
    log_index           bigint,
    occurred_at         timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, sequence),
    -- Scoped to the agent, not global. What must not happen is one CHAIN
    -- carrying the same hash twice, which would make "the event with hash X"
    -- ambiguous when the chain is walked. Global uniqueness would additionally
    -- couple unrelated agents to each other and buy nothing.
    UNIQUE (agent_id, event_hash),
    CONSTRAINT chain_sequence_positive CHECK (sequence > 0)
);

-- Makes a fork impossible to commit within one database, now across EVERY kind
-- of event rather than only actions: two successors to the same predecessor
-- cannot both exist. Fork detection therefore stays a cross-instance and
-- cross-log question rather than an application-level race.
CREATE UNIQUE INDEX agent_chain_events_link_uq
    ON agent_chain_events (agent_id, previous_event_hash)
    WHERE previous_event_hash IS NOT NULL;

CREATE INDEX agent_chain_events_timeline_idx ON agent_chain_events (agent_id, sequence DESC);

-- ── action_events joins the shared chain ────────────────────────────────────
--
-- Its ordering and linkage columns move to agent_chain_events, keyed by the
-- same id. Keeping copies here would mean two rows could disagree about where
-- an event sits in history, and nothing could say which one was right.
ALTER TABLE action_events
    DROP CONSTRAINT action_events_agent_id_sequence_key,
    DROP COLUMN sequence,
    DROP COLUMN previous_event_hash,
    DROP COLUMN event_hash,
    ADD CONSTRAINT action_events_in_chain FOREIGN KEY (id) REFERENCES agent_chain_events(id);

-- Both indexes covered dropped columns, so PostgreSQL removed them with the
-- columns. IF EXISTS keeps this migration honest about that rather than relying
-- on the reader knowing it.
DROP INDEX IF EXISTS action_events_chain_uq;
DROP INDEX IF EXISTS action_events_timeline_idx;

-- ── agent_bindings gains what §9.1 actually signs ───────────────────────────
ALTER TABLE agent_bindings
    DROP CONSTRAINT rebind_requires_continuity,
    DROP COLUMN previous_event_hash,
    ADD COLUMN audience             text,
    ADD COLUMN svid_cert_hash       sha256_digest,
    ADD COLUMN image_digest         text,
    ADD COLUMN runtime_identity_id  text REFERENCES runtime_identities(id),
    ADD COLUMN continuity_signer_kid text,
    ADD COLUMN occurred_at          timestamptz NOT NULL DEFAULT now(),
    ADD CONSTRAINT agent_bindings_in_chain FOREIGN KEY (id) REFERENCES agent_chain_events(id),
    -- §9.3: without this, "unbind, rotate the key, rebind" would launder a
    -- stolen identity. A rebind must be vouched for by a key that was valid at
    -- the moment of unbinding, and that proof must name the key that made it.
    ADD CONSTRAINT rebind_requires_continuity
        CHECK (operation <> 'REBIND_AGENT'
               OR (continuity_proof IS NOT NULL AND continuity_signer_kid IS NOT NULL)),
    -- §9.1: a bind ties "who I am" to "where I am running". A bind row without
    -- the runtime it bound records only half of that.
    ADD CONSTRAINT bind_requires_runtime
        CHECK (operation <> 'BIND_AGENT' OR (spiffe_id IS NOT NULL AND svid_cert_hash IS NOT NULL));

-- ── binding challenges ──────────────────────────────────────────────────────
--
-- Server-issued, single-use and short-lived. The agent already authenticates
-- with proof of possession, so this is not what proves who is calling: it is
-- what makes the SIGNED STATEMENT fresh. Without a server-chosen value, a
-- statement captured once could be replayed into a future binding decision.
CREATE TABLE binding_challenges (
    id           text PRIMARY KEY,
    agent_id     text NOT NULL REFERENCES agents(id),
    operation    binding_operation NOT NULL,
    challenge    text NOT NULL UNIQUE,
    audience     text NOT NULL,
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    consumed_by  text REFERENCES agent_bindings(id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT consumption_complete
        CHECK ((consumed_at IS NULL) = (consumed_by IS NULL))
);

CREATE INDEX binding_challenges_agent_idx ON binding_challenges (agent_id, operation)
    WHERE consumed_at IS NULL;
CREATE INDEX binding_challenges_expiry_idx ON binding_challenges (expires_at)
    WHERE consumed_at IS NULL;

-- A challenge is single-use and its terms are fixed at issuance. Everything
-- except consumption is frozen, so a challenge cannot be redirected to another
-- agent or another operation after the fact.
CREATE OR REPLACE FUNCTION uai_binding_challenge_single_use() RETURNS trigger AS $fn$
BEGIN
    IF OLD.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'UAI_CHALLENGE_CONSUMED: binding challenge % was already used by %',
            OLD.id, OLD.consumed_by
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.agent_id  IS DISTINCT FROM OLD.agent_id
    OR NEW.operation IS DISTINCT FROM OLD.operation
    OR NEW.challenge IS DISTINCT FROM OLD.challenge
    OR NEW.audience  IS DISTINCT FROM OLD.audience
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'UAI_CHALLENGE_IMMUTABLE: the terms of challenge % cannot be changed', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

CREATE TRIGGER binding_challenges_single_use
    BEFORE UPDATE ON binding_challenges
    FOR EACH ROW EXECUTE FUNCTION uai_binding_challenge_single_use();

-- The chain is append-only like everything else that records what happened.
CREATE TRIGGER agent_chain_events_append_only BEFORE UPDATE OR DELETE ON agent_chain_events
    FOR EACH ROW EXECUTE FUNCTION uai_reject_mutation();
CREATE TRIGGER agent_chain_events_no_write_stmt BEFORE UPDATE OR DELETE ON agent_chain_events
    FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation();
CREATE TRIGGER agent_chain_events_no_truncate BEFORE TRUNCATE ON agent_chain_events
    FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation();

COMMIT;
