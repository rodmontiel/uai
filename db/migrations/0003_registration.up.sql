-- 0003 · Agent registration (docs/protocol/05-registration-binding.md §8)
--
-- Registration is a two-step flow because it has to be. The registry cannot
-- authenticate the first call against a key it knows -- establishing that key is
-- what registration IS -- so the identity is minted only after two independent
-- signatures agree on the same subject. This table is where a registration
-- lives between the two calls.

BEGIN;

-- ── owner keys ──────────────────────────────────────────────────────────────
--
-- Owners sign: the ownership half of a registration proof, and unbind requests
-- for a lost agent (§9.2). Their keys are provisioned administratively rather
-- than through a public endpoint -- §22.2 defines no owner-registration route
-- on purpose, because the party that vouches for agents cannot itself be
-- self-asserted.
--
-- This table is why ownership can be PROVEN. If the owner's public key arrived
-- in the proof submission instead, "ownership" would mean "whoever sent this
-- request said so", which is the exact failure mode §6.4.1 exists to prevent.
CREATE TABLE owner_keys (
    id              text PRIMARY KEY,
    owner_id        text NOT NULL REFERENCES owners(id),
    key_id          text NOT NULL,          -- DID URL fragment, e.g. "key-1"
    alg             signature_alg NOT NULL,
    public_jwk      jsonb NOT NULL,
    protection      key_protection NOT NULL,
    attestation     jsonb,
    valid_from      timestamptz NOT NULL,
    valid_until     timestamptz,
    revoked_at      timestamptz,
    compromise_declared_at timestamptz,
    log_index       bigint,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_id, key_id),
    CONSTRAINT owner_key_validity_ordered
        CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE INDEX owner_keys_owner_idx ON owner_keys (owner_id);

-- ── the salt behind the on-chain identity commitment ────────────────────────
--
-- agents.identity_commitment is what the consortium ledger stores (§8.2): a
-- salted commitment, never the identity itself (project rule 5). A commitment
-- whose salt was discarded can never be opened, which would make it a decorative
-- hash rather than evidence — so the salt is kept here, on the private side.
--
-- Nullable only because the column is added to an existing table. The
-- registration flow always sets it; a row without one is a row nobody can ever
-- prove corresponds to its on-chain entry.
ALTER TABLE agents ADD COLUMN identity_commitment_salt bytea;

COMMENT ON COLUMN agents.identity_commitment_salt IS
    'Salt for identity_commitment. Required to open the on-chain commitment; never leaves this database.';

-- ── registrations ───────────────────────────────────────────────────────────
CREATE TABLE registrations (
    id                   text PRIMARY KEY,
    -- Draft identity, as requested. None of this is trusted until both proofs
    -- verify; it is a request, not a record.
    logical_name         text NOT NULL,
    version              text NOT NULL DEFAULT '0.0.0',
    agent_type           text NOT NULL,
    owner_id             text NOT NULL REFERENCES owners(id),
    owner_did            uai_did NOT NULL,
    organization_id      text REFERENCES organizations(id),
    vendor               text,
    model_family         text,
    model_pinned         boolean NOT NULL DEFAULT false,
    framework            text,
    primary_jurisdiction iso_country NOT NULL REFERENCES jurisdictions(code),
    requested_capabilities text[] NOT NULL DEFAULT '{}',
    policy_version       text NOT NULL,

    -- Two independent challenges. They are not derived from one another: if the
    -- agent's challenge were a function of the owner's, holding one key would be
    -- enough to predict the other half of the proof.
    challenge_owner      text NOT NULL,
    challenge_agent      text NOT NULL,
    expires_at           timestamptz NOT NULL,

    -- The subject both halves must name. Set by whichever proof arrives first;
    -- the second is required to match it (§8.5 UAI_PROOF_MISMATCH).
    agent_key_thumbprint sha256_digest,

    owner_proof_sig      jsonb,
    owner_proof_kid      text,
    owner_proved_at      timestamptz,

    agent_proof_sig      jsonb,
    agent_public_jwk     jsonb,
    agent_proved_at      timestamptz,

    -- Set exactly once, when the identity is minted.
    minted_agent_id      text UNIQUE REFERENCES agents(id),
    minted_at            timestamptz,

    created_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT registration_challenges_distinct
        CHECK (challenge_owner <> challenge_agent),
    -- A proof is a triple: signature, signer and time. Half a proof is not a
    -- weaker proof, it is a corrupt row.
    CONSTRAINT owner_proof_complete
        CHECK (num_nonnulls(owner_proof_sig, owner_proof_kid, owner_proved_at) IN (0, 3)),
    CONSTRAINT agent_proof_complete
        CHECK (num_nonnulls(agent_proof_sig, agent_public_jwk, agent_proved_at) IN (0, 3)),
    CONSTRAINT minted_consistent
        CHECK ((minted_agent_id IS NULL) = (minted_at IS NULL)),
    -- An identity cannot be minted from a registration that is not fully proven.
    CONSTRAINT mint_requires_both_proofs
        CHECK (minted_agent_id IS NULL
               OR (owner_proved_at IS NOT NULL AND agent_proved_at IS NOT NULL
                   AND agent_key_thumbprint IS NOT NULL))
);

CREATE INDEX registrations_owner_idx ON registrations (owner_id);
CREATE INDEX registrations_expiry_idx ON registrations (expires_at) WHERE minted_agent_id IS NULL;

-- ── a submitted proof is final ──────────────────────────────────────────────
--
-- Without this, an owner who proved first could resubmit naming a DIFFERENT
-- agent key after the agent had proved, and the registry would mint an identity
-- for a key its owner never actually vouched for. That is identity substitution
-- at the one moment the system has no prior key to check against, so the rule is
-- enforced here rather than left to the handler.
--
-- The columns a registration may legitimately gain after creation are exactly:
-- the first proof of each side, the thumbprint the first proof establishes, and
-- the mint result.
CREATE OR REPLACE FUNCTION uai_registration_proof_write_once() RETURNS trigger AS $fn$
BEGIN
    IF OLD.minted_agent_id IS NOT NULL THEN
        RAISE EXCEPTION 'UAI_REGISTRATION_CLOSED: registration % was already minted as %',
            OLD.id, OLD.minted_agent_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF OLD.owner_proved_at IS NOT NULL AND (
           NEW.owner_proof_sig IS DISTINCT FROM OLD.owner_proof_sig
        OR NEW.owner_proof_kid IS DISTINCT FROM OLD.owner_proof_kid
        OR NEW.owner_proved_at IS DISTINCT FROM OLD.owner_proved_at) THEN
        RAISE EXCEPTION 'UAI_PROOF_FINAL: the owner proof for registration % cannot be replaced', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF OLD.agent_proved_at IS NOT NULL AND (
           NEW.agent_proof_sig IS DISTINCT FROM OLD.agent_proof_sig
        OR NEW.agent_public_jwk IS DISTINCT FROM OLD.agent_public_jwk
        OR NEW.agent_proved_at IS DISTINCT FROM OLD.agent_proved_at) THEN
        RAISE EXCEPTION 'UAI_PROOF_FINAL: the agent proof for registration % cannot be replaced', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- The subject is fixed by the first proof. Both halves must name it, so it
    -- can never be renegotiated mid-flow.
    IF OLD.agent_key_thumbprint IS NOT NULL
       AND NEW.agent_key_thumbprint IS DISTINCT FROM OLD.agent_key_thumbprint THEN
        RAISE EXCEPTION 'UAI_PROOF_MISMATCH: registration % already names agent key %',
            OLD.id, OLD.agent_key_thumbprint
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- The draft itself is frozen: re-reading it at mint time must yield what the
    -- parties signed against, not what someone rewrote afterwards.
    IF NEW.logical_name         IS DISTINCT FROM OLD.logical_name
    OR NEW.agent_type           IS DISTINCT FROM OLD.agent_type
    OR NEW.owner_id             IS DISTINCT FROM OLD.owner_id
    OR NEW.owner_did            IS DISTINCT FROM OLD.owner_did
    OR NEW.primary_jurisdiction IS DISTINCT FROM OLD.primary_jurisdiction
    OR NEW.requested_capabilities IS DISTINCT FROM OLD.requested_capabilities
    OR NEW.challenge_owner      IS DISTINCT FROM OLD.challenge_owner
    OR NEW.challenge_agent      IS DISTINCT FROM OLD.challenge_agent
    OR NEW.expires_at           IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'UAI_REGISTRATION_IMMUTABLE: the draft of registration % cannot be edited', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

CREATE TRIGGER registrations_proof_write_once
    BEFORE UPDATE ON registrations
    FOR EACH ROW EXECUTE FUNCTION uai_registration_proof_write_once();

-- Owner keys follow agent keys: never deleted, never truncated. A key that
-- signed something must stay resolvable, or every signature it ever made
-- becomes unverifiable (§6.7, "valid at event time").
CREATE TRIGGER owner_keys_no_delete BEFORE DELETE ON owner_keys
    FOR EACH ROW EXECUTE FUNCTION uai_reject_mutation();
CREATE TRIGGER owner_keys_no_delete_stmt BEFORE DELETE ON owner_keys
    FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation();
CREATE TRIGGER owner_keys_no_truncate BEFORE TRUNCATE ON owner_keys
    FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation();

COMMIT;
