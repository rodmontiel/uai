-- Policy, actions, transparency, harm, governance and audit.
--
-- This migration carries the append-only guarantees. They are enforced three
-- ways -- grants, triggers and commitments published outside the database --
-- because a single layer is a single point of failure, and the whole claim of
-- the system is that its records survive a compromised operator.

BEGIN;

-- ── policy ──────────────────────────────────────────────────────────────────

CREATE TABLE policies (
    id              text PRIMARY KEY,           -- e.g. 'GASC'
    description     text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy_versions (
    id                   text PRIMARY KEY,
    policy_id            text NOT NULL REFERENCES policies(id),
    version              text NOT NULL,          -- e.g. '2027.4'
    bundle_hash          sha256_digest NOT NULL UNIQUE,
    previous_policy_hash sha256_digest,
    effective_date       timestamptz NOT NULL,
    sunset_date          timestamptz,
    signature_threshold  text NOT NULL,          -- e.g. '3-of-5'
    approval_signatures  jsonb NOT NULL,
    ledger_tx            text,
    log_index            bigint,
    created_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (policy_id, version)
);

CREATE TABLE policy_rules (
    id              text PRIMARY KEY,
    policy_version_id text NOT NULL REFERENCES policy_versions(id),
    rule_id         text NOT NULL,              -- e.g. 'gasc.infra.cross_border_change'
    harm_category   harm_category,
    severity        smallint CHECK (severity BETWEEN 0 AND 4),
    effect          policy_decision_effect NOT NULL,
    description     text NOT NULL,
    UNIQUE (policy_version_id, rule_id)
);

CREATE TABLE policy_decisions (
    id                  text PRIMARY KEY,
    agent_id            text NOT NULL REFERENCES agents(id),
    capability          text,
    purpose             text,
    resource            text,
    jurisdiction        jsonb NOT NULL,
    checks              jsonb NOT NULL,
    rules_fired         text[] NOT NULL DEFAULT '{}',
    harm_assessment     jsonb NOT NULL DEFAULT '[]'::jsonb,
    effect              policy_decision_effect NOT NULL,
    conditions          jsonb NOT NULL DEFAULT '{}'::jsonb,
    degraded            boolean NOT NULL DEFAULT false,
    bundle_staleness_seconds integer NOT NULL DEFAULT 0,
    policy_version      text NOT NULL,
    bundle_hash         sha256_digest NOT NULL,
    signature           text NOT NULL,
    signer_kid          text NOT NULL,
    evaluated_at        timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- INV-009: every guardrail decision names the exact policy version used.
    -- The bundle_hash domain already enforces the shape; this makes the intent
    -- explicit and survives a future change to the domain.
    CONSTRAINT decision_names_policy
        CHECK (length(policy_version) > 0 AND bundle_hash IS NOT NULL)
);

CREATE INDEX policy_decisions_agent_idx ON policy_decisions (agent_id, evaluated_at DESC);

-- ── actions and attestations ────────────────────────────────────────────────

CREATE TABLE action_events (
    id                  text PRIMARY KEY,           -- ULID, = event_id on the wire
    agent_id            text NOT NULL REFERENCES agents(id),
    owner_id            text NOT NULL REFERENCES owners(id),
    runtime_identity_id text REFERENCES runtime_identities(id),
    decision_id         text REFERENCES policy_decisions(id),
    sequence            bigint NOT NULL,
    action_type         text NOT NULL,
    resource            text,
    capability          text,
    risk                risk_class NOT NULL DEFAULT 'LOW',
    purpose             text NOT NULL,
    jurisdiction_origin iso_country NOT NULL,
    jurisdiction_targets iso_country[] NOT NULL DEFAULT '{}',
    cross_border        boolean NOT NULL DEFAULT false,
    jurisdiction_basis  text NOT NULL,
    passport_id         text REFERENCES passports(id),
    passport_required   boolean NOT NULL DEFAULT false,
    passport_status_at_decision passport_state,
    input_commitment    sha256_digest,
    output_commitment   sha256_digest,
    outcome             action_outcome NOT NULL,
    previous_event_hash sha256_digest,
    event_hash          sha256_digest NOT NULL,
    asserted_at         timestamptz NOT NULL,       -- self-asserted, untrusted
    log_time            timestamptz,                -- authoritative ordering
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, sequence),
    -- A cross-border action must name at least one target jurisdiction;
    -- otherwise the record could not be audited against passport scope.
    CONSTRAINT cross_border_has_targets
        CHECK (NOT cross_border OR cardinality(jurisdiction_targets) > 0)
);

-- Makes a fork impossible to commit within one database: two successors to the
-- same predecessor cannot both exist. Fork detection therefore reduces to a
-- cross-instance and cross-log check rather than an application-level race.
CREATE UNIQUE INDEX action_events_chain_uq
    ON action_events (agent_id, previous_event_hash)
    WHERE previous_event_hash IS NOT NULL;

CREATE INDEX action_events_timeline_idx ON action_events (agent_id, sequence DESC);
CREATE INDEX action_events_time_brin ON action_events USING brin (created_at);

CREATE TABLE action_attestations (
    event_id        text PRIMARY KEY REFERENCES action_events(id),
    agent_id        text NOT NULL REFERENCES agents(id),
    payload         jsonb NOT NULL,
    alg             signature_alg NOT NULL,
    signature       text NOT NULL,
    signer_kid      text NOT NULL,
    domain          text NOT NULL DEFAULT 'UAI-v1:attestation',
    nonce           text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- INV-002: an action is never attributed by a string identifier alone.
    CONSTRAINT attestation_must_be_signed
        CHECK (length(signature) > 0 AND length(signer_kid) > 0),
    CONSTRAINT attestation_domain_fixed
        CHECK (domain = 'UAI-v1:attestation')
);

CREATE UNIQUE INDEX action_attestations_nonce_uq ON action_attestations (agent_id, nonce);

-- ── transparency and ledger ─────────────────────────────────────────────────

CREATE TABLE transparency_receipts (
    id              text PRIMARY KEY,
    log_origin      text NOT NULL,
    log_index       bigint NOT NULL,
    leaf_hash       sha256_digest NOT NULL,
    subject_kind    text NOT NULL,      -- attestation | decision | vote | credential | ...
    subject_id      text NOT NULL,
    checkpoint_size bigint NOT NULL,
    checkpoint_root sha256_digest NOT NULL,
    inclusion_proof jsonb NOT NULL,
    log_signature   text NOT NULL,
    witness_signatures jsonb NOT NULL DEFAULT '[]'::jsonb,
    issued_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (log_origin, log_index)
);

CREATE INDEX transparency_receipts_subject_idx ON transparency_receipts (subject_kind, subject_id);

CREATE TABLE ledger_commitments (
    id              text PRIMARY KEY,
    chain_id        bigint NOT NULL,
    contract        text NOT NULL,
    event_name      text NOT NULL,
    tx_hash         text NOT NULL,
    block_number    bigint NOT NULL,
    epoch           bigint,
    checkpoint_root sha256_digest,
    checkpoint_size bigint,
    subject_kind    text,
    subject_id      text,
    anchored_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (chain_id, tx_hash, event_name, subject_id)
);

CREATE INDEX ledger_commitments_subject_idx ON ledger_commitments (subject_kind, subject_id);

-- ── harm, quarantine, investigation ─────────────────────────────────────────

CREATE TABLE harm_suspicions (
    id                  text PRIMARY KEY,
    agent_id            text NOT NULL REFERENCES agents(id),
    owner_id            text NOT NULL REFERENCES owners(id),
    reporter_did        uai_did NOT NULL,
    reporter_type       reporter_type NOT NULL,
    reporter_credential_hash sha256_digest,
    related_event_ids   text[] NOT NULL DEFAULT '{}',
    harm_categories     jsonb NOT NULL,     -- [{category, severity}]
    guardrail_rule      text,
    policy_version      text,
    bundle_hash         sha256_digest,
    evidence_commitments sha256_digest[] NOT NULL DEFAULT '{}',
    confidence          numeric(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    affected_jurisdictions iso_country[] NOT NULL DEFAULT '{}',
    -- Deduplication key: (agent, rule, related events). Merging on this is what
    -- stops one adversary manufacturing corroboration from many identities.
    dedup_key           text NOT NULL,
    corroboration_count integer NOT NULL DEFAULT 1,
    signature           text NOT NULL,
    signer_kid          text NOT NULL,
    case_id             text,
    log_index           bigint,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- Accusation is a consequential act and must itself be attributable:
    -- there is no anonymous path into this table.
    CONSTRAINT suspicion_reporter_identified
        CHECK (length(reporter_did) > 0 AND length(signature) > 0)
);

CREATE INDEX harm_suspicions_agent_idx ON harm_suspicions (agent_id, created_at DESC);
CREATE INDEX harm_suspicions_dedup_idx ON harm_suspicions (dedup_key);
CREATE INDEX harm_suspicions_reporter_idx ON harm_suspicions (reporter_did, created_at DESC);

CREATE TABLE harm_cases (
    id                  text PRIMARY KEY,           -- e.g. UAI-INC-000041
    agent_id            text NOT NULL REFERENCES agents(id),
    owner_id            text NOT NULL REFERENCES owners(id),
    state               case_state NOT NULL DEFAULT 'OPEN',
    summary             text NOT NULL,
    harm_categories     harm_category[] NOT NULL DEFAULT '{}',
    affected_jurisdictions iso_country[] NOT NULL DEFAULT '{}',
    investigator_did    uai_did,
    evidence_digest     sha256_digest,
    response_window_ends timestamptz,
    opened_at           timestamptz NOT NULL DEFAULT now(),
    closed_at           timestamptz,
    log_index           bigint,
    CONSTRAINT case_closed_has_timestamp
        CHECK ((state = 'CLOSED') = (closed_at IS NOT NULL))
);

CREATE INDEX harm_cases_open_idx ON harm_cases (agent_id, state) WHERE state <> 'CLOSED';

CREATE TABLE evidence_items (
    id                  text PRIMARY KEY,
    case_id             text NOT NULL REFERENCES harm_cases(id),
    kind                evidence_kind NOT NULL,
    commitment          sha256_digest NOT NULL,
    salt_ref            text,           -- vault reference; destroying it crypto-shreds
    vault_ref           text,
    source_event_id     text,
    supersedes          text REFERENCES evidence_items(id),
    collected_by        uai_did NOT NULL,
    collected_at        timestamptz NOT NULL DEFAULT now(),
    signature           text NOT NULL,
    signer_kid          text NOT NULL,
    log_index           bigint,
    shredded_at         timestamptz
);

CREATE INDEX evidence_items_case_idx ON evidence_items (case_id, collected_at);

-- Who read the evidence is part of the custody chain, not an afterthought.
CREATE TABLE evidence_access_log (
    id              text PRIMARY KEY,
    evidence_id     text NOT NULL REFERENCES evidence_items(id),
    actor_did       uai_did NOT NULL,
    actor_role      text NOT NULL,
    action          text NOT NULL,      -- SUBMITTED | ACCESSED | DISCLOSED | SHREDDED
    declared_purpose text NOT NULL,
    signature       text NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX evidence_access_log_evidence_idx ON evidence_access_log (evidence_id, occurred_at);

CREATE TABLE quarantine_orders (
    id                  text PRIMARY KEY,
    agent_id            text NOT NULL REFERENCES agents(id),
    owner_id            text NOT NULL REFERENCES owners(id),
    case_id             text REFERENCES harm_cases(id),
    reason_category     harm_category NOT NULL,
    reason_text         text NOT NULL,
    policy_version      text NOT NULL,
    bundle_hash         sha256_digest NOT NULL,
    initiating_rule     text NOT NULL,
    triggering_suspicions text[] NOT NULL DEFAULT '{}',
    evidence_commitments sha256_digest[] NOT NULL DEFAULT '{}',
    capabilities_suspended text[] NOT NULL DEFAULT '{}',
    capabilities_retained  text[] NOT NULL DEFAULT '{}',
    owner_restrictions     text[] NOT NULL DEFAULT '{}',
    issued_at           timestamptz NOT NULL DEFAULT now(),
    review_by           timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    released_at         timestamptz,
    release_reason      text,
    signature           text NOT NULL,
    signer_kid          text NOT NULL,
    log_index           bigint,
    -- Preventive measures are time-boxed by construction: inaction must not
    -- become a sanction (docs/protocol/09 section 13.4 rule 3).
    CONSTRAINT quarantine_is_time_boxed
        CHECK (expires_at > issued_at AND review_by > issued_at AND review_by <= expires_at)
);

CREATE INDEX quarantine_expiry_sweep_idx
    ON quarantine_orders (expires_at) WHERE released_at IS NULL;

-- ── governance ──────────────────────────────────────────────────────────────

CREATE TABLE country_members (
    code            iso_country PRIMARY KEY REFERENCES jurisdictions(code),
    did             uai_did NOT NULL UNIQUE,
    display_name    text NOT NULL,
    status          entity_status NOT NULL DEFAULT 'ACTIVE',
    joined_at       timestamptz NOT NULL DEFAULT now(),
    credential_hash sha256_digest NOT NULL
);

CREATE TABLE human_delegates (
    id                  text PRIMARY KEY,
    uai_id              uai_id NOT NULL UNIQUE,
    did                 uai_did NOT NULL UNIQUE,
    country_code        iso_country NOT NULL REFERENCES country_members(code),
    display_name        text NOT NULL,
    is_alternate        boolean NOT NULL DEFAULT false,
    -- The vote signature is a WebAuthn assertion from a hardware authenticator
    -- with user verification required. There is no software key here for an
    -- automated process to steal and use: INV-005 rests on this column.
    webauthn_credential_id bytea NOT NULL UNIQUE,
    webauthn_public_key    jsonb NOT NULL,
    webauthn_aaguid        uuid,
    credential_hash     sha256_digest NOT NULL,
    status              entity_status NOT NULL DEFAULT 'ACTIVE',
    appointed_at        timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz
);

CREATE INDEX human_delegates_country_idx ON human_delegates (country_code, status);

CREATE TABLE governance_proposals (
    id                  text PRIMARY KEY,
    case_id             text NOT NULL REFERENCES harm_cases(id),
    kind                proposal_kind NOT NULL,
    subject_agent_id    text NOT NULL REFERENCES agents(id),
    evidence_digest     sha256_digest NOT NULL,
    policy_version      text NOT NULL,
    bundle_hash         sha256_digest NOT NULL,
    threshold_snapshot  text NOT NULL,      -- e.g. '4-of-5', captured at open time
    state               proposal_state NOT NULL DEFAULT 'DRAFT',
    opened_at           timestamptz NOT NULL DEFAULT now(),
    closes_at           timestamptz NOT NULL,
    resolved_at         timestamptz,
    log_index           bigint
);

CREATE INDEX governance_proposals_case_idx ON governance_proposals (case_id, state);

CREATE TABLE votes (
    id                  text PRIMARY KEY,
    proposal_id         text NOT NULL REFERENCES governance_proposals(id),
    delegate_id         text NOT NULL REFERENCES human_delegates(id),
    country_code        iso_country NOT NULL REFERENCES country_members(code),
    value               vote_value NOT NULL,
    evidence_digest     sha256_digest NOT NULL,
    rationale_hash      sha256_digest,
    -- The WebAuthn challenge IS the vote digest, so this assertion is a
    -- hardware signature over the voted content, not merely over a session.
    vote_digest         sha256_digest NOT NULL,
    authenticator_data  bytea NOT NULL,
    client_data_json    bytea NOT NULL,
    assertion_signature bytea NOT NULL,
    user_verified       boolean NOT NULL,
    superseded_by       text REFERENCES votes(id),
    cast_at             timestamptz NOT NULL DEFAULT now(),
    log_index           bigint,
    ledger_tx           text,
    -- No proxy voting and no automated voting: an assertion without user
    -- verification is not a vote.
    CONSTRAINT vote_requires_user_verification CHECK (user_verified)
);

-- One live vote per delegate per proposal. A change of vote is a new signed
-- statement that supersedes the old one; nothing is modified in place.
CREATE UNIQUE INDEX votes_one_live_per_delegate
    ON votes (proposal_id, delegate_id) WHERE superseded_by IS NULL;

CREATE TABLE revocation_decisions (
    id                  text PRIMARY KEY,
    proposal_id         text NOT NULL REFERENCES governance_proposals(id),
    case_id             text NOT NULL REFERENCES harm_cases(id),
    subject_agent_id    text NOT NULL REFERENCES agents(id),
    tally_yes           integer NOT NULL,
    tally_no            integer NOT NULL,
    tally_pending       integer NOT NULL,
    threshold_applied   text NOT NULL,
    evidence_digest     sha256_digest NOT NULL,
    governance_proof    sha256_digest NOT NULL UNIQUE,
    authorized_at       timestamptz NOT NULL DEFAULT now(),
    log_index           bigint
);

CREATE TABLE revocations (
    id                  text PRIMARY KEY,
    decision_id         text NOT NULL UNIQUE REFERENCES revocation_decisions(id),
    agent_id            text NOT NULL REFERENCES agents(id),
    executed_by_did     uai_did NOT NULL,
    executor_signature  text NOT NULL,
    governance_proof    sha256_digest NOT NULL,
    chain_id            bigint,
    tx_hash             text,
    executed_at         timestamptz NOT NULL DEFAULT now(),
    log_index           bigint
);

-- ── audit ───────────────────────────────────────────────────────────────────

CREATE TABLE audit_events (
    id                  text PRIMARY KEY,
    actor_did           text NOT NULL,
    actor_type          text NOT NULL,
    operation           text NOT NULL,
    object_kind         text NOT NULL,
    object_id           text NOT NULL,
    source              text NOT NULL,
    policy_version      text,
    before_state_hash   sha256_digest,
    after_state_hash    sha256_digest,
    outcome             text NOT NULL,
    detail              jsonb NOT NULL DEFAULT '{}'::jsonb,
    signature           text NOT NULL,
    signer_kid          text NOT NULL,
    occurred_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_object_idx ON audit_events (object_kind, object_id, occurred_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events (actor_did, occurred_at DESC);
CREATE INDEX audit_events_time_brin ON audit_events USING brin (occurred_at);

-- ── request hygiene ─────────────────────────────────────────────────────────

CREATE TABLE idempotency_keys (
    key             text NOT NULL,
    endpoint        text NOT NULL,
    request_hash    sha256_digest NOT NULL,
    response_status integer,
    -- text, not jsonb: an idempotent replay must return the EXACT bytes of the
    -- original response. jsonb normalizes key order and whitespace, so a client
    -- that hashed or signed the first response would see a different document
    -- on retry.
    response_body   text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    PRIMARY KEY (key, endpoint)
);

CREATE INDEX idempotency_keys_expiry_idx ON idempotency_keys (expires_at);

CREATE TABLE nonces (
    signer_kid      text NOT NULL,
    nonce           text NOT NULL,
    seen_at         timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    PRIMARY KEY (signer_kid, nonce)
);

CREATE INDEX nonces_expiry_idx ON nonces (expires_at);

-- ── append-only enforcement ─────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION uai_reject_mutation() RETURNS trigger AS $fn$
BEGIN
    RAISE EXCEPTION 'UAI_APPEND_ONLY: % on % is forbidden', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'integrity_constraint_violation';
END;
$fn$ LANGUAGE plpgsql;

-- Guards are installed at three granularities on purpose:
--   FOR EACH ROW        catches modification of existing rows;
--   FOR EACH STATEMENT  catches a DELETE that matches nothing today but would
--                       match tomorrow, so the refusal does not depend on the
--                       table's current contents;
--   BEFORE TRUNCATE     catches TRUNCATE, which row triggers never see at all.
-- Without the third, an administrator could erase the evidence table wholesale
-- while every row-level guard stayed silent.

-- Fully append-only: no UPDATE, no DELETE, no TRUNCATE.
-- INV-002 (attested actions), INV-003 (evidence custody and the audit trail
-- itself), INV-009 (decision records).
DO $do$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'action_events', 'action_attestations', 'audit_events', 'policy_decisions',
        'transparency_receipts', 'ledger_commitments', 'revocations',
        'revocation_decisions', 'evidence_access_log', 'policy_versions', 'policy_rules'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I_append_only BEFORE UPDATE OR DELETE ON %I
             FOR EACH ROW EXECUTE FUNCTION uai_reject_mutation()', t, t);
        EXECUTE format(
            'CREATE TRIGGER %I_no_write_stmt BEFORE UPDATE OR DELETE ON %I
             FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation()', t, t);
        EXECUTE format(
            'CREATE TRIGGER %I_no_truncate BEFORE TRUNCATE ON %I
             FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation()', t, t);
    END LOOP;
END
$do$;

-- INV-006: identities and case records are never deleted or truncated; their
-- lifecycle is a status transition. Updates remain allowed.
DO $do$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'agents', 'owners', 'organizations', 'credentials', 'harm_cases',
        'harm_suspicions', 'quarantine_orders', 'agent_bindings', 'agent_keys',
        'runtime_identities', 'capability_grants', 'passports',
        'governance_proposals', 'human_delegates', 'country_members',
        'evidence_items', 'votes'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I_no_delete BEFORE DELETE ON %I
             FOR EACH ROW EXECUTE FUNCTION uai_reject_mutation()', t, t);
        EXECUTE format(
            'CREATE TRIGGER %I_no_delete_stmt BEFORE DELETE ON %I
             FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation()', t, t);
        EXECUTE format(
            'CREATE TRIGGER %I_no_truncate BEFORE TRUNCATE ON %I
             FOR EACH STATEMENT EXECUTE FUNCTION uai_reject_mutation()', t, t);
    END LOOP;
END
$do$;

-- INV-003 · evidence is immutable, with exactly one exception: crypto-shredding.
--
-- Privacy deletion destroys the salt and the vault object so the content becomes
-- unrecoverable, while the commitment -- and therefore every proof derived from
-- it -- survives (docs/protocol/12-privacy.md section 19.5). That is a narrow,
-- one-way update: shredding may only clear the references and stamp the time. It
-- can never alter what the evidence committed to, who collected it, or its
-- signature, and it cannot be undone.
CREATE OR REPLACE FUNCTION uai_evidence_only_shred() RETURNS trigger AS $fn$
BEGIN
    IF OLD.shredded_at IS NOT NULL THEN
        RAISE EXCEPTION 'UAI_EVIDENCE_IMMUTABLE: evidence % is already shredded', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.shredded_at IS NULL THEN
        RAISE EXCEPTION 'UAI_EVIDENCE_IMMUTABLE: the only permitted update to evidence is shredding'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.salt_ref IS NOT NULL OR NEW.vault_ref IS NOT NULL THEN
        RAISE EXCEPTION 'UAI_EVIDENCE_SHRED_INCOMPLETE: shredding must clear salt_ref and vault_ref'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.id, NEW.case_id, NEW.kind, NEW.commitment, NEW.source_event_id, NEW.supersedes,
        NEW.collected_by, NEW.collected_at, NEW.signature, NEW.signer_kid, NEW.log_index)
       IS DISTINCT FROM
       (OLD.id, OLD.case_id, OLD.kind, OLD.commitment, OLD.source_event_id, OLD.supersedes,
        OLD.collected_by, OLD.collected_at, OLD.signature, OLD.signer_kid, OLD.log_index) THEN
        RAISE EXCEPTION 'UAI_EVIDENCE_IMMUTABLE: shredding may not alter the evidence record'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

CREATE TRIGGER evidence_items_shred_only
    BEFORE UPDATE ON evidence_items
    FOR EACH ROW EXECUTE FUNCTION uai_evidence_only_shred();

-- INV-004 · a cast vote cannot be modified. Superseding a vote writes a new
-- signed statement and marks the old one; that single column is the only
-- permitted update, and both rows survive forever.
CREATE OR REPLACE FUNCTION uai_votes_only_supersede() RETURNS trigger AS $fn$
BEGIN
    IF OLD.superseded_by IS NOT NULL THEN
        RAISE EXCEPTION 'UAI_VOTE_IMMUTABLE: vote % is already superseded', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.id, NEW.proposal_id, NEW.delegate_id, NEW.country_code, NEW.value, NEW.vote_digest,
        NEW.authenticator_data, NEW.client_data_json, NEW.assertion_signature,
        NEW.user_verified, NEW.evidence_digest, NEW.rationale_hash, NEW.cast_at)
       IS DISTINCT FROM
       (OLD.id, OLD.proposal_id, OLD.delegate_id, OLD.country_code, OLD.value, OLD.vote_digest,
        OLD.authenticator_data, OLD.client_data_json, OLD.assertion_signature,
        OLD.user_verified, OLD.evidence_digest, OLD.rationale_hash, OLD.cast_at) THEN
        RAISE EXCEPTION 'UAI_VOTE_IMMUTABLE: only superseded_by may be set on an existing vote'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

CREATE TRIGGER votes_immutable
    BEFORE UPDATE ON votes
    FOR EACH ROW EXECUTE FUNCTION uai_votes_only_supersede();

COMMIT;
