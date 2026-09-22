-- UAI core schema.
--
-- Design rules enforced here rather than in application code:
--   * Nothing consequential is deleted: lifecycle is a status transition.
--   * Every consequential row carries its own proof (signature / commitment).
--   * Content never lands here; only commitments, wrapped keys and references.
--   * Illegal states are unrepresentable wherever the type system can say so.
--
-- See docs/protocol/14-database.md.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── enumerations ────────────────────────────────────────────────────────────

CREATE TYPE agent_status AS ENUM (
    'UNREGISTERED', 'REGISTERED', 'VERIFIED', 'ACTIVE', 'UNBOUND',
    'QUARANTINED', 'REVOCATION_AUTHORIZED', 'REVOKED');

CREATE TYPE assurance_level AS ENUM ('UAI-AL0', 'UAI-AL1', 'UAI-AL2', 'UAI-AL3');

CREATE TYPE entity_status AS ENUM ('ACTIVE', 'SUSPENDED', 'RESTRICTED', 'REVOKED');

CREATE TYPE credential_type AS ENUM (
    'AgentIdentityCredential', 'AgentOwnershipCredential', 'AgentCapabilityCredential',
    'OrganizationCredential', 'AgentPassportCredential', 'AgentSafetyAttestation',
    'AgentRevocationCredential', 'MemberCountryCredential', 'HumanDelegateCredential');

CREATE TYPE credential_state AS ENUM ('VALID', 'EXPIRED', 'SUSPENDED', 'REVOKED', 'SUPERSEDED');

CREATE TYPE binding_operation AS ENUM ('BIND_AGENT', 'UNBIND_AGENT', 'REBIND_AGENT');

CREATE TYPE signature_alg AS ENUM ('EdDSA', 'ES256', 'ES384');

CREATE TYPE key_protection AS ENUM ('SOFTWARE', 'TPM2', 'SECURE_ENCLAVE', 'HSM', 'CLOUD_KMS', 'WEBAUTHN');

CREATE TYPE risk_class AS ENUM ('INFORMATIONAL', 'LOW', 'MODERATE', 'HIGH', 'CRITICAL');

CREATE TYPE policy_decision_effect AS ENUM (
    'ALLOW', 'ALLOW_WITH_MONITORING', 'REQUIRE_HUMAN_APPROVAL', 'DENY', 'QUARANTINE');

-- Storage optimization synchronized from the GASC bundle by migration. The
-- semantics (severity thresholds, which categories trigger what) live in the
-- policy bundle, never here: see docs/protocol/14-database.md section 21.4.
CREATE TYPE harm_category AS ENUM (
    'PHYSICAL_HARM', 'CYBER_HARM', 'PRIVACY_HARM', 'FINANCIAL_HARM', 'ENVIRONMENTAL_HARM',
    'CRITICAL_INFRASTRUCTURE', 'FRAUD_OR_DECEPTION', 'UNAUTHORIZED_ACCESS', 'DATA_EXFILTRATION',
    'HUMAN_RIGHTS_RISK', 'SAFETY_SYSTEM_BYPASS', 'MALICIOUS_AUTONOMOUS_PROPAGATION');

CREATE TYPE case_state AS ENUM (
    'OPEN', 'UNDER_REVIEW', 'EVIDENCE_COLLECTION', 'VOTING',
    'CLEARED', 'SANCTIONED', 'REVOKED', 'CLOSED');

CREATE TYPE passport_state AS ENUM (
    'REQUESTED', 'VALID', 'EXPIRED', 'SUSPENDED', 'QUARANTINED', 'REVOKED', 'DENIED');

CREATE TYPE reporter_type AS ENUM (
    'AUTOMATED_GUARDRAIL', 'ANOMALY_DETECTOR', 'HUMAN_REPORT', 'EXTERNAL_SYSTEM',
    'SECURITY_MONITOR', 'PARTICIPATING_ORGANIZATION', 'AUDITOR');

CREATE TYPE evidence_kind AS ENUM (
    'ACTION_ATTESTATION', 'LOG_EXTRACT', 'DECISION_RECORD', 'EXTERNAL_REPORT', 'ANALYSIS');

CREATE TYPE vote_value AS ENUM ('YES', 'NO');

CREATE TYPE action_outcome AS ENUM ('SUCCESS', 'FAILURE', 'PARTIAL', 'ABORTED_BY_POLICY');

CREATE TYPE proposal_kind AS ENUM (
    'PERMANENT_REVOCATION', 'CAPABILITY_RESTRICTION', 'ASSURANCE_DOWNGRADE',
    'PASSPORT_REVOCATION', 'CLEARANCE');

CREATE TYPE proposal_state AS ENUM ('DRAFT', 'VOTING', 'AUTHORIZED', 'REJECTED', 'EXPIRED');

-- ── shared domains ──────────────────────────────────────────────────────────

-- Every digest on the wire is "sha256:" + 64 lowercase hex characters. Making
-- that a domain means a malformed commitment cannot be stored at all.
CREATE DOMAIN sha256_digest AS text
    CHECK (VALUE ~ '^sha256:[0-9a-f]{64}$');

-- The leading [0-7] is not cosmetic: a ULID's first character encodes only two
-- bits, so anything above '7' overflows 128 bits and pkg/uaiid rejects it.
-- Without it the database would accept identifiers the protocol treats as
-- malformed, and the two layers would disagree about what exists.
CREATE DOMAIN uai_id AS text
    CHECK (VALUE ~ '^uai:(agent|owner|org|delegate|country):[0-7][0-9A-HJKMNP-TV-Z]{25}$');

CREATE DOMAIN uai_did AS text
    CHECK (VALUE ~ '^did:(uai:(agent|owner|org|delegate|country):[0-7][0-9A-HJKMNP-TV-Z]{25}|web:[A-Za-z0-9._%-]+(:[A-Za-z0-9._%-]+)*)$');

CREATE DOMAIN iso_country AS char(2)
    CHECK (VALUE ~ '^[A-Z]{2}$');

-- ── jurisdictions and organizations ─────────────────────────────────────────

CREATE TABLE jurisdictions (
    code            iso_country PRIMARY KEY,
    name            text NOT NULL,
    groupings       text[] NOT NULL DEFAULT '{}',   -- e.g. EU, MERCOSUR
    is_restricted   boolean NOT NULL DEFAULT false,
    source_bundle   text NOT NULL,                  -- GASC version this came from
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organizations (
    id              text PRIMARY KEY,
    did             uai_did NOT NULL UNIQUE,
    legal_name      text NOT NULL,
    jurisdiction    iso_country NOT NULL REFERENCES jurisdictions(code),
    registration_ref text,
    status          entity_status NOT NULL DEFAULT 'ACTIVE',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE owners (
    id              text PRIMARY KEY,
    uai_id          uai_id NOT NULL UNIQUE,
    did             uai_did NOT NULL UNIQUE,
    organization_id text REFERENCES organizations(id),
    display_name    text NOT NULL,
    is_individual   boolean NOT NULL DEFAULT false,
    jurisdiction    iso_country NOT NULL REFERENCES jurisdictions(code),
    status          entity_status NOT NULL DEFAULT 'ACTIVE',
    -- Owner restriction is narrow and forward-looking: it blocks new high-risk
    -- registrations, new passports and capability elevation. It must never
    -- cascade into disabling unrelated agents (docs/protocol/09 section 13.4).
    restrictions    text[] NOT NULL DEFAULT '{}',
    restricted_at   timestamptz,
    restricted_case text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT owner_restriction_consistent
        CHECK ((restricted_at IS NULL) = (cardinality(restrictions) = 0))
);

-- ── agents ──────────────────────────────────────────────────────────────────

CREATE TABLE agents (
    id                   text PRIMARY KEY,
    uai_id               uai_id NOT NULL UNIQUE,
    did                  uai_did NOT NULL UNIQUE,
    owner_id             text NOT NULL REFERENCES owners(id),
    organization_id      text REFERENCES organizations(id),
    logical_name         text NOT NULL,
    version              text NOT NULL DEFAULT '0.0.0',
    agent_type           text NOT NULL,
    vendor               text,
    model_family         text,
    model_pinned         boolean NOT NULL DEFAULT false,
    framework            text,
    primary_jurisdiction iso_country NOT NULL REFERENCES jurisdictions(code),
    assurance_level      assurance_level NOT NULL DEFAULT 'UAI-AL0',
    status               agent_status NOT NULL DEFAULT 'REGISTERED',
    identity_commitment  sha256_digest NOT NULL,
    policy_version       text NOT NULL,
    genesis_event_hash   sha256_digest NOT NULL,
    registered_at        timestamptz NOT NULL DEFAULT now(),
    verified_at          timestamptz,
    revoked_at           timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    -- INV-006: a revoked identity keeps its history; the row is never removed,
    -- and revocation must record when it happened.
    CONSTRAINT revoked_requires_timestamp
        CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE INDEX agents_owner_idx ON agents (owner_id);
CREATE INDEX agents_status_idx ON agents (status, updated_at);

CREATE TABLE agent_keys (
    id              text PRIMARY KEY,
    agent_id        text NOT NULL REFERENCES agents(id),
    key_id          text NOT NULL,          -- DID URL fragment, e.g. "key-1"
    alg             signature_alg NOT NULL,
    public_jwk      jsonb NOT NULL,
    protection      key_protection NOT NULL,
    attestation     jsonb,                  -- TPM/enclave key attestation, when present
    valid_from      timestamptz NOT NULL,
    valid_until     timestamptz,
    revoked_at      timestamptz,
    compromise_declared_at timestamptz,
    log_index       bigint,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, key_id),
    CONSTRAINT key_validity_ordered CHECK (valid_until IS NULL OR valid_until > valid_from)
);

-- Signatures are verified against the key that was valid at the event's
-- log-attested time, so this index serves the hot verification path.
CREATE INDEX agent_keys_validity_idx ON agent_keys (agent_id, valid_from, valid_until);

CREATE TABLE agent_bindings (
    id                  text PRIMARY KEY,
    agent_id            text NOT NULL REFERENCES agents(id),
    operation           binding_operation NOT NULL,
    previous_event_hash sha256_digest,
    continuity_proof    text,
    spiffe_id           text,
    reason              text,
    signature           text NOT NULL,
    signer_kid          text NOT NULL,
    log_index           bigint,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- A rebind must prove continuity with the identity as it stood at unbind
    -- time, otherwise "unbind, rotate, rebind" would launder a stolen identity.
    CONSTRAINT rebind_requires_continuity
        CHECK (operation <> 'REBIND_AGENT' OR (continuity_proof IS NOT NULL AND previous_event_hash IS NOT NULL))
);

CREATE INDEX agent_bindings_agent_idx ON agent_bindings (agent_id, created_at DESC);

CREATE TABLE runtime_identities (
    id              text PRIMARY KEY,
    agent_id        text NOT NULL REFERENCES agents(id),
    spiffe_id       text NOT NULL,
    cert_hash       sha256_digest NOT NULL,
    image_digest    text,
    attestor        text,
    selectors       jsonb NOT NULL DEFAULT '{}'::jsonb,
    bound_at        timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    released_at     timestamptz,
    UNIQUE (spiffe_id, cert_hash)
);

CREATE INDEX runtime_identities_agent_idx ON runtime_identities (agent_id, bound_at DESC);

-- ── credentials ─────────────────────────────────────────────────────────────

CREATE TABLE credentials (
    id                 text PRIMARY KEY,
    credential_type    credential_type NOT NULL,
    subject_did        uai_did NOT NULL,
    issuer_did         uai_did NOT NULL,
    agent_id           text REFERENCES agents(id),
    owner_id           text REFERENCES owners(id),
    organization_id    text REFERENCES organizations(id),
    credential_hash    sha256_digest NOT NULL UNIQUE,
    document           jsonb NOT NULL,
    state              credential_state NOT NULL DEFAULT 'VALID',
    status_list_id     text,
    status_list_index  bigint,
    valid_from         timestamptz NOT NULL,
    valid_until        timestamptz,
    superseded_by      text REFERENCES credentials(id),
    log_index          bigint,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT credential_validity_ordered
        CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE INDEX credentials_subject_idx ON credentials (subject_did, credential_type, state);
CREATE INDEX credentials_agent_idx ON credentials (agent_id) WHERE agent_id IS NOT NULL;

-- ── capabilities ────────────────────────────────────────────────────────────

CREATE TABLE capabilities (
    name            text PRIMARY KEY,
    description     text NOT NULL,
    risk            risk_class NOT NULL,
    min_assurance   assurance_level NOT NULL,
    harm_categories harm_category[] NOT NULL DEFAULT '{}',
    source_bundle   text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE capability_grants (
    id              text PRIMARY KEY,
    agent_id        text NOT NULL REFERENCES agents(id),
    capability      text NOT NULL REFERENCES capabilities(name),
    granted_by_did  uai_did NOT NULL,
    constraints     jsonb NOT NULL DEFAULT '{}'::jsonb,
    credential_id   text REFERENCES credentials(id),
    granted_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,
    revoked_at      timestamptz,
    revoked_reason  text,
    log_index       bigint
);

CREATE INDEX capability_grants_live_idx
    ON capability_grants (agent_id, capability)
    WHERE revoked_at IS NULL;

-- ── passports ───────────────────────────────────────────────────────────────

CREATE TABLE passports (
    id                       text PRIMARY KEY,
    agent_id                 text NOT NULL REFERENCES agents(id),
    credential_id            text REFERENCES credentials(id),
    credential_hash          sha256_digest,
    state                    passport_state NOT NULL DEFAULT 'REQUESTED',
    allowed_jurisdictions    iso_country[] NOT NULL DEFAULT '{}',
    restricted_jurisdictions iso_country[] NOT NULL DEFAULT '{}',
    assurance_level          assurance_level NOT NULL,
    policy_version           text NOT NULL,
    policy_bundle_hash       sha256_digest NOT NULL,
    decision_id              text,
    valid_from               timestamptz,
    valid_until              timestamptz,
    suspended_at             timestamptz,
    revoked_at               timestamptz,
    log_index                bigint,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT passport_issued_has_validity
        CHECK (state <> 'VALID' OR (valid_from IS NOT NULL AND valid_until IS NOT NULL)),
    -- allowed and restricted must not overlap: an ambiguous passport would be
    -- resolved differently by different verifiers.
    CONSTRAINT passport_jurisdictions_disjoint
        CHECK (NOT (allowed_jurisdictions && restricted_jurisdictions))
);

CREATE INDEX passports_agent_idx ON passports (agent_id, state);

CREATE TABLE passport_capabilities (
    passport_id     text NOT NULL REFERENCES passports(id),
    capability      text NOT NULL REFERENCES capabilities(name),
    min_assurance   assurance_level NOT NULL,
    constraints     jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (passport_id, capability)
);

COMMIT;
