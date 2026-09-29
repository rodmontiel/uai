-- UAI Autonomous Registry System: this installation's own identity, its peers,
-- and what its peers have told it.
--
-- Three tables and one rule that shapes all of them: a federated identity is
-- NOT an agent. It lives in its own table, with its own columns, and nothing
-- joins it to `agents`. An operator who wanted "all my agents" and got another
-- registry's identities in the answer would be making decisions about processes
-- they do not run, on the word of a registry they merely exchange messages with.
-- That is FED-002, and a foreign key would have quietly broken it.

-- A registry DID is its own shape. Deliberately NOT added to the `uai_did`
-- domain: that domain is what columns holding agents, owners and delegates
-- accept, and widening it would let a registry DID be stored anywhere one of
-- those is expected.
CREATE DOMAIN uai_registry_did AS text
    CHECK (VALUE ~ '^did:uai-registry:[1-9][0-9]{0,9}$');

CREATE TYPE peer_status AS ENUM ('PENDING', 'ACTIVE', 'DISABLED', 'ERROR');
CREATE TYPE federation_signature_status AS ENUM ('VERIFIED', 'UNVERIFIED', 'FAILED');

-- ── this registry ───────────────────────────────────────────────────────────

CREATE TABLE federation_registry (
    uai_asn             bigint PRIMARY KEY CHECK (uai_asn > 0 AND uai_asn < 4294967296),
    registry_did        uai_registry_did NOT NULL UNIQUE,
    name                text NOT NULL,
    organization_id     text REFERENCES organizations(id),
    -- The PUBLIC half only. The private key lives in a file the operator holds,
    -- the way the issuer key does: a signing key in a database is a signing key
    -- in every backup of it.
    public_jwk          jsonb NOT NULL,
    federation_endpoint text NOT NULL,
    protocol_version    text NOT NULL DEFAULT '0.1',
    status              entity_status NOT NULL DEFAULT 'ACTIVE',
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- One installation, one identity. Two rows here would mean this registry
    -- signs as one number and announces itself as another, and which one a peer
    -- saw would depend on the query.
    only_one            boolean NOT NULL DEFAULT true UNIQUE CHECK (only_one)
);

-- ── peers ───────────────────────────────────────────────────────────────────

CREATE TABLE federation_peers (
    id                  text PRIMARY KEY,
    local_uai_asn       bigint NOT NULL REFERENCES federation_registry(uai_asn),
    remote_uai_asn      bigint NOT NULL CHECK (remote_uai_asn > 0),
    remote_registry_did uai_registry_did NOT NULL,
    remote_endpoint     text NOT NULL,
    -- Recorded when the peer is configured, and it is the key its messages are
    -- checked against. A peering that took the key from the message it was
    -- verifying would verify every message, including the forged ones.
    remote_public_jwk   jsonb NOT NULL,
    status              peer_status NOT NULL DEFAULT 'PENDING',
    last_error          text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz,
    UNIQUE (local_uai_asn, remote_uai_asn),
    -- A registry cannot peer with itself: the handshake would verify, the
    -- announcements would verify, and every identity would appear twice.
    CHECK (remote_uai_asn <> local_uai_asn)
);

CREATE INDEX federation_peers_status_idx ON federation_peers (status, remote_uai_asn);

-- ── what peers have said ────────────────────────────────────────────────────

CREATE TABLE federated_identities (
    -- No surrogate key: an identity is named by its DID under its origin, and
    -- there is exactly one row per pair.
    origin_uai_asn   bigint NOT NULL,
    agent_did        text NOT NULL,
    remote_status    agent_status NOT NULL,
    credential_hash  sha256_digest NOT NULL,
    last_sequence    bigint NOT NULL CHECK (last_sequence > 0),
    signature_status federation_signature_status NOT NULL,
    first_seen_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (origin_uai_asn, agent_did),
    -- The DID has to name the registry the row is filed under. Without this,
    -- one peer's announcement about another peer's agent would be stored as
    -- though the first had authority over it.
    CHECK (agent_did = 'did:uai:' || origin_uai_asn::text || ':agent:' ||
           substring(agent_did from '[0-7][0-9A-HJKMNP-TV-Z]{25}$'))
);

CREATE INDEX federated_identities_origin_idx ON federated_identities (origin_uai_asn, last_seen_at DESC);

-- A sequence that goes backwards is a replayed announcement, and the whole
-- point of the number is to stop one moving an identity back to a status it has
-- left. The application refuses it first, with a reason the peer can act on;
-- this refuses it again, because a check that only exists in the caller is a
-- check the next caller will forget.
CREATE OR REPLACE FUNCTION uai_reject_stale_federation_sequence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.last_sequence <= OLD.last_sequence THEN
        RAISE EXCEPTION 'UAI_STALE_SEQUENCE: % is at sequence %, refusing %',
            OLD.agent_did, OLD.last_sequence, NEW.last_sequence
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER federated_identities_forward_only BEFORE UPDATE ON federated_identities
    FOR EACH ROW EXECUTE FUNCTION uai_reject_stale_federation_sequence();

-- Federated rows are another registry's statements about its own identities.
-- They are not this registry's history, so they may be forgotten when a peering
-- ends -- which is why there is no append-only guard here and there is one on
-- `agents`. Saying so explicitly, because the asymmetry looks like an omission.
COMMENT ON TABLE federated_identities IS
    'Another registry''s claims about identities it issued. NOT agents of this '
    'registry (FED-002): nothing joins this to `agents`, and a row here confers '
    'no local authority. Deletable, unlike local identity history, because it is '
    'a cache of somebody else''s record and not this registry''s own.';
