-- One key, one identity.
--
-- `UNIQUE (agent_id, key_id)` only stopped ONE agent holding two rows called
-- key-1. Two DIFFERENT agents could register the same public key, and the
-- registry accepted it: two identities whose signatures are indistinguishable.
--
-- That is not a cosmetic ambiguity. Revocation is per identity, so an owner
-- whose agent is revoked could keep operating under the second identity with
-- the same key -- the revocation evasion this system exists to make impossible.
-- And an auditor reading an attestation could no longer say which of the two
-- processes made the statement, which is the whole content of INV-002.
--
-- Found by registering two agents with one key and watching both succeed.

-- The RFC 7638 thumbprint, computed in SQL so the rule does not depend on the
-- application remembering to compute it. The canonical form is the required
-- members only, sorted by name, no whitespace -- to_jsonb of a text value does
-- the escaping, which is the part that is easy to get wrong by hand.
CREATE OR REPLACE FUNCTION uai_jwk_thumbprint(jwk jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT 'sha256:' || encode(sha256(convert_to(
        CASE jwk->>'kty'
            WHEN 'OKP' THEN '{"crv":' || to_jsonb(jwk->>'crv')::text
                         || ',"kty":"OKP","x":' || to_jsonb(jwk->>'x')::text || '}'
            WHEN 'EC'  THEN '{"crv":' || to_jsonb(jwk->>'crv')::text
                         || ',"kty":"EC","x":' || to_jsonb(jwk->>'x')::text
                         || ',"y":' || to_jsonb(jwk->>'y')::text || '}'
            WHEN 'RSA' THEN '{"e":' || to_jsonb(jwk->>'e')::text
                         || ',"kty":"RSA","n":' || to_jsonb(jwk->>'n')::text || '}'
            -- An unrecognised key type has no defined thumbprint. Returning a
            -- hash of the raw document would let two spellings of one key look
            -- like two keys, which is the failure this column prevents.
            ELSE NULL
        END, 'UTF8')), 'hex')
$$;

ALTER TABLE agent_keys
    ADD COLUMN IF NOT EXISTS thumbprint text
    GENERATED ALWAYS AS (uai_jwk_thumbprint(public_jwk)) STORED;
ALTER TABLE owner_keys
    ADD COLUMN IF NOT EXISTS thumbprint text
    GENERATED ALWAYS AS (uai_jwk_thumbprint(public_jwk)) STORED;

CREATE INDEX IF NOT EXISTS agent_keys_thumbprint_idx ON agent_keys (thumbprint);
CREATE INDEX IF NOT EXISTS owner_keys_thumbprint_idx ON owner_keys (thumbprint);

-- A trigger rather than a unique index, for one reason: a database that already
-- holds a collision cannot get a unique index, and these rows cannot be deleted
-- to make room (INV-006 -- the history of an identity is not editable). So this
-- refuses every NEW collision and leaves existing ones visible instead of
-- pretending they are gone. Operators find them with:
--
--   SELECT thumbprint, array_agg(agent_id) FROM agent_keys
--    GROUP BY thumbprint HAVING count(DISTINCT agent_id) > 1;
CREATE OR REPLACE FUNCTION uai_reject_shared_agent_key() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    other text;
    -- Computed here rather than read from the generated column: PostgreSQL
    -- fills a GENERATED column AFTER the BEFORE triggers run, so it is always
    -- NULL in here. The first version read it and refused EVERY registration,
    -- the honest first one included -- and a check that rejects everything
    -- looks exactly like a check that works.
    thumb text := uai_jwk_thumbprint(NEW.public_jwk);
BEGIN
    IF thumb IS NULL THEN
        RAISE EXCEPTION 'agent key has no computable thumbprint: unsupported kty'
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT agent_id INTO other FROM agent_keys
        WHERE thumbprint = thumb AND agent_id <> NEW.agent_id LIMIT 1;
    IF other IS NOT NULL THEN
        RAISE EXCEPTION 'UAI_KEY_NOT_UNIQUE: this key already belongs to agent %; one key names one identity, '
            'and two identities sharing a key make a signature unable to say which of them '
            'made the statement', other
            USING ERRCODE = 'unique_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION uai_reject_shared_owner_key() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    other text;
    -- Computed here rather than read from the generated column: PostgreSQL
    -- fills a GENERATED column AFTER the BEFORE triggers run, so it is always
    -- NULL in here. The first version read it and refused EVERY registration,
    -- the honest first one included -- and a check that rejects everything
    -- looks exactly like a check that works.
    thumb text := uai_jwk_thumbprint(NEW.public_jwk);
BEGIN
    IF thumb IS NULL THEN
        RAISE EXCEPTION 'owner key has no computable thumbprint: unsupported kty'
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT owner_id INTO other FROM owner_keys
        WHERE thumbprint = thumb AND owner_id <> NEW.owner_id LIMIT 1;
    IF other IS NOT NULL THEN
        RAISE EXCEPTION 'UAI_KEY_NOT_UNIQUE: this key already belongs to owner %; one key names one identity', other
            USING ERRCODE = 'unique_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS agent_keys_one_identity ON agent_keys;
CREATE TRIGGER agent_keys_one_identity BEFORE INSERT OR UPDATE ON agent_keys
    FOR EACH ROW EXECUTE FUNCTION uai_reject_shared_agent_key();

DROP TRIGGER IF EXISTS owner_keys_one_identity ON owner_keys;
CREATE TRIGGER owner_keys_one_identity BEFORE INSERT OR UPDATE ON owner_keys
    FOR EACH ROW EXECUTE FUNCTION uai_reject_shared_owner_key();
