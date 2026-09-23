-- Executable form of the security invariants (docs/protocol/13-threat-model.md
-- section 20.3). Each block asserts that a FORBIDDEN operation fails. A passing
-- run means the database refuses what the threat model says it must refuse.
--
-- Run with:  psql -v ON_ERROR_STOP=1 -f test/invariants/invariants.sql

\set ON_ERROR_STOP on
\timing off

BEGIN;

-- ── fixtures ────────────────────────────────────────────────────────────────

-- ON CONFLICT so this file runs against both an empty database and one that
-- already carries the development seed.
INSERT INTO jurisdictions (code, name, source_bundle) VALUES
    ('AR', 'Argentina', 'GASC-2027.4'),
    ('DE', 'Germany',   'GASC-2027.4'),
    ('JP', 'Japan',     'GASC-2027.4'),
    ('CA', 'Canada',    'GASC-2027.4'),
    ('IN', 'India',     'GASC-2027.4')
ON CONFLICT (code) DO NOTHING;

INSERT INTO organizations (id, did, legal_name, jurisdiction)
VALUES ('org-acme', 'did:web:acme-robotics.example', 'ACME Robotics', 'AR');

INSERT INTO owners (id, uai_id, did, organization_id, display_name, jurisdiction)
VALUES ('own-1', 'uai:owner:01JY8R9ZB00000000000000000',
        'did:uai:owner:01JY8R9ZB00000000000000000', 'org-acme', 'ACME Ops', 'AR');

INSERT INTO agents (id, uai_id, did, owner_id, organization_id, logical_name, agent_type,
                    primary_jurisdiction, identity_commitment, policy_version, genesis_event_hash)
VALUES ('ag-1', 'uai:agent:01JY8R9ZAF392N7QX2T81JH6KM',
        'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM', 'own-1', 'org-acme',
        'DeliveryOptimizer', 'autonomous_task_agent', 'AR',
        'sha256:' || repeat('a', 64), 'GASC-2027.4', 'sha256:' || repeat('0', 64));

INSERT INTO policies (id, description) VALUES ('GASC', 'Global Agent Safety Convention');
INSERT INTO policy_versions (id, policy_id, version, bundle_hash, effective_date,
                             signature_threshold, approval_signatures)
VALUES ('pv-1', 'GASC', '2027.4', 'sha256:' || repeat('1', 64), now(), '3-of-5', '[]'::jsonb);

INSERT INTO policy_decisions (id, agent_id, capability, purpose, jurisdiction, checks, effect,
                              policy_version, bundle_hash, signature, signer_kid, evaluated_at)
VALUES ('dec-1', 'ag-1', 'route.optimize', 'delivery', '{"origin":"AR"}'::jsonb,
        '{"identity":"PASS"}'::jsonb, 'ALLOW', 'GASC-2027.4', 'sha256:' || repeat('1', 64),
        'sig', 'did:web:pdp.uai.world#key-1', now());

-- Registration is the first link of the chain (section 9.4), so an agent's
-- first action is sequence 2.
INSERT INTO agent_chain_events (id, agent_id, sequence, kind, event_hash, occurred_at)
VALUES ('reg-ev-1', 'ag-1', 1, 'REGISTER', 'sha256:' || repeat('0', 64), now());

INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
                                event_hash, occurred_at)
VALUES ('ev-1', 'ag-1', 2, 'ACTION', 'sha256:' || repeat('0', 64),
        'sha256:' || repeat('b', 64), now());

INSERT INTO action_events (id, agent_id, owner_id, decision_id, action_type, purpose,
                           jurisdiction_origin, jurisdiction_basis, outcome, asserted_at)
VALUES ('ev-1', 'ag-1', 'own-1', 'dec-1', 'route.optimize', 'delivery', 'AR',
        'owner_jurisdiction', 'SUCCESS', now());

INSERT INTO action_attestations (event_id, agent_id, payload, alg, signature, signer_kid, nonce)
VALUES ('ev-1', 'ag-1', '{}'::jsonb, 'EdDSA', 'zSig',
        'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1', 'nonce-1');

INSERT INTO audit_events (id, actor_did, actor_type, operation, object_kind, object_id,
                          source, outcome, signature, signer_kid)
VALUES ('aud-1', 'did:uai:owner:01JY8R9ZB00000000000000000', 'OWNER', 'REGISTER_AGENT',
        'agent', 'ag-1', 'api', 'SUCCESS', 'sig', 'kid');

INSERT INTO harm_cases (id, agent_id, owner_id, summary)
VALUES ('UAI-INC-000041', 'ag-1', 'own-1', 'Access to infrastructure outside declared scope');

INSERT INTO evidence_items (id, case_id, kind, commitment, collected_by, signature, signer_kid)
VALUES ('evi-1', 'UAI-INC-000041', 'ACTION_ATTESTATION', 'sha256:' || repeat('c', 64),
        'did:uai:delegate:01JY8R9ZC00000000000000000', 'sig', 'kid');

INSERT INTO evidence_items (id, case_id, kind, commitment, salt_ref, vault_ref,
                            collected_by, signature, signer_kid)
VALUES ('evi-2', 'UAI-INC-000041', 'LOG_EXTRACT', 'sha256:' || repeat('7', 64),
        'vault://evidence/evi-2/salt', 'vault://evidence/evi-2/object',
        'did:uai:delegate:01JY8R9ZC00000000000000000', 'sig', 'kid');

INSERT INTO evidence_access_log (id, evidence_id, actor_did, actor_role, action,
                                 declared_purpose, signature)
VALUES ('acc-1', 'evi-1', 'did:uai:delegate:01JY8R9ZC00000000000000000', 'INVESTIGATOR',
        'SUBMITTED', 'harm_investigation', 'sig');

INSERT INTO country_members (code, did, display_name, credential_hash) VALUES
    ('AR', 'did:web:ar.gov.example', 'Argentina', 'sha256:' || repeat('d', 64)),
    ('DE', 'did:web:de.gov.example', 'Germany',   'sha256:' || repeat('d', 64));

INSERT INTO human_delegates (id, uai_id, did, country_code, display_name,
                             webauthn_credential_id, webauthn_public_key, credential_hash)
VALUES ('del-ar', 'uai:delegate:01JY8R9ZD00000000000000000',
        'did:uai:delegate:01JY8R9ZD00000000000000000', 'AR', 'AR Delegate',
        '\x01'::bytea, '{}'::jsonb, 'sha256:' || repeat('e', 64)),
       ('del-de', 'uai:delegate:01JY8R9ZE00000000000000000',
        'did:uai:delegate:01JY8R9ZE00000000000000000', 'DE', 'DE Delegate',
        '\x02'::bytea, '{}'::jsonb, 'sha256:' || repeat('e', 64));

INSERT INTO governance_proposals (id, case_id, kind, subject_agent_id, evidence_digest,
                                  policy_version, bundle_hash, threshold_snapshot, state, closes_at)
VALUES ('prop-1', 'UAI-INC-000041', 'PERMANENT_REVOCATION', 'ag-1', 'sha256:' || repeat('f', 64),
        'GASC-2027.4', 'sha256:' || repeat('1', 64), '4-of-5', 'VOTING', now() + interval '7 days');

INSERT INTO votes (id, proposal_id, delegate_id, country_code, value, evidence_digest, vote_digest,
                   authenticator_data, client_data_json, assertion_signature, user_verified)
VALUES ('vote-1', 'prop-1', 'del-ar', 'AR', 'YES', 'sha256:' || repeat('f', 64),
        'sha256:' || repeat('9', 64), '\x01'::bytea, '\x02'::bytea, '\x03'::bytea, true);

-- ── assertion helper ────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION assert_fails(inv text, label text, stmt text) RETURNS void AS $fn$
BEGIN
    BEGIN
        EXECUTE stmt;
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'PASS  %  %  (refused: %)', inv, label, left(SQLERRM, 70);
        RETURN;
    END;
    RAISE EXCEPTION 'FAIL  %  %  -- the forbidden operation SUCCEEDED', inv, label;
END;
$fn$ LANGUAGE plpgsql;

-- ── INV-002 · an action is never attributed by string ID alone ──────────────

SELECT assert_fails('INV-002', 'unsigned attestation rejected', $$
    INSERT INTO action_attestations (event_id, agent_id, payload, alg, signature, signer_kid, nonce)
    VALUES ('ev-1', 'ag-1', '{}'::jsonb, 'EdDSA', '', '', 'nonce-x')$$);

SELECT assert_fails('INV-002', 'attestation cannot be relabelled to another domain', $$
    INSERT INTO action_attestations (event_id, agent_id, payload, alg, signature, signer_kid,
                                     domain, nonce)
    VALUES ('ev-1', 'ag-1', '{}'::jsonb, 'EdDSA', 'sig', 'kid', 'UAI-v1:vote', 'nonce-y')$$);

SELECT assert_fails('INV-002', 'attested action is immutable', $$
    UPDATE action_events SET outcome = 'FAILURE' WHERE id = 'ev-1'$$);

SELECT assert_fails('INV-002', 'attested action cannot be deleted', $$
    DELETE FROM action_events WHERE id = 'ev-1'$$);

-- ── INV-003 · no administrator can edit or delete evidence ──────────────────

SELECT assert_fails('INV-003', 'evidence cannot be edited', $$
    UPDATE evidence_items SET commitment = 'sha256:' || repeat('0', 64) WHERE id = 'evi-1'$$);

SELECT assert_fails('INV-003', 'evidence custody log cannot be rewritten', $$
    UPDATE evidence_access_log SET actor_did = 'did:web:someone.example' WHERE true$$);

SELECT assert_fails('INV-003', 'evidence cannot be deleted', $$
    DELETE FROM evidence_items WHERE id = 'evi-1'$$);

SELECT assert_fails('INV-003', 'audit trail cannot be erased', $$
    DELETE FROM audit_events WHERE true$$);

SELECT assert_fails('INV-003', 'evidence cannot be truncated', $$
    TRUNCATE evidence_items CASCADE$$);

SELECT assert_fails('INV-003', 'audit trail cannot be truncated', $$
    TRUNCATE audit_events$$);

SELECT assert_fails('INV-003', 'attested actions cannot be truncated', $$
    TRUNCATE action_events CASCADE$$);

-- Privacy deletion is the one permitted update to evidence: it destroys the
-- salt and the vault object, and leaves the commitment intact.
UPDATE evidence_items SET shredded_at = now(), salt_ref = NULL, vault_ref = NULL
WHERE id = 'evi-1';
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM evidence_items
                   WHERE id = 'evi-1' AND shredded_at IS NOT NULL
                     AND commitment = 'sha256:' || repeat('c', 64)) THEN
        RAISE EXCEPTION 'FAIL  INV-003  shredding lost the commitment';
    END IF;
    RAISE NOTICE 'PASS  INV-003  crypto-shredding clears content and keeps the commitment';
END $$;

SELECT assert_fails('INV-003', 'shredding cannot double as tampering', $$
    UPDATE evidence_items SET shredded_at = now(), salt_ref = NULL, vault_ref = NULL,
                              commitment = 'sha256:' || repeat('0', 64)
    WHERE id = 'evi-2'$$);

SELECT assert_fails('INV-003', 'a shred that keeps the salt is rejected', $$
    UPDATE evidence_items SET shredded_at = now() WHERE id = 'evi-2'$$);

SELECT assert_fails('INV-003', 'evidence cannot be re-shredded', $$
    UPDATE evidence_items SET shredded_at = now(), salt_ref = NULL, vault_ref = NULL
    WHERE id = 'evi-1'$$);

-- ── INV-004 · no administrator can modify votes ─────────────────────────────

SELECT assert_fails('INV-004', 'vote value cannot be changed', $$
    UPDATE votes SET value = 'NO' WHERE id = 'vote-1'$$);

SELECT assert_fails('INV-004', 'vote assertion cannot be swapped', $$
    UPDATE votes SET assertion_signature = '\xFF'::bytea WHERE id = 'vote-1'$$);

SELECT assert_fails('INV-004', 'vote cannot be deleted', $$
    DELETE FROM votes WHERE id = 'vote-1'$$);

SELECT assert_fails('INV-004', 'one live vote per delegate per proposal', $$
    INSERT INTO votes (id, proposal_id, delegate_id, country_code, value, evidence_digest,
                       vote_digest, authenticator_data, client_data_json, assertion_signature,
                       user_verified)
    VALUES ('vote-dup', 'prop-1', 'del-ar', 'AR', 'NO', 'sha256:' || repeat('f', 64),
            'sha256:' || repeat('8', 64), '\x01'::bytea, '\x02'::bytea, '\x03'::bytea, true)$$);

-- ── INV-005 · no AI can execute a permanent revocation ──────────────────────
-- An automated process has no hardware authenticator, so it cannot produce a
-- user-verified assertion. A vote without user verification is not a vote.

SELECT assert_fails('INV-005', 'vote without user verification rejected', $$
    INSERT INTO votes (id, proposal_id, delegate_id, country_code, value, evidence_digest,
                       vote_digest, authenticator_data, client_data_json, assertion_signature,
                       user_verified)
    VALUES ('vote-bot', 'prop-1', 'del-de', 'DE', 'YES', 'sha256:' || repeat('f', 64),
            'sha256:' || repeat('7', 64), '\x01'::bytea, '\x02'::bytea, '\x03'::bytea, false)$$);

-- ── INV-006 · a revoked identity retains its history ────────────────────────

SELECT assert_fails('INV-006', 'agents cannot be deleted', $$
    DELETE FROM agents WHERE id = 'ag-1'$$);

SELECT assert_fails('INV-006', 'owners cannot be deleted', $$
    DELETE FROM owners WHERE id = 'own-1'$$);

SELECT assert_fails('INV-006', 'revocation requires a timestamp', $$
    UPDATE agents SET status = 'REVOKED' WHERE id = 'ag-1'$$);

-- Revocation done correctly: status changes, the row survives.
UPDATE agents SET status = 'REVOKED', revoked_at = now() WHERE id = 'ag-1';
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM agents WHERE id = 'ag-1' AND status = 'REVOKED') THEN
        RAISE EXCEPTION 'FAIL  INV-006  revoked agent disappeared from the record';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM action_events WHERE agent_id = 'ag-1') THEN
        RAISE EXCEPTION 'FAIL  INV-006  history was lost on revocation';
    END IF;
    RAISE NOTICE 'PASS  INV-006  revoked identity keeps status and history';
END $$;
UPDATE agents SET status = 'ACTIVE', revoked_at = NULL WHERE id = 'ag-1';

-- ── INV-009 · every guardrail decision names its exact policy version ───────

SELECT assert_fails('INV-009', 'decision without policy version rejected', $$
    INSERT INTO policy_decisions (id, agent_id, jurisdiction, checks, effect, policy_version,
                                  bundle_hash, signature, signer_kid, evaluated_at)
    VALUES ('dec-bad', 'ag-1', '{}'::jsonb, '{}'::jsonb, 'ALLOW', '',
            'sha256:' || repeat('1', 64), 'sig', 'kid', now())$$);

SELECT assert_fails('INV-009', 'decision with a malformed bundle hash rejected', $$
    INSERT INTO policy_decisions (id, agent_id, jurisdiction, checks, effect, policy_version,
                                  bundle_hash, signature, signer_kid, evaluated_at)
    VALUES ('dec-bad2', 'ag-1', '{}'::jsonb, '{}'::jsonb, 'ALLOW', 'GASC-2027.4',
            'not-a-digest', 'sig', 'kid', now())$$);

SELECT assert_fails('INV-009', 'decision record is immutable', $$
    UPDATE policy_decisions SET effect = 'DENY' WHERE id = 'dec-1'$$);

-- ── chain and protocol integrity ────────────────────────────────────────────

INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
                                event_hash, occurred_at)
VALUES ('ev-2', 'ag-1', 3, 'ACTION', 'sha256:' || repeat('b', 64),
        'sha256:' || repeat('2', 64), now());

-- The fork rule now covers EVERY kind of event, not only actions. A BIND that
-- claimed an already-claimed predecessor is as much a fork as a second action
-- would be, and before the chain was unified nothing said so.
SELECT assert_fails('CHAIN', 'a fork cannot be committed', $$
    INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
                                    event_hash, occurred_at)
    VALUES ('ev-2b', 'ag-1', 4, 'ACTION', 'sha256:' || repeat('b', 64),
            'sha256:' || repeat('3', 64), now())$$);

SELECT assert_fails('CHAIN', 'a binding cannot fork the chain either', $$
    INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
                                    event_hash, occurred_at)
    VALUES ('ev-2c', 'ag-1', 4, 'BIND', 'sha256:' || repeat('b', 64),
            'sha256:' || repeat('7', 64), now())$$);

SELECT assert_fails('CHAIN', 'duplicate sequence rejected', $$
    INSERT INTO agent_chain_events (id, agent_id, sequence, kind, event_hash, occurred_at)
    VALUES ('ev-3', 'ag-1', 3, 'ACTION', 'sha256:' || repeat('4', 64), now())$$);

SELECT assert_fails('CHAIN', 'one chain cannot carry the same event hash twice', $$
    INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
                                    event_hash, occurred_at)
    VALUES ('ev-3b', 'ag-1', 4, 'ACTION', 'sha256:' || repeat('2', 64),
            'sha256:' || repeat('b', 64), now())$$);

SELECT assert_fails('CHAIN', 'the chain is append-only', $$
    UPDATE agent_chain_events SET event_hash = 'sha256:' || repeat('9', 64)
     WHERE id = 'ev-2'$$);

SELECT assert_fails('CHAIN', 'a chain event cannot be deleted', $$
    DELETE FROM agent_chain_events WHERE id = 'ev-2'$$);

-- An action row with no link in the chain would be an event outside history:
-- verifiable on its own, invisible to anyone walking the chain.
SELECT assert_fails('CHAIN', 'an action cannot exist outside the chain', $$
    INSERT INTO action_events (id, agent_id, owner_id, action_type, purpose,
                               jurisdiction_origin, jurisdiction_basis, outcome, asserted_at)
    VALUES ('ev-orphan', 'ag-1', 'own-1', 'route.optimize', 'delivery', 'AR',
            'owner_jurisdiction', 'SUCCESS', now())$$);

SELECT assert_fails('PROTO', 'cross-border action without a target jurisdiction rejected', $$
    INSERT INTO action_events (id, agent_id, owner_id, action_type, purpose,
                               jurisdiction_origin, jurisdiction_basis, cross_border, outcome,
                               asserted_at)
    VALUES ('ev-1', 'ag-1', 'own-1', 'infra.modify', 'remediation', 'AR',
            'resource_location', true, 'SUCCESS', now())$$);

SELECT assert_fails('PROTO', 'malformed UAI-ID rejected', $$
    INSERT INTO owners (id, uai_id, did, display_name, jurisdiction)
    VALUES ('own-bad', 'uai:owner:not-a-ulid', 'did:uai:owner:01JY8R9ZB00000000000000000',
            'Bad', 'AR')$$);

SELECT assert_fails('PROTO', 'passport with overlapping allow/restrict lists rejected', $$
    INSERT INTO passports (id, agent_id, state, allowed_jurisdictions, restricted_jurisdictions,
                           assurance_level, policy_version, policy_bundle_hash)
    VALUES ('pp-bad', 'ag-1', 'REQUESTED', ARRAY['DE']::iso_country[],
            ARRAY['DE']::iso_country[], 'UAI-AL2', 'GASC-2027.4',
            'sha256:' || repeat('1', 64))$$);

SELECT assert_fails('PROTO', 'quarantine without an expiry rejected', $$
    INSERT INTO quarantine_orders (id, agent_id, owner_id, reason_category, reason_text,
                                   policy_version, bundle_hash, initiating_rule, issued_at,
                                   review_by, expires_at, signature, signer_kid)
    VALUES ('qo-bad', 'ag-1', 'own-1', 'UNAUTHORIZED_ACCESS', 'test', 'GASC-2027.4',
            'sha256:' || repeat('1', 64), 'rule', now(), now() - interval '1 day',
            now() - interval '1 day', 'sig', 'kid')$$);

SELECT assert_fails('PROTO', 'unattributable suspicion rejected', $$
    INSERT INTO harm_suspicions (id, agent_id, owner_id, reporter_did, reporter_type,
                                 harm_categories, confidence, dedup_key, signature, signer_kid)
    VALUES ('sus-bad', 'ag-1', 'own-1', 'did:web:anon.example', 'HUMAN_REPORT',
            '[]'::jsonb, 0.5, 'k', '', 'kid')$$);

-- A vote may be superseded by a NEW signed statement; that is the only
-- permitted update, and both rows survive.
INSERT INTO votes (id, proposal_id, delegate_id, country_code, value, evidence_digest, vote_digest,
                   authenticator_data, client_data_json, assertion_signature, user_verified)
VALUES ('vote-1b', 'prop-1', 'del-de', 'DE', 'NO', 'sha256:' || repeat('f', 64),
        'sha256:' || repeat('6', 64), '\x01'::bytea, '\x02'::bytea, '\x03'::bytea, true);
UPDATE votes SET superseded_by = 'vote-1b' WHERE id = 'vote-1';
DO $$
BEGIN
    IF (SELECT count(*) FROM votes WHERE proposal_id = 'prop-1') <> 2 THEN
        RAISE EXCEPTION 'FAIL  INV-004  superseding a vote destroyed the original';
    END IF;
    RAISE NOTICE 'PASS  INV-004  superseding writes a new statement and keeps the old one';
END $$;

-- ── §8 registration: the two-sided ownership proof ──────────────────────────
--
-- These assert the part of registration the database is responsible for. The
-- signature checks live in internal/api; what must hold HERE is that no path --
-- including a direct SQL statement by an administrator -- can rewrite what the
-- two parties agreed to.

INSERT INTO owner_keys (id, owner_id, key_id, alg, public_jwk, protection, valid_from)
VALUES ('okey-1', 'own-1', 'key-1', 'EdDSA',
        '{"kty":"OKP","crv":"Ed25519","x":"abc"}'::jsonb, 'HSM', now() - interval '1 hour');

INSERT INTO registrations (id, logical_name, agent_type, owner_id, owner_did,
                           primary_jurisdiction, policy_version,
                           challenge_owner, challenge_agent, expires_at)
VALUES ('reg_01JY8R9ZAF392N7QX2T81JH6KP', 'DeliveryOptimizer', 'autonomous_task_agent',
        'own-1', 'did:uai:owner:01JY8R9ZB00000000000000000', 'AR', 'GASC-2027.4',
        'challenge-for-the-owner', 'challenge-for-the-agent', now() + interval '300 seconds');

SELECT assert_fails('REG', 'the two challenges cannot be the same value', $$
    INSERT INTO registrations (id, logical_name, agent_type, owner_id, owner_did,
                               primary_jurisdiction, policy_version,
                               challenge_owner, challenge_agent, expires_at)
    VALUES ('reg-same', 'X', 'autonomous_task_agent', 'own-1',
            'did:uai:owner:01JY8R9ZB00000000000000000', 'AR', 'GASC-2027.4',
            'same', 'same', now() + interval '300 seconds')$$);

SELECT assert_fails('REG', 'half a proof is not a weaker proof, it is a corrupt row', $$
    UPDATE registrations SET owner_proof_sig = '{"alg":"EdDSA"}'::jsonb
     WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP'$$);

SELECT assert_fails('REG', 'an identity cannot be minted without both proofs', $$
    UPDATE registrations SET minted_agent_id = 'ag-1', minted_at = now()
     WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP'$$);

SELECT assert_fails('REG', 'the challenge window cannot be extended', $$
    UPDATE registrations SET expires_at = now() + interval '1 year'
     WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP'$$);

SELECT assert_fails('REG', 'a challenge cannot be swapped after issuance', $$
    UPDATE registrations SET challenge_owner = 'attacker-chosen'
     WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP'$$);

SELECT assert_fails('REG', 'the owner named by a registration cannot be changed', $$
    UPDATE registrations SET owner_did = 'did:uai:owner:01ZZZZZZZZZZZZZZZZZZZZZZZZ'
     WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP'$$);

-- The owner vouches for one agent key.
UPDATE registrations
   SET agent_key_thumbprint = 'sha256:' || repeat('7', 64),
       owner_proof_sig = '{"alg":"EdDSA","value":"zOwner"}'::jsonb,
       owner_proof_kid = 'did:uai:owner:01JY8R9ZB00000000000000000#key-1',
       owner_proved_at = now()
 WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP';

SELECT assert_fails('REG', 'the subject cannot be renegotiated after the first proof', $$
    UPDATE registrations SET agent_key_thumbprint = 'sha256:' || repeat('8', 64)
     WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP'$$);

SELECT assert_fails('REG', 'a submitted proof cannot be replaced', $$
    UPDATE registrations
       SET owner_proof_sig = '{"alg":"EdDSA","value":"zRewritten"}'::jsonb,
           owner_proof_kid = 'did:uai:owner:01JY8R9ZB00000000000000000#key-2',
           owner_proved_at = now()
     WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP'$$);

-- INV-006 extends to owner keys: a key that signed something stays resolvable,
-- or every signature it ever made becomes unverifiable.
SELECT assert_fails('REG', 'owner keys cannot be deleted', $$
    DELETE FROM owner_keys WHERE id = 'okey-1'$$);

SELECT assert_fails('REG', 'owner keys cannot be truncated', $$
    TRUNCATE owner_keys$$);

-- Closing the registration is the one legitimate transition, and it closes for
-- good.
UPDATE registrations
   SET agent_proof_sig = '{"alg":"EdDSA","value":"zAgent"}'::jsonb,
       agent_public_jwk = '{"kty":"OKP","crv":"Ed25519","x":"abc"}'::jsonb,
       agent_proved_at = now()
 WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP';
UPDATE registrations SET minted_agent_id = 'ag-1', minted_at = now()
 WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP';

SELECT assert_fails('REG', 'a minted registration cannot mint again', $$
    UPDATE registrations SET minted_agent_id = NULL, minted_at = NULL
     WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP'$$);

DO $$
BEGIN
    IF (SELECT minted_agent_id FROM registrations
         WHERE id = 'reg_01JY8R9ZAF392N7QX2T81JH6KP') <> 'ag-1' THEN
        RAISE EXCEPTION 'FAIL  REG  a fully proven registration could not be minted';
    END IF;
    RAISE NOTICE 'PASS  REG  a registration with both proofs mints exactly once';
END $$;

-- ── §8.2 credentials issued with an identity ────────────────────────────────

INSERT INTO credentials (id, credential_type, subject_did, issuer_did, agent_id, owner_id,
                         credential_hash, document, valid_from, valid_until)
VALUES ('cred-identity-1', 'AgentIdentityCredential',
        'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM', 'did:web:credentials.uai.world',
        'ag-1', 'own-1', 'sha256:' || repeat('c', 64),
        '{"type":["VerifiableCredential","AgentIdentityCredential"]}'::jsonb,
        now(), now() + interval '365 days');

INSERT INTO credentials (id, credential_type, subject_did, issuer_did, agent_id, owner_id,
                         credential_hash, document, valid_from)
VALUES ('cred-ownership-1', 'AgentOwnershipCredential',
        'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM', 'did:web:credentials.uai.world',
        'ag-1', 'own-1', 'sha256:' || repeat('d', 64),
        '{"type":["VerifiableCredential","AgentOwnershipCredential"]}'::jsonb, now());

-- INV-006: a credential that was ever issued stays resolvable. Deleting one
-- would make every signature it vouched for unverifiable after the fact, which
-- is indistinguishable from the credential never having existed.
SELECT assert_fails('CRED', 'an issued credential cannot be deleted', $$
    DELETE FROM credentials WHERE id = 'cred-identity-1'$$);

-- CASCADE deliberately: a plain TRUNCATE is refused by the foreign key alone,
-- so it would pass this assertion without the guard ever running. An assertion
-- that passes for the wrong reason is worse than no assertion.
SELECT assert_fails('CRED', 'credentials cannot be truncated, even with CASCADE', $$
    TRUNCATE credentials CASCADE$$);

-- The hash identifies the SIGNED document. Two rows sharing one hash would mean
-- an index keyed by it could return either, so one credential could be
-- substituted for another wherever that index is consulted.
SELECT assert_fails('CRED', 'two credentials cannot share one hash', $$
    INSERT INTO credentials (id, credential_type, subject_did, issuer_did, agent_id,
                             credential_hash, document, valid_from)
    VALUES ('cred-clone', 'AgentIdentityCredential',
            'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM', 'did:web:credentials.uai.world',
            'ag-1', 'sha256:' || repeat('c', 64), '{}'::jsonb, now())$$);

SELECT assert_fails('CRED', 'a credential hash must be a real digest', $$
    INSERT INTO credentials (id, credential_type, subject_did, issuer_did, agent_id,
                             credential_hash, document, valid_from)
    VALUES ('cred-badhash', 'AgentIdentityCredential',
            'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM', 'did:web:credentials.uai.world',
            'ag-1', 'deadbeef', '{}'::jsonb, now())$$);

SELECT assert_fails('CRED', 'a credential cannot expire before it starts', $$
    INSERT INTO credentials (id, credential_type, subject_did, issuer_did, agent_id,
                             credential_hash, document, valid_from, valid_until)
    VALUES ('cred-backwards', 'AgentIdentityCredential',
            'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM', 'did:web:credentials.uai.world',
            'ag-1', 'sha256:' || repeat('e', 64), '{}'::jsonb,
            now(), now() - interval '1 day')$$);

DO $$
BEGIN
    IF (SELECT valid_until FROM credentials WHERE id = 'cred-ownership-1') IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL  CRED  ownership must hold until unbound, not until a date';
    END IF;
    RAISE NOTICE 'PASS  CRED  an ownership credential carries no expiry date';
END $$;

-- ── §9 binding ──────────────────────────────────────────────────────────────

INSERT INTO binding_challenges (id, agent_id, operation, challenge, audience, expires_at)
VALUES ('bch-1', 'ag-1', 'BIND_AGENT', 'challenge-for-the-bind', 'uai-agent-registry',
        now() + interval '300 seconds');

SELECT assert_fails('BIND', 'a challenge cannot be redirected to another operation', $$
    UPDATE binding_challenges SET operation = 'UNBIND_AGENT' WHERE id = 'bch-1'$$);

SELECT assert_fails('BIND', 'a challenge cannot be redirected to another agent', $$
    UPDATE binding_challenges SET agent_id = 'ag-1', challenge = 'attacker-chosen'
     WHERE id = 'bch-1'$$);

SELECT assert_fails('BIND', 'a challenge window cannot be extended', $$
    UPDATE binding_challenges SET expires_at = now() + interval '1 year' WHERE id = 'bch-1'$$);

-- A bind that does not name the runtime it bound records who, but not where --
-- and "where" is the half of the claim the operation exists to establish.
SELECT assert_fails('BIND', 'a bind must name the runtime it bound', $$
    INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
                                    event_hash, occurred_at)
    VALUES ('bind-bad', 'ag-1', 4, 'BIND', 'sha256:' || repeat('2', 64),
            'sha256:' || repeat('a', 64), now());
    INSERT INTO agent_bindings (id, agent_id, operation, signature, signer_kid)
    VALUES ('bind-bad', 'ag-1', 'BIND_AGENT', 'zSig',
            'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1')$$);

-- Section 9.3: without a continuity proof naming the key that made it,
-- "unbind, rotate the key, rebind" would launder a stolen identity.
SELECT assert_fails('BIND', 'a rebind without continuity is refused', $$
    INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
                                    event_hash, occurred_at)
    VALUES ('rebind-bad', 'ag-1', 4, 'REBIND', 'sha256:' || repeat('2', 64),
            'sha256:' || repeat('c', 64), now());
    INSERT INTO agent_bindings (id, agent_id, operation, signature, signer_kid)
    VALUES ('rebind-bad', 'ag-1', 'REBIND_AGENT', 'zSig',
            'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1')$$);

SELECT assert_fails('BIND', 'a continuity proof must name the key that made it', $$
    INSERT INTO agent_chain_events (id, agent_id, sequence, kind, previous_event_hash,
                                    event_hash, occurred_at)
    VALUES ('rebind-anon', 'ag-1', 4, 'REBIND', 'sha256:' || repeat('2', 64),
            'sha256:' || repeat('d', 64), now());
    INSERT INTO agent_bindings (id, agent_id, operation, continuity_proof, signature, signer_kid)
    VALUES ('rebind-anon', 'ag-1', 'REBIND_AGENT', 'zContinuity', 'zSig',
            'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1')$$);

-- A binding outside the chain would be a state change nobody walking the
-- history can see.
SELECT assert_fails('BIND', 'a binding cannot exist outside the chain', $$
    INSERT INTO agent_bindings (id, agent_id, operation, spiffe_id, svid_cert_hash,
                                signature, signer_kid)
    VALUES ('bind-orphan', 'ag-1', 'BIND_AGENT', 'spiffe://uai.world/x',
            'sha256:' || repeat('8', 64), 'zSig',
            'did:uai:agent:01JY8R9ZAF392N7QX2T81JH6KM#key-1')$$);

-- INV-006 reaches bindings too: unbinding is not deletion (section 9.2).
SELECT assert_fails('BIND', 'a binding event cannot be deleted', $$
    DELETE FROM agent_bindings WHERE agent_id = 'ag-1'$$);

-- Two workloads cannot present the same SVID.
INSERT INTO runtime_identities (id, agent_id, spiffe_id, cert_hash, expires_at)
VALUES ('rt-1', 'ag-1', 'spiffe://uai.world/agents/01JY/i/aaaa',
        'sha256:' || repeat('9', 64), now() + interval '1 hour');

SELECT assert_fails('BIND', 'one SVID cannot back two runtime identities', $$
    INSERT INTO runtime_identities (id, agent_id, spiffe_id, cert_hash, expires_at)
    VALUES ('rt-2', 'ag-1', 'spiffe://uai.world/agents/01JY/i/aaaa',
            'sha256:' || repeat('9', 64), now() + interval '1 hour')$$);

ROLLBACK;
