-- The nonce that made a vote digest, kept so the tally can rebuild it.
--
-- §20.3 claims INV-004 is enforced by, among other things, "tally recomputed
-- from signatures". It was not. The tally verified each assertion against the
-- vote_digest COLUMN and then reported the value COLUMN, and nothing rechecked
-- that the two belonged together. The binding existed only at cast time.
--
-- That leaves a gap for anyone who can INSERT: take a genuine assertion the
-- delegate produced on another proposal, store it here with its real digest and
-- the opposite value, and every application-layer check passes. Only the
-- contract would refuse it, and a deployment anchoring to `noop-dev` has no
-- contract.
--
-- Rebuilding the digest needs the whole statement of §15.3, and the nonce was
-- the one member never written down.
ALTER TABLE votes ADD COLUMN IF NOT EXISTS nonce text;

COMMENT ON COLUMN votes.nonce IS
    'The statement nonce of §15.3. Required to rebuild vote_digest at tally '
    'time; without it the value column cannot be checked against the signature.';

-- NOT VALID on purpose: every vote cast from here on must carry its nonce, and
-- votes recorded before this migration are not retroactively invented one. They
-- keep the only honest description available -- a vote whose binding cannot be
-- rechecked -- and the tally refuses to count them rather than pretending.
ALTER TABLE votes ADD CONSTRAINT votes_nonce_required
    CHECK (nonce IS NOT NULL) NOT VALID;

-- A nonce that is present but empty would rebuild a digest that silently
-- differs from the one signed, which reads as tampering rather than as a
-- missing field.
ALTER TABLE votes ADD CONSTRAINT votes_nonce_nonempty
    CHECK (nonce IS NULL OR length(nonce) BETWEEN 8 AND 128) NOT VALID;
