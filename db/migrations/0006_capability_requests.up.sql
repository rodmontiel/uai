-- 0006 · Capability requests (docs/protocol/15-api.md §22.9)
--
-- The MCP server exposes `uai_request_capability`, and §22.9 states the rule it
-- exists to respect: no tool grants capabilities. That rule is worth nothing as
-- prose in a handler, because the handler is exactly what an attacker who has
-- reached the process gets to influence. It is written here instead, as two
-- separate tables and a trigger, so that the shortest path from "an agent asked"
-- to "an agent may" crosses a party the agent is not.
--
-- A request is therefore a different object from a grant, in a different table,
-- with no state transition that turns one into the other.

BEGIN;

CREATE TYPE capability_request_state AS ENUM ('PENDING', 'APPROVED', 'DENIED', 'WITHDRAWN', 'EXPIRED');

CREATE TABLE capability_requests (
    id                text PRIMARY KEY,
    agent_id          text NOT NULL REFERENCES agents(id),
    owner_id          text NOT NULL REFERENCES owners(id),
    capability        text NOT NULL,
    -- Free text, required. An owner deciding out of band needs to know what the
    -- agent said it was for; a request with no stated purpose puts the owner in
    -- the position of approving a capability name.
    justification     text NOT NULL CHECK (length(justification) > 0),
    requested_purpose text,
    resource          text,
    state             capability_request_state NOT NULL DEFAULT 'PENDING',
    requested_by_did  uai_did NOT NULL,
    requested_at      timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    -- Filled only by the out-of-band approval path. The API has no route that
    -- writes them, which is the point: an approval carries an owner signature,
    -- and the agent cannot produce one.
    decided_by_did    uai_did,
    decided_at        timestamptz,
    decision_signature text,
    decision_note     text,
    CONSTRAINT capability_request_decided_is_attributable
        CHECK (state IN ('PENDING', 'WITHDRAWN', 'EXPIRED')
               OR (decided_by_did IS NOT NULL AND decided_at IS NOT NULL
                   AND decision_signature IS NOT NULL))
);

CREATE INDEX capability_requests_pending_idx
    ON capability_requests (owner_id, requested_at DESC)
    WHERE state = 'PENDING';

-- One live request per (agent, capability). Without it, an agent that is denied
-- can re-ask in a loop until an owner approves out of fatigue, which is a
-- social attack the database can simply refuse to host.
CREATE UNIQUE INDEX capability_requests_one_pending_uq
    ON capability_requests (agent_id, capability)
    WHERE state = 'PENDING';

-- ── an agent may not grant to itself ────────────────────────────────────────
--
-- This is the confused-deputy control (T-11/T-13) in its structural form. The
-- MCP server runs under the agent's identity; if the path from tool call to
-- capability_grants existed at all, every bug in that server would be a
-- privilege escalation. So the row is refused at the storage layer when the
-- grantor is the agent itself, and required to be a party that answers for it.
CREATE OR REPLACE FUNCTION uai_grant_by_another_party() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    agent_did   text;
    owner_did   text;
    org_did     text;
BEGIN
    SELECT a.did, o.did, org.did
      INTO agent_did, owner_did, org_did
      FROM agents a
      JOIN owners o ON o.id = a.owner_id
      LEFT JOIN organizations org ON org.id = a.organization_id
     WHERE a.id = NEW.agent_id;

    IF agent_did IS NULL THEN
        RAISE EXCEPTION 'capability grant for unknown agent %', NEW.agent_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF NEW.granted_by_did = agent_did THEN
        RAISE EXCEPTION 'an agent cannot grant itself a capability (agent %)', agent_did
            USING ERRCODE = 'check_violation',
                  HINT = 'A capability is granted by the owner or the organization, out of band.';
    END IF;

    IF NEW.granted_by_did <> owner_did AND (org_did IS NULL OR NEW.granted_by_did <> org_did) THEN
        RAISE EXCEPTION 'capability granted by %, who does not answer for agent %', NEW.granted_by_did, agent_did
            USING ERRCODE = 'check_violation',
                  HINT = 'granted_by_did must be the agent owner or its organization.';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER capability_grants_by_another_party
    BEFORE INSERT OR UPDATE ON capability_grants
    FOR EACH ROW EXECUTE FUNCTION uai_grant_by_another_party();

COMMIT;
