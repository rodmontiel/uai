-- Say, at the column, that it carries nothing.
--
-- `selectors` has existed since 0001 and has never been written: nothing in the
-- Go code fills it. A reader running \d+ or querying it finds an empty jsonb and
-- concludes "no selectors were used", which is a different statement from "we
-- never recorded them" -- and the difference matters, because the selector is
-- the only thing that says WHAT the attestor checked.
--
-- A runtime attested on `unix:uid:1000` (any process of that user) and one
-- attested on an image digest produce the same row here. The SPIFFE ID is a
-- NAME; the selector is the evidence behind it, and the evidence is what a
-- relying party would need to judge the name. §20.5 records this as a control
-- that does not exist.
COMMENT ON COLUMN runtime_identities.selectors IS
    'ALWAYS EMPTY as of 0009. The attestation selectors are known to the SPIRE '
    'server and never reach this registry, so this records no evidence about '
    'what the attestor checked. Empty here means "not recorded", not "none '
    'used". See threat model §20.5.';

COMMENT ON COLUMN runtime_identities.image_digest IS
    'The AGENT''s claim about its own code, not the attestor''s observation. '
    '§6.8 wants the second; until a selector supplies it the runtime dimension '
    'stops at AL1. See threat model §20.5.';

COMMENT ON COLUMN runtime_identities.spiffe_id IS
    'Read off the X509-SVID presented as a client certificate, never off the '
    'request body, whenever a trust bundle is configured (§9.1).';
