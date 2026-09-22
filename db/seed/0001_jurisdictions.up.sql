-- Development bootstrap: jurisdictions.
--
-- This file is a BOOTSTRAP, not the authoritative registry. Per
-- docs/protocol/14-database.md section 21.7, jurisdiction data -- which regions
-- exist, which are restricted, which treaty groupings apply -- is generated
-- from the signed GASC policy bundle so that the database and the policy in
-- force cannot drift. That bundle arrives in Phase 6.
--
-- Until then this seed exists so the foreign keys have something to point at in
-- development. It carries NO restriction flags: marking a jurisdiction
-- restricted is a policy decision, and policy decisions do not belong in a
-- hand-written migration.

BEGIN;

INSERT INTO jurisdictions (code, name, groupings, is_restricted, source_bundle) VALUES
    ('AR', 'Argentina',              ARRAY['MERCOSUR','G20'],   false, 'bootstrap'),
    ('AT', 'Austria',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('AU', 'Australia',              ARRAY['G20'],              false, 'bootstrap'),
    ('BE', 'Belgium',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('BR', 'Brazil',                 ARRAY['MERCOSUR','G20'],   false, 'bootstrap'),
    ('CA', 'Canada',                 ARRAY['G20'],              false, 'bootstrap'),
    ('CH', 'Switzerland',            ARRAY['EFTA'],             false, 'bootstrap'),
    ('CL', 'Chile',                  ARRAY[]::text[],           false, 'bootstrap'),
    ('CN', 'China',                  ARRAY['G20'],              false, 'bootstrap'),
    ('CO', 'Colombia',               ARRAY[]::text[],           false, 'bootstrap'),
    ('CZ', 'Czechia',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('DE', 'Germany',                ARRAY['EU','EEA','G20'],   false, 'bootstrap'),
    ('DK', 'Denmark',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('EE', 'Estonia',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('ES', 'Spain',                  ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('FI', 'Finland',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('FR', 'France',                 ARRAY['EU','EEA','G20'],   false, 'bootstrap'),
    ('GB', 'United Kingdom',         ARRAY['G20'],              false, 'bootstrap'),
    ('GR', 'Greece',                 ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('HU', 'Hungary',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('ID', 'Indonesia',              ARRAY['G20','ASEAN'],      false, 'bootstrap'),
    ('IE', 'Ireland',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('IL', 'Israel',                 ARRAY[]::text[],           false, 'bootstrap'),
    ('IN', 'India',                  ARRAY['G20'],              false, 'bootstrap'),
    ('IS', 'Iceland',                ARRAY['EEA','EFTA'],       false, 'bootstrap'),
    ('IT', 'Italy',                  ARRAY['EU','EEA','G20'],   false, 'bootstrap'),
    ('JP', 'Japan',                  ARRAY['G20'],              false, 'bootstrap'),
    ('KE', 'Kenya',                  ARRAY[]::text[],           false, 'bootstrap'),
    ('KR', 'Korea, Republic of',     ARRAY['G20'],              false, 'bootstrap'),
    ('LT', 'Lithuania',              ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('LU', 'Luxembourg',             ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('LV', 'Latvia',                 ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('MX', 'Mexico',                 ARRAY['G20'],              false, 'bootstrap'),
    ('MY', 'Malaysia',               ARRAY['ASEAN'],            false, 'bootstrap'),
    ('NG', 'Nigeria',                ARRAY[]::text[],           false, 'bootstrap'),
    ('NL', 'Netherlands',            ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('NO', 'Norway',                 ARRAY['EEA','EFTA'],       false, 'bootstrap'),
    ('NZ', 'New Zealand',            ARRAY[]::text[],           false, 'bootstrap'),
    ('PE', 'Peru',                   ARRAY[]::text[],           false, 'bootstrap'),
    ('PH', 'Philippines',            ARRAY['ASEAN'],            false, 'bootstrap'),
    ('PL', 'Poland',                 ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('PT', 'Portugal',               ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('RO', 'Romania',                ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('SA', 'Saudi Arabia',           ARRAY['G20'],              false, 'bootstrap'),
    ('SE', 'Sweden',                 ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('SG', 'Singapore',              ARRAY['ASEAN'],            false, 'bootstrap'),
    ('SI', 'Slovenia',               ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('SK', 'Slovakia',               ARRAY['EU','EEA'],         false, 'bootstrap'),
    ('TH', 'Thailand',               ARRAY['ASEAN'],            false, 'bootstrap'),
    ('TR', 'Turkey',                 ARRAY['G20'],              false, 'bootstrap'),
    ('TW', 'Taiwan',                 ARRAY[]::text[],           false, 'bootstrap'),
    ('UA', 'Ukraine',                ARRAY[]::text[],           false, 'bootstrap'),
    ('US', 'United States',          ARRAY['G20'],              false, 'bootstrap'),
    ('UY', 'Uruguay',                ARRAY['MERCOSUR'],         false, 'bootstrap'),
    ('VN', 'Viet Nam',               ARRAY['ASEAN'],            false, 'bootstrap'),
    ('ZA', 'South Africa',           ARRAY['G20'],              false, 'bootstrap')
ON CONFLICT (code) DO NOTHING;

COMMIT;
