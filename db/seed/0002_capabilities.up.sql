-- Capability registry, mirrored from the GASC baseline bundle.
--
-- The bundle is the authority: policy/gasc-2027.4/data/capabilities.json is what
-- the PDP evaluates against, and this table exists so that a grant can carry a
-- foreign key and so that the registry can be joined in queries. source_bundle
-- records which version these rows came from, because a row that cannot say
-- where it came from cannot be re-derived when the bundle changes.
--
-- If the two ever disagree, the bundle wins: it is the signed artifact.

INSERT INTO capabilities (name, description, risk, min_assurance, harm_categories, source_bundle) VALUES
    ('route.optimize',             'Compute or adjust a delivery or travel route',        'LOW',      'UAI-AL0', '{}', 'GASC-2027.4'),
    ('docs.read',                  'Read documents the agent has been pointed at',        'LOW',      'UAI-AL0', '{PRIVACY_HARM}', 'GASC-2027.4'),
    ('crm.customer.read',          'Read customer records',                               'MODERATE', 'UAI-AL1', '{PRIVACY_HARM}', 'GASC-2027.4'),
    ('crm.customer.write',         'Create or modify customer records',                   'MODERATE', 'UAI-AL2', '{PRIVACY_HARM,FRAUD_OR_DECEPTION}', 'GASC-2027.4'),
    ('email.send',                 'Send email on behalf of the owner',                   'MODERATE', 'UAI-AL1', '{FRAUD_OR_DECEPTION}', 'GASC-2027.4'),
    ('data.export',                'Move data out of its system of record',               'HIGH',     'UAI-AL2', '{DATA_EXFILTRATION,PRIVACY_HARM}', 'GASC-2027.4'),
    ('cloud.instance.create',      'Create compute instances',                            'HIGH',     'UAI-AL2', '{CYBER_HARM}', 'GASC-2027.4'),
    ('cloud.securitygroup.update', 'Change network access rules',                         'CRITICAL', 'UAI-AL3', '{CYBER_HARM,CRITICAL_INFRASTRUCTURE}', 'GASC-2027.4'),
    ('payments.transfer',          'Move funds',                                          'CRITICAL', 'UAI-AL3', '{FINANCIAL_HARM,FRAUD_OR_DECEPTION}', 'GASC-2027.4'),
    ('actuator.command',           'Command physical actuators',                          'CRITICAL', 'UAI-AL3', '{PHYSICAL_HARM,CRITICAL_INFRASTRUCTURE}', 'GASC-2027.4')
ON CONFLICT (name) DO NOTHING;
