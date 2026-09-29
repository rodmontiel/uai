import { h, api, page, pill, when, field, shortDigest, errorBox } from './ui.js';

const content = page('/federation.html', 'Federation',
  'This registry as a UAI Autonomous Registry System, who it exchanges with, and what they have said.');

// The sentence this page exists to keep visible. A peers table beside an
// identities table reads, at a glance, as "these are our partners and these are
// their agents we trust" -- which is exactly the conflation the model forbids.
content.append(h('p', { class: 'note' },
  'Peering is not trust in agents. A configured peer may send this registry signed statements; ' +
  'nothing about that makes its identities usable here. Every row under Federated identities ' +
  'is another registry’s claim about its own agent, recorded as a claim.'));

const body = h('div', {}, h('p', { class: 'empty' }, 'Loading…'));
content.append(body);

function registryPanel(reg) {
  return h('div', { class: 'panel' },
    h('h2', {}, 'This registry'),
    h('dl', { class: 'fields' },
      field('UAI-AS', h('span', { class: 'mono' }, String(reg.uai_asn))),
      field('Registry', reg.name),
      field('Registry DID', reg.registry_did, { mono: true }),
      field('Status', pill(reg.status, reg.status === 'ACTIVE' ? 'ok' : 'warn')),
      field('Federation endpoint', reg.federation_endpoint, { mono: true }),
      field('Protocol', reg.protocol_version),
      field('Public key', shortDigest(reg.public_key && reg.public_key.x), { mono: true })));
}

function peersPanel(peers) {
  if (!peers.length) {
    return h('div', { class: 'panel' },
      h('h2', {}, 'Peers'),
      h('p', { class: 'empty' },
        'None configured. A peering is set up deliberately, by an operator holding this ' +
        'registry’s key — there is no discovery here, and that is the design.'));
  }
  const tone = (s) => (s === 'ACTIVE' ? 'ok' : s === 'ERROR' ? 'bad' : 'warn');
  return h('div', { class: 'panel' },
    h('h2', {}, `Peers (${peers.length})`),
    h('div', { class: 'scroll' },
      h('table', {},
        h('thead', {}, h('tr', {},
          h('th', {}, 'UAI-AS'), h('th', {}, 'Registry DID'), h('th', {}, 'Status'),
          h('th', {}, 'Endpoint'), h('th', {}, 'Last seen'))),
        h('tbody', {}, peers.map((p) => h('tr', {},
          h('td', { class: 'mono' }, `AS${p.remote_uai_asn}`),
          h('td', { class: 'mono' }, p.remote_registry_did),
          h('td', {}, pill(p.status, tone(p.status)),
            p.last_error ? h('div', { class: 'subtle' }, p.last_error) : null),
          h('td', { class: 'mono' }, p.remote_endpoint),
          h('td', {}, when(p.last_seen_at)))))) ));
}

function identitiesPanel(rows) {
  if (!rows.length) {
    return h('div', { class: 'panel' },
      h('h2', {}, 'Federated identities'),
      h('p', { class: 'empty' }, 'No peer has announced anything yet.'));
  }
  return h('div', { class: 'panel' },
    h('h2', {}, `Federated identities (${rows.length})`),
    h('p', { class: 'note' },
      'Not agents of this registry. They are not in the local identity tables, they hold no ' +
      'capabilities here, and this registry cannot revoke them — only the registry that ' +
      'issued them can say anything about them.'),
    h('div', { class: 'scroll' },
      h('table', {},
        h('thead', {}, h('tr', {},
          h('th', {}, 'Agent DID'), h('th', {}, 'Origin'), h('th', {}, 'Remote status'),
          h('th', {}, 'Signature'), h('th', {}, 'Seq'), h('th', {}, 'Last seen'))),
        h('tbody', {}, rows.map((f) => h('tr', {},
          h('td', { class: 'mono' }, f.agent_did),
          h('td', { class: 'mono' }, `AS${f.origin_uai_asn}`),
          h('td', {}, pill(f.remote_status, f.remote_status === 'REVOKED' ? 'bad' : 'neutral')),
          h('td', {}, pill(f.signature_status,
            f.signature_status === 'VERIFIED' ? 'ok' : 'warn')),
          h('td', { class: 'mono' }, String(f.last_sequence)),
          h('td', {}, when(f.last_seen_at)))))) ));
}

try {
  const { body: reg } = await api('/v1/federation/registry');
  const [{ body: peers }, { body: ids }] = await Promise.all([
    api('/v1/federation/peers'),
    api('/v1/federation/identities'),
  ]);
  body.replaceChildren(
    registryPanel(reg),
    peersPanel(peers.peers || []),
    identitiesPanel(ids.identities || []));
} catch (err) {
  // A registry with no ASN is not a broken registry. Saying "not configured"
  // where the error box would say "could not complete that" is the difference
  // between a state and a fault.
  if (err.status === 404) {
    body.replaceChildren(h('div', { class: 'panel' },
      h('h2', {}, 'Not federated'),
      h('p', {},
        'This registry has no UAI-AS number, so it belongs to no federation. That is a ' +
        'configuration, not a failure: an installation that was never given a number has ' +
        'not silently joined anything.'),
      h('p', { class: 'subtle mono' }, 'UAI_ASN, UAI_REGISTRY_NAME, UAI_FEDERATION_ENDPOINT')));
  } else {
    body.replaceChildren(errorBox(err));
  }
}
