import { h, api, page, field, pill, when, shortDigest, errorBox, REVOCATION_NOTE } from './ui.js';

const content = page('/verify.html', 'Agent passport',
  'What an identity is, who answers for it, and what it is authorised to do.');

const input = h('input', {
  type: 'text', placeholder: 'uai:agent:01JY8R9ZAF392N7QX2T81JH6KM',
  autocapitalize: 'off', spellcheck: 'false',
});
const submit = h('button', { type: 'submit' }, 'Load');
const results = h('div', {});
content.append(h('form', { class: 'search', onsubmit: onSubmit }, input, submit), results);

const params = new URLSearchParams(location.search);
if (params.get('id')) { input.value = params.get('id'); load(params.get('id')); }

function onSubmit(e) {
  e.preventDefault();
  const id = input.value.trim();
  if (!id) return;
  history.replaceState(null, '', `?id=${encodeURIComponent(id)}`);
  load(id);
}

const STATUS = {
  ACTIVE: 'ok', VERIFIED: 'ok', REGISTERED: 'info', UNBOUND: 'neutral',
  QUARANTINED: 'warn', REVOCATION_AUTHORIZED: 'warn', REVOKED: 'bad',
};

async function load(id) {
  results.replaceChildren(h('p', { class: 'empty' }, 'Loading…'));
  submit.disabled = true;
  try {
    const { body: agent } = await api(`/v1/agents/${encodeURIComponent(id)}`);
    let credentials = [];
    try {
      const { body } = await api(`/v1/agents/${encodeURIComponent(id)}/credentials`);
      credentials = body.credentials || [];
    } catch { /* an identity with no credentials is a state, not an error */ }

    const card = h('div', { class: 'panel' },
      h('h2', {}, agent.logical_name || 'Agent'),
      h('dl', { class: 'fields' },
        field('UAI-ID', h('span', { class: 'mono' }, agent.uai_id)),
        field('DID', h('span', { class: 'mono' }, agent.did)),
        field('Status', pill(agent.status, STATUS[agent.status] || 'neutral')),
        // Assurance says how strongly the IDENTITY was established. It says
        // nothing about whether the agent behaves well, and the label has to
        // make that impossible to misread.
        field('Assurance', h('span', {}, agent.assurance_level || '—',
          h('span', { class: 'detail' },
            ' — how strongly the identity was established, not how safe the agent is'))),
        field('Type', agent.agent_type),
        field('Version', agent.version),
        field('Jurisdiction', agent.primary_jurisdiction),
        field('Policy', agent.policy_version),
        field('Genesis', h('span', { class: 'mono' }, shortDigest(agent.genesis_event_hash))),
        field('Registered', when(agent.registered_at)),
      ));
    if (agent.status === 'REVOKED') card.append(h('p', { class: 'note' }, REVOCATION_NOTE));

    const creds = h('div', { class: 'panel' },
      h('h2', {}, `Credentials (${credentials.length})`));
    if (!credentials.length) {
      creds.append(h('p', { class: 'empty' }, 'None issued.'));
    } else {
      creds.append(h('div', { class: 'scroll' }, h('table', {},
        h('thead', {}, h('tr', {},
          h('th', {}, 'Type'), h('th', {}, 'Issuer'), h('th', {}, 'Valid from'), h('th', {}, 'Valid until'))),
        h('tbody', {}, credentials.map((c) => h('tr', {},
          h('td', {}, (c.type || []).slice(1).join(', ')),
          h('td', { class: 'mono' }, c.issuer || '—'),
          h('td', {}, when(c.validFrom)),
          // No expiry on an ownership credential is correct, not missing:
          // ownership holds until the agent is unbound, which is an event.
          h('td', {}, c.validUntil ? when(c.validUntil) : 'until unbound'),
        ))))));
    }

    results.replaceChildren(card, creds,
      h('p', {},
        h('a', { href: `/verify.html?id=${encodeURIComponent(agent.uai_id)}` }, 'Verify this identity →'),
        ' · ',
        h('a', { href: `/explorer.html?id=${encodeURIComponent(agent.uai_id)}` }, 'See what it did →')));
  } catch (err) {
    results.replaceChildren(errorBox(err));
  } finally {
    submit.disabled = false;
  }
}
