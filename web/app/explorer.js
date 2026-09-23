import { h, api, page, field, pill, when, shortDigest, errorBox } from './ui.js';
import { checkChain } from './verify.js';

const content = page('/explorer.html', 'Action explorer',
  'Every attested action of one identity, in the order the chain says they happened.');

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

const OUTCOME = { SUCCESS: 'ok', FAILURE: 'bad', PARTIAL: 'warn', ABORTED_BY_POLICY: 'warn' };

async function load(id) {
  results.replaceChildren(h('p', { class: 'empty' }, 'Loading…'));
  submit.disabled = true;
  try {
    const [{ body: agent }, { body: page_ }] = await Promise.all([
      api(`/v1/agents/${encodeURIComponent(id)}`),
      api(`/v1/agents/${encodeURIComponent(id)}/events?limit=200`),
    ]);
    const events = page_.events || [];
    const [chain] = checkChain(events, agent.genesis_event_hash);

    const header = h('div', { class: 'panel' },
      h('h2', {}, 'Identity'),
      h('dl', { class: 'fields' },
        field('UAI-ID', h('span', { class: 'mono' }, agent.uai_id)),
        field('Status', pill(agent.status, agent.status === 'ACTIVE' ? 'ok' : 'neutral')),
        field('Chain', pill(chain.ok ? 'unbroken' : 'broken', chain.ok ? 'ok' : 'bad')),
        field('Genesis', h('span', { class: 'mono' }, shortDigest(agent.genesis_event_hash))),
      ),
      h('p', { class: 'note' }, chain.detail));

    if (!events.length) {
      results.replaceChildren(header, h('p', { class: 'empty' },
        'This identity has attested no actions. That is not evidence that it did nothing: ' +
        'an actor that never submits an event leaves no trace, which is a limit this system ' +
        'states rather than hides.'));
      return;
    }

    const rows = events.map((ev) => h('tr', {},
      h('td', {}, String(ev.sequence)),
      h('td', {}, ev.action_type || '—'),
      h('td', {}, pill(ev.outcome, OUTCOME[ev.outcome] || 'neutral')),
      h('td', { class: 'mono' }, shortDigest(ev.previous_event_hash)),
      h('td', { class: 'mono' }, shortDigest(ev.event_hash)),
      h('td', {}, when(ev.asserted_at)),
    ));
    results.replaceChildren(header,
      h('div', { class: 'panel' },
        h('h2', {}, `${events.length} attested action(s)`),
        h('div', { class: 'scroll' },
          h('table', {},
            h('thead', {}, h('tr', {},
              h('th', {}, '#'), h('th', {}, 'Action'), h('th', {}, 'Outcome'),
              h('th', {}, 'Links to'), h('th', {}, 'Hash'), h('th', {}, 'Asserted at'))),
            h('tbody', {}, rows))),
        h('p', { class: 'note' },
          'Asserted at is what the agent said. It is untrusted input: the log’s ordering is ' +
          'the authority, and a large divergence between the two is itself a signal.')));
  } catch (err) {
    results.replaceChildren(errorBox(err));
  } finally {
    submit.disabled = false;
  }
}
