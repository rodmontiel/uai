import { h, api, page, field, pill, when, errorBox, REVOCATION_NOTE, shortDigest } from './ui.js';
import { checkChain, ed25519Available } from './verify.js';

const content = page('/verify.html', 'Verify an identity',
  'Enter a UAI-ID. This page fetches public data and checks the chain in your browser; ' +
  'the proofs are shown, not summarised.');

const input = h('input', {
  type: 'text', name: 'uai_id', placeholder: 'uai:agent:01JY8R9ZAF392N7QX2T81JH6KM',
  autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', required: true,
});
const submit = h('button', { type: 'submit' }, 'Verify');
const form = h('form', { class: 'search', onsubmit: onSubmit }, input, submit);
const results = h('div', {});
content.append(form, results);

const params = new URLSearchParams(location.search);
if (params.get('id')) { input.value = params.get('id'); run(params.get('id')); }

function onSubmit(e) {
  e.preventDefault();
  const id = input.value.trim();
  if (!id) return;
  history.replaceState(null, '', `?id=${encodeURIComponent(id)}`);
  run(id);
}

const TONE = {
  UAI_VERIFIED: 'ok', UAI_REGISTERED: 'info', UAI_UNVERIFIED: 'neutral',
  UAI_QUARANTINED: 'warn', UAI_REVOKED: 'bad',
};

async function run(id) {
  results.replaceChildren(h('p', { class: 'empty' }, 'Checking…'));
  submit.disabled = true;
  try {
    const { body: verdict } = await api(`/v1/verify/${encodeURIComponent(id)}`);
    const out = [renderVerdict(id, verdict)];

    // The API's answer is one input, shown as such. Everything below it is
    // checked here, so a reader can see which parts they had to take our word
    // for and which they did not.
    if (verdict.verified || verdict.revoked || verdict.quarantined) {
      out.push(await renderChain(id));
    }
    results.replaceChildren(...out);
  } catch (err) {
    results.replaceChildren(errorBox(err));
  } finally {
    submit.disabled = false;
  }
}

function renderVerdict(id, v) {
  const panel = h('div', { class: 'panel' },
    h('h2', {}, 'What the registry reports'),
    h('dl', { class: 'fields' },
      field('Identity', h('span', { class: 'mono' }, id)),
      field('Status', pill(v.status, TONE[v.status] || 'neutral')),
      field('As of', when(v.as_of)),
      // The level AND why it is not higher. The API sends both; showing only the
      // level leaves a bare "UAI-AL0", which is indistinguishable from a
      // misconfiguration and tells a reader nothing about what would change it.
      v.assurance_level
        ? field('Assurance', v.assurance_limited_by
          ? h('span', {}, v.assurance_level,
            h('span', { class: 'muted' }, ` — limited by ${v.assurance_limited_by}`),
            v.assurance_detail ? h('div', { class: 'muted' }, v.assurance_detail) : null)
          : v.assurance_level)
        : null,
      v.policy_version ? field('Policy', v.policy_version) : null,
    ));
  if (v.note) panel.append(h('p', { class: 'note' }, v.note));
  if (v.revoked) panel.append(h('p', { class: 'note' }, REVOCATION_NOTE));
  if (v.quarantined) {
    panel.append(h('p', { class: 'note' },
      'Quarantine is preventive, reversible and time-boxed. It is not a finding of fault.'));
  }
  panel.append(h('p', { class: 'note' },
    'This panel is the registry’s answer. The checks below are performed in your browser.'));
  return panel;
}

async function renderChain(id) {
  const panel = h('div', { class: 'panel' }, h('h2', {}, 'Checked in your browser'));
  try {
    const [{ body: agent }, { body: events }] = await Promise.all([
      api(`/v1/agents/${encodeURIComponent(id)}`),
      api(`/v1/agents/${encodeURIComponent(id)}/events?limit=200`),
    ]);
    const list = events.events || [];
    const checks = checkChain(list, agent.genesis_event_hash);

    if (!(await ed25519Available())) {
      checks.push({
        name: 'Signature checks', ok: null,
        detail: 'this browser does not expose Ed25519 to WebCrypto, so signatures could not be ' +
                'checked here. The chain check above still ran.',
      });
    }
    panel.append(renderChecks(checks));
    panel.append(h('p', { class: 'note' },
      `Genesis ${shortDigest(agent.genesis_event_hash)} · ${list.length} event(s) examined. ` +
      'A gap in this chain is what a deleted or never-submitted event looks like from outside.'));
    panel.append(h('p', {}, h('a', { href: `/explorer.html?id=${encodeURIComponent(id)}` },
      'Open the full timeline →')));
  } catch (err) {
    panel.append(errorBox(err));
  }
  return panel;
}

function renderChecks(checks) {
  return h('ul', { class: 'checks' },
    checks.map((c) => h('li', {},
      pill(c.ok === true ? 'holds' : c.ok === false ? 'fails' : 'not checked',
        c.ok === true ? 'ok' : c.ok === false ? 'bad' : 'neutral'),
      h('span', {}, c.name),
      c.detail ? h('span', { class: 'detail' }, c.detail) : null)));
}
