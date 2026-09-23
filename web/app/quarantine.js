import { h, api, page, pill, when, errorBox } from './ui.js';

const content = page('/quarantine.html', 'Quarantine centre',
  'Preventive, reversible and time-boxed restrictions in force right now.');

content.append(h('p', { class: 'note' },
  'A quarantine is not a finding of fault and must not be read as one. Each order lapses on ' +
  'its own at its expiry unless a case advances — a preventive measure that outlived its ' +
  'window would be punishment by inertia.'));

const results = h('div', {}, h('p', { class: 'empty' }, 'Loading…'));
content.append(results);

try {
  const { body } = await api('/v1/quarantines');
  const orders = body.quarantines || [];
  if (!orders.length) {
    results.replaceChildren(h('p', { class: 'empty' }, 'No identities are under quarantine.'));
  } else {
    results.replaceChildren(h('div', { class: 'panel' },
      h('h2', {}, `${orders.length} active order(s)`),
      h('div', { class: 'scroll' },
        h('table', {},
          h('thead', {}, h('tr', {},
            h('th', {}, 'Identity'), h('th', {}, 'Category'), h('th', {}, 'Suspended'),
            h('th', {}, 'Retained'), h('th', {}, 'Review by'), h('th', {}, 'Lapses'))),
          h('tbody', {}, orders.map((q) => h('tr', {},
            h('td', { class: 'mono' },
              h('a', { href: `/verify.html?id=${encodeURIComponent(q.uai_id)}` }, q.uai_id)),
            h('td', {}, pill(q.reason_category, 'warn')),
            // Both lists are shown. Naming only what was taken away would let a
            // reader assume everything else was taken away too.
            h('td', {}, (q.capabilities_suspended || []).join(', ') || '—'),
            h('td', {}, (q.capabilities_retained || []).join(', ') || 'none stated'),
            h('td', {}, when(q.review_by)),
            h('td', {}, when(q.expires_at)),
          )))))));
  }
} catch (err) {
  results.replaceChildren(errorBox(err));
}
