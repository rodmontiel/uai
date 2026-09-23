import { h, api, page, pill, when, errorBox, REVOCATION_NOTE } from './ui.js';

const content = page('/governance.html', 'Governance',
  'Proposals before the delegate assembly, with their live tallies.');

const results = h('div', {}, h('p', { class: 'empty' }, 'Loading…'));
content.append(results);

const STATE = { DRAFT: 'neutral', VOTING: 'info', AUTHORIZED: 'warn', REJECTED: 'neutral', CLOSED: 'neutral' };

try {
  const { body } = await api('/v1/governance/proposals');
  const proposals = body.proposals || [];
  const panels = [];

  if (!proposals.length) {
    panels.push(h('p', { class: 'empty' }, 'No proposals have been opened.'));
  } else {
    panels.push(h('div', { class: 'panel' },
      h('h2', {}, `${proposals.length} proposal(s)`),
      h('div', { class: 'scroll' },
        h('table', {},
          h('thead', {}, h('tr', {},
            h('th', {}, 'Proposal'), h('th', {}, 'Subject'), h('th', {}, 'Kind'),
            h('th', {}, 'State'), h('th', {}, 'Threshold'), h('th', {}, 'Yes / No'),
            h('th', {}, 'Countries'), h('th', {}, 'Closes'))),
          h('tbody', {}, proposals.map((p) => h('tr', {},
            h('td', { class: 'mono' }, p.id),
            h('td', { class: 'mono' },
              h('a', { href: `/verify.html?id=${encodeURIComponent(p.uai_id)}` }, p.uai_id)),
            h('td', {}, p.kind),
            h('td', {}, pill(p.state, STATE[p.state] || 'neutral')),
            // The threshold is the one captured when the proposal opened, which
            // is what stops a quorum being moved under a vote in progress.
            h('td', {}, p.threshold),
            h('td', {}, `${p.votes_yes} / ${p.votes_no}`),
            h('td', {}, String(p.countries_in_favour)),
            h('td', {}, when(p.closes_at)),
          ))))),
      h('p', { class: 'note' },
        'A quorum drawn from one jurisdiction is refused on chain: several countries must be ' +
        'represented, which is what stops one government — or one operator holding several ' +
        'delegates — from revoking alone.')));
  }

  panels.push(h('div', { class: 'panel' },
    h('h2', {}, 'How a vote is cast'),
    h('p', {},
      'A delegate signs with a hardware authenticator, and the WebAuthn challenge ',
      h('strong', {}, 'is'),
      ' the vote digest. A compromised web page cannot alter what was voted without ' +
      'invalidating the assertion, and a delegate can compute the digest independently to ' +
      'check what they are being asked to sign.'),
    h('p', { class: 'note' }, REVOCATION_NOTE)));

  results.replaceChildren(...panels);
} catch (err) {
  results.replaceChildren(errorBox(err));
}
