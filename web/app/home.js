import { h, page, REVOCATION_NOTE } from './ui.js';

const content = page('/', 'Universal Agent Identity',
  'A way to tell who an autonomous agent is, who answers for it, and what it did — ' +
  'and to check all three without asking us.');

const artefacts = [
  ['UAI-ID', 'A stable identifier for one agent, and the DID that resolves it. Allocated once, never reused.'],
  ['UAI Credential', 'What the agent is and who owns it, as W3C Verifiable Credentials. The ownership credential embeds the two registration signatures, so a relying party checks ownership from the document and the owner’s key alone.'],
  ['UAI Passport', 'Time-boxed, scoped authorisation to act across jurisdictions. Separate from identity, because suspending a passport must not invalidate a history.'],
  ['UAI Action Attestation', 'A signed statement that an identity claims to have performed an action, hash-chained to everything it did before.'],
];

content.append(
  h('div', { class: 'panel' },
    h('h2', {}, 'Four artefacts'),
    h('dl', { class: 'fields' },
      artefacts.map(([name, text]) =>
        h('div', { class: 'field' }, h('dt', {}, name), h('dd', {}, text))))),

  h('div', { class: 'panel' },
    h('h2', {}, 'What this can prove'),
    h('ul', {},
      h('li', {}, 'A statement existed at the time of a checkpoint, by inclusion proof.'),
      h('li', {}, 'The log has not been rewritten, by consistency proof.'),
      h('li', {}, 'Independent witnesses saw the same history, by co-signature.'),
      h('li', {}, 'The history is pinned where its operator cannot rewrite it, by anchor.'))),

  h('div', { class: 'panel' },
    h('h2', {}, 'What it cannot, and never claims'),
    h('ul', {},
      h('li', {}, 'That a statement is ', h('strong', {}, 'true'),
        '. The log records what was said, not what happened.'),
      h('li', {}, 'That nothing was ', h('strong', {}, 'withheld'),
        '. An actor that never submits an event leaves no trace; what is detectable is a gap in a chain.'),
      h('li', {}, 'That a signer was not coerced.')),
    h('p', { class: 'note' }, REVOCATION_NOTE)),

  h('div', { class: 'panel' },
    h('h2', {}, 'Check something'),
    h('p', {}, 'The ', h('a', { href: '/verify.html' }, 'verify page'),
      ' fetches public data and checks the proofs in your browser. It shows you the proofs, ' +
      'not our opinion of them.')),
);
