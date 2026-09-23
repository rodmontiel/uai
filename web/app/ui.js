// Shared UI helpers. No framework, no build step: what is served is what is in
// the repository, which is the property the verify page needs most.

/** Create an element with attributes and children. */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    // Strings become text nodes, never markup. Every value on these pages comes
    // from an API that returns data written by other parties, and innerHTML
    // would make a logical_name an injection point.
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

/** Fetch JSON from the API, surfacing RFC 9457 problem documents as errors. */
export async function api(path, options = {}) {
  const res = await fetch(path, { headers: { accept: 'application/json' }, ...options });
  const text = await res.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { /* handled below */ }
  if (!res.ok) {
    const problem = body && body.title
      ? `${body.title}: ${body.detail || ''}`
      : `HTTP ${res.status}`;
    const err = new Error(problem.trim());
    err.problem = body;
    err.status = res.status;
    throw err;
  }
  if (body === null) throw new Error('the API returned something that is not JSON');
  return { body, raw: text };
}

/** Render the shared navigation. */
export function nav(current) {
  const links = [
    ['/', 'Home'],
    ['/verify.html', 'Verify'],
    ['/agent.html', 'Passport'],
    ['/explorer.html', 'Explorer'],
    ['/quarantine.html', 'Quarantine'],
    ['/governance.html', 'Governance'],
  ];
  return h('nav', { class: 'nav' },
    h('a', { class: 'brand', href: '/' }, 'UAI'),
    h('div', { class: 'links' },
      links.map(([href, label]) =>
        h('a', { href, class: href === current ? 'active' : null }, label))),
  );
}

/** A labelled value in a definition list. */
export function field(label, value, extra = {}) {
  return h('div', { class: 'field ' + (extra.class || '') },
    h('dt', {}, label),
    h('dd', { class: extra.mono ? 'mono' : null }, value === '' || value === null || value === undefined ? '—' : value));
}

/** A status pill. Colour carries no meaning on its own — the text always does. */
export function pill(text, tone = 'neutral') {
  return h('span', { class: `pill ${tone}` }, text);
}

/** Format an ISO timestamp for display, keeping UTC explicit. */
export function when(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

/** Shorten a digest for display without hiding that it was shortened. */
export function shortDigest(d) {
  if (!d) return '—';
  const hex = d.startsWith('sha256:') ? d.slice(7) : d;
  return hex.length > 20 ? `${hex.slice(0, 10)}…${hex.slice(-6)}` : hex;
}

/** Mount a page: nav, a heading, and a container the page fills in. */
export function page(current, title, subtitle) {
  document.body.append(
    nav(current),
    h('main', { class: 'main' },
      h('header', { class: 'page-head' },
        h('h1', {}, title),
        subtitle ? h('p', { class: 'subtitle' }, subtitle) : null),
      h('div', { id: 'content' })),
  );
  return document.getElementById('content');
}

/** Render an error the way a refusal should read: what happened, not a stack. */
export function errorBox(err) {
  const box = h('div', { class: 'error' }, h('strong', {}, 'Could not complete that.'), ' ', err.message);
  if (err.problem && err.problem.remediation) {
    box.append(h('p', { class: 'remediation' }, err.problem.remediation));
  }
  return box;
}

/** The sentence this product must never contradict (project rule 2). */
export const REVOCATION_NOTE =
  'Revocation means UAI participants stop honouring this identity’s credentials. ' +
  'It is not a switch that stops software from running, and no protocol could be.';
