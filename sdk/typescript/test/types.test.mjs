// The declarations and the implementation must name the same things.
//
// `src/index.d.ts` is hand-written, because this package has no build step: what
// is published is what is in the repository. The cost is that the declarations
// can drift, so this test asserts the one kind of drift it can catch -- an
// export that exists on one side and not the other. It does not catch a changed
// signature, which is the honest limit of the approach.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import * as sdk from '../src/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, '..', 'src');

function declaredNames() {
  const text = readFileSync(join(SRC, 'index.d.ts'), 'utf8');
  const names = new Set();
  const pattern = /^export declare (?:async )?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)/gm;
  for (const match of text.matchAll(pattern)) names.add(match[1]);
  return names;
}

test('every runtime export has a declaration', () => {
  const declared = declaredNames();
  const missing = Object.keys(sdk).filter((name) => !declared.has(name));
  assert.deepEqual(missing, [], `declared in index.js but not in index.d.ts: ${missing}`);
});

test('every declaration has a runtime export', () => {
  const runtime = new Set(Object.keys(sdk));
  const orphans = [...declaredNames()].filter((name) => !runtime.has(name));
  assert.deepEqual(orphans, [], `declared in index.d.ts but not exported: ${orphans}`);
});

// The package must stay dependency-free. It holds the agent's signing key, so
// every dependency here is a dependency that could sign on the agent's behalf
// (T-07) -- and Node supplies everything this needs.
test('the package has no dependencies', () => {
  const manifest = JSON.parse(readFileSync(join(SRC, '..', 'package.json'), 'utf8'));
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    assert.deepEqual(manifest[field] ?? {}, {},
      `${field} is not empty; this package must stay dependency-free`);
  }
});

// Nothing outside node: may be imported. A bare specifier would be a dependency
// the manifest does not declare.
test('nothing outside node: builtins is imported', () => {
  for (const file of readdirSync(SRC).filter((f) => f.endsWith('.js'))) {
    // Comments are stripped first: the module docs contain example imports, and
    // a check that read those would be checking the prose rather than the code.
    const text = readFileSync(join(SRC, file), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    for (const match of text.matchAll(/from\s+'([^']+)'|import\('([^']+)'\)/g)) {
      const specifier = match[1] ?? match[2];
      const allowed = specifier.startsWith('node:') || specifier.startsWith('./') ||
        specifier.startsWith('../');
      assert.ok(allowed, `${file} imports ${specifier}, which is not a node: builtin or a local file`);
    }
  }
});
