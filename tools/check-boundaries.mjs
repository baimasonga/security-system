#!/usr/bin/env node
// Enforces the architecture rules from docs/architecture/01-system-context.md mechanically:
//  1. packages may import only the workspace packages on their allow-list (acyclic by construction)
//  2. sdk-core (ships to untrusted clients) may import ONLY the verification entrypoint of crypto
//  3. shared-types (kernel) stays free of node:* imports
//  4. no private key material is committed
//  5. deployment templates contain no credentials
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

const ALLOWED = {
  'shared-types': [],
  crypto: ['shared-types'],
  audit: ['crypto', 'shared-types'],
  telemetry: ['crypto', 'shared-types'],
  entitlements: ['shared-types'],
  auth: ['audit', 'crypto', 'shared-types'],
  licensing: ['audit', 'crypto', 'entitlements', 'shared-types', 'telemetry'],
  sharing: ['audit', 'crypto', 'shared-types'],
  privileged: ['audit', 'crypto', 'shared-types'],
  'sdk-core': ['crypto/verify', 'shared-types'],
  'platform-api': [
    'audit',
    'auth',
    'crypto',
    'entitlements',
    'licensing',
    'privileged',
    'sdk-core',
    'sharing',
    'shared-types',
    'telemetry',
  ],
};

const errors = [];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git') continue;
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

// --- 1 & 2 & 3: import rules over production sources (src/), not tests ---------------------
const IMPORT = /(?:from\s+|import\s*\(\s*|import\s+)['"]([^'"]+)['"]/g;
for (const [pkg, allowed] of Object.entries(ALLOWED)) {
  const base =
    pkg === 'platform-api'
      ? join(root, 'services/platform-api/src')
      : join(root, 'packages', pkg, 'src');
  for (const file of walk(base).filter((f) => f.endsWith('.ts'))) {
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(IMPORT)) {
      const spec = m[1];
      const rel = relative(root, file);
      if (spec.startsWith('@trust/')) {
        const target = spec.slice('@trust/'.length); // e.g. crypto or crypto/verify
        // 'crypto' allows the package and any subpath; 'crypto/verify' allows exactly that entrypoint.
        const ok = allowed.some((a) =>
          a.includes('/') ? target === a : target === a || target.startsWith(a + '/'),
        );
        if (!ok)
          errors.push(
            `${rel}: ${pkg} may not import ${spec} (allowed: ${allowed.join(', ') || 'none'})`,
          );
      }
      if (pkg === 'shared-types' && spec.startsWith('node:'))
        errors.push(`${rel}: shared-types must stay free of node:* imports`);
    }
  }
}

// allow-list must itself be acyclic
(function checkAcyclic() {
  const edges = Object.fromEntries(
    Object.entries(ALLOWED).map(([k, v]) => [k, v.map((x) => x.split('/')[0])]),
  );
  const state = {};
  const visit = (n, path) => {
    if (state[n] === 2) return;
    if (state[n] === 1) {
      errors.push(`dependency cycle: ${[...path, n].join(' -> ')}`);
      return;
    }
    state[n] = 1;
    for (const d of edges[n] ?? []) visit(d, [...path, n]);
    state[n] = 2;
  };
  Object.keys(edges).forEach((n) => visit(n, []));
})();

// --- 4: private key material in the tree --------------------------------------------------
const PRIV = /-----BEGIN [A-Z ]{0,10}PRIVATE KEY-----/;
for (const f of walk(root)) {
  if (
    /\.(png|jpg|ico|zip)$/.test(f) ||
    f.endsWith('check-boundaries.mjs') ||
    f.includes('package-lock.json')
  )
    continue;
  let text;
  try {
    text = readFileSync(f, 'utf8');
  } catch {
    continue;
  }
  if (PRIV.test(text)) errors.push(`${relative(root, f)}: contains private key material`);
}

// --- 5: deployment templates never contain credentials ----------------------------------------
// docs/deploy/supabase-setup.sql is pasted into a SQL editor; the password is set in a separate statement. A password
// literal in the committed file would be a leaked credential in git history.
{
  const f = join(root, 'docs/deploy/supabase-setup.sql');
  const text = readFileSync(f, 'utf8');
  if (/PASSWORD\s+'/i.test(text))
    errors.push(
      'docs/deploy/supabase-setup.sql: contains a password literal; set the password in a separate statement, never in the file',
    );
}

if (errors.length) {
  console.error('Architecture boundary violations:\n' + errors.map((e) => ' - ' + e).join('\n'));
  process.exit(1);
}
console.log('boundaries ok');
