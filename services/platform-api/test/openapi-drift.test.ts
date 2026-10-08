import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { buildApp } from '../src/app.ts';
import { loadConfig } from '../src/config.ts';
import { createContainer } from '../src/container.ts';

const specPath = fileURLToPath(new URL('../../../docs/api/openapi.yaml', import.meta.url));
const spec = parse(readFileSync(specPath, 'utf8')) as {
  paths: Record<string, Record<string, { security?: unknown[] }>>;
};
const METHODS = ['get', 'post', 'patch', 'put', 'delete'];

describe('OpenAPI ↔ implementation drift', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  afterEach(async () => app?.close());

  it('every implemented route is documented, and every documented route is implemented', async () => {
    const seen = new Set<string>();
    const c = await createContainer(loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv));
    app = await buildApp(c, {
      onRoute: (m, u) => {
        if (m !== 'HEAD' && m !== 'OPTIONS')
          seen.add(`${m.toLowerCase()} ${u.replace(/:(\w+)/g, '{$1}')}`);
      },
    });
    await app.ready();
    const documented = new Set<string>();
    for (const [path, item] of Object.entries(spec.paths)) {
      for (const m of Object.keys(item)) if (METHODS.includes(m)) documented.add(`${m} ${path}`);
    }
    expect(
      [...seen].filter((r) => !documented.has(r)).sort(),
      'implemented but undocumented',
    ).toEqual([]);
    expect(
      [...documented].filter((r) => !seen.has(r)).sort(),
      'documented but not implemented',
    ).toEqual([]);
    expect(seen.size).toBeGreaterThan(30);
  });

  it('only the intended routes are public (no security requirement)', () => {
    const open: string[] = [];
    for (const [path, item] of Object.entries(spec.paths)) {
      for (const [m, op] of Object.entries(item)) {
        if (METHODS.includes(m) && !(op.security && op.security.length)) open.push(`${m} ${path}`);
      }
    }
    expect(open.sort()).toEqual([
      'get /healthz',
      'get /v1/keys/trust-bundle',
      'post /v1/auth/login',
      'post /v1/auth/register',
      'post /v1/devices/challenges',
      'post /v1/licenses/deactivate',
      'post /v1/licenses/refresh',
      'post /v1/licenses/validate',
    ]);
  });

  it('every admin route is documented as authenticated', () => {
    for (const [path, item] of Object.entries(spec.paths)) {
      if (!path.startsWith('/v1/admin/')) continue;
      for (const [m, op] of Object.entries(item))
        if (METHODS.includes(m)) expect(op.security?.length, `${m} ${path}`).toBeGreaterThan(0);
    }
  });
});
