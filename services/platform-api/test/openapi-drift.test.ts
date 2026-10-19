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
    expect(open.sort()).toEqual(
      [
        'get /',
        'get /checkout',
        'get /checkout.mjs',
        'get /v1/billing/checkout-options',
        'get /device.mjs',
        'get /healthz',
        'get /rokela-icon.png',
        'get /portal.css',
        'get /portal.mjs',
        'get /v1/auth/options',
        'get /v1/keys/trust-bundle',
        'post /v1/auth/login',
        'post /v1/auth/passkeys/login/begin',
        'post /v1/auth/passkeys/login/finish',
        'post /v1/billing/webhooks/paddle',
        'post /v1/auth/register',
        'post /v1/auth/password/request',
        'post /v1/auth/password/reset',
        'post /v1/auth/email/verify',
        'post /v1/devices/challenges',
        'post /v1/licenses/deactivate',
        'post /v1/licenses/refresh',
        'post /v1/capabilities/token',
        'post /v1/licenses/validate',
        // File sharing (ADR-021): public pages and endpoints authorize by unpredictable token, grant or
        // submission secret, and accept an optional session for restricted recipients.
        'get /s/{token}',
        'get /r/{token}',
        'get /l/{code}',
        'get /d/{code}',
        'get /files.mjs',
        'get /uploader.mjs',
        'get /share.mjs',
        'get /request.mjs',
        'get /link.mjs',
        'get /public.mjs',
        'post /v1/public/short-links/{code}/unlock',
        'post /v1/public/shares/{token}/open',
        'post /v1/public/shares/{token}/files/url',
        'post /v1/public/shares/{token}/acknowledge',
        'get /v1/public/shares/{token}/comments',
        'post /v1/public/shares/{token}/comments',
        'post /v1/public/shares/{token}/review',
        'post /v1/public/upload-requests/{token}/open',
        'post /v1/public/upload-requests/{token}/submissions',
        'get /v1/public/upload-requests/{token}/submission',
        'post /v1/public/upload-requests/{token}/submission/submit',
        'post /v1/public/upload-requests/{token}/uploads',
        'post /v1/public/upload-requests/{token}/uploads/{uploadId}/parts',
        'get /v1/public/upload-requests/{token}/uploads/{uploadId}',
        'post /v1/public/upload-requests/{token}/uploads/{uploadId}/complete',
        'post /v1/public/upload-requests/{token}/uploads/{uploadId}/abort',
        'post /v1/public/abuse-reports',
      ].sort(),
    );
  });

  it('every admin route is documented as authenticated', () => {
    for (const [path, item] of Object.entries(spec.paths)) {
      if (!path.startsWith('/v1/admin/')) continue;
      for (const [m, op] of Object.entries(item))
        if (METHODS.includes(m)) expect(op.security?.length, `${m} ${path}`).toBeGreaterThan(0);
    }
  });
});
