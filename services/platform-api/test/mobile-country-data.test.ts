import { afterEach, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { prepareCountry } from '../../../tools/prepare-mobile-country.ts';
import {
  createCountryLookup,
  railwayCountrySourceEnabled,
  railwayClientIp,
  WARRIOR_PUBLIC_DOMAIN,
} from '../src/integrations/mobile-country.ts';
import { countryFixture } from './country-fixture.ts';
import { loadConfig } from '../src/config.ts';
import { makeEnv } from './harness.ts';

const directories: string[] = [];
const now = new Date('2026-10-26T00:00:00Z');
const directory = async () => {
  const path = await mkdtemp(join(tmpdir(), 'country-test-'));
  directories.push(path);
  return path;
};
afterEach(async () => {
  for (const path of directories.splice(0)) await rm(path, { recursive: true, force: true });
});
const response = (bytes = countryFixture()) => new Response(gzipSync(bytes));
it('downloads only the fixed edition, validates a real MMDB and writes provenance', async () => {
  const dir = await directory();
  const calls: unknown[] = [];
  const result = await prepareCountry(
    dir,
    '2026-10',
    async (url, options) => {
      calls.push([url, options?.redirect, options?.credentials]);
      return response();
    },
    now,
  );
  expect(calls).toEqual([
    ['https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz', 'error', 'omit'],
  ]);
  expect(result.sha256).toMatch(/^[a-f0-9]{64}$/);
  expect(JSON.parse(await readFile(join(dir, 'mobile-country.json'), 'utf8'))).toEqual(result);
  const lookup = createCountryLookup(join(dir, 'mobile-country.mmdb'), () => now);
  expect(await lookup.status()).toEqual({ state: 'ready', built_at: '2026-10-01T00:00:00.000Z' });
  expect(await lookup('8.8.8.8')).toBe('US');
  expect(await lookup('invalid')).toBeNull();
});
it('rejects arbitrary editions, HTTP failures, redirects and corrupt or stale databases', async () => {
  const dir = await directory();
  let called = false;
  await expect(
    prepareCountry(
      dir,
      '../../private',
      async () => {
        called = true;
        return response();
      },
      now,
    ),
  ).rejects.toThrow();
  expect(called).toBe(false);
  for (const request of [
    async () => new Response('no', { status: 503 }),
    async () => new Response(null, { status: 302 }),
    async () => response(Buffer.from('not a database')),
    async () => response(countryFixture(new Date('2025-10-01T00:00:00Z'))),
    async () => {
      const r = response();
      Object.defineProperty(r, 'redirected', { value: true });
      return r;
    },
  ])
    await expect(prepareCountry(dir, '2026-10', request, now)).rejects.toThrow();
  await expect(readFile(join(dir, 'mobile-country.mmdb'))).rejects.toThrow();
  for (const edition of ['2026-01', '2027-01'])
    await expect(
      prepareCountry(
        dir,
        edition,
        async () => response(countryFixture(new Date(`${edition}-01`))),
        now,
      ),
    ).rejects.toThrow();
});

it('aborts a stalled download and optional CLI failure leaves no stale artifact', async () => {
  const dir = await directory();
  await expect(
    prepareCountry(
      dir,
      '2026-10',
      async (_url, options) =>
        new Promise<Response>((_resolve, reject) => {
          options?.signal?.addEventListener('abort', () => reject(new Error('aborted')), {
            once: true,
          });
        }),
      now,
      10,
    ),
  ).rejects.toThrow('aborted');
  await writeFile(join(dir, 'mobile-country.mmdb'), countryFixture());
  await writeFile(join(dir, 'mobile-country.json'), '{}');
  const output = execFileSync(
    process.execPath,
    [
      fileURLToPath(new URL('../../../tools/prepare-mobile-country.ts', import.meta.url)),
      dir,
      'invalid',
      '--optional',
    ],
    { encoding: 'utf8', timeout: 10000 },
  );
  expect(output).toContain('runtime will report unknown country');
  await expect(readFile(join(dir, 'mobile-country.mmdb'))).rejects.toThrow();
  await expect(readFile(join(dir, 'mobile-country.json'))).rejects.toThrow();
});
it('bounds advertised, streamed and decompressed bodies', async () => {
  const dir = await directory();
  await expect(
    prepareCountry(
      dir,
      '2026-10',
      async () => new Response('x', { headers: { 'content-length': String(17 * 1024 * 1024) } }),
      now,
    ),
  ).rejects.toThrow('too large');
  await expect(
    prepareCountry(dir, '2026-10', async () => new Response(Buffer.alloc(17 * 1024 * 1024)), now),
  ).rejects.toThrow('too large');
  await expect(
    prepareCountry(
      dir,
      '2026-10',
      async () => response(Buffer.concat([countryFixture(), Buffer.alloc(65 * 1024 * 1024)])),
      now,
    ),
  ).rejects.toThrow();
});
it('reports absent, broken, expired and future data without leaking paths or inferring country', async () => {
  expect(await createCountryLookup().status()).toEqual({ state: 'not_configured', built_at: null });
  const file = join(await directory(), 'private-path.mmdb');
  const missing = createCountryLookup(file, () => now);
  expect(await missing.status()).toEqual({ state: 'unavailable', built_at: null });
  expect(await missing('8.8.8.8')).toBeNull();
  for (const [built, state] of [
    ['2025-01-01', 'stale'],
    ['2027-01-01', 'unavailable'],
  ] as const) {
    await writeFile(file, countryFixture(new Date(built)));
    const lookup = createCountryLookup(file, () => now);
    expect((await lookup.status()).state).toBe(state);
    expect(await lookup('8.8.8.8')).toBeNull();
  }
});

const railwayEnvironment = {
  NODE_ENV: 'test',
  MOBILE_USE_RAILWAY_IP: '1',
  RAILWAY_PUBLIC_DOMAIN: WARRIOR_PUBLIC_DOMAIN,
  RAILWAY_SERVICE_ID: '65ed934a-51a6-428a-8ba6-95f8f3bd6a18',
  RAILWAY_PROJECT_ID: '05a9a91d-5099-4e32-897e-d882b9367ef2',
  RAILWAY_ENVIRONMENT_ID: '1e6c985f-6089-403c-a2b1-d80b6dedd357',
};
it('enables the Railway source only for the exact deployment and rejects ambiguous headers', () => {
  expect(railwayCountrySourceEnabled(railwayEnvironment)).toBe(true);
  for (const key of Object.keys(railwayEnvironment).filter((k) => k !== 'NODE_ENV'))
    expect(railwayCountrySourceEnabled({ ...railwayEnvironment, [key]: 'other' })).toBe(false);
  expect(railwayCountrySourceEnabled({})).toBe(false);
  expect(
    railwayClientIp({
      host: WARRIOR_PUBLIC_DOMAIN,
      'x-real-ip': '8.8.8.8',
      'x-forwarded-for': '1.1.1.1',
    }),
  ).toBe('8.8.8.8');
  for (const headers of [
    { host: 'other', 'x-real-ip': '8.8.8.8' },
    { host: WARRIOR_PUBLIC_DOMAIN, 'x-forwarded-for': '8.8.8.8' },
    { host: WARRIOR_PUBLIC_DOMAIN, 'x-real-ip': '8.8.8.8, 1.1.1.1' },
    { host: WARRIOR_PUBLIC_DOMAIN, 'x-real-ip': ['8.8.8.8'] },
  ])
    expect(railwayClientIp(headers)).toBe('');
});
it('connects the GitHub deployment settings, actual local database, ingestion and operator readiness', async () => {
  const file = join(await directory(), 'country.mmdb');
  await writeFile(file, countryFixture(new Date()));
  const env = await makeEnv({
    config: {
      mobileRailwayIp: loadConfig(railwayEnvironment).mobileRailwayIp,
      mobileCountryDatabase: file,
    },
  });
  try {
    for (let n = 0; n < 7; n++) {
      const headers: Record<string, string> = {
        host: WARRIOR_PUBLIC_DOMAIN,
        'x-real-ip': '8.8.8.8',
        'x-forwarded-for': '1.1.1.1',
        'cf-ipcountry': 'SL',
      };
      if (n === 5) delete headers['x-real-ip'];
      if (n === 6) headers.host = 'other';
      expect(
        (
          await env.call('POST', '/v1/mobile/rokela-pdf/events', {
            headers,
            body: {
              installation_id: randomUUID(),
              events: [
                {
                  id: randomUUID(),
                  occurred_at: env.clock.now().toISOString(),
                  feature: 'app_open',
                  app_version: '1',
                  os_major: 14,
                  device_class: 'phone',
                },
              ],
            },
          })
        ).status,
      ).toBe(202);
    }
    const result = await env.call('GET', '/v1/admin/mobile-analytics', {
      token: await env.operatorToken(),
    });
    expect(result.body).toMatchObject({
      reports: 7,
      country_lookup_configured: true,
      country_ip_source_configured: true,
      country_database: { state: 'ready' },
      countries: [{ label: 'US', events: 5, installations: 5 }],
    });
    expect(JSON.stringify(result.body)).not.toContain(file);
    expect(JSON.stringify(result.body)).not.toContain('8.8.8.8');
  } finally {
    await env.app.close();
  }
});
