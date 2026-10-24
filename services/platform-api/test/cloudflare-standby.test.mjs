import { expect, it, vi } from 'vitest';
import { runtimeConfig, forward } from '../../../infrastructure/cloudflare/config.mjs';

const values = () => ({
  DATABASE_URL: 'postgres://app:fixture@db.example.test/trust?sslmode=verify-full',
  DATABASE_CA_PEM: 'fixture-ca',
  DB_SCHEMA: 'trust',
  LICENSE_KEY_PEPPER: 'fixture-pepper',
  PSEUDONYM_KEY: 'fixture-pseudonym',
  LICENSE_SIGNING_KEY_PEM: 'fixture-key',
  PUBLIC_ORIGIN: 'https://standby.example.test',
});
const bindings = (extra = {}) => ({
  ...values(),
  ...extra,
  PUBLIC_HOST: 'standby.example.test',
  TRAFFIC_ENABLED: 'true',
});
const request = (headers = {}) =>
  new globalThis.Request('https://standby.example.test/healthz', {
    headers: { 'CF-Connecting-IP': '203.0.113.7', ...headers },
  });
it('forces production, durable persistence and shared rate limiting', () => {
  expect(runtimeConfig(bindings())).toMatchObject({
    NODE_ENV: 'production',
    PERSISTENCE: 'postgres',
    HOST: '0.0.0.0',
    PORT: '8080',
    TRUST_PROXY: 'true',
    RATE_LIMIT_STORE: 'postgres',
  });
});
it.each([
  'DATABASE_MIGRATE_URL',
  'APP_DB_ROLE',
  'DATABASE_INSECURE_TRANSPORT',
  'DB_ALLOW_SUPERUSER',
  'SHARING_MALWARE_SCAN_DISABLED',
  'NODE_ENV',
  'ARBITRARY_SECRET',
])('refuses unreviewed or privileged setting %s without disclosing values', (key) => {
  expect(() => runtimeConfig(bindings({ [key]: 'private-value' }))).toThrow(
    'Standby configuration is unavailable',
  );
});
it.each([
  'DATABASE_URL',
  'DATABASE_CA_PEM',
  'DB_SCHEMA',
  'LICENSE_SIGNING_KEY_PEM',
  'LICENSE_KEY_PEPPER',
  'PSEUDONYM_KEY',
  'PUBLIC_ORIGIN',
])('refuses missing required %s', (key) => {
  expect(() => runtimeConfig(bindings({ [key]: '' }))).toThrow();
});
it.each([
  'http://standby.example.test',
  'https://other.example.test',
  'https://standby.example.test/path',
  'https://standby.example.test/',
])('refuses mismatched origins %s', (PUBLIC_ORIGIN) => {
  expect(() => runtimeConfig(bindings({ PUBLIC_ORIGIN }))).toThrow();
});
it('refuses Railway-private scanner addresses and nonstring configuration', () => {
  expect(() => runtimeConfig(bindings({ CLAMD_HOST: 'scanner.railway.internal' }))).toThrow();
  expect(() => runtimeConfig(bindings({ DB_POOL_MAX: 4 }))).toThrow();
});
it('does not start a container when traffic is disabled, host mismatches or secrets are invalid', async () => {
  const getByName = vi.fn();
  const env = { ...bindings(), WARRIOR: { getByName } };
  for (const config of [
    { ...env, TRAFFIC_ENABLED: 'false' },
    { ...env, PUBLIC_HOST: 'other.example.test' },
    { ...env, DATABASE_URL: null },
  ]) {
    const res = await forward(request(), config);
    expect(res.status).toBe(503);
    expect(await res.text()).toBe('Service unavailable');
    expect(res.headers.get('cache-control')).toBe('no-store');
  }
  expect(getByName).not.toHaveBeenCalled();
});
it('overwrites client-supplied forwarding headers and always uses the singleton', async () => {
  const fetch = vi.fn(async () => new globalThis.Response('{"status":"ok"}'));
  const getByName = vi.fn(() => ({ fetch }));
  const result = await forward(
    request({
      'X-Forwarded-For': 'attacker',
      Forwarded: 'attacker',
      'X-Real-IP': 'attacker',
      'X-Forwarded-Host': 'evil.test',
      'X-Forwarded-Proto': 'http',
    }),
    { ...bindings(), WARRIOR: { getByName } },
  );
  expect(result.status).toBe(200);
  expect(getByName).toHaveBeenCalledWith('warrior-singleton');
  const sent = fetch.mock.calls[0][0];
  expect(sent.url).toBe('https://standby.example.test/healthz');
  expect(sent.headers.get('x-forwarded-for')).toBe('203.0.113.7');
  expect(sent.headers.get('x-forwarded-host')).toBe('standby.example.test');
  expect(sent.headers.get('x-forwarded-proto')).toBe('https');
  expect(sent.headers.has('forwarded')).toBe(false);
  expect(sent.headers.has('x-real-ip')).toBe(false);
});
it('returns a fixed refusal for missing edge identity or container errors', async () => {
  const env = {
    ...bindings(),
    WARRIOR: {
      getByName() {
        throw new Error('private provider details');
      },
    },
  };
  const req = request();
  req.headers.delete('CF-Connecting-IP');
  expect((await forward(req, env)).status).toBe(503);
  expect(await (await forward(request(), env)).text()).toBe('Service unavailable');
});

it('enforces the per-binding UTF-8 byte limit', () => {
  expect(() => runtimeConfig(bindings({ DATABASE_CA_PEM: 'x'.repeat(5001) }))).toThrow();
  expect(() => runtimeConfig(bindings({ DATABASE_CA_PEM: 'é'.repeat(2501) }))).toThrow();
});
it('forwards the reviewed incident email settings', () => {
  const email = {
    OPERATIONS_EMAIL_NOTIFICATIONS_ENABLED: 'true',
    MAIL_PROVIDER: 'cloudflare',
    CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32),
    CLOUDFLARE_EMAIL_API_TOKEN: 'fixture-token',
    EMAIL_FROM: 'alerts@example.test',
    OPERATIONS_PROBES_ENABLED: 'true',
    OPERATIONS_PROBE_TARGETS: '[]',
  };
  expect(runtimeConfig(bindings(email))).toMatchObject(email);
  // A general Cloudflare deployment token is still not a runtime setting.
  expect(() => runtimeConfig(bindings({ CLOUDFLARE_API_TOKEN: 'private-value' }))).toThrow(
    'Standby configuration is unavailable',
  );
});
