import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.ts';

const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;
const STRONG = 'x'.repeat(40);

describe('loadConfig — fail closed', () => {
  it('production refuses to start without strong secrets or a signing key', () => {
    expect(() => loadConfig(env({ NODE_ENV: 'production' }))).toThrow(/SIGNING_KEY/);
    const base = { NODE_ENV: 'production', LICENSE_SIGNING_KEY_PEM: 'pem' };
    expect(() =>
      loadConfig(env({ ...base, LICENSE_KEY_PEPPER: 'short', PSEUDONYM_KEY: STRONG })),
    ).toThrow(/LICENSE_KEY_PEPPER/);
    expect(() => loadConfig(env({ ...base, LICENSE_KEY_PEPPER: STRONG }))).toThrow(/PSEUDONYM_KEY/);
    expect(() =>
      loadConfig(
        env({ NODE_ENV: 'production', LICENSE_KEY_PEPPER: STRONG, PSEUDONYM_KEY: STRONG }),
      ),
    ).toThrow(/SIGNING_KEY/);
  });

  it('production requires PostgreSQL persistence and a database URL; volatile storage is refused', () => {
    const base = {
      NODE_ENV: 'production',
      LICENSE_KEY_PEPPER: STRONG,
      PSEUDONYM_KEY: STRONG,
      LICENSE_SIGNING_KEY_PEM: 'pem',
    };
    expect(() => loadConfig(env({ ...base, PERSISTENCE: 'memory' }))).toThrow(
      /requires PERSISTENCE=postgres/,
    );
    expect(() => loadConfig(env(base))).toThrow(/DATABASE_URL is required/); // postgres is the production default
    const ok = loadConfig(
      env({
        ...base,
        DATABASE_URL: 'postgres://u:p@db/trust?sslmode=require',
        AUDIT_ANCHOR_URL: 'https://witness.example/anchors',
      }),
    );
    expect(ok).toMatchObject({ persistence: 'postgres', env: 'production' });
  });

  it('validates the pool size', () => {
    expect(() => loadConfig(env({ DB_POOL_MAX: '0' }))).toThrow(/DB_POOL_MAX/);
    expect(() => loadConfig(env({ DB_POOL_MAX: '1000' }))).toThrow(/DB_POOL_MAX/);
  });

  it('rejects unknown modes, persistence kinds and bad ports', () => {
    expect(() => loadConfig(env({ NODE_ENV: 'staging' }))).toThrow(/NODE_ENV/);
    expect(() => loadConfig(env({ PERSISTENCE: 'sqlite' }))).toThrow(/PERSISTENCE/);
    expect(() => loadConfig(env({ PORT: '99999' }))).toThrow(/PORT/);
  });

  it('development works out of the box with ephemeral dev-only secrets, bound to loopback', () => {
    const c = loadConfig(env({}));
    expect(c.env).toBe('development');
    expect(c.host).toBe('127.0.0.1');
    expect(c.licenseKeyPepper.length).toBeGreaterThanOrEqual(32);
    expect(c.signingKeyPem).toBeUndefined();
  });

  it('never trusts forwarded headers unless explicitly enabled', () => {
    expect(loadConfig(env({})).trustProxy).toBe(false);
    expect(loadConfig(env({ TRUST_PROXY: '1' })).trustProxy).toBe(true);
  });
});

describe('loadConfig — operational knobs', () => {
  it('accepts validated retention / maintenance / rate-limit / log overrides and rejects nonsense', () => {
    const c = loadConfig(
      env({
        CHALLENGE_RETENTION_SECONDS: '120',
        LEASE_RETENTION_SECONDS: '86400',
        MAINTENANCE_INTERVAL_SECONDS: '15',
        RATE_LIMIT_GLOBAL: '5000',
        LOG_LEVEL: 'warn',
      }),
    );
    expect(c).toMatchObject({
      challengeRetentionSeconds: 120,
      leaseRetentionSeconds: 86400,
      maintenanceIntervalSeconds: 15,
      logLevel: 'warn',
    });
    expect(c.rateLimits.global).toBe(5000);
    expect(loadConfig(env({})).maintenanceIntervalSeconds).toBe(60);
    const bads: Array<Record<string, string>> = [
      { CHALLENGE_RETENTION_SECONDS: '-1' },
      { MAINTENANCE_INTERVAL_SECONDS: '0' },
      { LEASE_RETENTION_SECONDS: 'abc' },
      { RATE_LIMIT_LOGIN: '0' },
      { LOG_LEVEL: 'chatty' },
    ];
    for (const bad of bads) {
      expect(() => loadConfig(env(bad)), JSON.stringify(bad)).toThrow();
    }
  });
});

describe('loadConfig — audit anchoring (ADR-010)', () => {
  const prod = {
    NODE_ENV: 'production',
    LICENSE_KEY_PEPPER: STRONG,
    PSEUDONYM_KEY: STRONG,
    LICENSE_SIGNING_KEY_PEM: 'pem',
    DATABASE_URL: 'postgres://u:p@db/trust?sslmode=require',
  };

  it('production must name a witness or explicitly accept the risk; development defaults to off', () => {
    expect(() => loadConfig(env(prod))).toThrow(/AUDIT_ANCHOR_URL is required/);
    expect(loadConfig(env({ ...prod, AUDIT_ANCHOR_DISABLED: 'true' })).auditAnchor).toBeUndefined();
    expect(() => loadConfig(env({ ...prod, AUDIT_ANCHOR_DISABLED: 'yes' }))).toThrow(
      /AUDIT_ANCHOR_URL is required/,
    );
    expect(loadConfig(env({})).auditAnchor).toBeUndefined();
  });

  it('accepts a validated https witness with an optional token and interval; refuses weak or inconsistent settings', () => {
    const c = loadConfig(
      env({
        ...prod,
        AUDIT_ANCHOR_URL: 'https://w.example/a',
        AUDIT_ANCHOR_TOKEN: 't'.repeat(20),
        AUDIT_ANCHOR_INTERVAL_SECONDS: '600',
      }),
    );
    expect(c.auditAnchor).toEqual({
      url: 'https://w.example/a',
      token: 't'.repeat(20),
      intervalSeconds: 600,
    });
    expect(
      loadConfig(env({ ...prod, AUDIT_ANCHOR_URL: 'https://w.example/a' })).auditAnchor
        ?.intervalSeconds,
    ).toBe(3600);
    const bads: Array<Record<string, string>> = [
      { ...prod, AUDIT_ANCHOR_URL: 'http://w.example/a' },
      { ...prod, AUDIT_ANCHOR_URL: 'http://127.0.0.1:9/a' }, // loopback http is for development only
      { ...prod, AUDIT_ANCHOR_URL: 'https://u:p@w.example/a' },
      { ...prod, AUDIT_ANCHOR_URL: 'https://w.example/a', AUDIT_ANCHOR_TOKEN: 'short' },
      { ...prod, AUDIT_ANCHOR_URL: 'https://w.example/a', AUDIT_ANCHOR_INTERVAL_SECONDS: '5' },
      { ...prod, AUDIT_ANCHOR_URL: 'https://w.example/a', AUDIT_ANCHOR_INTERVAL_SECONDS: '999999' },
      { AUDIT_ANCHOR_TOKEN: 't'.repeat(20) }, // token without a URL
    ];
    for (const bad of bads) expect(() => loadConfig(env(bad)), JSON.stringify(bad)).toThrow();
    expect(loadConfig(env({ AUDIT_ANCHOR_URL: 'http://127.0.0.1:9/a' })).auditAnchor?.url).toBe(
      'http://127.0.0.1:9/a',
    );
  });
});

describe('Paddle checkout configuration', () => {
  const settings = {
    PADDLE_API_KEY: 'test-api-key',
    PADDLE_WEBHOOK_SECRET: 'x'.repeat(32),
    PADDLE_ENVIRONMENT: 'sandbox',
    PADDLE_PAYMENT_URL: 'https://pay.example/checkout',
    PADDLE_PRICE_MAP: JSON.stringify({ pln_example: 'pri_' + 'a'.repeat(26) }),
  };
  it('remains disabled without provider settings and maps only operator-configured prices', () => {
    expect(loadConfig({}).billing).toBeUndefined();
    expect(loadConfig(settings).billing?.prices).toEqual({ pln_example: 'pri_' + 'a'.repeat(26) });
  });
  it.each(Object.keys(settings))('rejects partial configuration missing %s', (key) => {
    const partial = { ...settings };
    delete partial[key as keyof typeof partial];
    expect(() => loadConfig(partial)).toThrow();
  });
  it.each([
    { PADDLE_ENVIRONMENT: 'other' },
    { PADDLE_PAYMENT_URL: 'http://pay.example' },
    { PADDLE_PRICE_MAP: '{"pln_example":"client-price"}' },
    { PADDLE_PRICE_MAP: '[]' },
    { PADDLE_WEBHOOK_SECRET: 'short' },
  ])('rejects unsafe or malformed provider settings', (patch) =>
    expect(() => loadConfig({ ...settings, ...patch })).toThrow(),
  );
});

it('never exposes API credentials as Paddle client-token configuration', () => {
  const base = {
    PADDLE_API_KEY: 'pdl_live_apikey_' + 'x'.repeat(32),
    PADDLE_WEBHOOK_SECRET: 'w'.repeat(32),
    PADDLE_ENVIRONMENT: 'sandbox',
    PADDLE_PAYMENT_URL: 'https://pay.example/checkout',
    PADDLE_PRICE_MAP: JSON.stringify({ pln_example: 'pri_' + 'a'.repeat(26) }),
  };
  expect(() => loadConfig({ ...base, PADDLE_CLIENT_TOKEN: base.PADDLE_API_KEY })).toThrow(
    'public client token',
  );
  expect(() => loadConfig({ ...base, PADDLE_CLIENT_TOKEN: 'live_' + 'x'.repeat(32) })).toThrow(
    'public client token',
  );
  expect(
    loadConfig({ ...base, PADDLE_CLIENT_TOKEN: 'test_' + 'x'.repeat(32) }).billing?.clientToken,
  ).toBe('test_' + 'x'.repeat(32));
});

it('requires production payment-origin separation from account storage', () => {
  const base = {
    PADDLE_API_KEY: 'test-key',
    PADDLE_WEBHOOK_SECRET: 'w'.repeat(32),
    PADDLE_ENVIRONMENT: 'sandbox',
    PADDLE_PAYMENT_URL: 'https://pay.example/checkout',
    PADDLE_PRICE_MAP: JSON.stringify({ pln_example: 'pri_' + 'a'.repeat(26) }),
  };
  expect(() => loadConfig({ ...base, NODE_ENV: 'production' })).toThrow(
    'PUBLIC_ORIGIN is required',
  );
  expect(() => loadConfig({ ...base, PUBLIC_ORIGIN: 'https://pay.example' })).toThrow(
    'separate origins',
  );
  expect(
    loadConfig({ ...base, PUBLIC_ORIGIN: 'https://accounts.example' }).billing?.portalOrigin,
  ).toBe('https://accounts.example');
});
