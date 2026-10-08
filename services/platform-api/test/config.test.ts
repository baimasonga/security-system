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
    const ok = loadConfig(env({ ...base, DATABASE_URL: 'postgres://u:p@db/trust' }));
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
