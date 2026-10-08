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

  it('production refuses volatile in-memory persistence even when fully configured', () => {
    expect(() =>
      loadConfig(
        env({
          NODE_ENV: 'production',
          LICENSE_KEY_PEPPER: STRONG,
          PSEUDONYM_KEY: STRONG,
          LICENSE_SIGNING_KEY_PEM: 'pem',
        }),
      ),
    ).toThrow(/PostgreSQL persistence adapters/);
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
