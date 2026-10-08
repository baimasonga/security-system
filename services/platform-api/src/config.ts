import { readFileSync } from 'node:fs';
import type { ScryptParams } from '@trust/auth';

export interface PlatformConfig {
  env: 'development' | 'test' | 'production';
  host: string;
  port: number;
  /** Behind a reverse proxy/CDN, trust X-Forwarded-For for client IP (rate limiting). */
  trustProxy: boolean;
  licenseKeyPepper: string;
  pseudonymKey: string;
  /** PKCS#8 PEM of the license-signing key. Required in production; ephemeral in dev/test. */
  signingKeyPem: string | undefined;
  persistence: 'memory' | 'postgres';
  /** Required when persistence is postgres. Never logged. */
  databaseUrl: string | undefined;
  /** Pool size for the PostgreSQL adapters. */
  dbPoolMax: number;
  scrypt?: ScryptParams;
  rateLimits: {
    global: number;
    login: number;
    register: number;
    challenge: number;
    activate: number;
  };
}

const ephemeral = (label: string) => `dev-only-${label}-${'x'.repeat(40)}`;

/**
 * Production fails closed: missing/weak secrets or an unsupported persistence mode abort startup
 * rather than falling back to development defaults.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): PlatformConfig {
  const mode = (env['NODE_ENV'] ?? 'development') as PlatformConfig['env'];
  if (!['development', 'test', 'production'].includes(mode)) throw new Error('invalid NODE_ENV');
  const prod = mode === 'production';

  const need = (name: string, fallbackLabel: string): string => {
    const v = env[name];
    if (v && v.length >= 32) return v;
    if (prod) throw new Error(`${name} must be set (>= 32 chars) in production`);
    return ephemeral(fallbackLabel);
  };

  let signingKeyPem = env['LICENSE_SIGNING_KEY_PEM'];
  const file = env['LICENSE_SIGNING_KEY_FILE'];
  if (!signingKeyPem && file) signingKeyPem = readFileSync(file, 'utf8');
  if (prod && !signingKeyPem)
    throw new Error('LICENSE_SIGNING_KEY_FILE (or _PEM) is required in production');

  const licenseKeyPepper = need('LICENSE_KEY_PEPPER', 'pepper');
  const pseudonymKey = need('PSEUDONYM_KEY', 'pseudonym');

  const persistence = (env['PERSISTENCE'] ?? (prod ? 'postgres' : 'memory')) as string;
  if (persistence !== 'memory' && persistence !== 'postgres') {
    throw new Error(`unsupported PERSISTENCE=${persistence}`);
  }
  const databaseUrl = env['DATABASE_URL'];
  if (persistence === 'postgres' && !databaseUrl) {
    throw new Error('DATABASE_URL is required when PERSISTENCE=postgres');
  }
  if (prod && persistence !== 'postgres') {
    // Volatile storage must never serve production traffic.
    throw new Error('production requires PERSISTENCE=postgres');
  }
  const dbPoolMax = Number(env['DB_POOL_MAX'] ?? 10);
  if (!Number.isInteger(dbPoolMax) || dbPoolMax < 1 || dbPoolMax > 200)
    throw new Error('invalid DB_POOL_MAX');

  const port = Number(env['PORT'] ?? 8080);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('invalid PORT');

  return {
    env: mode,
    host: env['HOST'] ?? '127.0.0.1',
    port,
    trustProxy: env['TRUST_PROXY'] === '1',
    licenseKeyPepper,
    pseudonymKey,
    signingKeyPem,
    persistence,
    databaseUrl,
    dbPoolMax,
    rateLimits: { global: 300, login: 10, register: 5, challenge: 60, activate: 20 },
  };
}
