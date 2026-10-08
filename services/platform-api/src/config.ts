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
  /** Retention and maintenance cadence (seconds). */
  challengeTtlSeconds: number | undefined;
  challengeRetentionSeconds: number | undefined;
  leaseRetentionSeconds: number | undefined;
  maintenanceIntervalSeconds: number;
  /** Audit chains per organization (ADR-008). 1 = one chain per organization. */
  auditChainShards: number;
  logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
  scrypt?: ScryptParams;
  rateLimits: {
    global: number;
    login: number;
    register: number;
    challenge: number;
    activate: number;
  };
}

/** Per-IP requests/minute. Tunable by operators (e.g. behind a CDN with its own limits); validated. */
function limit(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 10_000_000) throw new Error(`invalid ${name}`);
  return n;
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

  const optInt = (name: string, min: number, max: number): number | undefined => {
    const raw = env[name];
    if (raw === undefined) return undefined;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`invalid ${name}`);
    return n;
  };
  const challengeTtlSeconds = optInt('CHALLENGE_TTL_SECONDS', 10, 3600);
  const challengeRetentionSeconds = optInt('CHALLENGE_RETENTION_SECONDS', 0, 30 * 86400);
  const leaseRetentionSeconds = optInt('LEASE_RETENTION_SECONDS', 0, 3650 * 86400);
  const maintenanceIntervalSeconds = optInt('MAINTENANCE_INTERVAL_SECONDS', 1, 86400) ?? 60;

  const auditChainShards = optInt('AUDIT_CHAIN_SHARDS', 1, 64) ?? 1;

  const logLevel = (env['LOG_LEVEL'] ?? 'info') as PlatformConfig['logLevel'];
  if (!['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'].includes(logLevel)) {
    throw new Error('invalid LOG_LEVEL');
  }

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
    challengeTtlSeconds,
    challengeRetentionSeconds,
    leaseRetentionSeconds,
    maintenanceIntervalSeconds,
    auditChainShards,
    logLevel,
    rateLimits: {
      global: limit(env, 'RATE_LIMIT_GLOBAL', 300),
      login: limit(env, 'RATE_LIMIT_LOGIN', 10),
      register: limit(env, 'RATE_LIMIT_REGISTER', 5),
      challenge: limit(env, 'RATE_LIMIT_CHALLENGE', 60),
      activate: limit(env, 'RATE_LIMIT_ACTIVATE', 20),
    },
  };
}
