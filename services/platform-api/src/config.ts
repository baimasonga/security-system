import { readFileSync } from 'node:fs';
import type { BillingConfig } from './billing.ts';
import { PaddleCheckoutProvider, PaddleWebhookVerifier } from './integrations/billing.ts';
import { MfaCipher, type ScryptParams } from '@trust/auth';
import { validateAnchorUrl } from './anchors.ts';
import { assertSchemaName, readCaPem, tlsProblem } from './db/connection.ts';

export interface PlatformConfig {
  env: 'development' | 'test' | 'production';
  mfaEncryptionKey?: string;
  requireOperatorMfa: boolean;
  emailDelivery?: { apiKey: string; from: string; publicOrigin: string };
  billing?: BillingConfig;
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
  /** Schema holding the platform's tables (e.g. `trust` on a managed platform). Unset = the role's default. */
  dbSchema: string | undefined;
  /** PEM of the CA that signed the database server certificate; enables verified TLS. Never logged. */
  databaseCaPem: string | undefined;
  /** Accept a database superuser as the application role in production (not recommended). */
  allowDbSuperuser: boolean;
  /** Pool size for the PostgreSQL adapters. */
  dbPoolMax: number;
  /** Retention and maintenance cadence (seconds). */
  challengeTtlSeconds: number | undefined;
  challengeRetentionSeconds: number | undefined;
  leaseRetentionSeconds: number | undefined;
  maintenanceIntervalSeconds: number;
  /** Audit chains per organization (ADR-008). 1 = one chain per organization. */
  auditChainShards: number;
  /**
   * External witness for the audit log (ADR-010). Undefined = anchoring off (development, or production with the
   * risk explicitly accepted via AUDIT_ANCHOR_DISABLED=true).
   */
  auditAnchor: { url: string; token: string | undefined; intervalSeconds: number } | undefined;
  /**
   * Where HTTP rate-limit counters live (R-7). `postgres` shares them across instances; `memory` is per process
   * (development, or a deliberately single-instance deployment).
   */
  rateLimitStore: 'memory' | 'postgres';
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
  const mfaEncryptionKey = env['MFA_ENCRYPTION_KEY'];
  if (mfaEncryptionKey) new MfaCipher(mfaEncryptionKey);
  const requireOperatorMfa = env['REQUIRE_OPERATOR_MFA'] === 'true';
  if (env['REQUIRE_OPERATOR_MFA'] && !['true', 'false'].includes(env['REQUIRE_OPERATOR_MFA']))
    throw new Error('REQUIRE_OPERATOR_MFA must be true or false');
  if (requireOperatorMfa && !mfaEncryptionKey)
    throw new Error('MFA_ENCRYPTION_KEY is required for operator MFA');
  let billing: BillingConfig | undefined;
  if (
    [
      'PADDLE_API_KEY',
      'PADDLE_WEBHOOK_SECRET',
      'PADDLE_ENVIRONMENT',
      'PADDLE_PAYMENT_URL',
      'PADDLE_PRICE_MAP',
      'PADDLE_CLIENT_TOKEN',
    ].some((name) => env[name] !== undefined)
  ) {
    const apiKey = env['PADDLE_API_KEY'],
      webhookSecret = env['PADDLE_WEBHOOK_SECRET'],
      environment = env['PADDLE_ENVIRONMENT'],
      paymentUrl = env['PADDLE_PAYMENT_URL'];
    if (
      !apiKey ||
      !webhookSecret ||
      !['sandbox', 'live'].includes(environment ?? '') ||
      !paymentUrl ||
      !env['PADDLE_PRICE_MAP']
    )
      throw new Error('all Paddle checkout settings are required');
    let prices: unknown;
    try {
      prices = JSON.parse(env['PADDLE_PRICE_MAP']);
    } catch {
      throw new Error('invalid PADDLE_PRICE_MAP');
    }
    if (
      !prices ||
      typeof prices !== 'object' ||
      Array.isArray(prices) ||
      Object.keys(prices).length < 1 ||
      Object.entries(prices).some(
        ([plan, price]) =>
          !/^pln_[A-Za-z0-9_-]+$/.test(plan) ||
          typeof price !== 'string' ||
          !/^pri_[a-z0-9]{26}$/.test(price),
      )
    )
      throw new Error('invalid PADDLE_PRICE_MAP');
    const clientToken = env['PADDLE_CLIENT_TOKEN'];
    if (
      clientToken &&
      (!/^(test|live)_[A-Za-z0-9_-]{16,256}$/.test(clientToken) ||
        clientToken === apiKey ||
        clientToken === webhookSecret ||
        (environment === 'sandbox'
          ? !clientToken.startsWith('test_')
          : !clientToken.startsWith('live_')))
    )
      throw new Error(
        'PADDLE_CLIENT_TOKEN must be a public client token for the selected environment',
      );
    new PaddleCheckoutProvider({
      apiKey,
      environment: environment as 'sandbox' | 'live',
      paymentUrl,
    });
    new PaddleWebhookVerifier({ secret: webhookSecret });
    billing = {
      apiKey,
      webhookSecret,
      environment: environment as 'sandbox' | 'live',
      paymentUrl,
      prices: prices as Record<string, string>,
      clientToken: env['PADDLE_CLIENT_TOKEN'],
    };
  }
  let emailDelivery: PlatformConfig['emailDelivery'];
  if (env['RESEND_API_KEY']) {
    const from = env['EMAIL_FROM'];
    const origin = env['PUBLIC_ORIGIN'];
    if (!from || /[\r\n]/.test(from) || !origin)
      throw new Error('EMAIL_FROM and PUBLIC_ORIGIN are required with RESEND_API_KEY');
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new Error('PUBLIC_ORIGIN is not a valid origin');
    }
    if (
      url.username ||
      url.password ||
      url.pathname !== '/' ||
      url.search ||
      url.hash ||
      (prod ? url.protocol !== 'https:' : !['http:', 'https:'].includes(url.protocol))
    )
      throw new Error('PUBLIC_ORIGIN must be an origin (HTTPS in production)');
    emailDelivery = { apiKey: env['RESEND_API_KEY']!, from, publicOrigin: url.origin };
  }

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
  const dbSchemaRaw = env['DB_SCHEMA'];
  if (dbSchemaRaw !== undefined) {
    try {
      assertSchemaName(dbSchemaRaw);
    } catch {
      throw new Error('invalid DB_SCHEMA (lowercase letters, digits, underscore)');
    }
  }
  const databaseCaPem = readCaPem(env, (p) => readFileSync(p, 'utf8'));
  if (persistence === 'postgres' && databaseUrl && !databaseCaPem) {
    // A managed database is reached over the internet: credentials and data must not cross it in clear text.
    const problem = tlsProblem(databaseUrl);
    if (problem && prod && env['DATABASE_INSECURE_TRANSPORT'] !== 'true') throw new Error(problem);
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

  // Audit anchoring: production must either witness the log externally or say, explicitly, that it does not.
  const anchorUrl = env['AUDIT_ANCHOR_URL'];
  const anchorToken = env['AUDIT_ANCHOR_TOKEN'];
  if (anchorToken !== undefined && anchorToken.length < 16)
    throw new Error('AUDIT_ANCHOR_TOKEN must be at least 16 characters');
  if (anchorToken !== undefined && !anchorUrl)
    throw new Error('AUDIT_ANCHOR_TOKEN is set without AUDIT_ANCHOR_URL');
  if (prod && !anchorUrl && env['AUDIT_ANCHOR_DISABLED'] !== 'true')
    throw new Error(
      'AUDIT_ANCHOR_URL is required in production (set AUDIT_ANCHOR_DISABLED=true to accept that history rewrites by a database superuser go undetected)',
    );
  const auditAnchor = anchorUrl
    ? {
        url: validateAnchorUrl(anchorUrl, prod).toString(),
        token: anchorToken,
        intervalSeconds: optInt('AUDIT_ANCHOR_INTERVAL_SECONDS', 60, 86400) ?? 3600,
      }
    : undefined;

  const rateLimitStore = (env['RATE_LIMIT_STORE'] ?? (prod ? 'postgres' : 'memory')) as string;
  if (rateLimitStore !== 'memory' && rateLimitStore !== 'postgres')
    throw new Error(`unsupported RATE_LIMIT_STORE=${rateLimitStore}`);
  if (rateLimitStore === 'postgres' && persistence !== 'postgres')
    throw new Error('RATE_LIMIT_STORE=postgres requires PERSISTENCE=postgres');

  const logLevel = (env['LOG_LEVEL'] ?? 'info') as PlatformConfig['logLevel'];
  if (!['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'].includes(logLevel)) {
    throw new Error('invalid LOG_LEVEL');
  }

  const port = Number(env['PORT'] ?? 8080);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('invalid PORT');

  return {
    env: mode,
    emailDelivery,
    billing,
    mfaEncryptionKey,
    requireOperatorMfa,
    host: env['HOST'] ?? '127.0.0.1',
    port,
    trustProxy: env['TRUST_PROXY'] === '1',
    licenseKeyPepper,
    pseudonymKey,
    signingKeyPem,
    persistence,
    databaseUrl,
    dbPoolMax,
    dbSchema: dbSchemaRaw,
    databaseCaPem,
    allowDbSuperuser: env['DB_ALLOW_SUPERUSER'] === 'true',
    challengeTtlSeconds,
    challengeRetentionSeconds,
    leaseRetentionSeconds,
    maintenanceIntervalSeconds,
    auditChainShards,
    auditAnchor,
    rateLimitStore,
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
