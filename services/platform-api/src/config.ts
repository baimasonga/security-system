import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateHostname } from '@trust/sharing';
import type { BillingConfig } from './billing.ts';
import { PaddleCheckoutProvider, PaddleWebhookVerifier } from './integrations/billing.ts';
import {
  IdentityMailCipher,
  MfaCipher,
  validateRelyingParty,
  type ScryptParams,
} from '@trust/auth';
import { validateAnchorUrl } from './anchors.ts';
import { assertSchemaName, readCaPem, tlsProblem } from './db/connection.ts';

export interface PlatformConfig {
  env: 'development' | 'test' | 'production';
  mfaEncryptionKey?: string;
  identityMailEncryptionKey?: string;
  requireOperatorMfa: boolean;
  /** PRIVILEGED_DUAL_CONTROL: license revocation needs a second operator's approval (ADR-022). */
  privilegedDualControl: boolean;
  /** Passkeys (ADR-023): WEBAUTHN_RP_ID + WEBAUTHN_ORIGIN (+ optional WEBAUTHN_RP_NAME); undefined = disabled. */
  webauthn?: { rpId: string; origin: string; rpName: string };
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
    /** Public share/short-link/upload-request opens and password attempts, per IP per minute (default 60). */
    sharing?: number;
  };
  /** File sharing and short links (ADR-021). Undefined = disabled (the production default until configured). */
  sharing: SharingSettings | undefined;
}

export interface SharingSettings {
  secret: string;
  publicOrigin: string;
  shortOrigin: string;
  storage:
    | {
        kind: 'local';
        root: string;
        contentOrigin: string;
        contentHost: string;
        contentPort: number;
      }
    | {
        kind: 's3';
        endpoint: string;
        region: string;
        bucket: string;
        accessKeyId: string;
        secretAccessKey: string;
      };
  clamd: { host: string; port: number } | undefined;
  blockedHosts: string[];
  eventRetentionDays: number;
  jobIntervalSeconds: number;
}

function httpOrigin(raw: string, name: string, prod: boolean): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`${name} must be an origin`);
  }
  if (
    u.username ||
    u.password ||
    u.pathname !== '/' ||
    u.search ||
    u.hash ||
    (prod ? u.protocol !== 'https:' : !['http:', 'https:'].includes(u.protocol))
  )
    throw new Error(`${name} must be an origin (HTTPS in production)`);
  return u.origin;
}

/**
 * Sharing fails closed in production: no local storage, a dedicated secret, HTTPS origins, and antivirus unless the
 * operator explicitly accepts structural checks only (SHARING_MALWARE_SCAN_DISABLED=true).
 */
function loadSharing(
  env: NodeJS.ProcessEnv,
  prod: boolean,
  port: number,
  otherSecrets: string[],
): SharingSettings | undefined {
  const kind = env['SHARING_STORAGE'] ?? (prod ? 'off' : 'local');
  if (kind === 'off') return undefined;
  if (kind !== 'local' && kind !== 's3')
    throw new Error('SHARING_STORAGE must be local, s3 or off');
  if (prod && kind === 'local')
    throw new Error('production sharing requires SHARING_STORAGE=s3 (private object storage)');
  const secret = env['SHARING_SECRET'] ?? (prod ? '' : ephemeral('sharing'));
  if (secret.length < 32) throw new Error('SHARING_SECRET must be set (>= 32 chars)');
  if (prod && otherSecrets.includes(secret))
    throw new Error('SHARING_SECRET must be separate from other keys');
  const publicRaw =
    env['SHARING_PUBLIC_ORIGIN'] ??
    env['PUBLIC_ORIGIN'] ??
    (prod ? '' : `http://127.0.0.1:${port}`);
  if (!publicRaw)
    throw new Error('SHARING_PUBLIC_ORIGIN (or PUBLIC_ORIGIN) is required for sharing');
  const publicOrigin = httpOrigin(publicRaw, 'SHARING_PUBLIC_ORIGIN', prod);
  const shortOrigin = env['SHARING_SHORT_ORIGIN']
    ? httpOrigin(env['SHARING_SHORT_ORIGIN'], 'SHARING_SHORT_ORIGIN', prod)
    : publicOrigin;
  let storage: SharingSettings['storage'];
  if (kind === 'local') {
    const contentPort = Number(env['SHARING_CONTENT_PORT'] ?? 8081);
    if (!Number.isInteger(contentPort) || contentPort < 0 || contentPort > 65535)
      throw new Error('invalid SHARING_CONTENT_PORT');
    const contentOrigin = httpOrigin(
      env['SHARING_CONTENT_ORIGIN'] ?? `http://127.0.0.1:${contentPort}`,
      'SHARING_CONTENT_ORIGIN',
      false,
    );
    if (contentOrigin === publicOrigin)
      throw new Error('the content origin must differ from the portal origin');
    storage = {
      kind,
      root: env['SHARING_LOCAL_DIR'] ?? join(tmpdir(), 'rokela-sharing-dev'),
      contentOrigin,
      contentHost: env['SHARING_CONTENT_HOST'] ?? '127.0.0.1',
      contentPort,
    };
  } else {
    const names = [
      'SHARING_S3_ENDPOINT',
      'SHARING_S3_BUCKET',
      'SHARING_S3_ACCESS_KEY_ID',
      'SHARING_S3_SECRET_ACCESS_KEY',
    ];
    if (names.some((n) => !env[n]))
      throw new Error(`${names.join(', ')} are required with SHARING_STORAGE=s3`);
    const endpoint = httpOrigin(env['SHARING_S3_ENDPOINT']!, 'SHARING_S3_ENDPOINT', prod);
    if (endpoint === publicOrigin)
      throw new Error('object storage must be a separate origin from the portal');
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(env['SHARING_S3_BUCKET']!))
      throw new Error('invalid SHARING_S3_BUCKET');
    storage = {
      kind,
      endpoint,
      region: env['SHARING_S3_REGION'] ?? 'auto',
      bucket: env['SHARING_S3_BUCKET']!,
      accessKeyId: env['SHARING_S3_ACCESS_KEY_ID']!,
      secretAccessKey: env['SHARING_S3_SECRET_ACCESS_KEY']!,
    };
  }
  let clamd: SharingSettings['clamd'];
  if (env['CLAMD_HOST']) {
    const p = Number(env['CLAMD_PORT'] ?? 3310);
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('invalid CLAMD_PORT');
    clamd = { host: env['CLAMD_HOST'], port: p };
  } else if (prod && env['SHARING_MALWARE_SCAN_DISABLED'] !== 'true')
    throw new Error(
      'CLAMD_HOST is required for production sharing (set SHARING_MALWARE_SCAN_DISABLED=true to accept structural checks only)',
    );
  const blockedHosts = (env['SHARING_BLOCKED_HOSTS'] ?? '')
    .split(',')
    .map((h) => h.trim())
    .filter(Boolean)
    .map((h) => {
      try {
        return validateHostname(h);
      } catch {
        throw new Error('invalid SHARING_BLOCKED_HOSTS');
      }
    });
  const int = (name: string, min: number, max: number, fallback: number) => {
    const raw = env[name];
    if (raw === undefined) return fallback;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`invalid ${name}`);
    return n;
  };
  return {
    secret,
    publicOrigin,
    shortOrigin,
    storage,
    clamd,
    blockedHosts,
    eventRetentionDays: int('SHARING_EVENT_RETENTION_DAYS', 1, 3650, 180),
    jobIntervalSeconds: int('SHARING_JOB_INTERVAL_SECONDS', 1, 3600, 5),
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
  const dualControlEnv = env['PRIVILEGED_DUAL_CONTROL'];
  if (dualControlEnv && !['true', 'false'].includes(dualControlEnv))
    throw new Error('PRIVILEGED_DUAL_CONTROL must be true or false');
  const privilegedDualControl = dualControlEnv === 'true';
  let webauthn: PlatformConfig['webauthn'];
  if (env['WEBAUTHN_RP_ID'] || env['WEBAUTHN_ORIGIN']) {
    if (!env['WEBAUTHN_RP_ID'] || !env['WEBAUTHN_ORIGIN'])
      throw new Error('passkeys need both WEBAUTHN_RP_ID and WEBAUTHN_ORIGIN');
    const rp = validateRelyingParty(
      { rpId: env['WEBAUTHN_RP_ID'], origin: env['WEBAUTHN_ORIGIN'] },
      env['NODE_ENV'] === 'production',
    );
    const rpName = (env['WEBAUTHN_RP_NAME'] ?? 'Rokela Bai Bureh Warrior').trim();
    if (rpName.length < 1 || rpName.length > 64)
      throw new Error('WEBAUTHN_RP_NAME must be 1-64 characters');
    webauthn = { ...rp, rpName };
  }
  // Approvals need a fresh authenticator code, which needs the MFA key.
  if (privilegedDualControl && !mfaEncryptionKey)
    throw new Error('MFA_ENCRYPTION_KEY is required for PRIVILEGED_DUAL_CONTROL');
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
    let portalOrigin: string | undefined;
    if (env['PUBLIC_ORIGIN']) {
      let portal: URL;
      try {
        portal = new URL(env['PUBLIC_ORIGIN']);
      } catch {
        throw new Error('PUBLIC_ORIGIN must be a valid HTTPS portal origin for billing');
      }
      if (
        portal.protocol !== 'https:' ||
        portal.username ||
        portal.password ||
        portal.pathname !== '/' ||
        portal.search ||
        portal.hash
      )
        throw new Error('PUBLIC_ORIGIN must be a valid HTTPS portal origin for billing');
      if (portal.origin === new URL(paymentUrl).origin)
        throw new Error('payment and account portal must use separate origins');
      portalOrigin = portal.origin;
    } else if (prod) throw new Error('PUBLIC_ORIGIN is required with production billing');
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
      portalOrigin,
    };
  }
  const identityMailEncryptionKey = env['MAIL_OUTBOX_ENCRYPTION_KEY'];
  if (identityMailEncryptionKey) {
    new IdentityMailCipher(identityMailEncryptionKey);
    if (!env['RESEND_API_KEY'])
      throw new Error('RESEND_API_KEY required with MAIL_OUTBOX_ENCRYPTION_KEY');
    if (identityMailEncryptionKey.toLowerCase() === env['MFA_ENCRYPTION_KEY']?.toLowerCase())
      throw new Error('identity mail key must be separate from MFA key');
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
    identityMailEncryptionKey,
    billing,
    mfaEncryptionKey,
    requireOperatorMfa,
    privilegedDualControl,
    ...(webauthn ? { webauthn } : {}),
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
      sharing: limit(env, 'RATE_LIMIT_SHARING', 60),
    },
    sharing: loadSharing(env, prod, port, [licenseKeyPepper, pseudonymKey]),
  };
}
