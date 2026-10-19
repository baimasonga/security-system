import { HealthService } from '@trust/operations';
import { persistenceReadiness } from './readiness.ts';
import {
  InventoryService,
  InMemoryInventoryStore,
  CredentialService,
  EventService,
} from '@trust/operations';
import { PgInventoryStore } from './db/pg-operations-store.ts';
import { BillingService } from './billing.ts';
import {
  PaddleCheckoutProvider,
  PaddleWebhookVerifier,
  type CheckoutProvider,
} from './integrations/billing.ts';
import { ResendMailDelivery } from './integrations/mail.ts';
import {
  AuthService,
  InMemoryAuthStore,
  hashPassword,
  verifyPassword,
  type AuthStore,
  type IdentityDelivery,
} from '@trust/auth';
import { resolveTxt } from 'node:dns/promises';
import {
  BasicContentScanner,
  ChainedScanner,
  DEFAULT_SHARING_CONFIG,
  InMemorySharingStore,
  SharingKeys,
  SharingService,
  type FileScanner,
  type ObjectStore,
  type SharingStore,
} from '@trust/sharing';
import { ClamdScanner } from './integrations/clamd.ts';
import { LocalObjectStore } from './integrations/object-store-local.ts';
import { S3ObjectStore } from './integrations/object-store-s3.ts';
import { PgSharingStore } from './db/pg-sharing-store.ts';
import { InMemoryAuditLog, type AuditLog } from '@trust/audit';
import { KeyRing, kidForPublicKey, type KeyRecord } from '@trust/crypto';
import {
  InMemoryLicensingStore,
  LicensingService,
  defaultLicensingConfig,
  type LicensingConfig,
  type LicensingStore,
} from '@trust/licensing';
import { DomainError, systemClock, type Clock } from '@trust/shared-types';
import { InMemoryTelemetrySink, Telemetry, type TelemetrySink } from '@trust/telemetry';
import pg from 'pg';
import type { PlatformConfig } from './config.ts';
import {
  describeConnectionTarget,
  explainDbError,
  gatherRoleFacts,
  judgeRole,
  poolSettings,
} from './db/connection.ts';
import { MIGRATIONS_DIR, assertSchemaCurrent } from './db/migrate.ts';
import { setTransactionObserver, type PgPool } from './db/pg.ts';
import {
  AnchorPublisher,
  HttpsAnchorSink,
  InMemoryAnchorStore,
  validateAnchorUrl,
  type AnchorSink,
  type AnchorStore,
} from './anchors.ts';
import { Metrics } from './metrics.ts';
import {
  MemoryRateBackend,
  PgRateBackend,
  ResilientRateBackend,
  type RateBackend,
} from './rate-limit.ts';
import { PgAnchorStore } from './db/pg-anchor-store.ts';
import { PgAuditLog } from './db/pg-audit-log.ts';
import { PgAuthStore } from './db/pg-auth-store.ts';
import { PgKeyStore } from './db/pg-key-store.ts';
import { PgLicensingStore } from './db/pg-licensing-store.ts';
import { PgTelemetrySink } from './db/pg-telemetry-sink.ts';
import { PgPrivilegedStore } from './db/pg-privileged-store.ts';
import {
  InMemoryPrivilegedStore,
  PrivilegedService,
  type PrivilegedStore,
} from '@trust/privileged';

export interface Container {
  config: PlatformConfig;
  clock: Clock;
  audit: AuditLog;
  auth: AuthService;
  operations: InventoryService;
  operationsCredentials: CredentialService;
  operationsEvents: EventService;
  operationsHealth: HealthService;
  readiness(): Promise<boolean>;
  licensing: LicensingService;
  billing: BillingService | undefined;
  /** File sharing and short links (ADR-021); undefined when not configured. */
  sharing: SharingService | undefined;
  /** The local signed-URL store, when sharing uses it (served by the separate content origin). */
  sharingLocalStore: LocalObjectStore | undefined;
  /** Dual control, JIT grants, freeze and break-glass (ADR-022). */
  privileged: PrivilegedService;
  keyring: KeyRing;
  telemetry: Telemetry;
  telemetrySink: TelemetrySink;
  metrics: Metrics;
  /** Index of published audit anchors (ADR-010). */
  anchorStore: AnchorStore;
  /** Present only when an external witness is configured. */
  anchors: AnchorPublisher | undefined;
  /** Shared HTTP rate-limit counters (R-7); undefined = the limiter's per-process default. */
  rateBackend: RateBackend | undefined;
  /** Startup findings about the database role (logged by the entry point). */
  dbWarnings: string[];
  /** Releases pooled resources. Idempotent. */
  close(): Promise<void>;
}

export interface ContainerOverrides {
  clock?: Clock;
  identityDelivery?: IdentityDelivery;
  checkoutProvider?: CheckoutProvider;
  licensing?: Partial<LicensingConfig>;
  /** Test seam: a ready-made pool (e.g. schema-scoped). Implies postgres persistence. */
  pool?: PgPool;
  /** Test seam: replaces the HTTPS witness. */
  anchorSink?: AnchorSink;
  /** Test seams for sharing. */
  sharingObjects?: ObjectStore;
  sharingScanner?: FileScanner;
  sharingResolveTxt?: (name: string) => Promise<string[][]>;
  sharingMailer?: IdentityDelivery;
  sharingConfig?: Partial<typeof DEFAULT_SHARING_CONFIG>;
}

/** Serializes background writes (key persistence, key audit) and surfaces failures at `flush()`. */
class WriteQueue {
  #tail: Promise<void> = Promise.resolve();
  #error: unknown;
  add(fn: () => Promise<unknown>): void {
    this.#tail = this.#tail.then(fn).then(
      () => undefined,
      (e) => {
        this.#error ??= e;
      },
    );
  }
  async flush(): Promise<void> {
    await this.#tail;
    if (this.#error) {
      const e = this.#error;
      this.#error = undefined;
      throw e;
    }
  }
}

/** Composition root. Everything environment-specific is chosen here and nowhere else. */
export async function createContainer(
  config: PlatformConfig,
  overrides?: ContainerOverrides,
): Promise<Container> {
  const clock = overrides?.clock ?? systemClock;
  const usePg = !!overrides?.pool || config.persistence === 'postgres';

  let pool: PgPool | undefined = overrides?.pool;
  let ownPool: pg.Pool | undefined;
  let roleWarnings: string[] = [];
  if (usePg && !pool) {
    ownPool = new pg.Pool(
      poolSettings({
        databaseUrl: config.databaseUrl!,
        max: config.dbPoolMax,
        caPem: config.databaseCaPem,
      }),
    );
    pool = ownPool;
    try {
      // Judge the role BEFORE trusting the schema: wrong schema or an over-privileged role is a deployment error.
      roleWarnings = judgeRole(await gatherRoleFacts(pool), {
        production: config.env === 'production',
        expectedSchema: config.dbSchema,
        allowSuperuser: config.allowDbSuperuser,
      });
      await assertSchemaCurrent(pool, MIGRATIONS_DIR);
    } catch (e) {
      await ownPool.end().catch(() => undefined);
      // Say what is wrong in plain words (and never print the URL or password).
      const hint = explainDbError(e, describeConnectionTarget(config.databaseUrl!));
      throw hint ? new Error(hint, { cause: e }) : e;
    }
  }

  const metrics = new Metrics();
  if (usePg) {
    setTransactionObserver({
      onTransaction: (e) => {
        metrics.inc('db_tx_total', { outcome: e.outcome });
        metrics.observe('db_tx_duration_ms', e.durationMs, { outcome: e.outcome });
      },
      onRetry: (e) => metrics.inc('db_tx_retries_total', { sqlstate: e.code }),
      onAuditLockWait: (ms) => metrics.observe('audit_lock_wait_ms', ms),
    });
  }
  if (ownPool) {
    const p = ownPool;
    metrics.gauge('db_pool_total', () => p.totalCount);
    metrics.gauge('db_pool_idle', () => p.idleCount);
    metrics.gauge('db_pool_waiting', () => p.waitingCount);
  }

  const shards = config.auditChainShards;
  const audit: AuditLog = pool
    ? new PgAuditLog(pool, clock, { shards })
    : new InMemoryAuditLog(clock, { shards });
  const telemetrySink: TelemetrySink = pool
    ? new PgTelemetrySink(pool)
    : new InMemoryTelemetrySink();
  const telemetry = new Telemetry({
    sink: telemetrySink,
    clock,
    pseudonymKey: config.pseudonymKey,
  });
  const authStore: AuthStore = pool
    ? new PgAuthStore(pool, clock, { auditShards: shards })
    : new InMemoryAuthStore({ audit });
  const licensingStore: LicensingStore = pool
    ? new PgLicensingStore(pool, clock, { auditShards: shards })
    : new InMemoryLicensingStore({ audit });
  const keyStore = pool ? new PgKeyStore(pool) : undefined;

  // ---- signing keys: restore persisted metadata, attach configured private key, persist changes ----
  const writes = new WriteQueue();
  // `ring` is referenced inside its own onEvent callback (invoked later), hence the annotation.
  const ring: KeyRing = new KeyRing({
    now: () => clock.now(),
    // Key lifecycle changes are high-blast-radius: always audited and persisted, never with key material.
    onEvent: (e) => {
      const rec: KeyRecord | undefined = ring.get(e.kid);
      if (keyStore && rec) writes.add(() => keyStore.upsert(rec));
      writes.add(() =>
        audit.append({
          actor: { type: 'system' },
          action: `key.${e.action}`,
          target: { type: 'signing_key', id: e.kid },
          reason: e.reason,
          metadata: { purpose: e.purpose, from: e.from, to: e.to },
        }),
      );
    },
  });
  const keyring = ring;
  if (keyStore) keyring.restore(await keyStore.list());

  if (config.signingKeyPem) {
    const { createPrivateKey, createPublicKey } = await import('node:crypto');
    const jwk = createPublicKey(createPrivateKey(config.signingKeyPem)).export({ format: 'jwk' });
    const kid = kidForPublicKey({ kty: 'OKP', crv: 'Ed25519', x: String(jwk.x) });
    const existing = keyring.get(kid);
    if (!existing) {
      keyring.importPrivateKeyPem('license', config.signingKeyPem, kid);
      keyring.activate(kid, 'configured signing key activated at startup');
    } else {
      if (
        existing.state === 'revoked' ||
        existing.state === 'archived' ||
        existing.state === 'destroyed'
      ) {
        throw new Error(`configured signing key ${kid} is ${existing.state}; configure a new key`);
      }
      if (existing.state === 'deprecated') {
        throw new Error(`configured signing key ${kid} was rotated out; configure the current key`);
      }
      keyring.attachPrivateKeyPem(kid, config.signingKeyPem);
      if (existing.state === 'generated')
        keyring.activate(kid, 'configured signing key activated at startup');
    }
  } else {
    if (config.env === 'production')
      throw new Error('a configured signing key is required in production');
    keyring.activate(keyring.generate('license').kid, 'ephemeral development key');
  }
  await writes.flush();

  const auth = new AuthService({
    store: authStore,
    identityMailEncryptionKey: config.identityMailEncryptionKey,
    identityMailOutcome: (outcome) => metrics.inc('identity_mail_outcomes_total', { outcome }),
    identityDelivery:
      overrides?.identityDelivery ??
      (config.emailDelivery ? new ResendMailDelivery(config.emailDelivery) : undefined),
    publicOrigin: config.emailDelivery?.publicOrigin,
    mfaEncryptionKey: config.mfaEncryptionKey,
    requireOperatorMfa: config.requireOperatorMfa,
    ...(config.webauthn ? { webauthn: config.webauthn } : {}),
    onSecuritySignal: (kind, ctx) => void telemetry.signal(kind, ctx).catch(() => undefined),
    clock,
    audit,
    ...(config.scrypt ? { config: { scrypt: config.scrypt } } : {}),
  });

  const licensing = new LicensingService({
    store: licensingStore,
    clock,
    audit,
    telemetry,
    keyring,
    config: defaultLicensingConfig({
      licenseKeyPepper: config.licenseKeyPepper,
      // Operator-tunable knobs (only when explicitly set; otherwise the licensing defaults apply).
      ...(config.challengeTtlSeconds !== undefined
        ? { challengeTtlSeconds: config.challengeTtlSeconds }
        : {}),
      ...(config.challengeRetentionSeconds !== undefined
        ? { challengeRetentionSeconds: config.challengeRetentionSeconds }
        : {}),
      ...(config.leaseRetentionSeconds !== undefined
        ? { leaseRetentionSeconds: config.leaseRetentionSeconds }
        : {}),
      devicePolicyMode: config.devicePolicyMode,
      ...overrides?.licensing,
    }),
    authorize: async (p, orgId, permission) => {
      await auth.requireOrgPermission(p, orgId, permission);
    },
    orgExists: (id) => auth.orgExists(id),
    isMember: (orgId, userId) => auth.isMember(orgId, userId),
  });

  const billing = config.billing
    ? new BillingService({
        store: licensingStore,
        auth,
        clock,
        provider: overrides?.checkoutProvider ?? new PaddleCheckoutProvider(config.billing),
        verifier: new PaddleWebhookVerifier({
          secret: config.billing.webhookSecret,
          now: () => clock.now().getTime(),
        }),
        prices: config.billing.prices,
      })
    : undefined;

  let sharing: SharingService | undefined;
  let sharingLocalStore: LocalObjectStore | undefined;
  const sc = config.sharing;
  if (sc) {
    const sharingStore: SharingStore = pool
      ? new PgSharingStore(pool, clock, { auditShards: shards })
      : new InMemorySharingStore({ audit });
    let objects: ObjectStore | undefined = overrides?.sharingObjects;
    if (!objects) {
      if (sc.storage.kind === 'local') {
        sharingLocalStore = new LocalObjectStore({
          root: sc.storage.root,
          signingSecret: sc.secret,
          contentOrigin: sc.storage.contentOrigin,
          ...(config.env === 'production' ? {} : { minPartBytes: 1 }),
        });
        objects = sharingLocalStore;
      } else objects = new S3ObjectStore(sc.storage, { now: () => clock.now() });
    }
    const basic = new BasicContentScanner();
    const scanner =
      overrides?.sharingScanner ??
      (sc.clamd ? new ChainedScanner([basic, new ClamdScanner(sc.clamd)]) : basic);
    const scrypt = config.scrypt;
    const mailer =
      overrides?.sharingMailer ??
      (config.emailDelivery ? new ResendMailDelivery(config.emailDelivery) : undefined);
    sharing = new SharingService({
      store: sharingStore,
      objects,
      scanner,
      keys: new SharingKeys(sc.secret),
      clock,
      config: {
        ...DEFAULT_SHARING_CONFIG,
        eventRetentionDays: sc.eventRetentionDays,
        ...(config.env === 'production' ? {} : { partBytes: 5 * 1024 * 1024 }),
        ...overrides?.sharingConfig,
        publicOrigin: sc.publicOrigin,
        shortOrigin: sc.shortOrigin,
      },
      destinations: {
        reservedHosts: [new URL(sc.publicOrigin).hostname, new URL(sc.shortOrigin).hostname],
        blockedHosts: sc.blockedHosts,
      },
      authorize: async (p, orgId, perm) => void (await auth.requireOrgPermission(p, orgId, perm)),
      identity: (userId) => auth.contact(userId),
      isMember: (orgId, userId) => auth.isMember(orgId, userId),
      entitlements: (orgId) => licensing.validEntitlements(orgId),
      passwords: {
        hash: (pw) => hashPassword(pw, scrypt),
        verify: (pw, h) => verifyPassword(pw, h),
      },
      ...(mailer ? { mailer } : {}),
      resolveTxt: overrides?.sharingResolveTxt ?? ((name) => resolveTxt(name)),
    });
  }

  const anchorStore: AnchorStore = pool ? new PgAnchorStore(pool) : new InMemoryAnchorStore();
  const sink =
    overrides?.anchorSink ??
    (config.auditAnchor
      ? new HttpsAnchorSink(
          validateAnchorUrl(config.auditAnchor.url, config.env === 'production'),
          {
            token: config.auditAnchor.token,
          },
        )
      : undefined);
  const anchors = sink
    ? new AnchorPublisher({
        audit,
        store: anchorStore,
        sink,
        clock,
        metrics,
        // A log that fails verification is never witnessed; it is a critical security signal instead.
        onChainInvalid: (f) =>
          telemetry.signal('audit_chain_broken', {
            attributes: { broken_at_seq: f.brokenAtSeq, reason: f.reason },
          }),
      })
    : undefined;
  await anchors?.init();

  const privilegedStore: PrivilegedStore = pool
    ? new PgPrivilegedStore(pool, clock, { auditShards: shards })
    : new InMemoryPrivilegedStore({ audit });
  const privileged = new PrivilegedService({
    store: privilegedStore,
    clock,
    config: {
      dualControlLicenseRevoke: config.privilegedDualControl,
      witnessConfigured: anchors !== undefined,
    },
    stepUp: (p, code) => auth.stepUp(p, code),
    orgExists: (id) => auth.orgExists(id),
    validateTarget: async (op, orgId, targetId) => {
      if (op === 'license.revoke') {
        const state = await licensing.adminLicenseState(orgId!, targetId!);
        if (!state) throw new DomainError('not_found', 'license not found');
        if (state === 'revoked') throw new DomainError('conflict', 'license is already revoked');
      } else if (op === 'operator.grant' || op === 'operator.revoke') {
        const u = await auth.operatorTarget(targetId!);
        if (!u?.active) throw new DomainError('not_found', 'user not found');
        const isOperator = u.platformRole === 'platform_admin';
        if (isOperator === (op === 'operator.grant'))
          throw new DomainError(
            'conflict',
            isOperator ? 'user is already an operator' : 'user is not an operator',
          );
      } else if (op === 'org.unfreeze' && !(await auth.orgExists(orgId!))) {
        throw new DomainError('not_found', 'organization not found');
      }
    },
    run: {
      'license.revoke': async (r) => {
        await licensing.setLicenseState(r.orgId!, r.targetId!, 'revoke', {
          id: r.requestedBy,
          reason: `${r.reason} (privileged request ${r.id})`,
        });
      },
      'operator.grant': (r) =>
        auth.setOperatorRole(r.targetId!, 'platform_admin', {
          id: r.requestedBy,
          reason: r.reason,
          requestId: r.id,
        }),
      'operator.revoke': (r) =>
        auth.setOperatorRole(r.targetId!, 'none', {
          id: r.requestedBy,
          reason: r.reason,
          requestId: r.id,
        }),
    },
  });

  const operationsStore = pool
    ? new PgInventoryStore(pool, clock, { auditShards: shards })
    : new InMemoryInventoryStore({ audit });
  const operations = new InventoryService({
    store: operationsStore,
    clock,
    authorize: async (p, orgId, permission) => {
      await auth.requireOrgPermission(p, orgId, permission);
    },
    assertWritable: (orgId) => privileged.assertWritable(orgId),
    activeMember: async (orgId, userId) =>
      !!(await authStore.findMembership(orgId, userId)) &&
      (await authStore.findUserById(userId))?.status === 'active',
    activeProduct: async (productId) =>
      (await licensingStore.findProductById(productId))?.status === 'active',
  });

  const operationsCredentials = new CredentialService({
    store: operationsStore,
    clock,
    enabled: () => config.operationsCredentialsEnabled && config.operationsInventoryEnabled,
    authorize: async (p, orgId, permission) => {
      await auth.requireOrgPermission(p, orgId, permission);
    },
    assertWritable: (orgId) => privileged.assertWritable(orgId),
    stepUp: (p, code) => auth.stepUp(p, code),
    sessionActive: async (p, now) => {
      const s = await authStore.findSessionById(p.sessionId);
      return (
        !!s &&
        s.userId === p.userId &&
        !s.revokedAt &&
        s.expiresAt > now &&
        (await authStore.findUserById(p.userId))?.status === 'active'
      );
    },
  });

  const operationsHealth = new HealthService({
    store: operationsStore,
    clock,
    enabled: () => config.operationsHealthEnabled && config.operationsInventoryEnabled,
    authorize: async (p, orgId, tx) => {
      if (tx?.authority) {
        await tx.authority.authorize(p, orgId, 'ops:read');
        if (!(await tx.authority.sessionActive?.(p, clock.now())))
          throw new DomainError('unauthenticated', 'authentication required');
      } else {
        await auth.requireOrgPermission(p, orgId, 'ops:read');
        const session = await authStore.findSessionById(p.sessionId);
        if (
          !session ||
          session.userId !== p.userId ||
          session.revokedAt ||
          session.expiresAt <= clock.now()
        )
          throw new DomainError('unauthenticated', 'authentication required');
      }
    },
  });
  const readiness = persistenceReadiness(async () => {
    if (pool) await pool.query('SELECT 1');
  });

  const operationsEvents = new EventService({
    store: operationsStore,
    credentials: operationsCredentials,
    clock,
    enabled: () => config.operationsIngestionEnabled,
  });

  const rateBackend: RateBackend | undefined =
    pool && config.rateLimitStore === 'postgres'
      ? new ResilientRateBackend(new PgRateBackend(pool), new MemoryRateBackend(), {
          // A database problem degrades to per-process counting; make it visible.
          onFallback: (reason) => metrics.inc('rate_limit_fallback_total', { reason }),
        })
      : undefined;

  let closed = false;
  return {
    config,
    clock,
    audit,
    auth,
    operations,
    operationsCredentials,
    operationsEvents,
    operationsHealth,
    readiness,
    licensing,
    billing,
    sharing,
    sharingLocalStore,
    privileged,
    keyring,
    telemetry,
    telemetrySink,
    metrics,
    anchorStore,
    anchors,
    rateBackend,
    dbWarnings: roleWarnings,
    async close() {
      if (closed) return;
      closed = true;
      await auth.closeIdentityMail();
      await writes.flush().catch(() => undefined);
      await (telemetrySink as { flush?: () => Promise<void> }).flush?.().catch(() => undefined);
      if (usePg) setTransactionObserver({});
      metrics.close();
      await ownPool?.end();
    },
  };
}
