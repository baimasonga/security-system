import { AuthService, InMemoryAuthStore, type AuthStore } from '@trust/auth';
import { InMemoryAuditLog, type AuditLog } from '@trust/audit';
import { KeyRing, kidForPublicKey, type KeyRecord } from '@trust/crypto';
import {
  InMemoryLicensingStore,
  LicensingService,
  defaultLicensingConfig,
  type LicensingConfig,
  type LicensingStore,
} from '@trust/licensing';
import { systemClock, type Clock } from '@trust/shared-types';
import { InMemoryTelemetrySink, Telemetry, type TelemetrySink } from '@trust/telemetry';
import pg from 'pg';
import type { PlatformConfig } from './config.ts';
import { MIGRATIONS_DIR, assertSchemaCurrent } from './db/migrate.ts';
import type { PgPool } from './db/pg.ts';
import { PgAuditLog } from './db/pg-audit-log.ts';
import { PgAuthStore } from './db/pg-auth-store.ts';
import { PgKeyStore } from './db/pg-key-store.ts';
import { PgLicensingStore } from './db/pg-licensing-store.ts';
import { PgTelemetrySink } from './db/pg-telemetry-sink.ts';

export interface Container {
  config: PlatformConfig;
  clock: Clock;
  audit: AuditLog;
  auth: AuthService;
  licensing: LicensingService;
  keyring: KeyRing;
  telemetry: Telemetry;
  telemetrySink: TelemetrySink;
  /** Releases pooled resources. Idempotent. */
  close(): Promise<void>;
}

export interface ContainerOverrides {
  clock?: Clock;
  licensing?: Partial<LicensingConfig>;
  /** Test seam: a ready-made pool (e.g. schema-scoped). Implies postgres persistence. */
  pool?: PgPool;
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
  if (usePg && !pool) {
    ownPool = new pg.Pool({ connectionString: config.databaseUrl, max: config.dbPoolMax });
    pool = ownPool;
    await assertSchemaCurrent(pool, MIGRATIONS_DIR);
  }

  const audit: AuditLog = pool ? new PgAuditLog(pool, clock) : new InMemoryAuditLog(clock);
  const telemetrySink: TelemetrySink = pool
    ? new PgTelemetrySink(pool)
    : new InMemoryTelemetrySink();
  const telemetry = new Telemetry({
    sink: telemetrySink,
    clock,
    pseudonymKey: config.pseudonymKey,
  });
  const authStore: AuthStore = pool
    ? new PgAuthStore(pool, clock)
    : new InMemoryAuthStore({ audit });
  const licensingStore: LicensingStore = pool
    ? new PgLicensingStore(pool, clock)
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
      ...overrides?.licensing,
    }),
    authorize: async (p, orgId, permission) => {
      await auth.requireOrgPermission(p, orgId, permission);
    },
    orgExists: (id) => auth.orgExists(id),
  });

  let closed = false;
  return {
    config,
    clock,
    audit,
    auth,
    licensing,
    keyring,
    telemetry,
    telemetrySink,
    async close() {
      if (closed) return;
      closed = true;
      await writes.flush().catch(() => undefined);
      await ownPool?.end();
    },
  };
}
