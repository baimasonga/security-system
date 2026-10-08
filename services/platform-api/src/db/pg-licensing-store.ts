import { AuditBuffer } from '@trust/audit';
import { appendAuditInTx } from './pg-audit-log.ts';
import type { Clock } from '@trust/shared-types';
import type {
  Activation,
  Challenge,
  ConsumeResult,
  Device,
  License,
  LicenseContext,
  LicensingRepo,
  LicensingStore,
  LicensingTx,
  LeaseRecord,
  Plan,
  Product,
  Subscription,
  TrialClaim,
} from '@trust/licensing';
import {
  FK_VIOLATION,
  UNIQUE_VIOLATION,
  pgErr,
  serialized,
  withTransaction,
  type PgPool,
  type Queryable,
} from './pg.ts';

// ---- row mapping -------------------------------------------------------------------------------
type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const product = (r: Row): Product => ({
  id: r.id,
  code: r.code,
  name: r.name,
  status: r.status,
  createdAt: r.created_at,
});
const plan = (r: Row): Plan => ({
  id: r.id,
  productId: r.product_id,
  code: r.code,
  tier: r.tier,
  version: r.version,
  entitlements: r.entitlements,
  capabilities: r.capabilities,
  deviceLimit: r.device_limit,
  updatedAt: r.updated_at,
});
const subscription = (r: Row): Subscription => ({
  id: r.id,
  orgId: r.org_id,
  planId: r.plan_id,
  status: r.status,
  trialEnd: r.trial_end,
  currentPeriodEnd: r.current_period_end,
  createdAt: r.created_at,
});
const license = (r: Row): License => ({
  id: r.id,
  orgId: r.org_id,
  productId: r.product_id,
  planId: r.plan_id,
  subscriptionId: r.subscription_id,
  kind: r.kind,
  state: r.status,
  keyDigest: r.key_hash,
  expiresAt: r.expires_at,
  overrides: r.entitlement_overrides,
  createdAt: r.created_at,
});
const device = (r: Row): Device => ({
  id: r.id,
  orgId: r.org_id,
  thumbprint: r.thumbprint,
  publicKey: r.public_key_jwk,
  createdAt: r.created_at,
});
const activation = (r: Row): Activation => ({
  id: r.id,
  orgId: r.org_id,
  licenseId: r.license_id,
  deviceId: r.device_id,
  installationId: r.installation_id,
  activatedBy: r.activated_by,
  status: r.status,
  activatedAt: r.activated_at,
  lastValidatedAt: r.last_validated_at,
  lastLeaseId: r.last_lease_id,
  lastLeaseExp: r.last_lease_exp,
  deactivatedAt: r.deactivated_at,
});
const challenge = (r: Row): Challenge => ({
  nonceHash: r.nonce_hash,
  purpose: r.purpose,
  installationId: r.installation_id,
  subjectId: r.subject_id,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  consumedAt: r.consumed_at,
});

/** `t.a AS p__a, t.b AS p__b, …` so several tables can be read in one row and split apart again. */
const prefixed = (t: string, p: string, cols: readonly string[]) =>
  cols.map((c) => `${t}.${c} AS ${p}__${c}`).join(', ');
const unprefix = (r: Row, p: string): Row => {
  const out: Row = {};
  for (const [k, v] of Object.entries(r))
    if (k.startsWith(`${p}__`)) out[k.slice(p.length + 2)] = v;
  return out;
};
const LICENSE_COLS = [
  'id',
  'org_id',
  'product_id',
  'plan_id',
  'subscription_id',
  'kind',
  'status',
  'key_hash',
  'expires_at',
  'entitlement_overrides',
  'created_at',
] as const;
const PLAN_COLS = [
  'id',
  'product_id',
  'code',
  'tier',
  'version',
  'entitlements',
  'capabilities',
  'device_limit',
  'updated_at',
] as const;
const PRODUCT_COLS = ['id', 'code', 'name', 'status', 'created_at'] as const;
const SUB_COLS = [
  'id',
  'org_id',
  'plan_id',
  'status',
  'trial_end',
  'current_period_end',
  'created_at',
] as const;
const DEVICE_COLS = ['id', 'org_id', 'thumbprint', 'public_key_jwk', 'created_at'] as const;
const ACTIVATION_COLS = [
  'id',
  'org_id',
  'license_id',
  'device_id',
  'installation_id',
  'activated_by',
  'status',
  'activated_at',
  'last_validated_at',
  'last_lease_id',
  'last_lease_exp',
  'deactivated_at',
] as const;

const CONTEXT_SQL = `SELECT ${prefixed('l', 'l', LICENSE_COLS)}, ${prefixed('p', 'p', PLAN_COLS)},
       ${prefixed('pr', 'pr', PRODUCT_COLS)}, ${prefixed('s', 's', SUB_COLS)}
  FROM licenses l
  JOIN plans p ON p.id = l.plan_id
  JOIN products pr ON pr.id = l.product_id
  LEFT JOIN subscriptions s ON s.id = l.subscription_id AND s.org_id = l.org_id
 WHERE l.id = $1 AND l.org_id = $2`;
const CONTEXT_LOCK = { none: '', share: ' FOR SHARE OF l', update: ' FOR UPDATE OF l' } as const;

/** Map PostgreSQL constraint failures to the same error messages the in-memory adapter throws. */
function translate(e: unknown, map: Record<string, string>): never {
  const { code, constraint } = pgErr(e);
  if (code === UNIQUE_VIOLATION && constraint && map[constraint]) throw new Error(map[constraint]);
  if (code === UNIQUE_VIOLATION && map['*unique']) throw new Error(map['*unique']);
  if (code === FK_VIOLATION && map['*fk']) throw new Error(map['*fk']);
  throw e;
}

class PgRepo implements LicensingRepo {
  readonly #q: Queryable;
  /** True inside a transaction: device-auth reads lock the activation row. */
  readonly #tx: boolean;
  constructor(q: Queryable, tx: boolean) {
    // Inside a transaction every read shares one connection: queue them explicitly.
    this.#q = tx ? serialized(q) : q;
    this.#tx = tx;
  }

  async #one(sql: string, params: unknown[]): Promise<Row | undefined> {
    return (await this.#q.query(sql, params)).rows[0];
  }
  async #many(sql: string, params: unknown[]): Promise<Row[]> {
    return (await this.#q.query(sql, params)).rows;
  }

  // ---- catalog ----
  async insertProduct(p: Product) {
    try {
      await this.#q.query(
        'INSERT INTO products (id, code, name, status, created_at) VALUES ($1,$2,$3,$4,$5)',
        [p.id, p.code, p.name, p.status, p.createdAt],
      );
    } catch (e) {
      translate(e, { products_code_uq: 'duplicate_product_code' });
    }
  }
  async findProductById(id: string) {
    const r = await this.#one('SELECT * FROM products WHERE id = $1', [id]);
    return r ? product(r) : undefined;
  }
  async findProductByCode(code: string) {
    const r = await this.#one('SELECT * FROM products WHERE code = $1', [code]);
    return r ? product(r) : undefined;
  }
  async listProducts() {
    return (await this.#many('SELECT * FROM products ORDER BY created_at, id', [])).map(product);
  }

  async insertPlan(p: Plan) {
    try {
      await this.#q.query(
        'INSERT INTO plans (id, product_id, code, tier, version, entitlements, capabilities, device_limit, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [
          p.id,
          p.productId,
          p.code,
          p.tier,
          p.version,
          p.entitlements,
          p.capabilities,
          p.deviceLimit,
          p.updatedAt,
        ],
      );
    } catch (e) {
      translate(e, { plans_product_code_uq: 'duplicate_plan_code' });
    }
  }
  async updatePlan(p: Plan) {
    await this.#q.query(
      'UPDATE plans SET tier=$2, version=$3, entitlements=$4, capabilities=$5, device_limit=$6, updated_at=$7 WHERE id=$1',
      [p.id, p.tier, p.version, p.entitlements, p.capabilities, p.deviceLimit, p.updatedAt],
    );
  }
  async findPlan(id: string) {
    const r = await this.#one('SELECT * FROM plans WHERE id = $1', [id]);
    return r ? plan(r) : undefined;
  }
  async findTrialPlan(productId: string) {
    const r = await this.#one(
      "SELECT * FROM plans WHERE product_id = $1 AND tier = 'trial' ORDER BY updated_at, id LIMIT 1",
      [productId],
    );
    return r ? plan(r) : undefined;
  }
  async listPlans(productId: string) {
    return (
      await this.#many('SELECT * FROM plans WHERE product_id = $1 ORDER BY updated_at, id', [
        productId,
      ])
    ).map(plan);
  }

  // ---- subscriptions ----
  async insertSubscription(s: Subscription) {
    await this.#q.query(
      'INSERT INTO subscriptions (id, org_id, plan_id, status, trial_end, current_period_end, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [s.id, s.orgId, s.planId, s.status, s.trialEnd, s.currentPeriodEnd, s.createdAt],
    );
  }
  async updateSubscription(s: Subscription) {
    const r = await this.#q.query(
      'UPDATE subscriptions SET plan_id=$3, status=$4, trial_end=$5, current_period_end=$6 WHERE id=$1 AND org_id=$2',
      [s.id, s.orgId, s.planId, s.status, s.trialEnd, s.currentPeriodEnd],
    );
    if (r.rowCount === 0) throw new Error('subscription_not_found');
  }
  async findSubscription(orgId: string, id: string) {
    const r = await this.#one('SELECT * FROM subscriptions WHERE id = $1 AND org_id = $2', [
      id,
      orgId,
    ]);
    return r ? subscription(r) : undefined;
  }
  async listSubscriptions(orgId: string) {
    return (
      await this.#many('SELECT * FROM subscriptions WHERE org_id = $1 ORDER BY created_at, id', [
        orgId,
      ])
    ).map(subscription);
  }

  // ---- licenses ----
  async insertLicense(l: License) {
    try {
      await this.#q.query(
        `INSERT INTO licenses (id, org_id, product_id, plan_id, subscription_id, kind, status, key_hash, expires_at, entitlement_overrides, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          l.id,
          l.orgId,
          l.productId,
          l.planId,
          l.subscriptionId,
          l.kind,
          l.state,
          l.keyDigest,
          l.expiresAt,
          l.overrides,
          l.createdAt,
        ],
      );
    } catch (e) {
      translate(e, { licenses_key_hash_uq: 'duplicate_key', '*fk': 'cross_tenant_reference' });
    }
  }
  async updateLicense(l: License) {
    const r = await this.#q.query(
      'UPDATE licenses SET status=$3, expires_at=$4, entitlement_overrides=$5, plan_id=$6 WHERE id=$1 AND org_id=$2',
      [l.id, l.orgId, l.state, l.expiresAt, l.overrides, l.planId],
    );
    if (r.rowCount === 0) throw new Error('license_not_found');
  }
  async findLicense(orgId: string, id: string) {
    const r = await this.#one('SELECT * FROM licenses WHERE id = $1 AND org_id = $2', [id, orgId]);
    return r ? license(r) : undefined;
  }
  async findLicenseForUpdate(orgId: string, id: string) {
    const r = await this.#one('SELECT * FROM licenses WHERE id = $1 AND org_id = $2 FOR UPDATE', [
      id,
      orgId,
    ]);
    return r ? license(r) : undefined;
  }
  async findLicenseForShare(orgId: string, id: string) {
    const r = await this.#one('SELECT * FROM licenses WHERE id = $1 AND org_id = $2 FOR SHARE', [
      id,
      orgId,
    ]);
    return r ? license(r) : undefined;
  }
  async listLicenses(orgId: string) {
    return (
      await this.#many('SELECT * FROM licenses WHERE org_id = $1 ORDER BY created_at, id', [orgId])
    ).map(license);
  }
  async findLicenseContext(
    orgId: string,
    id: string,
    lock: 'none' | 'share' | 'update',
  ): Promise<LicenseContext | undefined> {
    const r = await this.#one(CONTEXT_SQL + CONTEXT_LOCK[lock], [id, orgId]);
    if (!r) return undefined;
    const s = unprefix(r, 's');
    return {
      license: license(unprefix(r, 'l')),
      plan: plan(unprefix(r, 'p')),
      product: product(unprefix(r, 'pr')),
      subscription: s['id'] === null ? undefined : subscription(s),
    };
  }
  async findLicenseByKeyDigest(digest: string) {
    const r = await this.#one('SELECT * FROM licenses WHERE key_hash = $1', [digest]);
    return r ? license(r) : undefined;
  }

  async insertTrialClaim(c: TrialClaim) {
    try {
      await this.#q.query(
        'INSERT INTO trial_claims (product_id, org_id, user_id, license_id, created_at) VALUES ($1,$2,$3,$4,$5)',
        [c.productId, c.orgId, c.userId, c.licenseId, c.createdAt],
      );
    } catch (e) {
      translate(e, { '*unique': 'trial_exists' });
    }
  }

  // ---- devices & activations ----
  async findDeviceByThumbprint(thumbprint: string) {
    const r = await this.#one('SELECT * FROM devices WHERE thumbprint = $1', [thumbprint]);
    return r ? device(r) : undefined;
  }
  async findDevice(orgId: string, id: string) {
    const r = await this.#one('SELECT * FROM devices WHERE id = $1 AND org_id = $2', [id, orgId]);
    return r ? device(r) : undefined;
  }
  async insertDevice(d: Device): Promise<Device> {
    // One statement for both outcomes: the inserted row, else the one that already exists.
    const ins = await this.#one(
      `WITH ins AS (
         INSERT INTO devices (id, org_id, thumbprint, public_key_jwk, created_at) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (thumbprint) DO NOTHING RETURNING *)
       SELECT * FROM ins
       UNION ALL
       SELECT * FROM devices WHERE thumbprint = $3 AND NOT EXISTS (SELECT 1 FROM ins)`,
      [d.id, d.orgId, d.thumbprint, d.publicKey, d.createdAt],
    );
    if (ins) return device(ins);
    // Lost a race with a concurrent insert that committed after our statement started; it is visible now.
    const existing = await this.findDeviceByThumbprint(d.thumbprint);
    if (!existing) throw new Error('device insert raced with a delete'); // devices are never deleted
    return existing;
  }

  async insertActivation(a: Activation) {
    try {
      await this.#q.query(
        `INSERT INTO activations (id, org_id, license_id, device_id, installation_id, activated_by, status, activated_at,
           last_validated_at, last_lease_id, last_lease_exp, deactivated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          a.id,
          a.orgId,
          a.licenseId,
          a.deviceId,
          a.installationId,
          a.activatedBy,
          a.status,
          a.activatedAt,
          a.lastValidatedAt,
          a.lastLeaseId,
          a.lastLeaseExp,
          a.deactivatedAt,
        ],
      );
    } catch (e) {
      translate(e, {
        activations_one_active_uq: 'duplicate_active_activation',
        '*fk': 'cross_tenant_reference',
      });
    }
  }
  async updateActivation(a: Activation) {
    try {
      const r = await this.#q.query(
        `UPDATE activations SET installation_id=$3, status=$4, last_validated_at=$5, last_lease_id=$6, last_lease_exp=$7, deactivated_at=$8
         WHERE id=$1 AND org_id=$2`,
        [
          a.id,
          a.orgId,
          a.installationId,
          a.status,
          a.lastValidatedAt,
          a.lastLeaseId,
          a.lastLeaseExp,
          a.deactivatedAt,
        ],
      );
      if (r.rowCount === 0) throw new Error('activation_not_found');
    } catch (e) {
      translate(e, { activations_one_active_uq: 'duplicate_active_activation' });
    }
  }
  async findActivation(orgId: string, id: string) {
    const r = await this.#one('SELECT * FROM activations WHERE id = $1 AND org_id = $2', [
      id,
      orgId,
    ]);
    return r ? activation(r) : undefined;
  }
  async findActivationForDeviceAuth(id: string) {
    const r = await this.#one(
      `SELECT * FROM activations WHERE id = $1${this.#tx ? ' FOR UPDATE' : ''}`,
      [id],
    );
    return r ? activation(r) : undefined;
  }
  async findActivationWithDevice(id: string) {
    const r = await this.#one(
      `SELECT ${prefixed('a', 'a', ACTIVATION_COLS)}, ${prefixed('d', 'd', DEVICE_COLS)}
         FROM activations a JOIN devices d ON d.id = a.device_id AND d.org_id = a.org_id
        WHERE a.id = $1${this.#tx ? ' FOR UPDATE OF a' : ''}`,
      [id],
    );
    return r
      ? { activation: activation(unprefix(r, 'a')), device: device(unprefix(r, 'd')) }
      : undefined;
  }
  async findActivationSlot(licenseId: string, deviceId: string) {
    // Both facts in one read; the count row always exists, the activation columns are NULL when absent.
    const r = (await this.#one(
      `SELECT c.used, a.*
         FROM (SELECT count(*)::int AS used FROM activations WHERE license_id = $1 AND status = 'active') c
         LEFT JOIN activations a ON a.license_id = $1 AND a.device_id = $2 AND a.status = 'active'`,
      [licenseId, deviceId],
    ))!;
    return { existing: r['id'] === null ? undefined : activation(r), used: r['used'] as number };
  }
  async findActiveActivation(licenseId: string, deviceId: string) {
    const r = await this.#one(
      "SELECT * FROM activations WHERE license_id = $1 AND device_id = $2 AND status = 'active'",
      [licenseId, deviceId],
    );
    return r ? activation(r) : undefined;
  }
  async countActiveActivations(licenseId: string) {
    const r = await this.#one(
      "SELECT count(*)::int AS n FROM activations WHERE license_id = $1 AND status = 'active'",
      [licenseId],
    );
    return r?.n ?? 0;
  }
  async listActivationsForLicense(orgId: string, licenseId: string) {
    return (
      await this.#many(
        'SELECT * FROM activations WHERE org_id = $1 AND license_id = $2 ORDER BY activated_at, id',
        [orgId, licenseId],
      )
    ).map(activation);
  }

  async insertLease(r: LeaseRecord) {
    try {
      await this.#q.query(
        'INSERT INTO leases (jti, org_id, activation_id, plan_version, issued_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [r.jti, r.orgId, r.activationId, r.planVersion, r.issuedAt, r.expiresAt],
      );
    } catch (e) {
      translate(e, { '*fk': 'cross_tenant_reference' });
    }
  }

  async recordLease(r: LeaseRecord, a: Activation) {
    // One statement: the lease INSERT's foreign keys and the activation UPDATE succeed or fail together.
    try {
      const res = await this.#q.query(
        `WITH lease AS (
           INSERT INTO leases (jti, org_id, activation_id, plan_version, issued_at, expires_at)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING 1)
         UPDATE activations SET installation_id=$7, status=$8, last_validated_at=$9, last_lease_id=$10,
                last_lease_exp=$11, deactivated_at=$12
          WHERE id=$3 AND org_id=$2 AND EXISTS (SELECT 1 FROM lease)`,
        [
          r.jti,
          r.orgId,
          r.activationId,
          r.planVersion,
          r.issuedAt,
          r.expiresAt,
          a.installationId,
          a.status,
          a.lastValidatedAt,
          a.lastLeaseId,
          a.lastLeaseExp,
          a.deactivatedAt,
        ],
      );
      if (res.rowCount !== 1) throw new Error('activation_not_found');
    } catch (e) {
      translate(e, { '*fk': 'cross_tenant_reference' });
    }
  }

  // ---- challenges ----
  async insertChallenge(c: Challenge) {
    await this.#q.query(
      'INSERT INTO challenges (nonce_hash, purpose, installation_id, subject_id, created_at, expires_at, consumed_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [
        c.nonceHash,
        c.purpose,
        c.installationId,
        c.subjectId,
        c.createdAt,
        c.expiresAt,
        c.consumedAt,
      ],
    );
  }
  async insertChallengeIfBelow(c: Challenge, max: number, now: Date) {
    const r = await this.#q.query(
      `INSERT INTO challenges (nonce_hash, purpose, installation_id, subject_id, created_at, expires_at, consumed_at)
       SELECT $1::text,$2::text,$3::text,$4::text,$5::timestamptz,$6::timestamptz,$7::timestamptz
        WHERE (SELECT count(*) FROM challenges WHERE installation_id = $3 AND consumed_at IS NULL AND expires_at > $8) < $9`,
      [
        c.nonceHash,
        c.purpose,
        c.installationId,
        c.subjectId,
        c.createdAt,
        c.expiresAt,
        c.consumedAt,
        now,
        max,
      ],
    );
    return r.rowCount === 1;
  }
  async countOutstandingChallenges(installationId: string, now: Date) {
    const r = await this.#one(
      'SELECT count(*)::int AS n FROM challenges WHERE installation_id = $1 AND consumed_at IS NULL AND expires_at > $2',
      [installationId, now],
    );
    return r?.n ?? 0;
  }
  /** Single atomic UPDATE: exactly one concurrent caller gets the row back. */
  async consumeChallenge(nonceHash: string, now: Date): Promise<ConsumeResult> {
    const won = await this.#one(
      'UPDATE challenges SET consumed_at = $2 WHERE nonce_hash = $1 AND consumed_at IS NULL RETURNING *',
      [nonceHash, now],
    );
    if (won) {
      const c = challenge(won);
      return c.expiresAt <= now ? { status: 'expired' } : { status: 'ok', challenge: c };
    }
    const exists = await this.#one('SELECT 1 AS x FROM challenges WHERE nonce_hash = $1', [
      nonceHash,
    ]);
    return { status: exists ? 'used' : 'missing' };
  }
  // Batched with a ctid subselect so one call never holds a long lock or produces a huge WAL burst.
  async purgeExpiredChallenges(before: Date, limit = 5000) {
    const r = await this.#q.query(
      'DELETE FROM challenges WHERE ctid IN (SELECT ctid FROM challenges WHERE expires_at < $1 LIMIT $2)',
      [before, limit],
    );
    return r.rowCount ?? 0;
  }
  async purgeExpiredLeases(before: Date, limit = 5000) {
    const r = await this.#q.query(
      'DELETE FROM leases WHERE ctid IN (SELECT ctid FROM leases WHERE expires_at < $1 LIMIT $2)',
      [before, limit],
    );
    return r.rowCount ?? 0;
  }
}

export class PgLicensingStore extends PgRepo implements LicensingStore {
  readonly #pool: PgPool;
  readonly #clock: Clock;
  readonly #auditShards: number;
  constructor(pool: PgPool, clock: Clock, opts?: { auditShards?: number }) {
    super(pool, false);
    this.#pool = pool;
    this.#clock = clock;
    this.#auditShards = opts?.auditShards ?? 1;
  }

  transaction<T>(fn: (tx: LicensingTx) => Promise<T>): Promise<T> {
    return withTransaction(this.#pool, async (client) => {
      // A fresh buffer per attempt: if the attempt is retried, nothing from the failed one leaks.
      const buffer = new AuditBuffer();
      const tx = Object.assign(new PgRepo(client, true), {
        audit: buffer,
      }) as unknown as LicensingTx;
      const out = await fn(tx);
      // Last statement before COMMIT, so the chain lock is held only briefly.
      await appendAuditInTx(client, this.#clock, buffer.drain(), this.#auditShards);
      return out;
    });
  }
}
