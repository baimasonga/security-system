import { sign } from 'node:crypto';
import { InMemoryAuditLog } from '@trust/audit';
import {
  KeyRing,
  b64urlEncode,
  generateEd25519,
  jwkThumbprint,
  newId,
  type PublicJwk,
} from '@trust/crypto';
import { buildProofMessage, verifyJws, type ProofPurpose } from '@trust/crypto/verify';
import { DomainError, LEASE_TYP, type LeaseClaims, type UserPrincipal } from '@trust/shared-types';
import { InMemoryTelemetrySink, Telemetry } from '@trust/telemetry';
import { createSchemaPool, pgTestEnabled } from '../../../tests/support/pg.ts';
import { PgLicensingStore } from '../../../services/platform-api/src/db/pg-licensing-store.ts';
import {
  InMemoryLicensingStore,
  LicensingService,
  defaultLicensingConfig,
  type Authorizer,
  type LicensingConfig,
  type LicensingStore,
  type OperatorActor,
} from '../src/index.ts';

export const DAY = 86_400_000;
export const PEPPER = 'test-pepper-test-pepper-test-pepper-0123456789';

export interface World {
  svc: LicensingService;
  store: LicensingStore;
  audit: InMemoryAuditLog;
  sink: InMemoryTelemetrySink;
  keyring: KeyRing;
  config: LicensingConfig;
  clock: { now: () => Date; set: (d: Date) => void; advance: (ms: number) => void };
  members: Map<string, 'owner' | 'admin' | 'member'>; // `${orgId}|${userId}` -> role
  op: OperatorActor;
  user: (userId: string) => UserPrincipal;
  join: (orgId: string, userId: string, role?: 'owner' | 'admin' | 'member') => void;
}

export function world(cfg?: Partial<LicensingConfig>): World {
  let t = new Date('2026-03-01T00:00:00Z');
  // PostgreSQL enforces foreign keys, so fixture orgs/users need real rows (in-memory does not care).
  const pool = pgTestEnabled() ? createSchemaPool() : undefined;
  const fixtures: Promise<unknown>[] = [];
  const settle = () => Promise.all(fixtures.splice(0));
  const clock = {
    now: () => t,
    set: (d: Date) => void (t = d),
    advance: (ms: number) => void (t = new Date(t.getTime() + ms)),
  };
  const audit = new InMemoryAuditLog(clock);
  const sink = new InMemoryTelemetrySink();
  const telemetry = new Telemetry({ sink, clock, pseudonymKey: 'pk' });
  const keyring = new KeyRing({ now: clock.now });
  keyring.activate(keyring.generate('license').kid);
  const store: LicensingStore = pool ? new PgLicensingStore(pool) : new InMemoryLicensingStore();
  const members = new Map<string, 'owner' | 'admin' | 'member'>();

  const authorize: Authorizer = async (p, orgId, perm) => {
    await settle();
    const role = members.get(`${orgId}|${p.userId}`);
    if (!role) throw new DomainError('not_found', 'not found');
    if (perm === 'device:deactivate' && role === 'member') throw new DomainError('forbidden', 'no');
  };
  const config = defaultLicensingConfig({ licenseKeyPepper: PEPPER, ...cfg });
  const svc = new LicensingService({
    store,
    clock,
    audit,
    telemetry,
    keyring,
    config,
    authorize,
    orgExists: async (id) => {
      await settle();
      if (!pool) return id.startsWith('org_');
      return (await pool.query('SELECT 1 FROM organizations WHERE id = $1', [id])).rowCount === 1;
    },
  });
  return {
    svc,
    store,
    audit,
    sink,
    keyring,
    config,
    clock,
    members,
    op: { id: 'usr_operator', reason: 'test setup' },
    user: (userId) => ({ kind: 'user', userId, sessionId: `ses_${userId}`, platformRole: 'none' }),
    join: (orgId, userId, role = 'member') => {
      members.set(`${orgId}|${userId}`, role);
      if (pool) {
        fixtures.push(
          pool.query(
            "INSERT INTO organizations (id, name, kind) VALUES ($1, $1, 'team') ON CONFLICT DO NOTHING",
            [orgId],
          ),
          pool.query(
            "INSERT INTO users (id, email, password_hash) VALUES ($1, $1 || '@fixture.test', 'x') ON CONFLICT DO NOTHING",
            [userId],
          ),
        );
      }
    },
  };
}

/** A simulated customer device: owns a private key and an installation id. */
export class FakeDevice {
  readonly key = generateEd25519();
  readonly installationId = newId('inst').replace('_', '-') + '0123456789'; // 16+ chars
  get publicJwk(): PublicJwk {
    return this.key.publicJwk;
  }
  get thumbprint(): string {
    return jwkThumbprint(this.key.publicJwk);
  }
  sign(msg: string): string {
    return b64urlEncode(sign(null, Buffer.from(msg), this.key.privateKey));
  }
  proof(
    purpose: ProofPurpose,
    nonce: string,
    subjectId: string,
    installationId = this.installationId,
  ) {
    return this.sign(
      buildProofMessage({ purpose, nonce, installationId, subjectId, thumbprint: this.thumbprint }),
    );
  }
}

export async function activate(
  w: World,
  user: UserPrincipal,
  dev: FakeDevice,
  licenseKey: string,
  over?: { nonce?: string; signature?: string; installationId?: string; devicePublicKey?: unknown },
) {
  const installationId = over?.installationId ?? dev.installationId;
  const ch = await w.svc.issueChallenge({ purpose: 'activate', installationId });
  const nonce = over?.nonce ?? ch.nonce;
  return w.svc.activate(user, {
    licenseKey,
    installationId,
    devicePublicKey: over?.devicePublicKey ?? dev.publicJwk,
    nonce,
    signature: over?.signature ?? dev.proof('activate', ch.nonce, '', installationId),
  });
}

export async function deviceCall(
  w: World,
  dev: FakeDevice,
  purpose: Exclude<ProofPurpose, 'activate'>,
  activationId: string,
) {
  const ch = await w.svc.issueChallenge({
    purpose,
    installationId: dev.installationId,
    subjectId: activationId,
  });
  return {
    activationId,
    installationId: dev.installationId,
    nonce: ch.nonce,
    signature: dev.proof(purpose, ch.nonce, activationId),
  };
}

export const refresh = async (w: World, dev: FakeDevice, actId: string) =>
  w.svc.refresh(await deviceCall(w, dev, 'refresh', actId));
export const validate = async (w: World, dev: FakeDevice, actId: string) =>
  w.svc.validate(await deviceCall(w, dev, 'validate', actId));

export function readLease(w: World, token: string): LeaseClaims {
  return verifyJws<LeaseClaims>(token, {
    typ: LEASE_TYP,
    resolveKey: (kid) => w.keyring.resolveVerificationKey('license', kid),
  }).payload;
}

export async function errCode(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'ok';
  } catch (e) {
    if (e instanceof DomainError) return e.code;
    throw e;
  }
}

/** Standard fixture: product + professional plan + active subscription + license owned by org_a. */
export async function seed(
  w: World,
  over?: { deviceLimit?: number; tier?: 'professional' | 'trial' | 'standard' },
) {
  const product = await w.svc.createProduct({ code: 'pdf-pro', name: 'PDF Pro' }, w.op);
  const plan = await w.svc.createPlan(
    {
      productId: product.id,
      code: 'professional',
      tier: over?.tier ?? 'professional',
      entitlements: { pdf_editing: true, ocr_pages_monthly: 5000 },
      capabilities: ['OCR_ADVANCED', 'CLOUD_SYNC'],
      deviceLimit: over?.deviceLimit ?? 3,
    },
    w.op,
  );
  const orgId = 'org_a';
  w.join(orgId, 'usr_alice', 'owner');
  const sub = await w.svc.createSubscription(
    {
      orgId,
      planId: plan.id,
      status: 'active',
      currentPeriodEnd: new Date(w.clock.now().getTime() + 30 * DAY),
    },
    w.op,
  );
  const { license, licenseKey } = await w.svc.issueLicense(
    { orgId, productId: product.id, planId: plan.id, kind: 'subscription', subscriptionId: sub.id },
    w.op,
  );
  return { product, plan, sub, license, licenseKey, orgId, alice: w.user('usr_alice') };
}
