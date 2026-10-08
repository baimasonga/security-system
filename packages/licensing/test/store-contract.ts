import { describe, expect, it } from 'vitest';
import type {
  Activation,
  Device,
  License,
  LicensingStore,
  Plan,
  Subscription,
} from '../src/index.ts';

export interface StoreHarness {
  store: LicensingStore;
  /** Create the org / user rows other tables reference (no-ops for adapters without foreign keys). */
  seedOrg(id: string): Promise<void>;
  seedUser(id: string): Promise<void>;
  /** Actions of audit events that have been durably committed, oldest first. */
  audited(): Promise<string[]>;
}

const T = new Date('2026-03-01T00:00:00Z');
const later = (ms: number) => new Date(T.getTime() + ms);
let n = 0;
const uid = (p: string) => `${p}_${(++n).toString(16).padStart(8, '0')}`;

const code = (prefix: string) => `${prefix}-${(++n).toString(16)}`; // matches ^[a-z0-9][a-z0-9-]*$
const product = (productCode = code('prod')) => ({
  id: uid('prd'),
  code: productCode,
  name: 'P',
  status: 'active' as const,
  createdAt: T,
});
const plan = (productId: string, over: Partial<Plan> = {}): Plan => ({
  id: uid('pln'),
  productId,
  code: code('plan'),
  tier: 'professional',
  version: 1,
  entitlements: { pdf_editing: true, ocr_pages_monthly: 5000 },
  capabilities: ['CLOUD_SYNC', 'OCR_ADVANCED'],
  deviceLimit: 3,
  updatedAt: T,
  ...over,
});
const sub = (orgId: string, planId: string, over: Partial<Subscription> = {}): Subscription => ({
  id: uid('sub'),
  orgId,
  planId,
  status: 'active',
  trialEnd: null,
  currentPeriodEnd: later(30 * 86400_000),
  createdAt: T,
  ...over,
});
const lic = (
  orgId: string,
  productId: string,
  planId: string,
  subscriptionId: string | null,
  over: Partial<License> = {},
): License => ({
  id: uid('lic'),
  orgId,
  productId,
  planId,
  subscriptionId,
  kind: subscriptionId ? 'subscription' : 'perpetual',
  state: 'active',
  keyDigest: uid('digest'),
  expiresAt: null,
  overrides: {},
  createdAt: T,
  ...over,
});
const dev = (orgId: string, thumbprint = uid('tp')): Device => ({
  id: uid('dev'),
  orgId,
  thumbprint,
  publicKey: { kty: 'OKP', crv: 'Ed25519', x: 'abc' } as never,
  createdAt: T,
});
const act = (
  a: { orgId: string; licenseId: string; deviceId: string; by: string },
  over: Partial<Activation> = {},
): Activation => ({
  id: uid('act'),
  orgId: a.orgId,
  licenseId: a.licenseId,
  deviceId: a.deviceId,
  installationId: 'inst_0123456789abcdef',
  activatedBy: a.by,
  status: 'active',
  activatedAt: T,
  lastValidatedAt: null,
  lastLeaseId: null,
  lastLeaseExp: null,
  deactivatedAt: null,
  ...over,
});

/** One definition of correct LicensingStore behaviour, run against every adapter. */
export function licensingStoreContract(
  name: string,
  make: () => StoreHarness | Promise<StoreHarness>,
) {
  async function fixture() {
    const h = await make();
    const orgA = uid('org');
    const orgB = uid('org');
    const user = uid('usr');
    await Promise.all([h.seedOrg(orgA), h.seedOrg(orgB), h.seedUser(user)]);
    const prd = product();
    await h.store.insertProduct(prd);
    const pln = plan(prd.id);
    await h.store.insertPlan(pln);
    return { ...h, orgA, orgB, user, prd, pln };
  }

  describe(`LicensingStore contract: ${name}`, () => {
    describe('catalog', () => {
      it('enforces unique product codes and unique plan codes per product', async () => {
        const f = await fixture();
        await expect(f.store.insertProduct(product(f.prd.code))).rejects.toThrow(
          'duplicate_product_code',
        );
        await expect(f.store.insertPlan(plan(f.prd.id, { code: f.pln.code }))).rejects.toThrow(
          'duplicate_plan_code',
        );
        const other = product();
        await f.store.insertProduct(other);
        await f.store.insertPlan(plan(other.id, { code: f.pln.code })); // same code, different product: fine
        expect((await f.store.findProductByCode(f.prd.code))!.id).toBe(f.prd.id);
        expect(await f.store.findProductById('prd_nope')).toBeUndefined();
        expect((await f.store.listProducts()).map((p) => p.id)).toEqual(
          expect.arrayContaining([f.prd.id, other.id]),
        );
      });

      it('round-trips plan data and updates in place (version bump)', async () => {
        const f = await fixture();
        const got = (await f.store.findPlan(f.pln.id))!;
        expect(got).toMatchObject({
          entitlements: f.pln.entitlements,
          capabilities: ['CLOUD_SYNC', 'OCR_ADVANCED'],
          deviceLimit: 3,
          version: 1,
          tier: 'professional',
        });
        await f.store.updatePlan({
          ...got,
          version: 2,
          capabilities: ['AI_DOCUMENT_ASSISTANT'],
          entitlements: { x: 1 },
          deviceLimit: 5,
          updatedAt: later(1000),
        });
        expect(await f.store.findPlan(f.pln.id)).toMatchObject({
          version: 2,
          capabilities: ['AI_DOCUMENT_ASSISTANT'],
          entitlements: { x: 1 },
          deviceLimit: 5,
          updatedAt: later(1000),
        });
        expect((await f.store.listPlans(f.prd.id)).length).toBe(1);
      });

      it('finds the trial plan only', async () => {
        const f = await fixture();
        expect(await f.store.findTrialPlan(f.prd.id)).toBeUndefined();
        const tp = plan(f.prd.id, { tier: 'trial', deviceLimit: 1 });
        await f.store.insertPlan(tp);
        expect((await f.store.findTrialPlan(f.prd.id))!.id).toBe(tp.id);
      });
    });

    describe('tenant scoping', () => {
      it('subscriptions and licenses are visible only inside their org', async () => {
        const f = await fixture();
        const s = sub(f.orgA, f.pln.id);
        await f.store.insertSubscription(s);
        const l = lic(f.orgA, f.prd.id, f.pln.id, s.id);
        await f.store.insertLicense(l);
        expect(await f.store.findSubscription(f.orgA, s.id)).toMatchObject({
          id: s.id,
          status: 'active',
          currentPeriodEnd: s.currentPeriodEnd,
        });
        expect(await f.store.findSubscription(f.orgB, s.id)).toBeUndefined();
        expect(await f.store.findLicense(f.orgA, l.id)).toMatchObject({
          id: l.id,
          subscriptionId: s.id,
          kind: 'subscription',
          state: 'active',
        });
        expect(await f.store.findLicense(f.orgB, l.id)).toBeUndefined();
        expect(await f.store.findLicenseForUpdate(f.orgB, l.id)).toBeUndefined();
        expect((await f.store.listLicenses(f.orgA)).map((x) => x.id)).toEqual([l.id]);
        expect(await f.store.listLicenses(f.orgB)).toEqual([]);
        expect((await f.store.listSubscriptions(f.orgA)).map((x) => x.id)).toEqual([s.id]);
      });

      it('a license cannot reference another tenant’s subscription', async () => {
        const f = await fixture();
        const s = sub(f.orgA, f.pln.id);
        await f.store.insertSubscription(s);
        await expect(f.store.insertLicense(lic(f.orgB, f.prd.id, f.pln.id, s.id))).rejects.toThrow(
          'cross_tenant_reference',
        );
      });

      it('updates cannot cross tenants', async () => {
        const f = await fixture();
        const s = sub(f.orgA, f.pln.id);
        await f.store.insertSubscription(s);
        await expect(
          f.store.updateSubscription({ ...s, orgId: f.orgB, status: 'canceled' }),
        ).rejects.toThrow('subscription_not_found');
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        await expect(
          f.store.updateLicense({ ...l, orgId: f.orgB, state: 'revoked' }),
        ).rejects.toThrow('license_not_found');
        expect((await f.store.findLicense(f.orgA, l.id))!.state).toBe('active');
      });
    });

    describe('licenses', () => {
      it('key digests are unique and resolvable without a tenant', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null, {
          expiresAt: later(5000),
          overrides: { deviceLimit: 9, capabilities: { add: ['X_CAP'] } },
        });
        await f.store.insertLicense(l);
        await expect(
          f.store.insertLicense(lic(f.orgB, f.prd.id, f.pln.id, null, { keyDigest: l.keyDigest })),
        ).rejects.toThrow('duplicate_key');
        const found = (await f.store.findLicenseByKeyDigest(l.keyDigest))!;
        expect(found).toMatchObject({
          id: l.id,
          orgId: f.orgA,
          expiresAt: later(5000),
          overrides: { deviceLimit: 9, capabilities: { add: ['X_CAP'] } },
        });
        expect(await f.store.findLicenseByKeyDigest('nope')).toBeUndefined();
      });

      it('persists state changes', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        await f.store.updateLicense({ ...l, state: 'suspended' });
        expect((await f.store.findLicense(f.orgA, l.id))!.state).toBe('suspended');
      });

      it('one trial claim per (product, org) and per (product, user)', async () => {
        const f = await fixture();
        const user2 = uid('usr');
        await f.seedUser(user2);
        const mk = async (org: string) => {
          const s = sub(org, f.pln.id, {
            status: 'trialing',
            trialEnd: later(86400_000),
            currentPeriodEnd: null,
          });
          await f.store.insertSubscription(s);
          const l = lic(org, f.prd.id, f.pln.id, s.id, { kind: 'trial' });
          await f.store.insertLicense(l);
          return l;
        };
        const l1 = await mk(f.orgA);
        await f.store.insertTrialClaim({
          productId: f.prd.id,
          orgId: f.orgA,
          userId: f.user,
          licenseId: l1.id,
          createdAt: T,
        });
        const l2 = await mk(f.orgA);
        await expect(
          f.store.insertTrialClaim({
            productId: f.prd.id,
            orgId: f.orgA,
            userId: user2,
            licenseId: l2.id,
            createdAt: T,
          }),
        ).rejects.toThrow('trial_exists');
        const l3 = await mk(f.orgB);
        await expect(
          f.store.insertTrialClaim({
            productId: f.prd.id,
            orgId: f.orgB,
            userId: f.user,
            licenseId: l3.id,
            createdAt: T,
          }),
        ).rejects.toThrow('trial_exists');
        await f.store.insertTrialClaim({
          productId: f.prd.id,
          orgId: f.orgB,
          userId: user2,
          licenseId: l3.id,
          createdAt: T,
        }); // fresh org + fresh user
      });
    });

    describe('devices and activations', () => {
      it('insertDevice is idempotent on the key and returns the existing device', async () => {
        const f = await fixture();
        const d1 = dev(f.orgA, 'tp_same');
        expect((await f.store.insertDevice(d1)).id).toBe(d1.id);
        const again = await f.store.insertDevice({ ...dev(f.orgB, 'tp_same') });
        expect(again).toMatchObject({ id: d1.id, orgId: f.orgA }); // existing wins; caller detects the org mismatch
        expect((await f.store.findDeviceByThumbprint('tp_same'))!.id).toBe(d1.id);
        expect(await f.store.findDevice(f.orgB, d1.id)).toBeUndefined();
        expect((await f.store.findDevice(f.orgA, d1.id))!.publicKey).toMatchObject({ kty: 'OKP' });
      });

      it('allows one ACTIVE activation per license+device; history and re-activation are fine', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        const d = await f.store.insertDevice(dev(f.orgA));
        const a1 = act({ orgId: f.orgA, licenseId: l.id, deviceId: d.id, by: f.user });
        await f.store.insertActivation(a1);
        await expect(
          f.store.insertActivation(
            act({ orgId: f.orgA, licenseId: l.id, deviceId: d.id, by: f.user }),
          ),
        ).rejects.toThrow('duplicate_active_activation');
        expect((await f.store.findActiveActivation(l.id, d.id))!.id).toBe(a1.id);
        await f.store.updateActivation({ ...a1, status: 'deactivated', deactivatedAt: later(1) });
        expect(await f.store.findActiveActivation(l.id, d.id)).toBeUndefined();
        expect(await f.store.countActiveActivations(l.id)).toBe(0);
        await f.store.insertActivation(
          act({ orgId: f.orgA, licenseId: l.id, deviceId: d.id, by: f.user }),
        );
        expect(await f.store.countActiveActivations(l.id)).toBe(1);
        expect((await f.store.listActivationsForLicense(f.orgA, l.id)).length).toBe(2);
        expect(await f.store.listActivationsForLicense(f.orgB, l.id)).toEqual([]);
      });

      it('rejects activations that join different tenants’ licenses and devices', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        const dB = await f.store.insertDevice(dev(f.orgB));
        await expect(
          f.store.insertActivation(
            act({ orgId: f.orgA, licenseId: l.id, deviceId: dB.id, by: f.user }),
          ),
        ).rejects.toThrow('cross_tenant_reference');
      });

      it('round-trips activation fields and scopes lookups by tenant (device-auth lookup is unscoped by design)', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        const d = await f.store.insertDevice(dev(f.orgA));
        const a = act({ orgId: f.orgA, licenseId: l.id, deviceId: d.id, by: f.user });
        await f.store.insertActivation(a);
        await f.store.updateActivation({
          ...a,
          lastValidatedAt: later(5),
          lastLeaseId: 'lse_1',
          lastLeaseExp: later(9999),
          installationId: 'inst_changed0123456789',
        });
        expect(await f.store.findActivation(f.orgA, a.id)).toMatchObject({
          lastValidatedAt: later(5),
          lastLeaseId: 'lse_1',
          lastLeaseExp: later(9999),
          installationId: 'inst_changed0123456789',
          activatedBy: f.user,
        });
        expect(await f.store.findActivation(f.orgB, a.id)).toBeUndefined();
        expect((await f.store.findActivationForDeviceAuth(a.id))!.orgId).toBe(f.orgA);
        await expect(f.store.updateActivation({ ...a, orgId: f.orgB })).rejects.toThrow(
          'activation_not_found',
        );
      });

      it('lease records require an existing activation of the same tenant', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        const d = await f.store.insertDevice(dev(f.orgA));
        const a = act({ orgId: f.orgA, licenseId: l.id, deviceId: d.id, by: f.user });
        await f.store.insertActivation(a);
        await f.store.insertLease({
          jti: uid('lse'),
          orgId: f.orgA,
          activationId: a.id,
          planVersion: 1,
          issuedAt: T,
          expiresAt: later(1000),
        });
        await expect(
          f.store.insertLease({
            jti: uid('lse'),
            orgId: f.orgB,
            activationId: a.id,
            planVersion: 1,
            issuedAt: T,
            expiresAt: later(1000),
          }),
        ).rejects.toThrow('cross_tenant_reference');
      });
    });

    describe('challenges', () => {
      const ch = (hash: string, over = {}) => ({
        nonceHash: hash,
        purpose: 'activate' as const,
        installationId: 'inst_0123456789abcdef',
        subjectId: '',
        createdAt: T,
        expiresAt: later(300_000),
        consumedAt: null,
        ...over,
      });

      it('consume: ok once, then used; missing; expired (and an expired challenge is spent too)', async () => {
        const f = await fixture();
        await f.store.insertChallenge(ch('h1'));
        const first = await f.store.consumeChallenge('h1', later(1000));
        expect(first).toMatchObject({
          status: 'ok',
          challenge: {
            purpose: 'activate',
            subjectId: '',
            installationId: 'inst_0123456789abcdef',
          },
        });
        expect(await f.store.consumeChallenge('h1', later(2000))).toEqual({ status: 'used' });
        expect(await f.store.consumeChallenge('nope', later(0))).toEqual({ status: 'missing' });
        await f.store.insertChallenge(ch('h2'));
        expect(await f.store.consumeChallenge('h2', later(300_000))).toEqual({ status: 'expired' });
        expect(await f.store.consumeChallenge('h2', later(1))).toEqual({ status: 'used' });
      });

      it('consume is atomic: of 25 concurrent attempts exactly one wins', async () => {
        const f = await fixture();
        await f.store.insertChallenge(ch('race'));
        const res = await Promise.all(
          Array.from({ length: 25 }, () => f.store.consumeChallenge('race', later(10))),
        );
        expect(res.filter((r) => r.status === 'ok')).toHaveLength(1);
        expect(res.filter((r) => r.status === 'used')).toHaveLength(24);
      });

      it('counts only unconsumed, unexpired challenges per installation; purge removes expired', async () => {
        const f = await fixture();
        const inst = 'inst_countcountcountcount';
        await f.store.insertChallenge(ch('c1', { installationId: inst }));
        await f.store.insertChallenge(ch('c2', { installationId: inst }));
        await f.store.insertChallenge(ch('c3', { installationId: inst, expiresAt: later(100) }));
        await f.store.insertChallenge(ch('c4', { installationId: 'inst_otherotherotherother' }));
        await f.store.consumeChallenge('c2', later(1));
        expect(await f.store.countOutstandingChallenges(inst, later(1000))).toBe(1);
        expect(await f.store.purgeExpiredChallenges(later(10_000))).toBeGreaterThanOrEqual(1);
        expect(await f.store.consumeChallenge('c3', later(50))).toEqual({ status: 'missing' });
        expect((await f.store.consumeChallenge('c1', later(2000))).status).toBe('ok');
      });
    });

    describe('transactions', () => {
      it('commit makes writes visible; a throw rolls EVERYTHING back and surfaces the error', async () => {
        const f = await fixture();
        const l1 = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.transaction(async (tx) => tx.insertLicense(l1));
        expect(await f.store.findLicense(f.orgA, l1.id)).toBeDefined();

        const l2 = lic(f.orgA, f.prd.id, f.pln.id, null);
        const d = dev(f.orgA);
        await expect(
          f.store.transaction(async (tx) => {
            await tx.insertLicense(l2);
            await tx.insertDevice(d);
            throw new Error('boom');
          }),
        ).rejects.toThrow('boom');
        expect(await f.store.findLicense(f.orgA, l2.id)).toBeUndefined();
        expect(await f.store.findDeviceByThumbprint(d.thumbprint)).toBeUndefined();
      });

      it('rolls back after a constraint violation inside the transaction', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        const d = dev(f.orgA);
        await expect(
          f.store.transaction(async (tx) => {
            await tx.insertDevice(d);
            await tx.insertLicense(
              lic(f.orgA, f.prd.id, f.pln.id, null, { keyDigest: l.keyDigest }),
            );
          }),
        ).rejects.toThrow('duplicate_key');
        expect(await f.store.findDeviceByThumbprint(d.thumbprint)).toBeUndefined();
      });

      it('findLicenseForUpdate serializes per license: 12 concurrent “count then insert” never exceed the limit', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        const LIMIT = 3;
        const attempt = () =>
          f.store.transaction(async (tx) => {
            const locked = await tx.findLicenseForUpdate(f.orgA, l.id);
            if (!locked) throw new Error('license vanished');
            if ((await tx.countActiveActivations(l.id)) >= LIMIT) return 'limit' as const;
            const d = await tx.insertDevice(dev(f.orgA));
            await tx.insertActivation(
              act({ orgId: f.orgA, licenseId: l.id, deviceId: d.id, by: f.user }),
            );
            return 'ok' as const;
          });
        const res = await Promise.all(Array.from({ length: 12 }, () => attempt()));
        expect(res.filter((r) => r === 'ok')).toHaveLength(LIMIT);
        expect(await f.store.countActiveActivations(l.id)).toBe(LIMIT);
      });

      it('concurrent activations of the same device key converge on one device', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.insertLicense(l);
        const ids = await Promise.all(
          Array.from({ length: 8 }, () =>
            f.store.transaction(
              async (tx) => (await tx.insertDevice(dev(f.orgA, 'tp_shared_race'))).id,
            ),
          ),
        );
        expect(new Set(ids).size).toBe(1);
      });
    });

    describe('transactions with atomic audit', () => {
      it('commit persists the change and its audit events together', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await f.store.transaction(async (tx) => {
          await tx.insertLicense(l);
          await tx.audit.append({
            actor: { type: 'operator', id: 'usr_op' },
            action: 'license.issued',
            orgId: f.orgA,
          });
        });
        expect(await f.store.findLicense(f.orgA, l.id)).toBeDefined();
        expect(await f.audited()).toEqual(['license.issued']);
      });

      it('rollback discards the change AND the audit events', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await expect(
          f.store.transaction(async (tx) => {
            await tx.insertLicense(l);
            await tx.audit.append({ actor: { type: 'system' }, action: 'phantom' });
            throw new Error('boom');
          }),
        ).rejects.toThrow('boom');
        expect(await f.store.findLicense(f.orgA, l.id)).toBeUndefined();
        expect(await f.audited()).toEqual([]);
      });

      it('a failing audit write rolls the change back: there is no unaudited state change', async () => {
        const f = await fixture();
        const l = lic(f.orgA, f.prd.id, f.pln.id, null);
        await expect(
          f.store.transaction(async (tx) => {
            await tx.insertLicense(l);
            await tx.audit.append({ actor: { type: 'bogus' as never }, action: 'bad' });
          }),
        ).rejects.toThrow();
        expect(await f.store.findLicense(f.orgA, l.id)).toBeUndefined();
      });

      it('concurrent audited transactions each commit their own events as one contiguous run', async () => {
        const f = await fixture();
        await Promise.all(
          Array.from({ length: 10 }, (_, i) =>
            f.store.transaction(async (tx) => {
              await tx.insertLicense(lic(f.orgA, f.prd.id, f.pln.id, null));
              await tx.audit.append({ actor: { type: 'system' }, action: `t${i}.a` });
              await tx.audit.append({ actor: { type: 'system' }, action: `t${i}.b` });
            }),
          ),
        );
        const actions = await f.audited();
        expect(actions).toHaveLength(20);
        for (let i = 0; i < 10; i++) {
          const at = actions.indexOf(`t${i}.a`);
          expect(actions[at + 1]).toBe(`t${i}.b`); // never interleaved with another transaction's events
        }
      });
    });
  });
}
