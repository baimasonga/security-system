import { beforeEach, describe, expect, it } from 'vitest';
import {
  DAY,
  FakeDevice,
  activate,
  deviceCall,
  errCode,
  readLease,
  refresh,
  seed,
  validate,
  world,
  type World,
} from './harness.ts';

let w: World;
beforeEach(() => {
  w = world();
});

describe('review regressions', () => {
  it.each(['deactivate', 'revoke', 'reinstall'] as const)(
    'in-flight validation cannot undo concurrent %s',
    async (action) => {
      const s = await seed(w);
      const dev = new FakeDevice();
      const g = await activate(w, s.alice, dev, s.licenseKey);
      const input = await deviceCall(w, dev, 'validate', g.activationId);
      const original = w.store.findLicenseContext.bind(w.store);
      let first = true;
      w.store.findLicenseContext = async (...args) => {
        const context = await original(...args);
        if (first) {
          first = false;
          if (action === 'deactivate')
            await w.svc.deactivateActivation(s.alice, s.orgId, g.activationId);
          else if (action === 'revoke')
            await w.svc.setLicenseState(s.orgId, s.license.id, 'revoke', w.op);
          else
            await activate(w, s.alice, dev, s.licenseKey, {
              installationId: 'inst_reinstalled_0123456789',
            });
        }
        return context;
      };
      expect(await errCode(w.svc.validate(input))).toBe('activation_not_found');
      const stored = (await w.store.findActivation(s.orgId, g.activationId))!;
      if (action === 'reinstall') expect(stored.installationId).toBe('inst_reinstalled_0123456789');
      else {
        expect(stored.status).toBe(action === 'revoke' ? 'revoked' : 'deactivated');
        expect(await errCode(refresh(w, dev, g.activationId))).toBe('activation_not_found');
      }
    },
  );

  it('validation preserves a lease refreshed after its activation snapshot was read', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    w.clock.advance(DAY);
    const input = await deviceCall(w, dev, 'validate', g.activationId);
    const original = w.store.findLicenseContext.bind(w.store);
    let currentLease = '';
    let first = true;
    w.store.findLicenseContext = async (...args) => {
      const context = await original(...args);
      if (first) {
        first = false;
        const newer = await refresh(w, dev, g.activationId);
        currentLease = readLease(w, newer.lease).jti;
      }
      return context;
    };
    const validation = await w.svc.validate(input);
    const stored = (await w.store.findActivation(s.orgId, g.activationId))!;
    expect(stored.lastLeaseId).toBe(currentLease);
    expect(validation.leaseExpiresAt).toBe(stored.lastLeaseExp!.toISOString());
    expect(stored.lastLeaseId).not.toBe(readLease(w, g.lease).jti);
  });

  it('a subscription downgrade changes refreshed leases, customer views and new activation limits', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const old = await activate(w, s.alice, dev, s.licenseKey);
    const basic = await w.svc.createPlan(
      {
        productId: s.product.id,
        code: 'basic',
        tier: 'standard',
        entitlements: { pdf_editing: false },
        capabilities: [],
        deviceLimit: 1,
      },
      w.op,
    );
    await w.svc.updateSubscription(s.orgId, s.sub.id, { planId: basic.id }, w.op);
    const current = await refresh(w, dev, old.activationId);
    expect(readLease(w, current.lease)).toMatchObject({
      pln: basic.id,
      tier: 'standard',
      ent: { pdf_editing: false },
      cap: [],
      dl: 1,
    });
    expect(readLease(w, old.lease).tier).toBe('professional'); // existing offline evidence retains its bounded lifetime
    expect(await w.svc.getLicense(s.alice, s.orgId, s.license.id)).toMatchObject({
      planId: basic.id,
      tier: 'standard',
      deviceLimit: 1,
    });
    expect((await w.svc.listLicenses(s.alice, s.orgId))[0]).toMatchObject({ planId: basic.id });
    expect(await w.svc.getEntitlements(s.alice, s.orgId, s.license.id)).toMatchObject({
      entitlements: { planId: basic.id, tier: 'standard', capabilities: [] },
    });
    expect((await validate(w, dev, old.activationId)).entitlements.planId).toBe(basic.id);
    expect(await errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey))).toBe(
      'device_limit_reached',
    );
    await w.svc.updateSubscription(s.orgId, s.sub.id, { planId: s.plan.id }, w.op);
    expect(readLease(w, (await refresh(w, dev, old.activationId)).lease).tier).toBe('professional');
  });

  it('rejects a subscription switch to another product without changing state', async () => {
    const s = await seed(w);
    const product = await w.svc.createProduct({ code: 'other', name: 'Other' }, w.op);
    const plan = await w.svc.createPlan(
      { productId: product.id, code: 'basic', tier: 'standard', deviceLimit: 1 },
      w.op,
    );
    expect(
      await errCode(w.svc.updateSubscription(s.orgId, s.sub.id, { planId: plan.id }, w.op)),
    ).toBe('invalid_request');
    expect((await w.store.findSubscription(s.orgId, s.sub.id))!.planId).toBe(s.plan.id);
  });

  it('rejects oversized plans and merged overrides before saving them', async () => {
    const s = await seed(w);
    const entitlements = Object.fromEntries(
      Array.from({ length: 100 }, (_, i) => [
        `e${String(i).padStart(3, '0')}${'x'.repeat(60)}`,
        2 ** 40,
      ]),
    );
    const capabilities = Array.from(
      { length: 100 },
      (_, i) => `C${String(i).padStart(3, '0')}${'X'.repeat(60)}`,
    );
    expect(
      await errCode(
        w.svc.createPlan(
          {
            productId: s.product.id,
            code: 'oversized',
            tier: 'professional',
            entitlements,
            capabilities,
            deviceLimit: 3,
          },
          w.op,
        ),
      ),
    ).toBe('invalid_request');
    expect(await errCode(w.svc.updatePlan(s.plan.id, { entitlements, capabilities }, w.op))).toBe(
      'invalid_request',
    );
    expect((await w.store.findPlan(s.plan.id))!.version).toBe(1);
    // Either half fits; merging them into a license does not.
    await w.svc.updatePlan(s.plan.id, { capabilities }, w.op);
    expect(
      await errCode(
        w.svc.issueLicense(
          {
            orgId: s.orgId,
            productId: s.product.id,
            planId: s.plan.id,
            kind: 'perpetual',
            overrides: { entitlements },
          },
          w.op,
        ),
      ),
    ).toBe('invalid_request');
    expect(await w.store.listLicenses(s.orgId)).toHaveLength(1);
  });

  it('accepted large entitlement snapshots produce leases the SDK can verify', async () => {
    const s = await seed(w);
    const entitlements = Object.fromEntries(
      Array.from({ length: 55 }, (_, i) => [
        `e${String(i).padStart(3, '0')}${'x'.repeat(60)}`,
        2 ** 40,
      ]),
    );
    const capabilities = Array.from(
      { length: 50 },
      (_, i) => `C${String(i).padStart(3, '0')}${'X'.repeat(60)}`,
    );
    await w.svc.updatePlan(s.plan.id, { entitlements, capabilities }, w.op);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    const { verifyLease } = await import('@trust/sdk-core');
    expect(
      verifyLease(g.lease, {
        trust: w.svc.trustBundle(),
        productCode: s.product.code,
        installationId: dev.installationId,
        deviceThumbprint: dev.thumbprint,
        now: w.clock.now(),
      }).state,
    ).toBe('valid');
  });
});
