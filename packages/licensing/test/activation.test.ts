import { beforeEach, describe, expect, it } from 'vitest';
import { jwkThumbprint } from '@trust/crypto';
import {
  DAY,
  FakeDevice,
  activate,
  errCode,
  readLease,
  seed,
  world,
  refresh,
  validate,
  deviceCall,
  type World,
} from './harness.ts';

let w: World;
beforeEach(() => {
  w = world();
});

describe('activation — happy path', () => {
  it('registers a device and issues a lease bound to product, installation, device and license', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    const c = readLease(w, g.lease);
    expect(c).toMatchObject({
      v: 1,
      aud: 'product:pdf-pro',
      lic: s.license.id,
      org: 'org_a',
      prd: s.product.id,
      act: g.activationId,
      inst: dev.installationId,
      dev: g.deviceId,
      kind: 'subscription',
      tier: 'professional',
      plv: 1,
      dl: 3,
    });
    expect(c.cnf.jkt).toBe(dev.thumbprint);
    expect(c.ent).toEqual({ ocr_pages_monthly: 5000, pdf_editing: true });
    expect(c.cap).toEqual(['CLOUD_SYNC', 'OCR_ADVANCED']);
    // professional tier default: 30 days, refresh at half-life
    expect(c.exp - c.iat).toBe(30 * 86400);
    expect(c.refresh_after - c.iat).toBe(15 * 86400);
    expect(c.nbf).toBe(c.iat);
  });

  it('never leaks the license key, hashes, or private material into audit/telemetry', async () => {
    const s = await seed(w);
    await activate(w, s.alice, new FakeDevice(), s.licenseKey);
    const dump = JSON.stringify([await w.audit.list(), w.sink.telemetry, w.sink.security]);
    expect(dump).not.toContain(s.licenseKey);
    expect(dump).not.toMatch(/chal_|"d":|PRIVATE KEY/);
    expect(await w.audit.verifyChain()).toMatchObject({ ok: true });
  });

  it('the stored license holds only an HMAC of the key', async () => {
    const s = await seed(w);
    const stored = await w.store.findLicense('org_a', s.license.id);
    expect(JSON.stringify(stored)).not.toContain(s.licenseKey);
    expect(stored!.keyDigest).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('activation — authority is not the key alone', () => {
  it('an unknown key and a valid key from a non-member are indistinguishable', async () => {
    const s = await seed(w);
    const mallory = w.user('usr_mallory');
    const dev = new FakeDevice();
    const wrongKey = await activate(w, s.alice, dev, 'LK-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA').catch(
      (e: Error) => e,
    );
    const stolenKey = await activate(w, mallory, new FakeDevice(), s.licenseKey).catch(
      (e: Error) => e,
    );
    expect(wrongKey).toMatchObject({ code: 'invalid_license', message: 'invalid license' });
    expect(stolenKey).toMatchObject({ code: 'invalid_license', message: 'invalid license' });
    expect(await w.store.countActiveActivations(s.license.id)).toBe(0);
  });

  it('a member of the owning org can activate (any org role)', async () => {
    const s = await seed(w);
    w.join('org_a', 'usr_bob', 'member');
    expect(await errCode(activate(w, w.user('usr_bob'), new FakeDevice(), s.licenseKey))).toBe(
      'ok',
    );
  });

  it('rejects proof by a different key than the one being registered (no possession)', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const attacker = new FakeDevice();
    const ch = await w.svc.issueChallenge({
      purpose: 'activate',
      installationId: dev.installationId,
    });
    const code = await errCode(
      w.svc.activate(s.alice, {
        licenseKey: s.licenseKey,
        installationId: dev.installationId,
        devicePublicKey: dev.publicJwk,
        nonce: ch.nonce,
        signature: attacker.proof('activate', ch.nonce, '', dev.installationId),
      }),
    );
    expect(code).toBe('invalid_device_proof');
    expect(w.sink.security.map((x) => x.kind)).toContain('invalid_device_proof');
  });

  it('rejects malformed public keys, installation ids and signatures', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    expect(
      await errCode(activate(w, s.alice, dev, s.licenseKey, { devicePublicKey: { kty: 'RSA' } })),
    ).toBe('invalid_request');
    expect(
      await errCode(activate(w, s.alice, dev, s.licenseKey, { installationId: 'short' })),
    ).toBe('invalid_request');
    expect(await errCode(activate(w, s.alice, dev, s.licenseKey, { signature: 'AAAA' }))).toBe(
      'invalid_device_proof',
    );
  });
});

describe('challenges — replay, expiry, binding', () => {
  it('a challenge is single use; a replay is refused and raises a security signal', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const ch = await w.svc.issueChallenge({
      purpose: 'activate',
      installationId: dev.installationId,
    });
    const req = {
      licenseKey: s.licenseKey,
      installationId: dev.installationId,
      devicePublicKey: dev.publicJwk,
      nonce: ch.nonce,
      signature: dev.proof('activate', ch.nonce, ''),
    };
    expect(await errCode(w.svc.activate(s.alice, req))).toBe('ok');
    expect(await errCode(w.svc.activate(s.alice, req))).toBe('invalid_challenge');
    expect(w.sink.security.map((x) => x.kind)).toContain('challenge_replay');
  });

  it('expires after the configured TTL', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const ch = await w.svc.issueChallenge({
      purpose: 'activate',
      installationId: dev.installationId,
    });
    w.clock.advance((w.config.challengeTtlSeconds + 1) * 1000);
    expect(
      await errCode(
        w.svc.activate(s.alice, {
          licenseKey: s.licenseKey,
          installationId: dev.installationId,
          devicePublicKey: dev.publicJwk,
          nonce: ch.nonce,
          signature: dev.proof('activate', ch.nonce, ''),
        }),
      ),
    ).toBe('invalid_challenge');
  });

  it('a challenge issued for one purpose/installation/subject cannot be used for another', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    // refresh challenge presented to validate
    const rc = await w.svc.issueChallenge({
      purpose: 'refresh',
      installationId: dev.installationId,
      subjectId: g.activationId,
    });
    expect(
      await errCode(
        w.svc.validate({
          activationId: g.activationId,
          installationId: dev.installationId,
          nonce: rc.nonce,
          signature: dev.proof('validate', rc.nonce, g.activationId),
        }),
      ),
    ).toBe('invalid_challenge');
    // challenge from another installation
    const other = new FakeDevice();
    const oc = await w.svc.issueChallenge({
      purpose: 'validate',
      installationId: other.installationId,
      subjectId: g.activationId,
    });
    expect(
      await errCode(
        w.svc.validate({
          activationId: g.activationId,
          installationId: dev.installationId,
          nonce: oc.nonce,
          signature: dev.proof('validate', oc.nonce, g.activationId),
        }),
      ),
    ).toBe('invalid_challenge');
  });

  it('caps outstanding challenges per installation', async () => {
    const dev = new FakeDevice();
    for (let i = 0; i < w.config.maxOutstandingChallenges; i++) {
      await w.svc.issueChallenge({ purpose: 'activate', installationId: dev.installationId });
    }
    expect(
      await errCode(
        w.svc.issueChallenge({ purpose: 'activate', installationId: dev.installationId }),
      ),
    ).toBe('rate_limited');
  });

  it('validates challenge request shape', async () => {
    const dev = new FakeDevice();
    expect(
      await errCode(
        w.svc.issueChallenge({ purpose: 'refresh', installationId: dev.installationId }),
      ),
    ).toBe('invalid_request');
    expect(
      await errCode(
        w.svc.issueChallenge({
          purpose: 'activate',
          installationId: dev.installationId,
          subjectId: 'act_x',
        }),
      ),
    ).toBe('invalid_request');
    expect(
      await errCode(
        w.svc.issueChallenge({ purpose: 'nope' as never, installationId: dev.installationId }),
      ),
    ).toBe('invalid_request');
  });
});

describe('license / subscription state gates activation', () => {
  it.each([
    ['suspend', 'license_suspended'],
    ['revoke', 'license_revoked'],
  ] as const)('%s blocks activation with %s', async (action, code) => {
    const s = await seed(w);
    await w.svc.setLicenseState('org_a', s.license.id, action, w.op);
    expect(await errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey))).toBe(code);
  });

  it('reinstating a suspended license restores activation', async () => {
    const s = await seed(w);
    await w.svc.setLicenseState('org_a', s.license.id, 'suspend', w.op);
    await w.svc.setLicenseState('org_a', s.license.id, 'reinstate', w.op);
    expect(await errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey))).toBe('ok');
  });

  it('revoked is terminal; illegal transitions are conflicts; a reason is mandatory', async () => {
    const s = await seed(w);
    await w.svc.setLicenseState('org_a', s.license.id, 'revoke', w.op);
    expect(await errCode(w.svc.setLicenseState('org_a', s.license.id, 'reinstate', w.op))).toBe(
      'conflict',
    );
    expect(await errCode(w.svc.setLicenseState('org_a', s.license.id, 'suspend', w.op))).toBe(
      'conflict',
    );
    const s2 = await seed(world());
    void s2;
    expect(
      await errCode(
        w.svc.setLicenseState('org_a', s.license.id, 'revoke', { id: 'usr_operator', reason: '' }),
      ),
    ).toBe('invalid_request');
  });

  it('subscription lapse, cancellation and dunning window', async () => {
    const s = await seed(w);
    // lapse: period ended, no longer active
    w.clock.advance(31 * DAY);
    expect(await errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey))).toBe(
      'subscription_inactive',
    );
    // renewal restores
    await w.svc.updateSubscription(
      'org_a',
      s.sub.id,
      { currentPeriodEnd: new Date(w.clock.now().getTime() + 30 * DAY) },
      w.op,
    );
    expect(await errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey))).toBe('ok');
    // past_due keeps entitling inside the dunning grace, not after it
    await w.svc.updateSubscription(
      'org_a',
      s.sub.id,
      { status: 'past_due', currentPeriodEnd: new Date(w.clock.now().getTime() - 2 * DAY) },
      w.op,
    );
    expect(await errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey))).toBe('ok');
    w.clock.advance(6 * DAY);
    expect(await errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey))).toBe(
      'subscription_inactive',
    );
    await w.svc.updateSubscription('org_a', s.sub.id, { status: 'canceled' }, w.op);
    expect(await errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey))).toBe(
      'subscription_inactive',
    );
  });

  it('license expiry', async () => {
    const s = await seed(w);
    const { licenseKey } = await w.svc.issueLicense(
      {
        orgId: 'org_a',
        productId: s.product.id,
        planId: s.plan.id,
        kind: 'perpetual',
        expiresAt: new Date(w.clock.now().getTime() + DAY),
      },
      w.op,
    );
    expect(await errCode(activate(w, s.alice, new FakeDevice(), licenseKey))).toBe('ok');
    w.clock.advance(2 * DAY);
    expect(await errCode(activate(w, s.alice, new FakeDevice(), licenseKey))).toBe(
      'license_expired',
    );
  });

  it('perpetual licenses need no subscription and are not capped by subscription periods', async () => {
    const s = await seed(w);
    const { licenseKey } = await w.svc.issueLicense(
      { orgId: 'org_a', productId: s.product.id, planId: s.plan.id, kind: 'perpetual' },
      w.op,
    );
    const g = await activate(w, s.alice, new FakeDevice(), licenseKey);
    const c = readLease(w, g.lease);
    expect(c.kind).toBe('perpetual');
    expect(c.exp - c.iat).toBe(30 * 86400);
  });
});

describe('device limit', () => {
  it('enforces the plan limit, is idempotent for the same device, and frees slots on deactivation', async () => {
    const s = await seed(w, { deviceLimit: 2 });
    const [d1, d2, d3] = [new FakeDevice(), new FakeDevice(), new FakeDevice()];
    const g1 = await activate(w, s.alice, d1, s.licenseKey);
    await activate(w, s.alice, d2, s.licenseKey);
    expect(await errCode(activate(w, s.alice, d3, s.licenseKey))).toBe('device_limit_reached');
    // same device again: re-issue, no extra slot
    const again = await activate(w, s.alice, d1, s.licenseKey);
    expect(again.activationId).toBe(g1.activationId);
    expect(await w.store.countActiveActivations(s.license.id)).toBe(2);
    // deactivate d1 -> d3 fits
    await w.svc.deactivateActivation(s.alice, 'org_a', g1.activationId);
    expect(await errCode(activate(w, s.alice, d3, s.licenseKey))).toBe('ok');
  });

  it('is race-free: concurrent activations never exceed the limit', async () => {
    const s = await seed(w, { deviceLimit: 3 });
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        errCode(activate(w, s.alice, new FakeDevice(), s.licenseKey)),
      ),
    );
    expect(results.filter((r) => r === 'ok')).toHaveLength(3);
    expect(results.filter((r) => r === 'device_limit_reached')).toHaveLength(17);
    expect(await w.store.countActiveActivations(s.license.id)).toBe(3);
  });

  it('license-level override can raise the limit; the override is applied via entitlements', async () => {
    const s = await seed(w, { deviceLimit: 1 });
    const { licenseKey } = await w.svc.issueLicense(
      {
        orgId: 'org_a',
        productId: s.product.id,
        planId: s.plan.id,
        kind: 'perpetual',
        overrides: { deviceLimit: 2 },
      },
      w.op,
    );
    await activate(w, s.alice, new FakeDevice(), licenseKey);
    expect(await errCode(activate(w, s.alice, new FakeDevice(), licenseKey))).toBe('ok');
  });

  it('only admins/owners — or the activating user — may deactivate; non-members see not_found', async () => {
    const s = await seed(w);
    w.join('org_a', 'usr_bob', 'member');
    w.join('org_a', 'usr_carol', 'member');
    const bob = w.user('usr_bob');
    const g = await activate(w, bob, new FakeDevice(), s.licenseKey);
    expect(
      await errCode(w.svc.deactivateActivation(w.user('usr_carol'), 'org_a', g.activationId)),
    ).toBe('forbidden');
    expect(
      await errCode(w.svc.deactivateActivation(w.user('usr_eve'), 'org_a', g.activationId)),
    ).toBe('not_found');
    expect(await errCode(w.svc.deactivateActivation(bob, 'org_a', g.activationId))).toBe('ok');
    // idempotent
    expect(await errCode(w.svc.deactivateActivation(s.alice, 'org_a', g.activationId))).toBe('ok');
  });
});

describe('device key conflict (clone / reuse signal)', () => {
  it('the same device key cannot be registered under two organizations', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    await activate(w, s.alice, dev, s.licenseKey);
    w.join('org_b', 'usr_zed', 'owner');
    const sub = await w.svc.createSubscription(
      {
        orgId: 'org_b',
        planId: s.plan.id,
        status: 'active',
        currentPeriodEnd: new Date(w.clock.now().getTime() + DAY),
      },
      w.op,
    );
    const { licenseKey } = await w.svc.issueLicense(
      {
        orgId: 'org_b',
        productId: s.product.id,
        planId: s.plan.id,
        kind: 'subscription',
        subscriptionId: sub.id,
      },
      w.op,
    );
    expect(await errCode(activate(w, w.user('usr_zed'), dev, licenseKey))).toBe(
      'device_key_conflict',
    );
    expect(w.sink.security.map((x) => x.kind)).toContain('device_key_conflict');
    expect(await w.store.countActiveActivations(s.license.id)).toBe(1);
  });
});

describe('canary licenses', () => {
  it('record a high-severity signal, grant nothing, and look exactly like an unknown key', async () => {
    const s = await seed(w);
    const { licenseKey: canaryKey } = await w.svc.issueLicense(
      { orgId: 'org_a', productId: s.product.id, planId: s.plan.id, kind: 'canary' },
      w.op,
    );
    const dev = new FakeDevice();
    const canary = await activate(w, s.alice, dev, canaryKey).catch((e: Error) => e);
    const unknown = await activate(w, s.alice, dev, 'LK-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ').catch(
      (e: Error) => e,
    );
    expect(canary).toMatchObject({ code: 'invalid_license', message: 'invalid license' });
    expect(unknown).toMatchObject({ code: 'invalid_license', message: 'invalid license' });
    const sig = w.sink.security.find((x) => x.kind === 'canary_license_activated');
    expect(sig).toMatchObject({ severity: 'high', orgId: 'org_a' });
    expect((await w.audit.list({ action: 'security.canary_activated' })).length).toBe(1);
    expect(await w.store.countActiveActivations('x')).toBe(0);
    // canaries never appear in customer-facing listings
    expect((await w.svc.listLicenses(s.alice, 'org_a')).every((l) => l.kind !== 'canary')).toBe(
      true,
    );
  });
});

describe('lease timing policy', () => {
  it.each([
    ['trial', 3],
    ['standard', 14],
    ['professional', 30],
    ['business', 60],
    ['enterprise', 90],
  ] as const)('tier %s uses its configured TTL (%i days)', async (tier, days) => {
    const product = await w.svc.createProduct({ code: `p-${tier}`, name: tier }, w.op);
    const plan = await w.svc.createPlan(
      { productId: product.id, code: tier, tier, deviceLimit: 1 },
      w.op,
    );
    w.join('org_t', 'usr_t', 'owner');
    const { licenseKey } = await w.svc.issueLicense(
      { orgId: 'org_t', productId: product.id, planId: plan.id, kind: 'perpetual' },
      w.op,
    );
    const g = await activate(w, w.user('usr_t'), new FakeDevice(), licenseKey);
    const c = readLease(w, g.lease);
    expect(c.exp - c.iat).toBe(days * 86400);
  });

  it('TTLs are configuration, not constants', async () => {
    const w2 = world({
      leaseTtlSeconds: {
        trial: 60,
        standard: 120,
        professional: 3600,
        business: 7200,
        enterprise: 9999,
      },
    });
    const s = await seed(w2);
    const c = readLease(w2, (await activate(w2, s.alice, new FakeDevice(), s.licenseKey)).lease);
    expect(c.exp - c.iat).toBe(3600);
  });

  it('a lease never outlives the subscription period beyond the configured renewal grace', async () => {
    const s = await seed(w);
    w.clock.advance(28 * DAY); // 2 days of period left, plus 3 days grace = 5 days
    const c = readLease(w, (await activate(w, s.alice, new FakeDevice(), s.licenseKey)).lease);
    expect(c.exp - c.iat).toBe(5 * 86400);
  });

  it('rejects invalid configuration', async () => {
    expect(() => world({ licenseKeyPepper: 'short' })).toThrow(/pepper/i);
    expect(() =>
      world({
        leaseTtlSeconds: { trial: 1, standard: 1, professional: 1, business: 1, enterprise: 1 },
      }),
    ).toThrow(/ttl/);
  });
});

describe('validate / refresh / revocation / plan changes', () => {
  it('validate and refresh work for the registered device and fail for another key', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    expect((await validate(w, dev, g.activationId)).status).toBe('valid');
    w.clock.advance(20 * DAY);
    const r = await refresh(w, dev, g.activationId);
    expect(readLease(w, r.lease).iat).toBeGreaterThan(readLease(w, g.lease).iat);
    const thief = new FakeDevice();
    const ch = await w.svc.issueChallenge({
      purpose: 'refresh',
      installationId: dev.installationId,
      subjectId: g.activationId,
    });
    expect(
      await errCode(
        w.svc.refresh({
          activationId: g.activationId,
          installationId: dev.installationId,
          nonce: ch.nonce,
          signature: thief.proof('refresh', ch.nonce, g.activationId, dev.installationId),
        }),
      ),
    ).toBe('invalid_device_proof');
    // wrong installation id
    const ch2 = await w.svc.issueChallenge({
      purpose: 'refresh',
      installationId: thief.installationId,
      subjectId: g.activationId,
    });
    expect(
      await errCode(
        w.svc.refresh({
          activationId: g.activationId,
          installationId: thief.installationId,
          nonce: ch2.nonce,
          signature: dev.proof('refresh', ch2.nonce, g.activationId, thief.installationId),
        }),
      ),
    ).toBe('invalid_device_proof');
  });

  it('a lease without the device key cannot be turned into a new lease', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    // attacker has the lease and ids but not the key
    const attacker = new FakeDevice();
    const ch = await w.svc.issueChallenge({
      purpose: 'refresh',
      installationId: dev.installationId,
      subjectId: g.activationId,
    });
    expect(
      await errCode(
        w.svc.refresh({
          activationId: g.activationId,
          installationId: dev.installationId,
          nonce: ch.nonce,
          signature: attacker.sign('anything'),
        }),
      ),
    ).toBe('invalid_device_proof');
  });

  it.each([
    ['revoke', 'activation_not_found'], // revoking also revokes activations
  ] as const)('revocation (%s) is enforced at the next online contact', async (action, code) => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    await w.svc.setLicenseState('org_a', s.license.id, action, w.op);
    expect(await errCode(refresh(w, dev, g.activationId))).toBe(code);
    expect(await errCode(validate(w, dev, g.activationId))).toBe(code);
    expect(await w.store.countActiveActivations(s.license.id)).toBe(0);
  });

  it('suspension blocks refresh and validate but keeps the activation for reinstatement', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    await w.svc.setLicenseState('org_a', s.license.id, 'suspend', w.op);
    expect(await errCode(refresh(w, dev, g.activationId))).toBe('license_suspended');
    expect(await errCode(validate(w, dev, g.activationId))).toBe('license_suspended');
    expect((await w.audit.list({ action: 'license.validation_failed' })).length).toBe(2);
    await w.svc.setLicenseState('org_a', s.license.id, 'reinstate', w.op);
    expect(await errCode(refresh(w, dev, g.activationId))).toBe('ok');
  });

  it('refresh takes only a SHARED license lock, so hot licenses do not serialize (activation still takes the exclusive one)', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const calls: string[] = [];
    const orig = w.store.transaction.bind(w.store);
    w.store.transaction = (async (fn: Parameters<typeof orig>[0]) =>
      orig(async (tx) => {
        const share = tx.findLicenseForShare.bind(tx);
        const upd = tx.findLicenseForUpdate.bind(tx);
        tx.findLicenseForShare = async (...a) => (calls.push('share'), share(...a));
        tx.findLicenseForUpdate = async (...a) => (calls.push('update'), upd(...a));
        return fn(tx);
      })) as typeof w.store.transaction;
    const g = await activate(w, s.alice, dev, s.licenseKey);
    expect(calls).toEqual(['update']);
    calls.length = 0;
    await refresh(w, dev, g.activationId);
    expect(calls).toEqual(['share']);
  });

  it('a suspension that lands between device authentication and lease issuance is still honoured (no stale lease)', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    const input = await deviceCall(w, dev, 'refresh', g.activationId);
    // Inject the race: the first transaction refresh opens is preceded by an operator suspending the license.
    const store = w.store;
    const original = store.transaction.bind(store);
    let injected = false;
    store.transaction = (async (fn: Parameters<typeof original>[0]) => {
      if (!injected) {
        injected = true;
        store.transaction = original; // restore before the injected call
        await w.svc.setLicenseState('org_a', s.license.id, 'suspend', w.op);
      }
      return original(fn);
    }) as typeof store.transaction;
    expect(await errCode(w.svc.refresh(input))).toBe('license_suspended');
    expect(injected).toBe(true);
    // and no lease was recorded for the refused refresh
    const act = (await w.store.listActivationsForLicense('org_a', s.license.id))[0]!;
    expect(act.lastLeaseId).toBe(readLease(w, g.lease).jti);
  });

  it('subscription lapse blocks refresh', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    await w.svc.updateSubscription('org_a', s.sub.id, { status: 'canceled' }, w.op);
    expect(await errCode(refresh(w, dev, g.activationId))).toBe('subscription_inactive');
  });

  it('deactivated devices cannot validate or refresh; device self-deactivation works even if the license lapsed', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    await w.svc.updateSubscription('org_a', s.sub.id, { status: 'canceled' }, w.op);
    // device can still free its own slot
    await w.svc.deactivateByDevice(await deviceCall(w, dev, 'deactivate', g.activationId));
    expect(await errCode(refresh(w, dev, g.activationId))).toBe('activation_not_found');
    expect(await w.store.countActiveActivations(s.license.id)).toBe(0);
  });

  it('plan changes take effect on refresh with no client release; the version is carried in the lease', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    await w.svc.updatePlan(
      s.plan.id,
      {
        capabilities: ['OCR_ADVANCED', 'CLOUD_SYNC', 'AI_DOCUMENT_ASSISTANT'],
        entitlements: { pdf_editing: true, ocr_pages_monthly: 9000 },
      },
      w.op,
    );
    const r = await refresh(w, dev, g.activationId);
    const c = readLease(w, r.lease);
    expect(c.plv).toBe(2);
    expect(c.cap).toContain('AI_DOCUMENT_ASSISTANT');
    expect(c.ent['ocr_pages_monthly']).toBe(9000);
    // the old lease is untouched (still version 1)
    expect(readLease(w, g.lease).plv).toBe(1);
  });

  it('signing-key rotation: refresh after rotation is signed by the new key, the old lease still verifies', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    const oldKid = w.keyring.activeKeyId('license');
    w.keyring.activate(w.keyring.generate('license').kid);
    const r = await refresh(w, dev, g.activationId);
    expect(w.keyring.activeKeyId('license')).not.toBe(oldKid);
    expect(readLease(w, g.lease).act).toBe(readLease(w, r.lease).act);
    // emergency revoke of the old key: old leases stop verifying, refresh still works
    w.keyring.revoke(oldKid, 'compromise drill');
    expect(() => readLease(w, g.lease)).toThrow();
    expect(await errCode(refresh(w, dev, g.activationId))).toBe('ok');
  });

  it('refuses to issue anything when no signing key is active (fails closed)', async () => {
    const s = await seed(w);
    w.keyring.revoke(w.keyring.activeKeyId('license'), 'drill');
    const dev = new FakeDevice();
    expect(await errCode(activate(w, s.alice, dev, s.licenseKey))).toBe('internal');
    // nothing was persisted: the transaction rolled back (no activation, no device, no lease)
    expect(await w.store.countActiveActivations(s.license.id)).toBe(0);
    expect(await w.store.findDeviceByThumbprint(dev.thumbprint)).toBeUndefined();
  });
});

describe('retention (runMaintenance)', () => {
  it('removes spent/expired challenges and long-expired lease records, in bounded batches, and keeps live data', async () => {
    const s = await seed(w);
    const dev = new FakeDevice();
    const g = await activate(w, s.alice, dev, s.licenseKey);
    for (let i = 0; i < 6; i++) await refresh(w, dev, g.activationId); // 7 leases, 7+ spent challenges
    // Issuing challenges no longer deletes anything on the request path:
    const live = await w.svc.issueChallenge({
      purpose: 'activate',
      installationId: dev.installationId,
    });
    // Nothing is old enough yet.
    expect(await w.svc.runMaintenance()).toEqual({ challenges: 0, leases: 0 });
    // Past challenge retention (1h default) but well inside lease retention (90d):
    w.clock.advance(2 * 3600_000);
    const first = await w.svc.runMaintenance({ batch: 2, maxBatches: 2 }); // bounded: 2 batches x 2
    expect(first.challenges).toBe(4);
    expect(first.leases).toBe(0);
    const rest = await w.svc.runMaintenance();
    expect(rest.challenges).toBeGreaterThanOrEqual(4);
    // The still-valid challenge from before was also past its 5 minute expiry by now; a fresh one is untouched.
    const fresh = await w.svc.issueChallenge({
      purpose: 'activate',
      installationId: dev.installationId,
    });
    expect(await w.svc.runMaintenance()).toEqual({ challenges: 0, leases: 0 });
    expect(live.nonce).not.toBe(fresh.nonce);
    // Lease records only after expiry (day 30) + retention (90 days), i.e. beyond day 120
    w.clock.advance(60 * DAY);
    expect((await w.svc.runMaintenance()).leases).toBe(0); // day ~60: expired, but still inside retention
    w.clock.advance(65 * DAY);
    expect((await w.svc.runMaintenance()).leases).toBe(7);
    expect(await errCode(refresh(w, dev, g.activationId))).not.toBe('ok'); // sub lapsed by now; data purge never grants anything
  });

  it('issuing a challenge never deletes anything (retention is not on the request path)', async () => {
    const dev = new FakeDevice();
    const old = await w.svc.issueChallenge({
      purpose: 'activate',
      installationId: dev.installationId,
    });
    w.clock.advance(5 * 3600_000); // far past expiry AND retention
    await w.svc.issueChallenge({ purpose: 'activate', installationId: dev.installationId });
    // Still present (reported as expired, not 'missing') until maintenance runs.
    const { createHash } = await import('node:crypto');
    const hash = createHash('sha256').update(old.nonce).digest('hex');
    expect((await w.store.consumeChallenge(hash, w.clock.now())).status).toBe('expired');
  });

  it('rejects invalid retention configuration', () => {
    expect(() => world({ challengeRetentionSeconds: -1 })).toThrow(/Retention/i);
    expect(() => world({ leaseRetentionSeconds: 1.5 })).toThrow(/Retention/i);
  });
});

describe('trials', () => {
  async function trialWorld() {
    const product = await w.svc.createProduct({ code: 'pdf-pro', name: 'PDF Pro' }, w.op);
    await w.svc.createPlan(
      {
        productId: product.id,
        code: 'trial',
        tier: 'trial',
        entitlements: { pdf_editing: true },
        deviceLimit: 1,
      },
      w.op,
    );
    w.join('org_a', 'usr_alice', 'owner');
    w.join('org_b', 'usr_alice', 'owner');
    return { product, alice: w.user('usr_alice') };
  }

  it('starts a trial, which activates with a trial-tier lease capped by trial end', async () => {
    const { product, alice } = await trialWorld();
    const { licenseKey, license } = await w.svc.startTrial(alice, {
      orgId: 'org_a',
      productId: product.id,
    });
    expect(license.kind).toBe('trial');
    const c = readLease(w, (await activate(w, alice, new FakeDevice(), licenseKey)).lease);
    expect(c.tier).toBe('trial');
    expect(c.exp - c.iat).toBe(3 * 86400);
    // after trial end nothing works
    w.clock.advance(15 * DAY);
    expect(await errCode(activate(w, alice, new FakeDevice(), licenseKey))).toBe('license_expired');
  });

  it('cannot be restarted — not by repeating, not via another org, not by another user in the same org', async () => {
    const { product, alice } = await trialWorld();
    await w.svc.startTrial(alice, { orgId: 'org_a', productId: product.id });
    expect(await errCode(w.svc.startTrial(alice, { orgId: 'org_a', productId: product.id }))).toBe(
      'trial_not_available',
    );
    expect(await errCode(w.svc.startTrial(alice, { orgId: 'org_b', productId: product.id }))).toBe(
      'trial_not_available',
    );
    w.join('org_a', 'usr_bob', 'member');
    expect(
      await errCode(w.svc.startTrial(w.user('usr_bob'), { orgId: 'org_a', productId: product.id })),
    ).toBe('trial_not_available');
  });

  it('is not offered when the product has no trial plan; non-members cannot start one', async () => {
    const s = await seed(w);
    expect(
      await errCode(w.svc.startTrial(s.alice, { orgId: 'org_a', productId: s.product.id })),
    ).toBe('trial_not_available');
    expect(
      await errCode(
        w.svc.startTrial(w.user('usr_eve'), { orgId: 'org_a', productId: s.product.id }),
      ),
    ).toBe('not_found');
  });
});

describe('operator input validation & audit', () => {
  it('rejects cross-product plans, cross-org subscriptions, unknown orgs and bad overrides', async () => {
    const s = await seed(w);
    const other = await w.svc.createProduct({ code: 'other', name: 'Other' }, w.op);
    const otherPlan = await w.svc.createPlan(
      { productId: other.id, code: 'p1', tier: 'standard', deviceLimit: 1 },
      w.op,
    );
    expect(
      await errCode(
        w.svc.issueLicense(
          { orgId: 'org_a', productId: s.product.id, planId: otherPlan.id, kind: 'perpetual' },
          w.op,
        ),
      ),
    ).toBe('invalid_request');
    w.join('org_b', 'usr_zed', 'owner');
    expect(
      await errCode(
        w.svc.issueLicense(
          {
            orgId: 'org_b',
            productId: s.product.id,
            planId: s.plan.id,
            kind: 'subscription',
            subscriptionId: s.sub.id,
          },
          w.op,
        ),
      ),
    ).toBe('not_found');
    expect(
      await errCode(
        w.svc.issueLicense(
          { orgId: 'nope', productId: s.product.id, planId: s.plan.id, kind: 'perpetual' },
          w.op,
        ),
      ),
    ).toBe('not_found');
    expect(
      await errCode(
        w.svc.issueLicense(
          {
            orgId: 'org_a',
            productId: s.product.id,
            planId: s.plan.id,
            kind: 'perpetual',
            overrides: { deviceLimit: 0 },
          },
          w.op,
        ),
      ),
    ).toBe('invalid_request');
    expect(
      await errCode(
        w.svc.issueLicense(
          {
            orgId: 'org_a',
            productId: s.product.id,
            planId: s.plan.id,
            kind: 'perpetual',
            subscriptionId: s.sub.id,
          },
          w.op,
        ),
      ),
    ).toBe('invalid_request');
    expect(await errCode(w.svc.createProduct({ code: 'pdf-pro', name: 'dup' }, w.op))).toBe(
      'conflict',
    );
    expect(
      await errCode(
        w.svc.createPlan(
          { productId: s.product.id, code: 'professional', tier: 'standard', deviceLimit: 1 },
          w.op,
        ),
      ),
    ).toBe('conflict');
    expect(
      await errCode(
        w.svc.createPlan(
          {
            productId: s.product.id,
            code: 'x-1',
            tier: 'standard',
            deviceLimit: 1,
            entitlements: { 'Bad Key': true },
          },
          w.op,
        ),
      ),
    ).toBe('invalid_request');
  });

  it('every operator mutation is audited with actor and reason, and the chain verifies', async () => {
    const s = await seed(w);
    await w.svc.setLicenseState('org_a', s.license.id, 'suspend', {
      id: 'usr_operator',
      reason: 'chargeback dispute #1',
    });
    const ev = (await w.audit.list({ action: 'license.suspended' }))[0]!;
    expect(ev).toMatchObject({
      actor: { type: 'operator', id: 'usr_operator' },
      reason: 'chargeback dispute #1',
      orgId: 'org_a',
    });
    const actions = (await w.audit.list()).map((e) => e.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        'product.created',
        'plan.created',
        'subscription.created',
        'license.issued',
      ]),
    );
    expect(await w.audit.verifyChain()).toMatchObject({ ok: true });
  });
});

describe('tenant isolation', () => {
  it('org A members cannot read org B licenses, entitlements, activations; ids across orgs are not_found', async () => {
    const s = await seed(w);
    w.join('org_b', 'usr_zed', 'owner');
    const zed = w.user('usr_zed');
    const g = await activate(w, s.alice, new FakeDevice(), s.licenseKey);
    expect(await errCode(w.svc.getLicense(zed, 'org_a', s.license.id))).toBe('not_found');
    expect(await errCode(w.svc.getEntitlements(zed, 'org_a', s.license.id))).toBe('not_found');
    expect(await errCode(w.svc.listActivations(zed, 'org_a', s.license.id))).toBe('not_found');
    // right org id, wrong resource owner: also not_found
    expect(await errCode(w.svc.getLicense(zed, 'org_b', s.license.id))).toBe('not_found');
    expect(await errCode(w.svc.deactivateActivation(zed, 'org_b', g.activationId))).toBe(
      'not_found',
    );
    expect(await w.svc.listLicenses(zed, 'org_b')).toEqual([]);
  });

  it('customer views never expose the key digest or key', async () => {
    const s = await seed(w);
    const lic = await w.svc.getLicense(s.alice, 'org_a', s.license.id);
    expect(JSON.stringify(lic)).not.toMatch(/keyDigest|LK-/);
    expect(lic).toMatchObject({
      status: 'valid',
      deviceLimit: 3,
      activeDevices: 0,
      productCode: 'pdf-pro',
      tier: 'professional',
    });
    const ent = await w.svc.getEntitlements(s.alice, 'org_a', s.license.id);
    expect(ent.entitlements?.capabilities).toContain('OCR_ADVANCED');
    await w.svc.setLicenseState('org_a', s.license.id, 'suspend', w.op);
    expect(await w.svc.getEntitlements(s.alice, 'org_a', s.license.id)).toMatchObject({
      status: 'license_suspended',
      entitlements: null,
    });
    void jwkThumbprint;
  });
});
