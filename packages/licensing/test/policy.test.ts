import { describe, expect, it } from 'vitest';
import {
  computeLeaseTimes,
  defaultLicensingConfig,
  deterministicAccessEvaluator,
  subscriptionEntitlementEnd,
  type License,
  type Subscription,
} from '../src/index.ts';

const cfg = defaultLicensingConfig({ licenseKeyPepper: 'p'.repeat(32) });
const NOW = new Date('2026-03-01T00:00:00Z');
const d = (days: number) => new Date(NOW.getTime() + days * 86_400_000);

const lic = (over: Partial<License> = {}): License => ({
  id: 'lic_1',
  orgId: 'org_1',
  productId: 'prd_1',
  planId: 'pln_1',
  subscriptionId: 'sub_1',
  kind: 'subscription',
  state: 'active',
  keyDigest: 'x',
  expiresAt: null,
  overrides: {},
  createdAt: NOW,
  ...over,
});
const sub = (over: Partial<Subscription> = {}): Subscription => ({
  id: 'sub_1',
  orgId: 'org_1',
  planId: 'pln_1',
  status: 'active',
  trialEnd: null,
  currentPeriodEnd: d(10),
  createdAt: NOW,
  ...over,
});
const ev = (l: License, s?: Subscription) =>
  deterministicAccessEvaluator.evaluateLicense({
    license: l,
    subscription: s,
    now: NOW,
    config: cfg,
  });

describe('deterministic access evaluator', () => {
  it('canary licenses are denied by policy itself, whatever else is true (defense in depth)', () => {
    const r = ev(lic({ kind: 'canary', subscriptionId: null }));
    expect(r.outcome.decision).toBe('DENY');
    expect(r.code).toBe('invalid_license');
    expect(r.outcome.reasons).toEqual(['canary']);
  });

  it('hard states fail closed and take precedence over a healthy subscription', () => {
    expect(ev(lic({ state: 'revoked' }), sub()).code).toBe('license_revoked');
    expect(ev(lic({ state: 'suspended' }), sub()).code).toBe('license_suspended');
    expect(ev(lic({ expiresAt: d(-1) }), sub()).code).toBe('license_expired');
  });

  it('allows a healthy subscription license and reports the entitlement end', () => {
    const r = ev(lic(), sub());
    expect(r.outcome.decision).toBe('ALLOW');
    expect(r.entitlementEnd).toEqual(d(10));
  });

  it('the earlier of license expiry and subscription end bounds the entitlement', () => {
    expect(ev(lic({ expiresAt: d(5) }), sub()).entitlementEnd).toEqual(d(5));
    expect(ev(lic({ expiresAt: d(50) }), sub()).entitlementEnd).toEqual(d(10));
  });

  it('subscription-backed license without a subscription is not entitled; perpetual needs none', () => {
    expect(ev(lic(), undefined).code).toBe('subscription_inactive');
    expect(ev(lic({ kind: 'trial' }), undefined).code).toBe('license_expired');
    const p = ev(lic({ kind: 'perpetual', subscriptionId: null }), undefined);
    expect(p.outcome.decision).toBe('ALLOW');
    expect(p.entitlementEnd).toBeNull();
  });
});

describe('subscriptionEntitlementEnd', () => {
  const g = cfg.dunningGraceSeconds;
  it.each([
    ['trialing before end', sub({ status: 'trialing', trialEnd: d(2) }), d(2)],
    ['trialing after end', sub({ status: 'trialing', trialEnd: d(-1) }), undefined],
    ['trialing without end', sub({ status: 'trialing', trialEnd: null }), undefined],
    ['active in period', sub(), d(10)],
    ['active past period', sub({ currentPeriodEnd: d(-0.001) }), undefined],
    ['active open-ended', sub({ currentPeriodEnd: null }), null],
    [
      'past_due inside dunning',
      sub({ status: 'past_due', currentPeriodEnd: d(-3) }),
      new Date(d(-3).getTime() + g * 1000),
    ],
    ['past_due beyond dunning', sub({ status: 'past_due', currentPeriodEnd: d(-30) }), undefined],
    ['past_due no period', sub({ status: 'past_due', currentPeriodEnd: null }), undefined],
    ['suspended', sub({ status: 'suspended' }), undefined],
    ['canceled', sub({ status: 'canceled' }), undefined],
    ['expired', sub({ status: 'expired' }), undefined],
  ])('%s', (_n, s, expected) => {
    expect(subscriptionEntitlementEnd(s, NOW, g)).toEqual(expected);
  });
});

describe('computeLeaseTimes', () => {
  it('uses the tier TTL when the entitlement is open-ended; refresh at half-life', () => {
    const t = computeLeaseTimes(NOW, 'professional', 'perpetual', null, cfg);
    expect(t.expiresAt.getTime() - t.issuedAt.getTime()).toBe(30 * 86_400_000);
    expect(t.refreshAfter.getTime() - t.issuedAt.getTime()).toBe(15 * 86_400_000);
  });
  it('caps at entitlement end (+grace only for subscriptions)', () => {
    const sub_ = computeLeaseTimes(NOW, 'professional', 'subscription', d(2), cfg);
    expect(sub_.expiresAt).toEqual(
      new Date(d(2).getTime() + cfg.subscriptionLeaseGraceSeconds * 1000),
    );
    const trial = computeLeaseTimes(NOW, 'trial', 'trial', d(1), cfg);
    expect(trial.expiresAt).toEqual(d(1));
  });
  it('never produces a lease that is already expired, and truncates to whole seconds', () => {
    const t = computeLeaseTimes(
      new Date('2026-03-01T00:00:00.789Z'),
      'standard',
      'trial',
      new Date('2026-03-01T00:00:00.100Z'),
      cfg,
    );
    expect(t.expiresAt.getTime()).toBeGreaterThan(t.issuedAt.getTime());
    expect(t.issuedAt.getTime() % 1000).toBe(0);
    expect(t.expiresAt.getTime() % 1000).toBe(0);
  });
});
