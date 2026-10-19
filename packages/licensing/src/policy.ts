import {
  Decision,
  TIERS,
  type PolicyOutcome,
  type Tier,
  type ErrorCode,
} from '@trust/shared-types';
import type { License, Subscription } from './model.ts';

const DAY = 24 * 60 * 60;

/** All durations are configuration. These are defaults, not constants baked into code paths. */
export interface LicensingConfig {
  issuer: string;
  /** Server-side secret for HMAC of license keys. Never leaves the server. */
  licenseKeyPepper: string;
  /** Offline lease lifetime per tier, in seconds. */
  leaseTtlSeconds: Record<Tier, number>;
  /** Extra offline time after a *subscription* period ends, so renewals landing while offline do not lock users out. */
  subscriptionLeaseGraceSeconds: number;
  /** How long `past_due` subscriptions keep entitling (dunning window). */
  dunningGraceSeconds: number;
  trialDays: number;
  challengeTtlSeconds: number;
  maxOutstandingChallenges: number;
  /** How long spent/expired challenges are kept (replay detection needs them until they expire). */
  challengeRetentionSeconds: number;
  /** How long expired lease records are kept for forensics before maintenance deletes them. */
  leaseRetentionSeconds: number;
  /** Capability token lifetime (ADR-024); clamped to 30-900 seconds. */
  capabilityTtlSeconds: number;
}

export const DEFAULT_LEASE_TTL_SECONDS: Record<Tier, number> = {
  trial: 3 * DAY,
  standard: 14 * DAY,
  professional: 30 * DAY,
  business: 60 * DAY,
  enterprise: 90 * DAY,
};

export function defaultLicensingConfig(
  overrides: Partial<LicensingConfig> & Pick<LicensingConfig, 'licenseKeyPepper'>,
): LicensingConfig {
  const cfg: LicensingConfig = {
    issuer: 'trust-platform',
    leaseTtlSeconds: { ...DEFAULT_LEASE_TTL_SECONDS },
    subscriptionLeaseGraceSeconds: 3 * DAY,
    dunningGraceSeconds: 7 * DAY,
    trialDays: 14,
    challengeTtlSeconds: 300,
    maxOutstandingChallenges: 10,
    challengeRetentionSeconds: 3600,
    leaseRetentionSeconds: 90 * DAY,
    capabilityTtlSeconds: 300,
    ...overrides,
  };
  validateLicensingConfig(cfg);
  return cfg;
}

export function validateLicensingConfig(cfg: LicensingConfig): void {
  if (cfg.licenseKeyPepper.length < 32)
    throw new Error('licenseKeyPepper must be at least 32 characters');
  if (!Number.isInteger(cfg.challengeRetentionSeconds) || cfg.challengeRetentionSeconds < 0)
    throw new Error('invalid challengeRetentionSeconds');
  if (!Number.isInteger(cfg.leaseRetentionSeconds) || cfg.leaseRetentionSeconds < 0)
    throw new Error('invalid leaseRetentionSeconds');
  if (
    !Number.isInteger(cfg.capabilityTtlSeconds) ||
    cfg.capabilityTtlSeconds < 30 ||
    cfg.capabilityTtlSeconds > 900
  )
    throw new Error('capabilityTtlSeconds must be an integer between 30 and 900');
  for (const t of TIERS) {
    const ttl = cfg.leaseTtlSeconds[t];
    if (!Number.isInteger(ttl) || ttl < 60 || ttl > 366 * DAY)
      throw new Error(`invalid lease ttl for tier ${t}`);
  }
}

export interface AccessEvaluation {
  outcome: PolicyOutcome;
  /** Machine-readable error code when denied. */
  code?: ErrorCode;
  /** End of the commercial entitlement (null = open-ended), only when allowed. */
  entitlementEnd: Date | null;
}

/**
 * Port for the access decision. V1 ships the deterministic evaluator below; Milestone 2 replaces it
 * with a risk-weighted policy engine that can also return OBSERVE / STEP_UP_AUTH / RESTRICT /
 * SUSPEND. Callers must treat any decision other than ALLOW (and OBSERVE) as "no new lease".
 */
export interface AccessEvaluator {
  evaluateLicense(args: {
    license: License;
    subscription: Subscription | undefined;
    now: Date;
    config: LicensingConfig;
  }): AccessEvaluation;
}

function deny(code: ErrorCode, reason: string): AccessEvaluation {
  return { outcome: { decision: Decision.DENY, reasons: [reason] }, code, entitlementEnd: null };
}

/** Subscription → end of entitlement (null = open-ended) or undefined if not entitling. */
export function subscriptionEntitlementEnd(
  s: Subscription,
  now: Date,
  dunningGraceSeconds: number,
): Date | null | undefined {
  switch (s.status) {
    case 'trialing':
      return s.trialEnd && s.trialEnd > now ? s.trialEnd : undefined;
    case 'active':
      if (!s.currentPeriodEnd) return null;
      return s.currentPeriodEnd > now ? s.currentPeriodEnd : undefined;
    case 'past_due': {
      if (!s.currentPeriodEnd) return undefined;
      const end = new Date(s.currentPeriodEnd.getTime() + dunningGraceSeconds * 1000);
      return end > now ? end : undefined;
    }
    case 'suspended':
    case 'canceled':
    case 'expired':
      return undefined;
  }
}

export const deterministicAccessEvaluator: AccessEvaluator = {
  evaluateLicense({ license, subscription, now, config }) {
    // Hard invariants first; they fail closed regardless of any future risk score.
    if (license.kind === 'canary') return deny('invalid_license', 'canary');
    if (license.state === 'revoked') return deny('license_revoked', 'license_revoked');
    if (license.state === 'suspended') return deny('license_suspended', 'license_suspended');
    if (license.expiresAt && license.expiresAt <= now)
      return deny('license_expired', 'license_expired');

    let end: Date | null = license.expiresAt;
    if (license.kind === 'subscription' || license.kind === 'trial') {
      const subEnd = subscription
        ? subscriptionEntitlementEnd(subscription, now, config.dunningGraceSeconds)
        : undefined;
      if (subEnd === undefined) {
        return deny(
          license.kind === 'trial' ? 'license_expired' : 'subscription_inactive',
          subscription ? `subscription_${subscription.status}` : 'subscription_missing',
        );
      }
      if (subEnd !== null) end = end && end < subEnd ? end : subEnd;
    }
    return { outcome: { decision: Decision.ALLOW, reasons: [] }, entitlementEnd: end };
  },
};

export interface LeaseTimes {
  issuedAt: Date;
  refreshAfter: Date;
  expiresAt: Date;
}

/**
 * A lease never outlives the entitlement it attests to (plus an explicit, configured grace for
 * subscription renewals), and is otherwise bounded by the tier TTL policy.
 */
export function computeLeaseTimes(
  now: Date,
  tier: Tier,
  kind: License['kind'],
  entitlementEnd: Date | null,
  config: LicensingConfig,
): LeaseTimes {
  let expMs = now.getTime() + config.leaseTtlSeconds[tier] * 1000;
  if (entitlementEnd) {
    const grace = kind === 'subscription' ? config.subscriptionLeaseGraceSeconds * 1000 : 0;
    expMs = Math.min(expMs, entitlementEnd.getTime() + grace);
  }
  // Whole seconds only (JWT NumericDate); never in the past relative to issue time.
  expMs = Math.max(Math.floor(expMs / 1000) * 1000, Math.floor(now.getTime() / 1000) * 1000 + 1000);
  const issuedAt = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const refreshAfter = new Date(
    issuedAt.getTime() + Math.floor((expMs - issuedAt.getTime()) / 2000) * 1000,
  );
  return { issuedAt, refreshAfter, expiresAt: new Date(expMs) };
}
