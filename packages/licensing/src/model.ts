import type { EntitlementOverrides, PlanDefinition } from '@trust/entitlements';
import type { PublicJwk } from '@trust/crypto';
import type { ProofPurpose } from '@trust/crypto/verify';

export interface Product {
  id: string;
  code: string;
  name: string;
  status: 'active' | 'retired';
  createdAt: Date;
}

export type Plan = PlanDefinition & { updatedAt: Date };

export const SUBSCRIPTION_STATUSES = [
  'trialing',
  'active',
  'past_due',
  'suspended',
  'canceled',
  'expired',
] as const;
export type SubscriptionStatus = (typeof SUBSCRIPTION_STATUSES)[number];

export interface Subscription {
  id: string;
  orgId: string;
  planId: string;
  status: SubscriptionStatus;
  trialEnd: Date | null;
  currentPeriodEnd: Date | null;
  createdAt: Date;
}

export type LicenseKind = 'subscription' | 'trial' | 'perpetual' | 'canary';
export type LicenseState = 'active' | 'suspended' | 'revoked';

export interface License {
  id: string;
  orgId: string;
  productId: string;
  planId: string;
  subscriptionId: string | null;
  kind: LicenseKind;
  state: LicenseState;
  /** HMAC of the license key. The key itself is never stored. */
  keyDigest: string;
  expiresAt: Date | null;
  overrides: EntitlementOverrides;
  createdAt: Date;
}

export interface Device {
  id: string;
  orgId: string;
  thumbprint: string;
  publicKey: PublicJwk;
  createdAt: Date;
}

export type ActivationStatus = 'active' | 'deactivated' | 'revoked';

export interface Activation {
  id: string;
  orgId: string;
  licenseId: string;
  deviceId: string;
  installationId: string;
  activatedBy: string;
  status: ActivationStatus;
  activatedAt: Date;
  lastValidatedAt: Date | null;
  lastLeaseId: string | null;
  lastLeaseExp: Date | null;
  deactivatedAt: Date | null;
}

export interface LeaseRecord {
  jti: string;
  orgId: string;
  activationId: string;
  planVersion: number;
  issuedAt: Date;
  expiresAt: Date;
}

export interface TrialClaim {
  productId: string;
  orgId: string;
  userId: string;
  licenseId: string;
  createdAt: Date;
}

export interface Challenge {
  nonceHash: string;
  purpose: ProofPurpose;
  installationId: string;
  subjectId: string;
  createdAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
}

export type ConsumeResult =
  { status: 'ok'; challenge: Challenge } | { status: 'missing' | 'expired' | 'used' };

/**
 * Repository port. Every tenant-owned lookup takes `orgId` explicitly. The few unscoped lookups
 * (`findLicenseByKeyDigest`, `findDeviceByThumbprint`, `findActivationForDeviceAuth`) exist only
 * for flows where authority comes from a secret/proof rather than a tenant session, and are named
 * accordingly.
 */
export interface LicensingRepo {
  insertProduct(p: Product): Promise<void>;
  findProductById(id: string): Promise<Product | undefined>;
  findProductByCode(code: string): Promise<Product | undefined>;
  listProducts(): Promise<Product[]>;

  insertPlan(p: Plan): Promise<void>;
  updatePlan(p: Plan): Promise<void>;
  findPlan(id: string): Promise<Plan | undefined>;
  findTrialPlan(productId: string): Promise<Plan | undefined>;
  listPlans(productId: string): Promise<Plan[]>;

  insertSubscription(s: Subscription): Promise<void>;
  updateSubscription(s: Subscription): Promise<void>;
  findSubscription(orgId: string, id: string): Promise<Subscription | undefined>;
  listSubscriptions(orgId: string): Promise<Subscription[]>;

  insertLicense(l: License): Promise<void>;
  updateLicense(l: License): Promise<void>;
  findLicense(orgId: string, id: string): Promise<License | undefined>;
  listLicenses(orgId: string): Promise<License[]>;
  findLicenseByKeyDigest(digest: string): Promise<License | undefined>;

  /** Throws `trial_exists` if (product, org) or (product, user) already claimed. */
  insertTrialClaim(c: TrialClaim): Promise<void>;

  findDeviceByThumbprint(thumbprint: string): Promise<Device | undefined>;
  findDevice(orgId: string, id: string): Promise<Device | undefined>;
  insertDevice(d: Device): Promise<void>;

  insertActivation(a: Activation): Promise<void>;
  updateActivation(a: Activation): Promise<void>;
  findActivation(orgId: string, id: string): Promise<Activation | undefined>;
  findActivationForDeviceAuth(id: string): Promise<Activation | undefined>;
  findActiveActivation(licenseId: string, deviceId: string): Promise<Activation | undefined>;
  countActiveActivations(licenseId: string): Promise<number>;
  listActivationsForLicense(orgId: string, licenseId: string): Promise<Activation[]>;

  insertLease(r: LeaseRecord): Promise<void>;

  insertChallenge(c: Challenge): Promise<void>;
  countOutstandingChallenges(installationId: string, now: Date): Promise<number>;
  /** Atomic: exactly one concurrent caller can obtain `ok` for a given nonce. */
  consumeChallenge(nonceHash: string, now: Date): Promise<ConsumeResult>;
  purgeExpiredChallenges(before: Date): Promise<number>;
}

export interface LicensingStore extends LicensingRepo {
  /** Serializable unit of work. In PostgreSQL: SERIALIZABLE/`FOR UPDATE` on the license row. */
  transaction<T>(fn: (tx: LicensingRepo) => Promise<T>): Promise<T>;
}
