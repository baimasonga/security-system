import type { AuditWriter } from '@trust/audit';
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
export interface LicenseContext {
  license: License;
  plan: Plan;
  product: Product;
  subscription: Subscription | undefined;
}

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
  /**
   * Same as `findLicense` but takes a row lock held until the transaction ends. Everything that
   * counts or changes a license's activations must call this first so they serialize per license.
   * (Meaningful inside `transaction`; equivalent to `findLicense` for the in-memory adapter.)
   */
  findLicenseForUpdate(orgId: string, id: string): Promise<License | undefined>;
  /**
   * Shared row lock held until the transaction ends. Many holders may coexist, but it excludes (and is
   * excluded by) `findLicenseForUpdate`. Use it when a transaction must keep the license's STATE from
   * changing underneath it without needing to change activations itself (e.g. lease refresh), so hot
   * licenses do not serialize.
   */
  findLicenseForShare(orgId: string, id: string): Promise<License | undefined>;
  /**
   * License + plan + product + subscription in ONE read (one database round trip), optionally taking the
   * same row lock as `findLicenseForShare` / `findLicenseForUpdate` on the license row. Undefined if the
   * license does not exist in `orgId`. `subscription` is undefined when the license has none.
   */
  findLicenseContext(
    orgId: string,
    id: string,
    lock: 'none' | 'share' | 'update',
  ): Promise<LicenseContext | undefined>;
  listLicenses(orgId: string): Promise<License[]>;
  findLicenseByKeyDigest(digest: string): Promise<License | undefined>;

  /** Throws `trial_exists` if (product, org) or (product, user) already claimed. */
  insertTrialClaim(c: TrialClaim): Promise<void>;

  findDeviceByThumbprint(thumbprint: string): Promise<Device | undefined>;
  findDevice(orgId: string, id: string): Promise<Device | undefined>;
  /**
   * Idempotent on the device key: if a device with this thumbprint already exists (even created by
   * a concurrent transaction) the existing row is returned instead of failing. Callers must compare
   * `orgId` of the result.
   */
  insertDevice(d: Device): Promise<Device>;

  insertActivation(a: Activation): Promise<void>;
  updateActivation(a: Activation): Promise<void>;
  findActivation(orgId: string, id: string): Promise<Activation | undefined>;
  /** Inside a transaction this also locks the activation row (PostgreSQL adapter). */
  findActivationForDeviceAuth(id: string): Promise<Activation | undefined>;
  /** `findActivationForDeviceAuth` plus the activation's device, in one read. */
  findActivationWithDevice(
    id: string,
  ): Promise<{ activation: Activation; device: Device } | undefined>;
  /**
   * What activation needs to decide: this device's ACTIVE activation of the license (if any) and how many
   * active activations the license has — in one read. Call it under the license lock.
   */
  findActivationSlot(
    licenseId: string,
    deviceId: string,
  ): Promise<{ existing: Activation | undefined; used: number }>;
  findActiveActivation(licenseId: string, deviceId: string): Promise<Activation | undefined>;
  countActiveActivations(licenseId: string): Promise<number>;
  listActivationsForLicense(orgId: string, licenseId: string): Promise<Activation[]>;

  insertLease(r: LeaseRecord): Promise<void>;
  /**
   * `insertLease(r)` followed by `updateActivation(a)` as ONE write (one round trip). Throws
   * `cross_tenant_reference` / `activation_not_found` like the two calls would; nothing is written then.
   */
  recordLease(r: LeaseRecord, a: Activation): Promise<void>;

  insertChallenge(c: Challenge): Promise<void>;
  countOutstandingChallenges(installationId: string, now: Date): Promise<number>;
  /**
   * Stores `c` unless the installation already has `max` or more outstanding (unconsumed, unexpired at
   * `now`) challenges; returns whether it was stored. One round trip. A soft limit: concurrent callers may
   * overshoot by the number of racing requests (rate limiting is the hard control).
   */
  insertChallengeIfBelow(c: Challenge, max: number, now: Date): Promise<boolean>;
  /** Atomic: exactly one concurrent caller can obtain `ok` for a given nonce. */
  consumeChallenge(nonceHash: string, now: Date): Promise<ConsumeResult>;
  /** Deletes up to `limit` challenges that expired before `before`. Returns the number deleted. */
  purgeExpiredChallenges(before: Date, limit?: number): Promise<number>;
  /** Deletes up to `limit` lease records that expired before `before` (forensic history, not authority). */
  purgeExpiredLeases(before: Date, limit?: number): Promise<number>;
}

/** A transaction: every repository method, plus an audit writer that commits atomically with them. */
export interface LicensingTx extends LicensingRepo {
  audit: AuditWriter;
}

export interface LicensingStore extends LicensingRepo {
  /**
   * Serializable unit of work. Writes AND audit events appended through `tx.audit` commit together or
   * not at all. If the audit write fails the whole transaction rolls back.
   *
   * `fn` MUST be safe to re-run: the PostgreSQL adapter retries it from the start after a deadlock or
   * serialization failure. Keep irreversible side effects out of it.
   */
  transaction<T>(fn: (tx: LicensingTx) => Promise<T>): Promise<T>;
}
