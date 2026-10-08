import type { AuditLog } from '@trust/audit';
import {
  generateLicenseKey,
  jwkThumbprint,
  licenseKeyDigest,
  newId,
  newSecretToken,
  normalizePublicJwk,
  sha256Hex,
  signJws,
  isPublicJwk,
  type KeyRing,
  type PublicJwk,
} from '@trust/crypto';
import { buildProofMessage, verifySignature, type ProofPurpose } from '@trust/crypto/verify';
import {
  resolveEntitlements,
  validateCapabilities,
  validateDeviceLimit,
  validateEntitlementMap,
  EntitlementValidationError,
  type EntitlementOverrides,
  type ResolvedEntitlements,
} from '@trust/entitlements';
import {
  DomainError,
  LEASE_TYP,
  audienceForProduct,
  TIERS,
  type Clock,
  type LeaseClaims,
  type Tier,
  type UserPrincipal,
} from '@trust/shared-types';
import type { Telemetry } from '@trust/telemetry';
import {
  SUBSCRIPTION_STATUSES,
  type Activation,
  type Device,
  type License,
  type LicenseKind,
  type LicensingRepo,
  type LicensingStore,
  type Plan,
  type Product,
  type Subscription,
  type SubscriptionStatus,
} from './model.ts';
import {
  computeLeaseTimes,
  deterministicAccessEvaluator,
  type AccessEvaluation,
  type AccessEvaluator,
  type LicensingConfig,
} from './policy.ts';

export type OrgPermission =
  'license:read' | 'license:activate' | 'trial:start' | 'device:read' | 'device:deactivate';

/** Throws `not_found` for non-members and `forbidden` for members lacking the permission. */
export type Authorizer = (
  p: UserPrincipal,
  orgId: string,
  permission: OrgPermission,
) => Promise<void>;

export interface OperatorActor {
  id: string;
  /** Mandatory justification recorded in the audit log. */
  reason: string;
}

export interface LicensingDeps {
  store: LicensingStore;
  clock: Clock;
  audit: AuditLog;
  telemetry: Telemetry;
  keyring: KeyRing;
  config: LicensingConfig;
  authorize: Authorizer;
  orgExists: (orgId: string) => Promise<boolean>;
  evaluator?: AccessEvaluator;
}

const INSTALLATION_ID = /^[A-Za-z0-9_-]{16,64}$/;
const ACTIVATION_ID = /^act_[0-9a-f]{24}$/;
const CODE = /^[a-z0-9][a-z0-9-]{1,63}$/;
const UNIFORM_INVALID = 'invalid license';

export interface LicenseView {
  id: string;
  orgId: string;
  productId: string;
  productCode: string | null;
  planId: string;
  tier: Tier | null;
  subscriptionId: string | null;
  kind: LicenseKind;
  state: License['state'];
  /** `valid`, or the machine-readable reason the license currently confers nothing. */
  status: string;
  expiresAt: string | null;
  deviceLimit: number | null;
  activeDevices: number;
  createdAt: string;
}

export interface ActivationView {
  id: string;
  licenseId: string;
  deviceId: string;
  installationId: string;
  status: Activation['status'];
  activatedAt: string;
  lastValidatedAt: string | null;
  lastLeaseExpiresAt: string | null;
}

export interface LeaseGrant {
  activationId: string;
  deviceId: string;
  licenseId: string;
  lease: string;
  leaseExpiresAt: string;
  refreshAfter: string;
  entitlements: ResolvedEntitlements;
}

export interface ChallengeGrant {
  nonce: string;
  purpose: ProofPurpose;
  expiresAt: string;
}

function activationView(a: Activation): ActivationView {
  return {
    id: a.id,
    licenseId: a.licenseId,
    deviceId: a.deviceId,
    installationId: a.installationId,
    status: a.status,
    activatedAt: a.activatedAt.toISOString(),
    lastValidatedAt: a.lastValidatedAt?.toISOString() ?? null,
    lastLeaseExpiresAt: a.lastLeaseExp?.toISOString() ?? null,
  };
}

function need(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new DomainError('invalid_request', msg);
}

function requireReason(reason: string): string {
  const r = reason?.trim();
  need(r && r.length >= 3 && r.length <= 500, 'reason is required (3-500 chars)');
  return r;
}

export class LicensingService {
  readonly #d: LicensingDeps;
  readonly #evaluator: AccessEvaluator;

  constructor(deps: LicensingDeps) {
    this.#d = deps;
    this.#evaluator = deps.evaluator ?? deterministicAccessEvaluator;
  }

  // ===========================================================================================
  // Operator: catalog, subscriptions, license lifecycle
  // ===========================================================================================

  async createProduct(input: { code: string; name: string }, op: OperatorActor): Promise<Product> {
    need(CODE.test(input.code), 'invalid product code');
    need(input.name.trim().length >= 1 && input.name.length <= 200, 'invalid product name');
    const reason = requireReason(op.reason);
    const p: Product = {
      id: newId('prd'),
      code: input.code,
      name: input.name.trim(),
      status: 'active',
      createdAt: this.#d.clock.now(),
    };
    try {
      await this.#d.store.insertProduct(p);
    } catch {
      throw new DomainError('conflict', 'product code already exists');
    }
    await this.#opAudit('product.created', op, reason, { type: 'product', id: p.id }, undefined, {
      code: p.code,
    });
    return p;
  }

  async createPlan(
    input: {
      productId: string;
      code: string;
      tier: Tier;
      entitlements?: Record<string, unknown>;
      capabilities?: string[];
      deviceLimit: number;
    },
    op: OperatorActor,
  ): Promise<Plan> {
    const reason = requireReason(op.reason);
    need(CODE.test(input.code), 'invalid plan code');
    need((TIERS as readonly string[]).includes(input.tier), 'invalid tier');
    if (!(await this.#d.store.findProductById(input.productId)))
      throw new DomainError('not_found', 'product not found');
    const plan: Plan = {
      id: newId('pln'),
      productId: input.productId,
      code: input.code,
      tier: input.tier,
      version: 1,
      ...this.#validatePlanBody(input),
      updatedAt: this.#d.clock.now(),
    };
    try {
      await this.#d.store.insertPlan(plan);
    } catch {
      throw new DomainError('conflict', 'plan code already exists for product');
    }
    await this.#opAudit('plan.created', op, reason, { type: 'plan', id: plan.id }, undefined, {
      version: 1,
      tier: plan.tier,
    });
    return plan;
  }

  /** Changes take effect on the next lease refresh — no client release needed. Version is bumped. */
  async updatePlan(
    planId: string,
    patch: {
      entitlements?: Record<string, unknown>;
      capabilities?: string[];
      deviceLimit?: number;
    },
    op: OperatorActor,
  ): Promise<Plan> {
    const reason = requireReason(op.reason);
    const cur = await this.#d.store.findPlan(planId);
    if (!cur) throw new DomainError('not_found', 'plan not found');
    const next: Plan = {
      ...cur,
      ...this.#validatePlanBody({
        entitlements: patch.entitlements ?? cur.entitlements,
        capabilities: patch.capabilities ?? cur.capabilities,
        deviceLimit: patch.deviceLimit ?? cur.deviceLimit,
      }),
      version: cur.version + 1,
      updatedAt: this.#d.clock.now(),
    };
    await this.#d.store.updatePlan(next);
    await this.#opAudit('plan.updated', op, reason, { type: 'plan', id: planId }, undefined, {
      from_version: cur.version,
      to_version: next.version,
    });
    return next;
  }

  #validatePlanBody(b: {
    entitlements?: Record<string, unknown> | undefined;
    capabilities?: string[] | undefined;
    deviceLimit: number;
  }) {
    try {
      return {
        entitlements: validateEntitlementMap(b.entitlements ?? {}),
        capabilities: validateCapabilities(b.capabilities ?? []),
        deviceLimit: validateDeviceLimit(b.deviceLimit),
      };
    } catch (e) {
      if (e instanceof EntitlementValidationError)
        throw new DomainError('invalid_request', e.message);
      throw e;
    }
  }

  async createSubscription(
    input: {
      orgId: string;
      planId: string;
      status: SubscriptionStatus;
      trialEnd?: Date | null;
      currentPeriodEnd?: Date | null;
    },
    op: OperatorActor,
  ): Promise<Subscription> {
    const reason = requireReason(op.reason);
    need((SUBSCRIPTION_STATUSES as readonly string[]).includes(input.status), 'invalid status');
    if (!(await this.#d.orgExists(input.orgId)))
      throw new DomainError('not_found', 'organization not found');
    if (!(await this.#d.store.findPlan(input.planId)))
      throw new DomainError('not_found', 'plan not found');
    if (input.status === 'trialing') need(input.trialEnd, 'trialEnd required for trialing');
    if (input.status === 'active' || input.status === 'past_due') {
      need(input.currentPeriodEnd, 'currentPeriodEnd required for active/past_due');
    }
    const s: Subscription = {
      id: newId('sub'),
      orgId: input.orgId,
      planId: input.planId,
      status: input.status,
      trialEnd: input.trialEnd ?? null,
      currentPeriodEnd: input.currentPeriodEnd ?? null,
      createdAt: this.#d.clock.now(),
    };
    await this.#d.store.insertSubscription(s);
    await this.#opAudit(
      'subscription.created',
      op,
      reason,
      { type: 'subscription', id: s.id },
      s.orgId,
      {
        status: s.status,
        plan_id: s.planId,
      },
    );
    return s;
  }

  async updateSubscription(
    orgId: string,
    subscriptionId: string,
    patch: { status?: SubscriptionStatus; currentPeriodEnd?: Date | null; planId?: string },
    op: OperatorActor,
  ): Promise<Subscription> {
    const reason = requireReason(op.reason);
    const cur = await this.#d.store.findSubscription(orgId, subscriptionId);
    if (!cur) throw new DomainError('not_found', 'subscription not found');
    if (patch.status)
      need((SUBSCRIPTION_STATUSES as readonly string[]).includes(patch.status), 'invalid status');
    if (patch.planId && !(await this.#d.store.findPlan(patch.planId)))
      throw new DomainError('not_found', 'plan not found');
    const next: Subscription = {
      ...cur,
      status: patch.status ?? cur.status,
      planId: patch.planId ?? cur.planId,
      currentPeriodEnd:
        patch.currentPeriodEnd === undefined ? cur.currentPeriodEnd : patch.currentPeriodEnd,
    };
    await this.#d.store.updateSubscription(next);
    await this.#opAudit(
      'subscription.updated',
      op,
      reason,
      { type: 'subscription', id: cur.id },
      orgId,
      {
        from_status: cur.status,
        to_status: next.status,
      },
    );
    return next;
  }

  /** Returns the license and its plaintext key — the only time the key is ever available. */
  async issueLicense(
    input: {
      orgId: string;
      productId: string;
      planId: string;
      kind: LicenseKind;
      subscriptionId?: string | null;
      expiresAt?: Date | null;
      overrides?: EntitlementOverrides;
    },
    op: OperatorActor,
  ): Promise<{ license: LicenseView; licenseKey: string }> {
    const reason = requireReason(op.reason);
    need(['subscription', 'trial', 'perpetual', 'canary'].includes(input.kind), 'invalid kind');
    if (!(await this.#d.orgExists(input.orgId)))
      throw new DomainError('not_found', 'organization not found');
    const product = await this.#d.store.findProductById(input.productId);
    if (!product || product.status !== 'active')
      throw new DomainError('not_found', 'product not found');
    const plan = await this.#d.store.findPlan(input.planId);
    if (!plan || plan.productId !== product.id)
      throw new DomainError('invalid_request', 'plan does not belong to product');
    if (input.expiresAt)
      need(input.expiresAt > this.#d.clock.now(), 'expiresAt must be in the future');

    if (input.kind === 'subscription' || input.kind === 'trial') {
      need(input.subscriptionId, 'subscriptionId required for subscription-backed licenses');
      const sub = await this.#d.store.findSubscription(input.orgId, input.subscriptionId);
      if (!sub) throw new DomainError('not_found', 'subscription not found');
      need(sub.planId === plan.id, 'subscription plan differs from license plan');
    } else {
      need(!input.subscriptionId, 'perpetual/canary licenses must not reference a subscription');
    }
    const overrides = input.overrides ?? {};
    try {
      resolveEntitlements(plan, overrides); // dry run: reject malformed overrides at issue time
    } catch (e) {
      if (e instanceof EntitlementValidationError)
        throw new DomainError('invalid_request', e.message);
      throw e;
    }

    const licenseKey = generateLicenseKey();
    const license: License = {
      id: newId('lic'),
      orgId: input.orgId,
      productId: product.id,
      planId: plan.id,
      subscriptionId: input.subscriptionId ?? null,
      kind: input.kind,
      state: 'active',
      keyDigest: licenseKeyDigest(this.#d.config.licenseKeyPepper, licenseKey),
      expiresAt: input.expiresAt ?? null,
      overrides,
      createdAt: this.#d.clock.now(),
    };
    await this.#d.store.insertLicense(license);
    await this.#opAudit(
      input.kind === 'canary' ? 'license.canary_issued' : 'license.issued',
      op,
      reason,
      { type: 'license', id: license.id },
      license.orgId,
      { kind: license.kind, product_id: product.id, plan_id: plan.id },
    );
    return { license: await this.#licenseView(this.#d.store, license), licenseKey };
  }

  async setLicenseState(
    orgId: string,
    licenseId: string,
    action: 'suspend' | 'reinstate' | 'revoke',
    op: OperatorActor,
  ): Promise<LicenseView> {
    const reason = requireReason(op.reason);
    const next = await this.#d.store.transaction(async (tx) => {
      const lic = await tx.findLicense(orgId, licenseId);
      if (!lic) throw new DomainError('not_found', 'license not found');
      const allowed: Record<typeof action, License['state'][]> = {
        suspend: ['active'],
        reinstate: ['suspended'],
        revoke: ['active', 'suspended'],
      };
      if (!allowed[action].includes(lic.state)) {
        throw new DomainError('conflict', `cannot ${action} a license in state ${lic.state}`);
      }
      const state =
        action === 'suspend' ? 'suspended' : action === 'reinstate' ? 'active' : 'revoked';
      const updated: License = { ...lic, state };
      await tx.updateLicense(updated);
      if (state === 'revoked') {
        // Free slots and make every device re-authenticate against a revoked license.
        for (const a of await tx.listActivationsForLicense(orgId, licenseId)) {
          if (a.status === 'active')
            await tx.updateActivation({
              ...a,
              status: 'revoked',
              deactivatedAt: this.#d.clock.now(),
            });
        }
      }
      return updated;
    });
    await this.#opAudit(
      `license.${action === 'revoke' ? 'revoked' : action === 'suspend' ? 'suspended' : 'reinstated'}`,
      op,
      reason,
      { type: 'license', id: licenseId },
      orgId,
      { to_state: next.state },
    );
    return this.#licenseView(this.#d.store, next);
  }

  async adminListLicenses(orgId: string): Promise<LicenseView[]> {
    const lics = await this.#d.store.listLicenses(orgId);
    return Promise.all(lics.map((l) => this.#licenseView(this.#d.store, l)));
  }

  async adminListActivations(orgId: string, licenseId: string): Promise<ActivationView[]> {
    if (!(await this.#d.store.findLicense(orgId, licenseId)))
      throw new DomainError('not_found', 'license not found');
    return (await this.#d.store.listActivationsForLicense(orgId, licenseId)).map(activationView);
  }

  // ===========================================================================================
  // Customer (session-authenticated, org-scoped)
  // ===========================================================================================

  async listLicenses(p: UserPrincipal, orgId: string): Promise<LicenseView[]> {
    await this.#d.authorize(p, orgId, 'license:read');
    // Canary licenses are never shown to customers.
    const lics = (await this.#d.store.listLicenses(orgId)).filter((l) => l.kind !== 'canary');
    return Promise.all(lics.map((l) => this.#licenseView(this.#d.store, l)));
  }

  async getLicense(p: UserPrincipal, orgId: string, licenseId: string): Promise<LicenseView> {
    await this.#d.authorize(p, orgId, 'license:read');
    const lic = await this.#d.store.findLicense(orgId, licenseId);
    if (!lic || lic.kind === 'canary') throw new DomainError('not_found', 'not found');
    return this.#licenseView(this.#d.store, lic);
  }

  async getEntitlements(
    p: UserPrincipal,
    orgId: string,
    licenseId: string,
  ): Promise<{ licenseId: string; status: string; entitlements: ResolvedEntitlements | null }> {
    await this.#d.authorize(p, orgId, 'license:read');
    const lic = await this.#d.store.findLicense(orgId, licenseId);
    if (!lic || lic.kind === 'canary') throw new DomainError('not_found', 'not found');
    const plan = await this.#d.store.findPlan(lic.planId);
    const sub = lic.subscriptionId
      ? await this.#d.store.findSubscription(orgId, lic.subscriptionId)
      : undefined;
    const ev = this.#evaluate(lic, sub);
    if (!plan || ev.outcome.decision !== 'ALLOW') {
      return { licenseId, status: ev.code ?? 'invalid_license', entitlements: null };
    }
    return { licenseId, status: 'valid', entitlements: resolveEntitlements(plan, lic.overrides) };
  }

  async listActivations(
    p: UserPrincipal,
    orgId: string,
    licenseId: string,
  ): Promise<ActivationView[]> {
    await this.#d.authorize(p, orgId, 'device:read');
    if (!(await this.#d.store.findLicense(orgId, licenseId)))
      throw new DomainError('not_found', 'not found');
    return (await this.#d.store.listActivationsForLicense(orgId, licenseId)).map(activationView);
  }

  /** One trial per (product, org) and per (product, user), recorded server-side. */
  async startTrial(
    p: UserPrincipal,
    input: { orgId: string; productId: string },
  ): Promise<{ license: LicenseView; licenseKey: string }> {
    await this.#d.authorize(p, input.orgId, 'trial:start');
    const product = await this.#d.store.findProductById(input.productId);
    if (!product || product.status !== 'active')
      throw new DomainError('not_found', 'product not found');
    const plan = await this.#d.store.findTrialPlan(product.id);
    if (!plan) throw new DomainError('trial_not_available', 'no trial is offered for this product');
    const now = this.#d.clock.now();
    const licenseKey = generateLicenseKey();
    const license: License = {
      id: newId('lic'),
      orgId: input.orgId,
      productId: product.id,
      planId: plan.id,
      subscriptionId: null,
      kind: 'trial',
      state: 'active',
      keyDigest: licenseKeyDigest(this.#d.config.licenseKeyPepper, licenseKey),
      expiresAt: null,
      overrides: {},
      createdAt: now,
    };
    try {
      await this.#d.store.transaction(async (tx) => {
        await tx.insertTrialClaim({
          productId: product.id,
          orgId: input.orgId,
          userId: p.userId,
          licenseId: license.id,
          createdAt: now,
        });
        const sub: Subscription = {
          id: newId('sub'),
          orgId: input.orgId,
          planId: plan.id,
          status: 'trialing',
          trialEnd: new Date(now.getTime() + this.#d.config.trialDays * 86_400_000),
          currentPeriodEnd: null,
          createdAt: now,
        };
        await tx.insertSubscription(sub);
        license.subscriptionId = sub.id;
        await tx.insertLicense(license);
      });
    } catch (e) {
      if (e instanceof Error && e.message === 'trial_exists') {
        throw new DomainError(
          'trial_not_available',
          'a trial has already been used for this product',
        );
      }
      throw e;
    }
    await this.#d.audit.append({
      actor: { type: 'user', id: p.userId },
      action: 'trial.started',
      target: { type: 'license', id: license.id },
      orgId: input.orgId,
      metadata: { product_id: product.id },
    });
    await this.#d.telemetry.track('trial.started');
    return { license: await this.#licenseView(this.#d.store, license), licenseKey };
  }

  /** Owners/admins may deactivate any device; members only devices they activated themselves. */
  async deactivateActivation(
    p: UserPrincipal,
    orgId: string,
    activationId: string,
  ): Promise<ActivationView> {
    await this.#d.authorize(p, orgId, 'device:read');
    const act = await this.#d.store.findActivation(orgId, activationId);
    if (!act) throw new DomainError('not_found', 'not found');
    if (act.activatedBy !== p.userId) await this.#d.authorize(p, orgId, 'device:deactivate');
    const updated = await this.#deactivate(act);
    await this.#d.audit.append({
      actor: { type: 'user', id: p.userId },
      action: 'activation.deactivated',
      target: { type: 'activation', id: act.id },
      orgId,
      metadata: { license_id: act.licenseId },
    });
    await this.#d.telemetry.track('device.deactivated', { by: 'owner' });
    return activationView(updated);
  }

  // ===========================================================================================
  // Device-facing: challenges, activation, validation, refresh, deactivation
  // ===========================================================================================

  async issueChallenge(input: {
    purpose: ProofPurpose;
    installationId: string;
    subjectId?: string;
  }): Promise<ChallengeGrant> {
    need(
      ['activate', 'validate', 'refresh', 'deactivate'].includes(input.purpose),
      'invalid purpose',
    );
    need(INSTALLATION_ID.test(input.installationId), 'invalid installation id');
    const subjectId = input.subjectId ?? '';
    if (input.purpose === 'activate') need(subjectId === '', 'subject must be empty for activate');
    else need(ACTIVATION_ID.test(subjectId), 'invalid activation id');

    const now = this.#d.clock.now();
    await this.#d.store.purgeExpiredChallenges(new Date(now.getTime() - 3600_000));
    if (
      (await this.#d.store.countOutstandingChallenges(input.installationId, now)) >=
      this.#d.config.maxOutstandingChallenges
    ) {
      throw new DomainError('rate_limited', 'too many outstanding challenges');
    }
    const nonce = newSecretToken('chal');
    const expiresAt = new Date(now.getTime() + this.#d.config.challengeTtlSeconds * 1000);
    await this.#d.store.insertChallenge({
      nonceHash: sha256Hex(nonce),
      purpose: input.purpose,
      installationId: input.installationId,
      subjectId,
      createdAt: now,
      expiresAt,
      consumedAt: null,
    });
    return { nonce, purpose: input.purpose, expiresAt: expiresAt.toISOString() };
  }

  /**
   * Activation requires ALL of: an authenticated org member, the license key, and proof that the
   * caller currently holds the device private key (single-use challenge). The key alone is not authority.
   */
  async activate(
    p: UserPrincipal,
    input: {
      licenseKey: string;
      installationId: string;
      devicePublicKey: unknown;
      nonce: string;
      signature: string;
    },
  ): Promise<LeaseGrant> {
    need(INSTALLATION_ID.test(input.installationId), 'invalid installation id');
    need(isPublicJwk(input.devicePublicKey), 'invalid device public key');
    const devicePublicKey = normalizePublicJwk(input.devicePublicKey);
    const thumbprint = jwkThumbprint(devicePublicKey);

    // 1. Resolve the license from the key. Every failure here is indistinguishable to the caller.
    const digest = licenseKeyDigest(this.#d.config.licenseKeyPepper, input.licenseKey ?? '');
    const found = await this.#d.store.findLicenseByKeyDigest(digest);
    if (!found) {
      await this.#reject(p, 'unknown_key', undefined);
      throw new DomainError('invalid_license', UNIFORM_INVALID);
    }
    if (found.kind === 'canary') {
      // Honeypot: record a high-confidence signal, grant nothing, reveal nothing.
      await this.#d.audit.append({
        actor: { type: 'user', id: p.userId },
        action: 'security.canary_activated',
        target: { type: 'license', id: found.id },
        orgId: found.orgId,
      });
      await this.#d.telemetry.signal('canary_license_activated', {
        orgId: found.orgId,
        subject: input.installationId,
        attributes: { license_id: found.id, user_id: p.userId },
      });
      throw new DomainError('invalid_license', UNIFORM_INVALID);
    }
    try {
      await this.#d.authorize(p, found.orgId, 'license:activate');
    } catch {
      await this.#reject(p, 'not_authorized_for_license', found.orgId);
      throw new DomainError('invalid_license', UNIFORM_INVALID);
    }

    // 2. Proof of possession of the device key (consumes the challenge).
    await this.#consumeAndVerify({
      purpose: 'activate',
      nonce: input.nonce,
      installationId: input.installationId,
      subjectId: '',
      publicKey: devicePublicKey,
      thumbprint,
      signature: input.signature,
    });

    // 3. State change under a lock so the device limit cannot be exceeded concurrently.
    const now = this.#d.clock.now();
    const result = await this.#d.store
      .transaction(async (tx) => {
        const lic = await tx.findLicense(found.orgId, found.id);
        if (!lic) throw new DomainError('invalid_license', UNIFORM_INVALID);
        const ctx = await this.#loadContext(tx, lic);
        const ev = this.#evaluate(lic, ctx.sub);
        if (ev.outcome.decision !== 'ALLOW')
          throw new DomainError(ev.code ?? 'invalid_license', ev.outcome.reasons[0] ?? 'denied');

        let device = await tx.findDeviceByThumbprint(thumbprint);
        let newDevice = false;
        if (device && device.orgId !== lic.orgId) {
          throw new DomainError('device_key_conflict', 'device key is registered elsewhere');
        }
        if (!device) {
          device = {
            id: newId('dev'),
            orgId: lic.orgId,
            thumbprint,
            publicKey: devicePublicKey,
            createdAt: now,
          } satisfies Device;
          await tx.insertDevice(device);
          newDevice = true;
        }

        const resolved = resolveEntitlements(ctx.plan, lic.overrides);
        let act = await tx.findActiveActivation(lic.id, device.id);
        let reissued = false;
        if (act) {
          // Idempotent: same device re-activating (retry, reinstall) does not consume another slot.
          act = { ...act, installationId: input.installationId, lastValidatedAt: now };
          await tx.updateActivation(act);
          reissued = true;
        } else {
          const used = await tx.countActiveActivations(lic.id);
          if (used >= resolved.deviceLimit)
            throw new DomainError('device_limit_reached', 'device limit reached', {
              limit: resolved.deviceLimit,
            });
          act = {
            id: newId('act'),
            orgId: lic.orgId,
            licenseId: lic.id,
            deviceId: device.id,
            installationId: input.installationId,
            activatedBy: p.userId,
            status: 'active',
            activatedAt: now,
            lastValidatedAt: now,
            lastLeaseId: null,
            lastLeaseExp: null,
            deactivatedAt: null,
          };
          await tx.insertActivation(act);
        }
        const grant = await this.#issueLease(tx, {
          lic,
          act,
          device,
          product: ctx.product,
          plan: ctx.plan,
          resolved,
          ev,
          now,
        });
        return { grant, newDevice, reissued, act, lic };
      })
      .catch(async (e: unknown) => {
        if (e instanceof DomainError) {
          if (e.code === 'device_key_conflict') {
            await this.#d.telemetry.signal('device_key_conflict', {
              orgId: found.orgId,
              subject: input.installationId,
              attributes: { thumbprint_prefix: thumbprint.slice(0, 8) },
            });
            await this.#d.audit.append({
              actor: { type: 'user', id: p.userId },
              action: 'security.device_key_conflict',
              target: { type: 'license', id: found.id },
              orgId: found.orgId,
            });
            throw new DomainError('device_key_conflict', 'device key is already registered');
          }
          await this.#reject(p, e.code, found.orgId);
        }
        throw e;
      });

    const { grant, newDevice, reissued, act, lic } = result;
    if (newDevice)
      await this.#d.audit.append({
        actor: { type: 'user', id: p.userId },
        action: 'device.registered',
        target: { type: 'device', id: grant.deviceId },
        orgId: lic.orgId,
      });
    await this.#d.audit.append({
      actor: { type: 'user', id: p.userId },
      action: reissued ? 'activation.reissued' : 'activation.created',
      target: { type: 'activation', id: act.id },
      orgId: lic.orgId,
      metadata: { license_id: lic.id },
    });
    await this.#d.audit.append({
      actor: { type: 'system' },
      action: 'lease.issued',
      target: { type: 'activation', id: act.id },
      orgId: lic.orgId,
      metadata: { expires_at: grant.leaseExpiresAt, plan_version: grant.entitlements.planVersion },
    });
    await this.#d.telemetry.track('activation.succeeded', {
      tier: grant.entitlements.tier,
      reissued: reissued,
    });
    return grant;
  }

  /** Online validation. Authenticated by device proof; returns state, no new lease. */
  async validate(input: DeviceAuthInput): Promise<{
    status: 'valid';
    entitlements: ResolvedEntitlements;
    leaseExpiresAt: string | null;
  }> {
    const ctx = await this.#authenticateDevice('validate', input);
    const now = this.#d.clock.now();
    await this.#d.store.updateActivation({ ...ctx.act, lastValidatedAt: now });
    await this.#d.telemetry.track('validation.succeeded');
    return {
      status: 'valid',
      entitlements: resolveEntitlements(ctx.plan, ctx.lic.overrides),
      leaseExpiresAt: ctx.act.lastLeaseExp?.toISOString() ?? null,
    };
  }

  /** Online refresh. A lease alone can never obtain another lease: a device signature is required. */
  async refresh(input: DeviceAuthInput): Promise<LeaseGrant> {
    const ctx = await this.#authenticateDevice('refresh', input);
    const now = this.#d.clock.now();
    const grant = await this.#d.store.transaction(async (tx) => {
      const act = (await tx.findActivationForDeviceAuth(ctx.act.id))!;
      if (act.status !== 'active')
        throw new DomainError('activation_not_found', 'activation is not active');
      const resolved = resolveEntitlements(ctx.plan, ctx.lic.overrides);
      const g = await this.#issueLease(tx, {
        lic: ctx.lic,
        act: { ...act, lastValidatedAt: now },
        device: ctx.device,
        product: ctx.product,
        plan: ctx.plan,
        resolved,
        ev: ctx.ev,
        now,
      });
      return g;
    });
    await this.#d.audit.append({
      actor: { type: 'device', id: ctx.device.id },
      action: 'lease.issued',
      target: { type: 'activation', id: ctx.act.id },
      orgId: ctx.lic.orgId,
      metadata: {
        expires_at: grant.leaseExpiresAt,
        plan_version: grant.entitlements.planVersion,
        via: 'refresh',
      },
    });
    await this.#d.telemetry.track('lease.refreshed', { tier: grant.entitlements.tier });
    return grant;
  }

  /** Self-deactivation by the device (e.g. uninstall or "sign out this device"). */
  async deactivateByDevice(input: DeviceAuthInput): Promise<ActivationView> {
    const ctx = await this.#authenticateDevice('deactivate', input, { requireValidLicense: false });
    const updated = await this.#deactivate(ctx.act);
    await this.#d.audit.append({
      actor: { type: 'device', id: ctx.device.id },
      action: 'activation.deactivated',
      target: { type: 'activation', id: ctx.act.id },
      orgId: ctx.lic.orgId,
    });
    await this.#d.telemetry.track('device.deactivated', { by: 'device' });
    return activationView(updated);
  }

  trustBundle() {
    return this.#d.keyring.trustBundle('license');
  }

  // ===========================================================================================
  // Internals
  // ===========================================================================================

  #evaluate(lic: License, sub: Subscription | undefined): AccessEvaluation {
    return this.#evaluator.evaluateLicense({
      license: lic,
      subscription: sub,
      now: this.#d.clock.now(),
      config: this.#d.config,
    });
  }

  async #loadContext(repo: LicensingRepo, lic: License) {
    const [plan, product, sub] = await Promise.all([
      repo.findPlan(lic.planId),
      repo.findProductById(lic.productId),
      lic.subscriptionId
        ? repo.findSubscription(lic.orgId, lic.subscriptionId)
        : Promise.resolve(undefined),
    ]);
    if (!plan || !product) throw new DomainError('internal', 'catalog inconsistency');
    return { plan, product, sub };
  }

  async #licenseView(repo: LicensingRepo, lic: License): Promise<LicenseView> {
    const [plan, product, sub, active] = await Promise.all([
      repo.findPlan(lic.planId),
      repo.findProductById(lic.productId),
      lic.subscriptionId
        ? repo.findSubscription(lic.orgId, lic.subscriptionId)
        : Promise.resolve(undefined),
      repo.countActiveActivations(lic.id),
    ]);
    const ev = this.#evaluate(lic, sub);
    return {
      id: lic.id,
      orgId: lic.orgId,
      productId: lic.productId,
      productCode: product?.code ?? null,
      planId: lic.planId,
      tier: plan?.tier ?? null,
      subscriptionId: lic.subscriptionId,
      kind: lic.kind,
      state: lic.state,
      status: ev.outcome.decision === 'ALLOW' ? 'valid' : (ev.code ?? 'invalid_license'),
      expiresAt: lic.expiresAt?.toISOString() ?? null,
      deviceLimit: plan ? resolveEntitlements(plan, lic.overrides).deviceLimit : null,
      activeDevices: active,
      createdAt: lic.createdAt.toISOString(),
    };
  }

  async #deactivate(act: Activation): Promise<Activation> {
    return this.#d.store.transaction(async (tx) => {
      const cur = await tx.findActivationForDeviceAuth(act.id);
      if (!cur) throw new DomainError('not_found', 'not found');
      if (cur.status !== 'active') return cur; // idempotent
      const next: Activation = {
        ...cur,
        status: 'deactivated',
        deactivatedAt: this.#d.clock.now(),
      };
      await tx.updateActivation(next);
      return next;
    });
  }

  async #issueLease(
    tx: LicensingRepo,
    a: {
      lic: License;
      act: Activation;
      device: Device;
      product: Product;
      plan: Plan;
      resolved: ResolvedEntitlements;
      ev: AccessEvaluation;
      now: Date;
    },
  ): Promise<LeaseGrant> {
    const kind = a.lic.kind as 'subscription' | 'trial' | 'perpetual';
    const times = computeLeaseTimes(
      a.now,
      a.resolved.tier,
      kind,
      a.ev.entitlementEnd,
      this.#d.config,
    );
    const sec = (d: Date) => Math.floor(d.getTime() / 1000);
    const jti = newId('lse');
    const claims: LeaseClaims = {
      v: 1,
      jti,
      iss: this.#d.config.issuer,
      aud: audienceForProduct(a.product.code),
      lic: a.lic.id,
      org: a.lic.orgId,
      prd: a.product.id,
      pln: a.plan.id,
      plv: a.resolved.planVersion,
      act: a.act.id,
      inst: a.act.installationId,
      dev: a.device.id,
      cnf: { jkt: a.device.thumbprint },
      kind,
      tier: a.resolved.tier,
      ent: a.resolved.entitlements,
      cap: a.resolved.capabilities,
      dl: a.resolved.deviceLimit,
      iat: sec(times.issuedAt),
      nbf: sec(times.issuedAt),
      refresh_after: sec(times.refreshAfter),
      exp: sec(times.expiresAt),
    };
    let lease: string;
    try {
      const kid = this.#d.keyring.activeKeyId('license');
      lease = await signJws(
        claims as unknown as Record<string, unknown>,
        { typ: LEASE_TYP, kid },
        this.#d.keyring.custody,
      );
    } catch {
      // Fail closed: no signature, no lease, and the surrounding transaction rolls back.
      throw new DomainError('internal', 'lease signing unavailable');
    }
    await tx.insertLease({
      jti,
      orgId: a.lic.orgId,
      activationId: a.act.id,
      planVersion: a.resolved.planVersion,
      issuedAt: times.issuedAt,
      expiresAt: times.expiresAt,
    });
    await tx.updateActivation({ ...a.act, lastLeaseId: jti, lastLeaseExp: times.expiresAt });
    return {
      activationId: a.act.id,
      deviceId: a.device.id,
      licenseId: a.lic.id,
      lease,
      leaseExpiresAt: times.expiresAt.toISOString(),
      refreshAfter: times.refreshAfter.toISOString(),
      entitlements: a.resolved,
    };
  }

  /** Consumes the challenge (single use) and verifies the device signature over the bound message. */
  async #consumeAndVerify(a: {
    purpose: ProofPurpose;
    nonce: string;
    installationId: string;
    subjectId: string;
    publicKey: PublicJwk;
    thumbprint: string;
    signature: string;
  }): Promise<void> {
    const now = this.#d.clock.now();
    const nonceOk =
      typeof a.nonce === 'string' && a.nonce.startsWith('chal_') && a.nonce.length <= 128;
    const res = nonceOk
      ? await this.#d.store.consumeChallenge(sha256Hex(a.nonce), now)
      : ({ status: 'missing' } as const);
    if (res.status === 'used') {
      await this.#d.telemetry.signal('challenge_replay', {
        subject: a.installationId,
        attributes: { purpose: a.purpose },
      });
      await this.#d.audit.append({
        actor: { type: 'anonymous' },
        action: 'security.challenge_replay',
        metadata: { purpose: a.purpose },
      });
    }
    if (res.status !== 'ok')
      throw new DomainError('invalid_challenge', 'challenge is invalid or expired');
    const c = res.challenge;
    if (
      c.purpose !== a.purpose ||
      c.installationId !== a.installationId ||
      c.subjectId !== a.subjectId
    ) {
      throw new DomainError('invalid_challenge', 'challenge is invalid or expired');
    }
    const msg = buildProofMessage({
      purpose: a.purpose,
      nonce: a.nonce,
      installationId: a.installationId,
      subjectId: a.subjectId,
      thumbprint: a.thumbprint,
    });
    if (!verifySignature(a.publicKey, msg, a.signature)) {
      await this.#d.telemetry.signal('invalid_device_proof', {
        subject: a.installationId,
        attributes: { purpose: a.purpose },
      });
      throw new DomainError('invalid_device_proof', 'device proof is invalid');
    }
  }

  async #authenticateDevice(
    purpose: Exclude<ProofPurpose, 'activate'>,
    input: DeviceAuthInput,
    opts?: { requireValidLicense?: boolean },
  ) {
    need(INSTALLATION_ID.test(input.installationId), 'invalid installation id');
    need(ACTIVATION_ID.test(input.activationId), 'invalid activation id');
    const act = await this.#d.store.findActivationForDeviceAuth(input.activationId);
    if (!act || act.status !== 'active') {
      throw new DomainError('activation_not_found', 'activation is not active');
    }
    const device = await this.#d.store.findDevice(act.orgId, act.deviceId);
    if (!device) throw new DomainError('internal', 'device missing');
    if (act.installationId !== input.installationId) {
      throw new DomainError('invalid_device_proof', 'device proof is invalid');
    }
    await this.#consumeAndVerify({
      purpose,
      nonce: input.nonce,
      installationId: input.installationId,
      subjectId: act.id,
      publicKey: device.publicKey,
      thumbprint: device.thumbprint,
      signature: input.signature,
    });

    const lic = await this.#d.store.findLicense(act.orgId, act.licenseId);
    if (!lic) throw new DomainError('internal', 'license missing');
    const { plan, product, sub } = await this.#loadContext(this.#d.store, lic);
    const ev = this.#evaluate(lic, sub);
    if (opts?.requireValidLicense !== false && ev.outcome.decision !== 'ALLOW') {
      const code = ev.code ?? 'invalid_license';
      await this.#d.audit.append({
        actor: { type: 'device', id: device.id },
        action: 'license.validation_failed',
        target: { type: 'activation', id: act.id },
        orgId: act.orgId,
        metadata: { reason: code, purpose },
      });
      await this.#d.telemetry.track('validation.failed', { reason: code });
      throw new DomainError(code, ev.outcome.reasons[0] ?? 'denied');
    }
    return { act, device, lic, plan, product, sub, ev };
  }

  async #reject(p: UserPrincipal, reason: string, orgId: string | undefined) {
    await this.#d.audit.append({
      actor: { type: 'user', id: p.userId },
      action: 'activation.rejected',
      orgId,
      metadata: { reason },
    });
    await this.#d.telemetry.track('activation.rejected', { reason });
  }

  async #opAudit(
    action: string,
    op: OperatorActor,
    reason: string,
    target: { type: string; id: string },
    orgId: string | undefined,
    metadata?: Record<string, unknown>,
  ) {
    await this.#d.audit.append({
      actor: { type: 'operator', id: op.id },
      action,
      target,
      orgId,
      reason,
      metadata,
    });
  }
}

export interface DeviceAuthInput {
  activationId: string;
  installationId: string;
  nonce: string;
  signature: string;
}
