import { AuditBuffer, type AuditEventInput, type AuditLog } from '@trust/audit';
import type { DevicePosture, DeviceSignal } from './device-policy.ts';
import type {
  Activation,
  QuotaCharge,
  Seat,
  BillingCheckout,
  BillingEventReceipt,
  Challenge,
  ConsumeResult,
  Device,
  License,
  LicensingRepo,
  LicensingStore,
  LicensingTx,
  LeaseRecord,
  Plan,
  Product,
  Subscription,
  TrialClaim,
} from './model.ts';

interface State {
  quotaCharges: Map<string, QuotaCharge>;
  seats: Map<string, Seat>;
  billingCheckouts: Map<string, BillingCheckout>;
  billingEvents: Map<string, BillingEventReceipt>;
  products: Map<string, Product>;
  plans: Map<string, Plan>;
  subscriptions: Map<string, Subscription>;
  licenses: Map<string, License>;
  trialClaims: TrialClaim[];
  devices: Map<string, Device>;
  activations: Map<string, Activation>;
  leases: Map<string, LeaseRecord>;
  deviceSignals: Map<string, DeviceSignal>;
  devicePostures: Map<string, DevicePosture>;
  challenges: Map<string, Challenge>;
}

const clone = <T>(v: T): T => structuredClone(v);

function emptyState(): State {
  return {
    quotaCharges: new Map(),
    seats: new Map(),
    billingCheckouts: new Map(),
    billingEvents: new Map(),
    products: new Map(),
    plans: new Map(),
    subscriptions: new Map(),
    licenses: new Map(),
    trialClaims: [],
    devices: new Map(),
    activations: new Map(),
    leases: new Map(),
    deviceSignals: new Map(),
    devicePostures: new Map(),
    challenges: new Map(),
  };
}

class Repo implements LicensingRepo {
  readonly s: State;
  constructor(s: State) {
    this.s = s;
  }

  async findBillingCheckout(id: string) {
    return clone(this.s.billingCheckouts.get(id));
  }
  async findBillingCheckoutForLicense(orgId: string, licenseId: string) {
    return clone(
      [...this.s.billingCheckouts.values()].find(
        (c) => c.orgId === orgId && c.licenseId === licenseId,
      ),
    );
  }
  async insertBillingCheckout(c: BillingCheckout) {
    if (this.s.licenses.get(c.licenseId)?.orgId !== c.orgId || !this.s.plans.has(c.planId))
      throw new Error('cross_tenant_reference');
    if (
      [...this.s.billingCheckouts.values()].some(
        (x) =>
          x.id === c.id ||
          x.licenseId === c.licenseId ||
          (x.orgId === c.orgId && x.requestHash === c.requestHash),
      )
    )
      throw new Error('duplicate_checkout');
    this.s.billingCheckouts.set(c.id, clone(c));
  }
  async updateBillingCheckout(c: BillingCheckout) {
    const old = this.s.billingCheckouts.get(c.id);
    if (
      !old ||
      old.orgId !== c.orgId ||
      old.licenseId !== c.licenseId ||
      old.planId !== c.planId ||
      old.priceId !== c.priceId ||
      old.userId !== c.userId ||
      old.requestHash !== c.requestHash
    )
      throw new Error('checkout_not_found');
    if (
      [...this.s.billingCheckouts.values()].some(
        (x) =>
          x.id !== c.id &&
          ((c.transactionId && x.transactionId === c.transactionId) ||
            (c.providerSubscriptionId && x.providerSubscriptionId === c.providerSubscriptionId)),
      )
    )
      throw new Error('duplicate_checkout');
    this.s.billingCheckouts.set(c.id, clone(c));
  }
  async findBillingEvent(id: string) {
    return clone(this.s.billingEvents.get(id));
  }
  async insertBillingEvent(e: BillingEventReceipt) {
    if (this.s.billingEvents.has(e.id)) throw new Error('duplicate_billing_event');
    if (!this.s.billingCheckouts.has(e.checkoutId)) throw new Error('cross_tenant_reference');
    this.s.billingEvents.set(e.id, clone(e));
  }
  async listQuotaUsage(orgId: string, licenseId: string, period: string) {
    const usage = new Map<string, number>();
    for (const c of this.s.quotaCharges.values())
      if (c.orgId === orgId && c.licenseId === licenseId && c.period === period)
        usage.set(c.entitlement, (usage.get(c.entitlement) ?? 0) + c.units);
    return [...usage.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([entitlement, used]) => ({ entitlement, used }));
  }
  async findQuotaCharge(orgId: string, licenseId: string, requestHash: string) {
    return clone(
      [...this.s.quotaCharges.values()].find(
        (c) => c.orgId === orgId && c.licenseId === licenseId && c.requestHash === requestHash,
      ),
    );
  }
  async getQuotaUsed(orgId: string, licenseId: string, entitlement: string, period: string) {
    return [...this.s.quotaCharges.values()]
      .filter(
        (c) =>
          c.orgId === orgId &&
          c.licenseId === licenseId &&
          c.entitlement === entitlement &&
          c.period === period,
      )
      .reduce((n, c) => n + c.units, 0);
  }
  async insertSeat(seat: Seat) {
    const k = `${seat.licenseId}|${seat.userId}`;
    if (this.s.seats.has(k)) throw new Error('duplicate_seat');
    this.s.seats.set(k, clone(seat));
  }
  async deleteSeat(orgId: string, licenseId: string, userId: string) {
    const k = `${licenseId}|${userId}`;
    if (this.s.seats.get(k)?.orgId !== orgId) return false;
    this.s.seats.delete(k);
    return true;
  }
  async listSeats(orgId: string, licenseId: string) {
    return [...this.s.seats.values()]
      .filter((x) => x.orgId === orgId && x.licenseId === licenseId)
      .sort((a, b) => +a.assignedAt - +b.assignedAt || a.userId.localeCompare(b.userId))
      .map(clone);
  }
  async hasSeat(orgId: string, licenseId: string, userId: string) {
    return this.s.seats.get(`${licenseId}|${userId}`)?.orgId === orgId;
  }
  async insertQuotaCharge(c: QuotaCharge) {
    if (this.s.licenses.get(c.licenseId)?.orgId !== c.orgId)
      throw new Error('cross_tenant_reference');
    if (
      [...this.s.quotaCharges.values()].some(
        (x) => x.id === c.id || (x.licenseId === c.licenseId && x.requestHash === c.requestHash),
      )
    )
      throw new Error('duplicate_quota_request');
    this.s.quotaCharges.set(c.id, clone(c));
  }
  async insertProduct(p: Product) {
    if ([...this.s.products.values()].some((x) => x.code === p.code))
      throw new Error('duplicate_product_code');
    this.s.products.set(p.id, clone(p));
  }
  async findProductById(id: string) {
    return clone(this.s.products.get(id));
  }
  async findProductByCode(code: string) {
    return clone([...this.s.products.values()].find((p) => p.code === code));
  }
  async listProducts() {
    return clone([...this.s.products.values()]);
  }

  async insertPlan(p: Plan) {
    if ([...this.s.plans.values()].some((x) => x.productId === p.productId && x.code === p.code)) {
      throw new Error('duplicate_plan_code');
    }
    this.s.plans.set(p.id, clone(p));
  }
  async updatePlan(p: Plan) {
    this.s.plans.set(p.id, clone(p));
  }
  async findPlan(id: string) {
    return clone(this.s.plans.get(id));
  }
  async findTrialPlan(productId: string) {
    return clone(
      [...this.s.plans.values()].find((p) => p.productId === productId && p.tier === 'trial'),
    );
  }
  async listPlans(productId: string) {
    return clone([...this.s.plans.values()].filter((p) => p.productId === productId));
  }

  async insertSubscription(s: Subscription) {
    this.s.subscriptions.set(s.id, clone(s));
  }
  async updateSubscription(s: Subscription) {
    const cur = this.s.subscriptions.get(s.id);
    if (!cur || cur.orgId !== s.orgId) throw new Error('subscription_not_found');
    this.s.subscriptions.set(s.id, clone(s));
  }
  async findSubscription(orgId: string, id: string) {
    const s = this.s.subscriptions.get(id);
    return s && s.orgId === orgId ? clone(s) : undefined;
  }
  async listSubscriptions(orgId: string) {
    return clone([...this.s.subscriptions.values()].filter((s) => s.orgId === orgId));
  }

  async insertLicense(l: License) {
    if ([...this.s.licenses.values()].some((x) => x.keyDigest === l.keyDigest))
      throw new Error('duplicate_key');
    if (l.subscriptionId) {
      const sub = this.s.subscriptions.get(l.subscriptionId);
      if (!sub || sub.orgId !== l.orgId) throw new Error('cross_tenant_reference');
    }
    this.s.licenses.set(l.id, clone(l));
  }
  async updateLicense(l: License) {
    const cur = this.s.licenses.get(l.id);
    if (!cur || cur.orgId !== l.orgId) throw new Error('license_not_found');
    this.s.licenses.set(l.id, clone(l));
  }
  async findLicense(orgId: string, id: string) {
    const l = this.s.licenses.get(id);
    return l && l.orgId === orgId ? clone(l) : undefined;
  }
  async findLicenseForUpdate(orgId: string, id: string) {
    return this.findLicense(orgId, id);
  }
  async findLicenseForShare(orgId: string, id: string) {
    return this.findLicense(orgId, id);
  }
  async listLicenses(orgId: string) {
    return clone([...this.s.licenses.values()].filter((l) => l.orgId === orgId));
  }
  async findLicenseContext(orgId: string, id: string, _lock: 'none' | 'share' | 'update') {
    const license = await this.findLicense(orgId, id);
    if (!license) return undefined;
    const sub = license.subscriptionId
      ? this.s.subscriptions.get(license.subscriptionId)
      : undefined;
    const plan = this.s.plans.get(sub?.orgId === orgId ? sub.planId : license.planId);
    const product = this.s.products.get(license.productId);
    if (!plan || plan.productId !== license.productId || !product) return undefined;
    return clone({
      license,
      plan,
      product,
      subscription: sub && sub.orgId === orgId ? sub : undefined,
    });
  }
  async findLicenseByKeyDigest(digest: string) {
    return clone([...this.s.licenses.values()].find((l) => l.keyDigest === digest));
  }

  async insertTrialClaim(c: TrialClaim) {
    if (
      this.s.trialClaims.some(
        (x) => x.productId === c.productId && (x.orgId === c.orgId || x.userId === c.userId),
      )
    ) {
      throw new Error('trial_exists');
    }
    this.s.trialClaims.push(clone(c));
  }

  async findDeviceByThumbprint(thumbprint: string) {
    return clone([...this.s.devices.values()].find((d) => d.thumbprint === thumbprint));
  }
  async findDevice(orgId: string, id: string) {
    const d = this.s.devices.get(id);
    return d && d.orgId === orgId ? clone(d) : undefined;
  }
  async insertDevice(d: Device): Promise<Device> {
    const existing = [...this.s.devices.values()].find((x) => x.thumbprint === d.thumbprint);
    if (existing) return clone(existing);
    this.s.devices.set(d.id, clone(d));
    return clone(d);
  }

  async insertActivation(a: Activation) {
    const lic = this.s.licenses.get(a.licenseId);
    const dev = this.s.devices.get(a.deviceId);
    if (!lic || !dev || lic.orgId !== a.orgId || dev.orgId !== a.orgId)
      throw new Error('cross_tenant_reference');
    if (a.status === 'active' && (await this.findActiveActivation(a.licenseId, a.deviceId))) {
      throw new Error('duplicate_active_activation');
    }
    this.s.activations.set(a.id, clone(a));
  }
  async updateActivation(a: Activation) {
    const cur = this.s.activations.get(a.id);
    if (!cur || cur.orgId !== a.orgId) throw new Error('activation_not_found');
    this.s.activations.set(a.id, clone(a));
  }
  async touchActiveActivation(orgId: string, id: string, installationId: string, at: Date) {
    const cur = this.s.activations.get(id);
    if (
      !cur ||
      cur.orgId !== orgId ||
      cur.installationId !== installationId ||
      cur.status !== 'active'
    )
      return undefined;
    const next = { ...cur, lastValidatedAt: at };
    this.s.activations.set(id, clone(next));
    return clone(next);
  }
  async findActivation(orgId: string, id: string) {
    const a = this.s.activations.get(id);
    return a && a.orgId === orgId ? clone(a) : undefined;
  }
  async findActivationForDeviceAuth(id: string) {
    return clone(this.s.activations.get(id));
  }
  async findActivationWithDevice(id: string) {
    const activation = this.s.activations.get(id);
    const device = activation && this.s.devices.get(activation.deviceId);
    if (!activation || !device || device.orgId !== activation.orgId) return undefined;
    const posture = this.s.devicePostures.get(device.id);
    return clone({ activation, device, ...(posture ? { posture } : {}) });
  }
  async insertDeviceSignal(sig: DeviceSignal) {
    this.s.deviceSignals.set(sig.id, clone(sig));
  }
  async listDeviceSignals(orgId: string, deviceId: string, since: Date) {
    return [...this.s.deviceSignals.values()]
      .filter((x) => x.orgId === orgId && x.deviceId === deviceId && x.observedAt >= since)
      .sort((a, b) => +a.observedAt - +b.observedAt || a.id.localeCompare(b.id))
      .map(clone);
  }
  async purgeExpiredDeviceSignals(before: Date, limit = 5000) {
    let n = 0;
    for (const [k, x] of this.s.deviceSignals) {
      if (n >= limit) break;
      if (x.expiresAt < before) {
        this.s.deviceSignals.delete(k);
        n++;
      }
    }
    return n;
  }
  async upsertDevicePosture(p: DevicePosture) {
    this.s.devicePostures.set(p.deviceId, clone(p));
  }
  async findDevicePosture(orgId: string, deviceId: string) {
    const p = this.s.devicePostures.get(deviceId);
    return p && p.orgId === orgId ? clone(p) : undefined;
  }
  async findActivationSlot(licenseId: string, deviceId: string) {
    return {
      existing: await this.findActiveActivation(licenseId, deviceId),
      used: await this.countActiveActivations(licenseId),
    };
  }
  async findActiveActivation(licenseId: string, deviceId: string) {
    return clone(
      [...this.s.activations.values()].find(
        (a) => a.licenseId === licenseId && a.deviceId === deviceId && a.status === 'active',
      ),
    );
  }
  async countActiveActivations(licenseId: string) {
    return [...this.s.activations.values()].filter(
      (a) => a.licenseId === licenseId && a.status === 'active',
    ).length;
  }
  async listActivationsForLicense(orgId: string, licenseId: string) {
    return clone(
      [...this.s.activations.values()].filter(
        (a) => a.orgId === orgId && a.licenseId === licenseId,
      ),
    );
  }

  async insertLease(r: LeaseRecord) {
    const a = this.s.activations.get(r.activationId);
    if (!a || a.orgId !== r.orgId) throw new Error('cross_tenant_reference');
    this.s.leases.set(r.jti, clone(r));
  }

  async recordLease(r: LeaseRecord, a: Activation) {
    const act = this.s.activations.get(r.activationId);
    if (!act || act.orgId !== r.orgId || a.id !== r.activationId) {
      throw new Error('cross_tenant_reference');
    }
    await this.updateActivation(a); // throws before anything is stored if the update is invalid
    await this.insertLease(r);
  }

  async insertChallenge(c: Challenge) {
    this.s.challenges.set(c.nonceHash, clone(c));
  }
  async insertChallengeIfBelow(c: Challenge, max: number, now: Date) {
    if ((await this.countOutstandingChallenges(c.installationId, now)) >= max) return false;
    await this.insertChallenge(c);
    return true;
  }
  async countOutstandingChallenges(installationId: string, now: Date) {
    return [...this.s.challenges.values()].filter(
      (c) => c.installationId === installationId && !c.consumedAt && c.expiresAt > now,
    ).length;
  }
  async consumeChallenge(nonceHash: string, now: Date): Promise<ConsumeResult> {
    // Synchronous read-modify-write: atomic with respect to the event loop.
    const c = this.s.challenges.get(nonceHash);
    if (!c) return { status: 'missing' };
    if (c.consumedAt) return { status: 'used' };
    c.consumedAt = now;
    if (c.expiresAt <= now) return { status: 'expired' };
    return { status: 'ok', challenge: clone(c) };
  }
  async purgeExpiredChallenges(before: Date, limit = Number.MAX_SAFE_INTEGER) {
    let n = 0;
    for (const [k, c] of this.s.challenges) {
      if (n >= limit) break;
      if (c.expiresAt < before) {
        this.s.challenges.delete(k);
        n++;
      }
    }
    return n;
  }
  async purgeExpiredLeases(before: Date, limit = Number.MAX_SAFE_INTEGER) {
    let n = 0;
    for (const [k, l] of this.s.leases) {
      if (n >= limit) break;
      if (l.expiresAt < before) {
        this.s.leases.delete(k);
        n++;
      }
    }
    return n;
  }
}

/**
 * In-memory adapter. `transaction` serializes units of work with a mutex and rolls back by
 * restoring a snapshot when the callback (or the audit flush) throws — enough to test concurrency
 * invariants such as the device limit. The PostgreSQL adapter provides the same guarantees with row
 * locks. Audit events are buffered and handed to `audit` only if the transaction commits.
 */
export class InMemoryLicensingStore extends Repo implements LicensingStore {
  #lock: Promise<unknown> = Promise.resolve();
  readonly #audit: AuditLog | undefined;
  /** Committed audit inputs when no AuditLog was supplied (handy for standalone tests). */
  readonly committedAudit: AuditEventInput[] = [];

  constructor(opts?: { audit?: AuditLog }) {
    super(emptyState());
    this.#audit = opts?.audit;
  }

  transaction<T>(fn: (tx: LicensingTx) => Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      const snapshot = structuredClone(this.s);
      const buffer = new AuditBuffer();
      // Prototype delegation: the transaction sees the live state through the store's own methods.
      const tx = Object.assign(Object.create(this) as Repo, {
        audit: buffer,
      }) as unknown as LicensingTx;
      try {
        const out = await fn(tx);
        const events = buffer.drain();
        if (this.#audit) await this.#audit.appendMany(events);
        else this.committedAudit.push(...events);
        return out;
      } catch (e) {
        Object.assign(this.s, snapshot);
        throw e;
      }
    };
    const p = this.#lock.then(run, run);
    this.#lock = p.catch(() => undefined);
    return p;
  }
}
