import { createHash, randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { AuthService } from '@trust/auth';
import type { BillingCheckout, LicensingStore } from '@trust/licensing';
import { DomainError, type Clock, type UserPrincipal } from '@trust/shared-types';
import type {
  CheckoutProvider,
  PaddleWebhookVerifier,
  ProviderCheckout,
} from './integrations/billing.ts';

export interface BillingConfig {
  apiKey: string;
  webhookSecret: string;
  environment: 'sandbox' | 'live';
  paymentUrl: string;
  prices: Record<string, string>;
  clientToken?: string;
  portalOrigin?: string;
}
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const id = z.string().regex(/^bco_[a-z0-9_-]{16,64}$/);
const price = z.string().regex(/^pri_[a-z0-9]{26}$/);
const items = z
  .array(
    z
      .object({ quantity: z.literal(1), price: z.object({ id: price }).passthrough() })
      .passthrough(),
  )
  .length(1);
const custom = z.object({ trust_checkout_id: id }).passthrough();
const period = z.object({ ends_at: z.string().datetime({ offset: true }) }).passthrough();
const completed = z
  .object({
    id: z.string().regex(/^txn_[a-z0-9]{26}$/),
    status: z.literal('completed'),
    collection_mode: z.literal('automatic'),
    subscription_id: z.string().regex(/^sub_[a-z0-9]{26}$/),
    custom_data: custom,
    items,
    billing_period: period,
  })
  .passthrough();
const subscription = z
  .object({
    id: z.string().regex(/^sub_[a-z0-9]{26}$/),
    status: z.enum(['active', 'trialing', 'past_due', 'paused', 'canceled']),
    custom_data: custom,
    items,
    current_billing_period: period.nullable(),
  })
  .passthrough();

interface BillingDependencies {
  store: LicensingStore;
  auth: AuthService;
  clock: Clock;
  provider: CheckoutProvider;
  verifier: PaddleWebhookVerifier;
  prices: Record<string, string>;
}

/** All provider I/O is outside retryable transactions; only mapped verified events change access. */
export class BillingService {
  readonly #d: BillingDependencies;
  constructor(deps: BillingDependencies) {
    this.#d = deps;
  }
  catalog() {
    return { planIds: Object.keys(this.#d.prices) };
  }
  async #view(c: BillingCheckout) {
    const license = await this.#d.store.findLicense(c.orgId, c.licenseId);
    const sub = license?.subscriptionId
      ? await this.#d.store.findSubscription(c.orgId, license.subscriptionId)
      : undefined;
    return {
      id: c.id,
      licenseId: c.licenseId,
      planId: c.planId,
      status: c.status,
      checkoutUrl: c.status === 'ready' ? c.checkoutUrl : null,
      createdAt: c.createdAt,
      subscriptionStatus: sub?.status ?? null,
      currentPeriodEnd: sub?.currentPeriodEnd ?? null,
    };
  }
  async get(p: UserPrincipal, orgId: string, licenseId: string) {
    await this.#d.auth.requireOrgPermission(p, orgId, 'org:manage_members');
    const c = await this.#d.store.findBillingCheckoutForLicense(orgId, licenseId);
    if (!c) throw new DomainError('not_found', 'not found');
    return this.#view(c);
  }
  async create(
    p: UserPrincipal,
    orgId: string,
    licenseId: string,
    planId: string,
    operationId: string,
  ) {
    await this.#d.auth.requireOrgPermission(p, orgId, 'org:manage_members');
    const requestHash = hash(operationId),
      priceId = this.#d.prices[planId];
    if (!priceId) throw new DomainError('invalid_request', 'plan is not available for checkout');
    const reservation = await this.#d.store
      .transaction(async (tx) => {
        const ctx = await tx.findLicenseContext(orgId, licenseId, 'update');
        if (!ctx || ctx.license.kind === 'canary') throw new DomainError('not_found', 'not found');
        if (
          !ctx.subscription ||
          !['trial', 'subscription'].includes(ctx.license.kind) ||
          ctx.license.state !== 'active'
        )
          throw new DomainError('forbidden', 'license is not available for checkout');
        const existing = await tx.findBillingCheckoutForLicense(orgId, licenseId);
        if (existing) {
          if (existing.requestHash !== requestHash || existing.planId !== planId)
            throw new DomainError('conflict', 'a checkout already exists for this license');
          return { checkout: existing, submit: false };
        }
        const plan = await tx.findPlan(planId),
          product = plan ? await tx.findProductById(plan.productId) : undefined;
        if (
          !plan ||
          plan.productId !== ctx.license.productId ||
          product?.status !== 'active' ||
          plan.tier === 'trial'
        )
          throw new DomainError('invalid_request', 'plan is not available for checkout');
        const checkout: BillingCheckout = {
          id: 'bco_' + randomBytes(18).toString('hex'),
          orgId,
          userId: p.userId,
          licenseId,
          planId,
          priceId,
          requestHash,
          status: 'submitting',
          transactionId: null,
          checkoutUrl: null,
          providerSubscriptionId: null,
          lastEventAt: null,
          createdAt: this.#d.clock.now(),
        };
        await tx.insertBillingCheckout(checkout);
        await tx.audit.append({
          actor: { type: 'user', id: p.userId },
          action: 'billing.checkout_requested',
          orgId,
          target: { type: 'checkout', id: checkout.id },
          metadata: { license_id: licenseId, plan_id: planId },
        });
        return { checkout, submit: true };
      })
      .catch((error) => {
        if (error instanceof Error && error.message === 'duplicate_checkout')
          throw new DomainError(
            'conflict',
            'a checkout already exists for this operation or license',
          );
        throw error;
      });
    if (!reservation.submit) return this.#view(reservation.checkout);
    let response: ProviderCheckout;
    try {
      response = await this.#d.provider.createCheckout({
        intentId: reservation.checkout.id,
        priceId,
      });
    } catch {
      const failed = await this.#d.store.transaction(async (tx) => {
        await tx.findLicenseForUpdate(orgId, licenseId);
        const c = await tx.findBillingCheckout(reservation.checkout.id);
        if (!c) throw new Error('checkout missing');
        if (c.status === 'submitting') {
          c.status = 'uncertain';
          await tx.updateBillingCheckout(c);
          await tx.audit.append({
            actor: { type: 'system' },
            action: 'billing.checkout_uncertain',
            orgId,
            target: { type: 'checkout', id: c.id },
          });
        }
        return c;
      });
      return this.#view(failed);
    }
    return this.#view(await this.#finish(reservation.checkout, response));
  }
  async #finish(
    original: BillingCheckout,
    response: ProviderCheckout,
    actor?: { id: string; reason: string },
  ) {
    return this.#d.store.transaction(async (tx) => {
      await tx.findLicenseForUpdate(original.orgId, original.licenseId);
      const c = await tx.findBillingCheckout(original.id);
      if (!c) throw new Error('checkout missing');
      if (c.transactionId && c.transactionId !== response.transactionId)
        throw new DomainError('conflict', 'checkout transaction mismatch');
      c.transactionId = response.transactionId;
      c.checkoutUrl = response.url;
      if (c.status !== 'completed') c.status = 'ready';
      await tx.updateBillingCheckout(c);
      await tx.audit.append({
        actor: actor ? { type: 'user', id: actor.id } : { type: 'system' },
        action: actor ? 'billing.checkout_reconciled' : 'billing.checkout_ready',
        orgId: c.orgId,
        target: { type: 'checkout', id: c.id },
        ...(actor ? { reason: actor.reason } : {}),
        metadata: { transaction_id: c.transactionId },
      });
      return c;
    });
  }
  async reconcile(
    orgId: string,
    licenseId: string,
    transactionId: string,
    actor: { id: string; reason: string },
  ) {
    const c = await this.#d.store.findBillingCheckoutForLicense(orgId, licenseId);
    if (!c) throw new DomainError('not_found', 'not found');
    const response = await this.#d.provider.getCheckout(transactionId, {
      intentId: c.id,
      priceId: c.priceId,
    });
    return this.#view(await this.#finish(c, response, actor));
  }
  async webhook(raw: string, signature: string) {
    let event;
    try {
      event = this.#d.verifier.verify(raw, signature);
    } catch {
      throw new DomainError('forbidden', 'invalid billing webhook');
    }
    const isCompleted = event.type === 'transaction.completed';
    const isSubscription = [
      'subscription.activated',
      'subscription.updated',
      'subscription.past_due',
      'subscription.paused',
      'subscription.canceled',
      'subscription.resumed',
    ].includes(event.type);
    // Irrelevant notifications cannot grant access; avoid retaining their potentially personal payloads.
    if (!isCompleted && !isSubscription) return { accepted: true, ignored: true };
    const parsed = isCompleted
      ? completed.safeParse(event.data)
      : subscription.safeParse(event.data);
    if (!parsed.success) throw new DomainError('invalid_request', 'invalid billing event');
    if (isSubscription && event.type !== 'subscription.updated') {
      const required: Record<string, string> = {
        'subscription.activated': 'active',
        'subscription.resumed': 'active',
        'subscription.past_due': 'past_due',
        'subscription.paused': 'paused',
        'subscription.canceled': 'canceled',
      };
      if (parsed.data.status !== required[event.type])
        throw new DomainError('invalid_request', 'billing event status mismatch');
    }
    const data = parsed.data,
      occurredAt = new Date(event.occurredAt),
      now = this.#d.clock.now();
    if (occurredAt.getTime() > now.getTime() + 300_000)
      throw new DomainError('invalid_request', 'future billing event');
    const mapping = await this.#d.store.findBillingCheckout(data.custom_data.trust_checkout_id);
    if (!mapping) throw new DomainError('conflict', 'billing event requires reconciliation');
    const bodyHash = hash(raw);
    return this.#d.store.transaction(async (tx) => {
      const ctx = await tx.findLicenseContext(mapping.orgId, mapping.licenseId, 'update');
      const c = await tx.findBillingCheckout(mapping.id);
      if (!ctx?.subscription || !c)
        throw new DomainError('conflict', 'billing event requires reconciliation');
      const previous = await tx.findBillingEvent(event.id);
      if (previous) {
        if (previous.bodyHash !== bodyHash || previous.checkoutId !== c.id)
          throw new DomainError('conflict', 'billing event identity conflict');
        return { accepted: true, duplicate: true };
      }
      if (data.items[0]!.price.id !== c.priceId)
        throw new DomainError('forbidden', 'billing price mismatch');
      const paid = isCompleted ? completed.parse(data) : undefined,
        sub = isCompleted ? undefined : subscription.parse(data);
      if (paid) {
        if (
          !c.transactionId ||
          (!c.providerSubscriptionId && paid.id !== c.transactionId) ||
          (c.providerSubscriptionId && paid.subscription_id !== c.providerSubscriptionId)
        )
          throw new DomainError('conflict', 'billing event requires reconciliation');
      } else if (!c.providerSubscriptionId || sub!.id !== c.providerSubscriptionId)
        throw new DomainError('conflict', 'billing event requires reconciliation');
      if (c.lastEventAt && occurredAt.getTime() === c.lastEventAt.getTime())
        throw new DomainError('conflict', 'simultaneous billing events require reconciliation');
      const ignored = !!c.lastEventAt && occurredAt < c.lastEventAt;
      if (!ignored) {
        const plan = await tx.findPlan(c.planId);
        if (!plan || plan.productId !== ctx.license.productId)
          throw new DomainError('conflict', 'billing plan requires reconciliation');
        const end = paid
          ? new Date(paid.billing_period.ends_at)
          : sub!.current_billing_period
            ? new Date(sub!.current_billing_period.ends_at)
            : null;
        const status = paid ? 'active' : sub!.status === 'paused' ? 'suspended' : sub!.status;
        if (status === 'trialing')
          throw new DomainError('conflict', 'provider trial requires reconciliation');
        if (status === 'active' && (!end || end <= now))
          throw new DomainError('conflict', 'billing period requires reconciliation');
        ctx.subscription.planId = c.planId;
        ctx.subscription.status = status;
        ctx.subscription.trialEnd = null;
        ctx.subscription.currentPeriodEnd = end;
        await tx.updateSubscription(ctx.subscription);
        if (paid && ctx.license.kind === 'trial') {
          ctx.license.kind = 'subscription';
          await tx.updateLicense(ctx.license);
        }
        c.providerSubscriptionId = paid?.subscription_id ?? c.providerSubscriptionId;
        c.lastEventAt = occurredAt;
        c.status = 'completed';
        await tx.updateBillingCheckout(c);
      }
      await tx.insertBillingEvent({
        id: event.id,
        checkoutId: c.id,
        bodyHash,
        occurredAt,
        createdAt: now,
      });
      await tx.audit.append({
        actor: { type: 'system' },
        action: ignored ? 'billing.event_ignored' : 'billing.event_applied',
        orgId: c.orgId,
        target: { type: 'checkout', id: c.id },
        metadata: {
          event_id: event.id,
          event_type: event.type,
          license_id: c.licenseId,
          plan_id: c.planId,
        },
      });
      return { accepted: true, ignored };
    });
  }
}
