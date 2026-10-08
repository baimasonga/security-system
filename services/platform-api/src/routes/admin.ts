import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.ts';
import { operator, parse, principalOf, toWire } from '../http.ts';
import {
  auditQuery,
  issueLicenseBody,
  licenseParams,
  mapOverrides,
  orgParams,
  planBody,
  planParams,
  planPatchBody,
  productBody,
  productParams,
  reasonBody,
  subParams,
  subscriptionBody,
  subscriptionPatchBody,
} from '../schemas.ts';

/**
 * Platform-operator surface. Every route: authenticated, re-checks the operator role on each call,
 * requires a reason on mutations, and is tenant-explicit (org id in the path) — no cross-tenant
 * wildcard queries. JIT elevation / dual control arrive in Milestone 6.
 */
export function registerAdminRoutes(app: FastifyInstance, c: Container): void {
  const pre = { preHandler: operator(c) };
  const actor = (req: Parameters<typeof principalOf>[0], reason: string) => ({
    id: principalOf(req).userId,
    reason,
  });
  const date = (s: string | null | undefined) =>
    s === undefined ? undefined : s === null ? null : new Date(s);

  app.post('/v1/admin/products', pre, async (req, reply) => {
    const b = parse(productBody, req.body);
    return reply
      .status(201)
      .send(
        toWire(
          await c.licensing.createProduct({ code: b.code, name: b.name }, actor(req, b.reason)),
        ),
      );
  });

  app.post('/v1/admin/products/:productId/plans', pre, async (req, reply) => {
    const { productId } = parse(productParams, req.params);
    const b = parse(planBody, req.body);
    const plan = await c.licensing.createPlan(
      {
        productId,
        code: b.code,
        tier: b.tier,
        entitlements: b.entitlements,
        capabilities: b.capabilities,
        deviceLimit: b.device_limit,
      },
      actor(req, b.reason),
    );
    return reply.status(201).send(toWire(plan));
  });

  app.patch('/v1/admin/plans/:planId', pre, async (req) => {
    const { planId } = parse(planParams, req.params);
    const b = parse(planPatchBody, req.body);
    return toWire(
      await c.licensing.updatePlan(
        planId,
        {
          ...(b.entitlements ? { entitlements: b.entitlements } : {}),
          ...(b.capabilities ? { capabilities: b.capabilities } : {}),
          ...(b.device_limit !== undefined ? { deviceLimit: b.device_limit } : {}),
        },
        actor(req, b.reason),
      ),
    );
  });

  app.post('/v1/admin/organizations/:orgId/subscriptions', pre, async (req, reply) => {
    const { orgId } = parse(orgParams, req.params);
    const b = parse(subscriptionBody, req.body);
    const s = await c.licensing.createSubscription(
      {
        orgId,
        planId: b.plan_id,
        status: b.status,
        trialEnd: date(b.trial_end) ?? null,
        currentPeriodEnd: date(b.current_period_end) ?? null,
      },
      actor(req, b.reason),
    );
    return reply.status(201).send(toWire(s));
  });

  app.patch('/v1/admin/organizations/:orgId/subscriptions/:subscriptionId', pre, async (req) => {
    const { orgId, subscriptionId } = parse(subParams, req.params);
    const b = parse(subscriptionPatchBody, req.body);
    const cpe = date(b.current_period_end);
    return toWire(
      await c.licensing.updateSubscription(
        orgId,
        subscriptionId,
        {
          ...(b.status ? { status: b.status } : {}),
          ...(b.plan_id ? { planId: b.plan_id } : {}),
          ...(cpe !== undefined ? { currentPeriodEnd: cpe } : {}),
        },
        actor(req, b.reason),
      ),
    );
  });

  app.post('/v1/admin/organizations/:orgId/licenses', pre, async (req, reply) => {
    const { orgId } = parse(orgParams, req.params);
    const b = parse(issueLicenseBody, req.body);
    const overrides = mapOverrides(b.overrides);
    const r = await c.licensing.issueLicense(
      {
        orgId,
        productId: b.product_id,
        planId: b.plan_id,
        kind: b.kind,
        ...(b.subscription_id ? { subscriptionId: b.subscription_id } : {}),
        ...(b.expires_at ? { expiresAt: new Date(b.expires_at) } : {}),
        ...(overrides ? { overrides } : {}),
      },
      actor(req, b.reason),
    );
    // The plaintext key is returned exactly once, here.
    return reply.status(201).send({ license: toWire(r.license), license_key: r.licenseKey });
  });

  app.get('/v1/admin/organizations/:orgId/licenses', pre, async (req) => {
    const { orgId } = parse(orgParams, req.params);
    return { items: toWire(await c.licensing.adminListLicenses(orgId)) };
  });

  app.get('/v1/admin/organizations/:orgId/licenses/:licenseId/activations', pre, async (req) => {
    const { orgId, licenseId } = parse(licenseParams, req.params);
    return { items: toWire(await c.licensing.adminListActivations(orgId, licenseId)) };
  });

  for (const action of ['suspend', 'reinstate', 'revoke'] as const) {
    app.post(`/v1/admin/organizations/:orgId/licenses/:licenseId/${action}`, pre, async (req) => {
      const { orgId, licenseId } = parse(licenseParams, req.params);
      const { reason } = parse(reasonBody, req.body);
      return toWire(
        await c.licensing.setLicenseState(orgId, licenseId, action, actor(req, reason)),
      );
    });
  }

  app.get('/v1/admin/audit', pre, async (req) => {
    const q = parse(auditQuery, req.query);
    const items = await c.audit.list({
      ...(q.org_id ? { orgId: q.org_id } : {}),
      ...(q.action ? { action: q.action } : {}),
      limit: q.limit,
    });
    return { items: toWire(items) };
  });

  app.get('/v1/admin/audit/verify', pre, async () => toWire(await c.audit.verifyChain()));
}
