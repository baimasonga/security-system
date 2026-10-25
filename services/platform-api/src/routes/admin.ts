import type { FastifyInstance } from 'fastify';
import { DomainError } from '@trust/shared-types';
import { createApkDistributionReader } from '../integrations/apk-distribution.ts';
import type { Container } from '../container.ts';
import { operator, parse, principalOf, toWire } from '../http.ts';
import {
  emptyBody,
  auditQuery,
  deviceParams,
  anchorManifestBody,
  anchorsQuery,
  auditVerifyQuery,
  metricsQuery,
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
 * wildcard queries. Writes that grant or extend access are refused while the platform or the organization is
 * frozen; dual-control requests, JIT grants and break-glass live in routes/privileged.ts (ADR-022).
 */
export function registerAdminRoutes(app: FastifyInstance, c: Container): void {
  const pre = { preHandler: operator(c) };
  const readApkDistribution = createApkDistributionReader();
  app.get('/v1/admin/mobile-distribution', pre, async (req) => {
    parse(emptyBody, req.query);
    return readApkDistribution();
  });
  const actor = (req: Parameters<typeof principalOf>[0], reason: string) => ({
    id: principalOf(req).userId,
    reason,
  });
  const date = (s: string | null | undefined) =>
    s === undefined ? undefined : s === null ? null : new Date(s);

  app.post('/v1/admin/products', pre, async (req, reply) => {
    const b = parse(productBody, req.body);
    await c.privileged.assertWritable(null);
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
    await c.privileged.assertWritable(null);
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
    await c.privileged.assertWritable(null);
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
    await c.privileged.assertWritable(orgId);
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
    await c.privileged.assertWritable(orgId);
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
    await c.privileged.assertWritable(orgId);
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
      // Reinstating restores access; suspension and revocation are containment and stay available.
      if (action === 'reinstate') await c.privileged.assertWritable(orgId);
      if (action === 'revoke' && c.privileged.dualControlLicenseRevoke)
        throw new DomainError(
          'conflict',
          'license revocation requires a second operator: create a privileged request (license.revoke)',
          { approval_required: true },
        );
      return toWire(
        await c.licensing.setLicenseState(orgId, licenseId, action, actor(req, reason)),
      );
    });
  }

  app.get('/v1/admin/organizations/:orgId/devices/:deviceId/passport', pre, async (req) => {
    const { orgId, deviceId } = parse(deviceParams, req.params);
    return toWire(await c.licensing.devicePassport(null, orgId, deviceId));
  });

  app.get('/v1/admin/audit', pre, async (req) => {
    const q = parse(auditQuery, req.query);
    const items = await c.audit.list({
      ...(q.org_id ? { orgId: q.org_id } : {}),
      ...(q.action ? { action: q.action } : {}),
      limit: q.limit,
    });
    return { items: toWire(items) };
  });

  // Operational metrics (operator-only). JSON by default, Prometheus text with ?format=prometheus.
  app.get('/v1/admin/metrics', pre, async (req, reply) => {
    const { format } = parse(metricsQuery, req.query);
    if (format === 'prometheus') {
      return reply.type('text/plain; version=0.0.4').send(c.metrics.prometheus());
    }
    return c.metrics.snapshot();
  });

  // Verifies every chain and head (or one organization's chains with ?org_id=). Read-only.
  app.get('/v1/admin/audit/verify', pre, async (req) => {
    const q = parse(auditVerifyQuery, req.query);
    const v = await c.audit.verifyChain(q.org_id ? { orgId: q.org_id } : undefined);
    if (v.ok) {
      const { heads: _heads, ...summary } = v; // the per-chain list can be huge; it goes to the witness, not here
      void _heads;
      return toWire(summary);
    }
    return toWire(v);
  });

  // ---- external anchoring (ADR-010) ----
  app.get('/v1/admin/audit/anchors', pre, async (req) => {
    const q = parse(anchorsQuery, req.query);
    return {
      configured: c.anchors !== undefined,
      destination: c.anchors?.destination ?? null,
      items: toWire(await c.anchorStore.list(q.limit)),
    };
  });

  // Publish now (also when nothing changed). Verifies first; a log that fails verification is never anchored.
  app.post('/v1/admin/audit/anchors', pre, async (req) => {
    const b = parse(reasonBody, req.body);
    if (!c.anchors) throw new DomainError('conflict', 'external anchoring is not configured');
    const out = await c.anchors.publish({ force: true });
    await c.audit.append({
      actor: { type: 'operator', id: principalOf(req).userId },
      action:
        out.status === 'published'
          ? 'audit.anchor_published'
          : out.status === 'failed'
            ? 'audit.anchor_failed'
            : 'audit.anchor_refused',
      reason: b.reason,
      metadata:
        out.status === 'published' || out.status === 'failed'
          ? { anchor: out.record.anchor, chains: out.record.chains, status: out.status }
          : out.status === 'chain_invalid'
            ? { chain_invalid: true, broken_at_seq: out.brokenAtSeq }
            : { status: out.status },
    });
    return toWire(out.status === 'published' || out.status === 'failed' ? { ...out.record } : out);
  });

  // Is the live log consistent with a manifest the witness holds? Read-only (no state change, no reason needed).
  app.post('/v1/admin/audit/anchors/check', pre, async (req) => {
    const { manifest } = parse(anchorManifestBody, req.body);
    const log = await c.audit.verifyChain();
    if (!log.ok) return toWire({ stage: 'log', ...log });
    const w = await c.audit.checkAnchor(manifest);
    return toWire(w.ok ? w : { stage: 'witness', ...w });
  });
}
