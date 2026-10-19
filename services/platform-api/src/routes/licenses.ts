import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.ts';
import { authenticated, parse, principalOf, toWire } from '../http.ts';
import {
  productParams,
  quotaBody,
  activationParams,
  entitlementsQuery,
  licenseParams,
  orgParams,
  deviceParams,
  seatBody,
  seatParams,
  trialBody,
} from '../schemas.ts';

/** Customer self-service. Every route is tenant-scoped and authorized by org membership/role. */
export function registerLicenseRoutes(app: FastifyInstance, c: Container): void {
  const pre = { preHandler: authenticated(c) };
  app.get('/v1/organizations/:orgId/licenses/:licenseId/usage', pre, async (req) => {
    const { orgId, licenseId } = parse(licenseParams, req.params);
    return toWire(await c.licensing.getUsage(principalOf(req), orgId, licenseId));
  });
  app.post('/v1/organizations/:orgId/licenses/:licenseId/usage', pre, async (req) => {
    const { orgId, licenseId } = parse(licenseParams, req.params),
      body = parse(quotaBody, req.body);
    return toWire(
      await c.licensing.consumeQuota(principalOf(req), orgId, licenseId, {
        entitlement: body.entitlement,
        units: body.units,
        idempotencyKey: body.idempotency_key,
      }),
    );
  });

  app.get('/v1/catalog/products', pre, async () => ({
    items: toWire(await c.licensing.catalogProducts()),
  }));
  app.get('/v1/catalog/products/:productId/plans', pre, async (req) => {
    const { productId } = parse(productParams, req.params);
    return { items: toWire(await c.licensing.catalogPlans(productId)) };
  });

  app.get('/v1/organizations/:orgId/licenses', pre, async (req) => {
    const { orgId } = parse(orgParams, req.params);
    return { items: toWire(await c.licensing.listLicenses(principalOf(req), orgId)) };
  });

  app.get('/v1/organizations/:orgId/licenses/:licenseId', pre, async (req) => {
    const { orgId, licenseId } = parse(licenseParams, req.params);
    return toWire(await c.licensing.getLicense(principalOf(req), orgId, licenseId));
  });

  app.get('/v1/organizations/:orgId/licenses/:licenseId/activations', pre, async (req) => {
    const { orgId, licenseId } = parse(licenseParams, req.params);
    return { items: toWire(await c.licensing.listActivations(principalOf(req), orgId, licenseId)) };
  });

  app.post('/v1/organizations/:orgId/activations/:activationId/deactivate', pre, async (req) => {
    const { orgId, activationId } = parse(activationParams, req.params);
    return toWire(await c.licensing.deactivateActivation(principalOf(req), orgId, activationId));
  });

  // Device passport (ADR-026): key identity, attestation status, server-observed signals, posture.
  app.get('/v1/organizations/:orgId/devices/:deviceId/passport', pre, async (req) => {
    const { orgId, deviceId } = parse(deviceParams, req.params);
    return toWire(await c.licensing.devicePassport(principalOf(req), orgId, deviceId));
  });

  // ---- seats (ADR-025) ----
  app.get('/v1/organizations/:orgId/licenses/:licenseId/seats', pre, async (req) => {
    const { orgId, licenseId } = parse(licenseParams, req.params);
    return toWire(await c.licensing.listSeats(principalOf(req), orgId, licenseId));
  });
  app.post('/v1/organizations/:orgId/licenses/:licenseId/seats', pre, async (req, reply) => {
    const { orgId, licenseId } = parse(licenseParams, req.params);
    const { user_id } = parse(seatBody, req.body);
    await c.auth.getOrganization(principalOf(req), orgId); // 404 for non-members before revealing a freeze
    await c.privileged.assertWritable(orgId);
    const out = await c.licensing.assignSeat(principalOf(req), orgId, licenseId, user_id);
    return reply.status(201).send(toWire(out));
  });
  app.post(
    '/v1/organizations/:orgId/licenses/:licenseId/seats/:userId/unassign',
    pre,
    async (req) => {
      const { orgId, licenseId, userId } = parse(seatParams, req.params);
      return toWire(await c.licensing.unassignSeat(principalOf(req), orgId, licenseId, userId));
    },
  );

  app.post('/v1/organizations/:orgId/trials', pre, async (req, reply) => {
    const { orgId } = parse(orgParams, req.params);
    const { product_id } = parse(trialBody, req.body);
    await c.auth.getOrganization(principalOf(req), orgId); // 404 for non-members before revealing a freeze
    await c.privileged.assertWritable(orgId);
    const r = await c.licensing.startTrial(principalOf(req), { orgId, productId: product_id });
    return reply.status(201).send({ license: toWire(r.license), license_key: r.licenseKey });
  });

  app.get('/v1/entitlements', pre, async (req) => {
    const q = parse(entitlementsQuery, req.query);
    return toWire(await c.licensing.getEntitlements(principalOf(req), q.org_id, q.license_id));
  });
}
