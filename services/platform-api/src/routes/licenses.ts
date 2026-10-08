import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.ts';
import { authenticated, parse, principalOf, toWire } from '../http.ts';
import {
  activationParams,
  entitlementsQuery,
  licenseParams,
  orgParams,
  trialBody,
} from '../schemas.ts';

/** Customer self-service. Every route is tenant-scoped and authorized by org membership/role. */
export function registerLicenseRoutes(app: FastifyInstance, c: Container): void {
  const pre = { preHandler: authenticated(c) };

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

  app.post('/v1/organizations/:orgId/trials', pre, async (req, reply) => {
    const { orgId } = parse(orgParams, req.params);
    const { product_id } = parse(trialBody, req.body);
    const r = await c.licensing.startTrial(principalOf(req), { orgId, productId: product_id });
    return reply.status(201).send({ license: toWire(r.license), license_key: r.licenseKey });
  });

  app.get('/v1/entitlements', pre, async (req) => {
    const q = parse(entitlementsQuery, req.query);
    return toWire(await c.licensing.getEntitlements(principalOf(req), q.org_id, q.license_id));
  });
}
