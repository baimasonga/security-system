import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Container } from '../container.ts';
import { authenticated, operator, parse, principalOf, toWire } from '../http.ts';
import { licenseParams, reasonBody } from '../schemas.ts';
const checkoutBody = z
  .object({
    plan_id: z.string().regex(/^pln_[A-Za-z0-9_-]+$/),
    idempotency_key: z.string().regex(/^[A-Za-z0-9_-]{16,128}$/),
  })
  .strict();
const reconcileBody = reasonBody
  .extend({ transaction_id: z.string().regex(/^txn_[a-z0-9]{26}$/) })
  .strict();
export function registerBillingRoutes(app: FastifyInstance, c: Container): void {
  const disabled = { code: 'unavailable', message: 'billing is not configured' };
  app.get('/v1/billing/checkout-options', async (_req, reply) => {
    if (!c.config.billing?.clientToken) return reply.status(503).send(disabled);
    return {
      environment: c.config.billing.environment,
      client_token: c.config.billing.clientToken,
      portal_origin: c.config.billing.portalOrigin,
    };
  });
  app.get('/v1/billing/catalog', { preHandler: authenticated(c) }, async () =>
    c.billing ? toWire(c.billing.catalog()) : { plan_ids: [] },
  );
  const path = '/v1/organizations/:orgId/licenses/:licenseId/checkout';
  app.get(path, { preHandler: authenticated(c) }, async (req, reply) => {
    if (!c.billing) return reply.status(503).send(disabled);
    const p = parse(licenseParams, req.params);
    return toWire(await c.billing.get(principalOf(req), p.orgId, p.licenseId));
  });
  app.post(path, { preHandler: authenticated(c) }, async (req, reply) => {
    if (!c.billing) return reply.status(503).send(disabled);
    const p = parse(licenseParams, req.params),
      body = parse(checkoutBody, req.body);
    return toWire(
      await c.billing.create(
        principalOf(req),
        p.orgId,
        p.licenseId,
        body.plan_id,
        body.idempotency_key,
      ),
    );
  });
  app.post(
    '/v1/admin/organizations/:orgId/licenses/:licenseId/checkout/reconcile',
    { preHandler: operator(c) },
    async (req, reply) => {
      if (!c.billing) return reply.status(503).send(disabled);
      const p = parse(licenseParams, req.params),
        body = parse(reconcileBody, req.body);
      return toWire(
        await c.billing.reconcile(p.orgId, p.licenseId, body.transaction_id, {
          id: principalOf(req).userId,
          reason: body.reason,
        }),
      );
    },
  );
  void app.register(async (webhook) => {
    // Encapsulated raw-byte parser: never change the application's normal JSON parser.
    webhook.removeContentTypeParser('application/json');
    webhook.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) =>
      done(null, body),
    );
    webhook.post('/v1/billing/webhooks/paddle', async (req, reply) => {
      if (!c.billing) return reply.status(503).send(disabled);
      const signature = req.headers['paddle-signature'];
      return c.billing.webhook(
        typeof req.body === 'string' ? req.body : '',
        typeof signature === 'string' ? signature : '',
      );
    });
  });
}
