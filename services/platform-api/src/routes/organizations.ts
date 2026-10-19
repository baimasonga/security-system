import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.ts';
import { authenticated, parse, principalOf, toWire } from '../http.ts';
import { clientTelemetryBody, memberBody, orgBody, orgParams } from '../schemas.ts';
import { securityCenter } from '../security-center.ts';

export function registerOrgRoutes(app: FastifyInstance, c: Container): void {
  const pre = { preHandler: authenticated(c) };

  // Security center (ADR-027): account protection, roles, devices and collected data categories.
  app.get('/v1/security-center', pre, async (req) =>
    toWire(await securityCenter(c, principalOf(req))),
  );

  // Privacy firewall (ADR-027): allow-listed client telemetry only; refusals name field and rule, never values.
  app.post(
    '/v1/telemetry/events',
    { ...pre, config: { rateLimit: { max: c.config.rateLimits.global, timeWindow: '1 minute' } } },
    async (req) => {
      const { events } = parse(clientTelemetryBody, req.body);
      const r = await c.telemetry.ingestClient(events);
      for (const x of r.rejected)
        for (const v of x.violations)
          c.metrics.inc('telemetry_firewall_rejected_total', { rule: v.rule });
      return r;
    },
  );

  app.post('/v1/organizations', pre, async (req, reply) => {
    const { name } = parse(orgBody, req.body);
    const org = await c.auth.createOrganization(principalOf(req), name);
    return reply
      .status(201)
      .send(toWire({ id: org.id, name: org.name, kind: org.kind, role: 'owner' }));
  });

  app.get('/v1/organizations', pre, async (req) => {
    const orgs = await c.auth.listOrganizations(principalOf(req));
    return {
      items: orgs.map((o) => toWire({ id: o.id, name: o.name, kind: o.kind, role: o.role })),
    };
  });

  app.get('/v1/organizations/:orgId', pre, async (req) => {
    const { orgId } = parse(orgParams, req.params);
    const o = await c.auth.getOrganization(principalOf(req), orgId);
    return toWire({ id: o.id, name: o.name, kind: o.kind, role: o.role });
  });

  app.get('/v1/organizations/:orgId/members', pre, async (req) => {
    const { orgId } = parse(orgParams, req.params);
    return { items: toWire(await c.auth.listMembers(principalOf(req), orgId)) };
  });

  app.post('/v1/organizations/:orgId/members', pre, async (req, reply) => {
    const { orgId } = parse(orgParams, req.params);
    const { email, role } = parse(memberBody, req.body);
    // Membership first (404 for non-members), so a freeze is never revealed to outsiders.
    await c.auth.getOrganization(principalOf(req), orgId);
    await c.privileged.assertWritable(orgId);
    const m = await c.auth.addMember(principalOf(req), orgId, email, role);
    return reply.status(201).send(toWire({ orgId: m.orgId, userId: m.userId, role: m.role }));
  });
}
