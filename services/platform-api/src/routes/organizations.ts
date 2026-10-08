import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.ts';
import { authenticated, parse, principalOf, toWire } from '../http.ts';
import { memberBody, orgBody, orgParams } from '../schemas.ts';

export function registerOrgRoutes(app: FastifyInstance, c: Container): void {
  const pre = { preHandler: authenticated(c) };

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
    const m = await c.auth.addMember(principalOf(req), orgId, email, role);
    return reply.status(201).send(toWire({ orgId: m.orgId, userId: m.userId, role: m.role }));
  });
}
