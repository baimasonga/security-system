import type { FastifyInstance } from 'fastify';
import { DomainError } from '@trust/shared-types';
import type { Container } from '../container.ts';
import { operator, parse, principalOf, toWire } from '../http.ts';
import {
  freezeBody,
  privilegedCreateBody,
  privilegedDecisionBody,
  privilegedListQuery,
  privilegedParams,
  reasonBody,
} from '../schemas.ts';

/**
 * Privileged operations (ADR-022): dual-control requests (JIT grants), freeze and break-glass. Operator-only; every
 * mutation takes a reason and is audited in the same transaction as its state change.
 */
export function registerPrivilegedRoutes(app: FastifyInstance, c: Container): void {
  const pre = { preHandler: operator(c) };
  const base = '/v1/admin/privileged/requests';

  app.post(base, pre, async (req, reply) => {
    const b = parse(privilegedCreateBody, req.body);
    const r = await c.privileged.create(principalOf(req).userId, {
      operation: b.operation,
      reason: b.reason,
      ...('org_id' in b ? { orgId: b.org_id } : {}),
      ...('license_id' in b ? { targetId: b.license_id } : {}),
      ...('user_id' in b ? { targetId: b.user_id } : {}),
    });
    return reply.status(201).send(toWire(r));
  });

  app.get(base, pre, async (req) => {
    const q = parse(privilegedListQuery, req.query);
    return { items: toWire(await c.privileged.list(q.status, q.limit)) };
  });

  app.get(`${base}/:requestId`, pre, async (req) => {
    const { requestId } = parse(privilegedParams, req.params);
    return toWire(await c.privileged.get(requestId));
  });

  app.post(`${base}/:requestId/approve`, pre, async (req) => {
    const { requestId } = parse(privilegedParams, req.params);
    const b = parse(privilegedDecisionBody, req.body);
    const p = principalOf(req);
    return toWire(
      await c.privileged.approve(
        { userId: p.userId, sessionId: p.sessionId },
        requestId,
        b.reason,
        b.code,
      ),
    );
  });

  app.post(`${base}/:requestId/reject`, pre, async (req) => {
    const { requestId } = parse(privilegedParams, req.params);
    const b = parse(reasonBody, req.body);
    return toWire(await c.privileged.reject(principalOf(req).userId, requestId, b.reason));
  });

  app.post(`${base}/:requestId/cancel`, pre, async (req) => {
    const { requestId } = parse(privilegedParams, req.params);
    const b = parse(reasonBody, req.body);
    return toWire(await c.privileged.cancel(principalOf(req).userId, requestId, b.reason));
  });

  app.post(`${base}/:requestId/execute`, pre, async (req) => {
    const { requestId } = parse(privilegedParams, req.params);
    const b = parse(reasonBody, req.body);
    return toWire(await c.privileged.execute(principalOf(req).userId, requestId, b.reason));
  });

  // Self-approval when no second operator is available: bounded and witnessed externally before it can be used.
  app.post(`${base}/:requestId/break-glass`, pre, async (req) => {
    const { requestId } = parse(privilegedParams, req.params);
    const b = parse(privilegedDecisionBody, req.body);
    const p = principalOf(req);
    const approved = await c.privileged.breakGlass(
      { userId: p.userId, sessionId: p.sessionId },
      requestId,
      b.reason,
      b.code,
    );
    return witness(approved);
  });

  // Retries the external witness for a break-glass approval whose anchor publication failed.
  app.post(`${base}/:requestId/witness`, pre, async (req) => {
    const { requestId } = parse(privilegedParams, req.params);
    parse(reasonBody, req.body);
    const r = await c.privileged.get(requestId);
    if (!r.breakGlass || r.status !== 'approved' || r.witnessedAt)
      throw new DomainError('conflict', 'request is not awaiting a witness');
    return witness(r);
  });

  /** Publishes an anchor covering the committed break-glass event; only the witness's receipt makes it usable. */
  async function witness(r: Awaited<ReturnType<Container['privileged']['get']>>) {
    if (!c.anchors) throw new DomainError('conflict', 'external anchoring is not configured');
    let status: string;
    try {
      const out = await c.anchors.publish({ force: true });
      if (out.status === 'published')
        return toWire(await c.privileged.markWitnessed(r.id, out.record.anchor));
      status = out.status;
    } catch {
      status = 'failed'; // e.g. a scheduled publication was running; retry with /witness
    }
    return toWire({ ...r, witness: { status } });
  }

  app.get('/v1/admin/freezes', pre, async () => ({
    items: toWire(await c.privileged.listFreezes()),
  }));

  app.post('/v1/admin/freezes', pre, async (req, reply) => {
    const b = parse(freezeBody, req.body);
    const f = await c.privileged.freeze(
      principalOf(req).userId,
      b.scope === 'organization' ? b.org_id : null,
      b.reason,
    );
    return reply.status(201).send(toWire(f));
  });
}
