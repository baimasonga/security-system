import type { FastifyInstance } from 'fastify';
import { DomainError } from '@trust/shared-types';
import type { Container } from '../container.ts';
import { operator, parse } from '../http.ts';
import { emptyBody } from '../schemas.ts';
import { mobileBatch } from '../mobile-analytics.ts';
import { mobileClientIp } from '../integrations/mobile-country.ts';

export function registerMobileRoutes(app: FastifyInstance, c: Container) {
  const country = c.mobileCountryLookup;
  const path = '/v1/mobile/rokela-pdf/events';
  const sourceIp = (req: { headers: Record<string, unknown> }) =>
    mobileClientIp(
      typeof req.headers['x-forwarded-for'] === 'string'
        ? req.headers['x-forwarded-for']
        : undefined,
      c.config.mobileProxyHops,
    );
  app.options(path, async (req, reply) => {
    if (
      req.headers.origin !== 'https://localhost' ||
      req.headers['access-control-request-method'] !== 'POST'
    )
      throw new DomainError('forbidden', 'origin not allowed');
    return reply
      .header('Access-Control-Allow-Origin', 'https://localhost')
      .header('Vary', 'Origin')
      .header('Access-Control-Allow-Methods', 'POST')
      .header('Access-Control-Allow-Headers', 'content-type')
      .status(204)
      .send();
  });
  app.post(
    path,
    {
      bodyLimit: 16384,
      logLevel: 'silent',
      config: {
        rateLimit: {
          max: 120,
          timeWindow: '1 minute',
          keyGenerator: (req) => sourceIp(req) || req.raw.socket.remoteAddress || 'unknown',
        },
      },
    },
    async (req, reply) => {
      if (req.headers.origin && req.headers.origin !== 'https://localhost')
        throw new DomainError('forbidden', 'origin not allowed');
      if (req.headers.origin)
        reply.header('Access-Control-Allow-Origin', 'https://localhost').header('Vary', 'Origin');
      parse(emptyBody, req.query);
      const batch = parse(mobileBatch, req.body);
      const result = await c.mobileAnalytics.accept(batch, await country(sourceIp(req)));
      return reply.status(202).send(result);
    },
  );
  app.get('/v1/admin/mobile-analytics', { preHandler: operator(c) }, async (req) => {
    parse(emptyBody, req.query);
    return {
      ...(await c.mobileAnalytics.summary()),
      country_lookup_configured: !!c.config.mobileCountryDatabase && c.config.mobileProxyHops > 0,
    };
  });
}
