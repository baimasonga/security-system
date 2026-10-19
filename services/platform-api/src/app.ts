import { registerOperationsRoutes } from './routes/operations.ts';
import Fastify, { type FastifyInstance } from 'fastify';
import rateLimit, { type FastifyRateLimitStoreCtor } from '@fastify/rate-limit';
import { fastifyRateStore } from './rate-limit.ts';
import { randomUUID } from 'node:crypto';
import type { Container } from './container.ts';
import { installErrorHandling, installSecurityHeaders } from './http.ts';
import { registerBillingRoutes } from './routes/billing.ts';
import { registerAuthRoutes } from './routes/auth.ts';
import { registerOrgRoutes } from './routes/organizations.ts';
import { registerLicenseRoutes } from './routes/licenses.ts';
import { registerDeviceRoutes } from './routes/devices.ts';
import { registerPortalRoutes } from './routes/portal.ts';
import { registerAdminRoutes } from './routes/admin.ts';
import { registerSharingRoutes } from './routes/sharing.ts';
import { registerPrivilegedRoutes } from './routes/privileged.ts';

export interface AppOptions {
  logger?: boolean;
  /** Test seam: capture structured logs (used to prove secrets are never logged). */
  logStream?: { write(msg: string): void };
  /** Test seam: observe every registered route (used by the OpenAPI drift test). */
  onRoute?: (method: string, url: string) => void;
}

export async function buildApp(c: Container, opts: AppOptions = {}): Promise<FastifyInstance> {
  const prod = c.config.env === 'production';
  const app = Fastify({
    logger: opts.logger
      ? {
          level: c.config.logLevel,
          redact: ['req.headers.authorization', 'req.headers.cookie'],
          ...(opts.logStream ? { stream: opts.logStream } : {}),
        }
      : false,
    trustProxy: c.config.trustProxy,
    bodyLimit: 64 * 1024,
    genReqId: () => randomUUID(),
    requestIdHeader: false, // never trust a client-supplied request id
    ajv: { customOptions: { removeAdditional: false } },
  });

  if (opts.onRoute) {
    app.addHook('onRoute', (r) => {
      for (const m of Array.isArray(r.method) ? r.method : [r.method]) opts.onRoute!(m, r.url);
    });
  }

  const sc = c.config.sharing;
  installSecurityHeaders(
    app,
    prod,
    sc ? (sc.storage.kind === 'local' ? sc.storage.contentOrigin : sc.storage.endpoint) : undefined,
  );
  installErrorHandling(app);
  app.addHook('onSend', async (req, reply) => void reply.header('x-request-id', req.id));

  await app.register(rateLimit, {
    max: c.config.rateLimits.global,
    timeWindow: '1 minute',
    // Shared across instances when configured (R-7); otherwise the plugin's per-process store.
    ...(c.rateBackend
      ? { store: fastifyRateStore(c.rateBackend) as unknown as FastifyRateLimitStoreCtor }
      : {}),
  });

  const pages = registerPortalRoutes(app, c.config.billing);

  app.get('/healthz', { config: { rateLimit: false } }, async () => ({ status: 'ok' }));

  app.get(
    '/readyz',
    { logLevel: 'silent', config: { rateLimit: { max: 60, timeWindow: '1 minute' } } },
    async (_req, reply) => {
      const ready = await c.readiness();
      return reply
        .header('Cache-Control', 'no-store')
        .status(ready ? 200 : 503)
        .send({ status: ready ? 'ready' : 'unavailable' });
    },
  );

  app.addHook('onClose', async () => c.close());

  // Request metrics: route TEMPLATE (never the raw URL), so labels cannot carry ids or secrets.
  app.addHook('onResponse', async (req, reply) => {
    const route = req.routeOptions?.url ?? 'unmatched';
    c.metrics.inc('http_requests_total', {
      method: req.method,
      route,
      status: String(reply.statusCode),
    });
    c.metrics.observe('http_request_duration_ms', reply.elapsedTime, { route });
  });

  registerAuthRoutes(app, c);
  registerBillingRoutes(app, c);
  registerOrgRoutes(app, c);
  registerOperationsRoutes(app, c);
  registerLicenseRoutes(app, c);
  registerDeviceRoutes(app, c);
  registerAdminRoutes(app, c);
  registerPrivilegedRoutes(app, c);
  registerSharingRoutes(app, c, pages);
  return app;
}
