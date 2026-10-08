import Fastify, { type FastifyInstance } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { randomUUID } from 'node:crypto';
import type { Container } from './container.ts';
import { installErrorHandling, installSecurityHeaders } from './http.ts';
import { registerAuthRoutes } from './routes/auth.ts';
import { registerOrgRoutes } from './routes/organizations.ts';
import { registerLicenseRoutes } from './routes/licenses.ts';
import { registerDeviceRoutes } from './routes/devices.ts';
import { registerAdminRoutes } from './routes/admin.ts';

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
          level: 'info',
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

  installSecurityHeaders(app, prod);
  installErrorHandling(app);
  app.addHook('onSend', async (req, reply) => void reply.header('x-request-id', req.id));

  await app.register(rateLimit, { max: c.config.rateLimits.global, timeWindow: '1 minute' });

  app.get('/healthz', { config: { rateLimit: false } }, async () => ({ status: 'ok' }));

  app.addHook('onClose', async () => c.close());

  registerAuthRoutes(app, c);
  registerOrgRoutes(app, c);
  registerLicenseRoutes(app, c);
  registerDeviceRoutes(app, c);
  registerAdminRoutes(app, c);
  return app;
}
