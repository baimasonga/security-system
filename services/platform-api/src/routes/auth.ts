import type { FastifyInstance } from 'fastify';
import type { Container } from '../container.ts';
import { authenticated, parse, principalOf } from '../http.ts';
import { loginBody, registerBody } from '../schemas.ts';

export function registerAuthRoutes(app: FastifyInstance, c: Container): void {
  const rl = c.config.rateLimits;

  app.post(
    '/v1/auth/register',
    { config: { rateLimit: { max: rl.register, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const body = parse(registerBody, req.body);
      const { user, personalOrg } = await c.auth.register(body);
      return reply.status(201).send({
        user: { id: user.id, email: user.email },
        personal_org: { id: personalOrg.id, name: personalOrg.name },
      });
    },
  );

  app.post(
    '/v1/auth/login',
    { config: { rateLimit: { max: rl.login, timeWindow: '1 minute' } } },
    async (req) => {
      const body = parse(loginBody, req.body);
      const s = await c.auth.login(body);
      return { token: s.token, expires_at: s.expiresAt.toISOString(), user_id: s.userId };
    },
  );

  app.post('/v1/auth/logout', { preHandler: authenticated(c) }, async (req, reply) => {
    await c.auth.logout(principalOf(req));
    return reply.status(204).send();
  });

  app.get('/v1/auth/me', { preHandler: authenticated(c) }, async (req) => {
    const p = principalOf(req);
    return { user_id: p.userId, platform_role: p.platformRole };
  });
}
