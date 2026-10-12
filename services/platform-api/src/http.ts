import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodError, type z } from 'zod';
import { DomainError, type UserPrincipal } from '@trust/shared-types';
import type { Container } from './container.ts';

declare module 'fastify' {
  interface FastifyRequest {
    principal?: UserPrincipal;
  }
}

export const snake = (s: string) => s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

/** Domain objects use camelCase; the wire format is snake_case. */
export function toWire(v: unknown): unknown {
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) return v.map(toWire);
  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).map(([k, x]) => [snake(k), toWire(x)]),
    );
  }
  return v;
}

export function bearer(req: FastifyRequest): string | undefined {
  const h = req.headers.authorization;
  if (!h) return undefined;
  const m = /^Bearer ([\x21-\x7e]{1,128})$/.exec(h);
  return m?.[1];
}

export function authenticated(c: Container) {
  return async (req: FastifyRequest): Promise<void> => {
    req.principal = await c.auth.authenticate(bearer(req));
  };
}

export function operator(c: Container) {
  return async (req: FastifyRequest): Promise<void> => {
    req.principal = await c.auth.authenticate(bearer(req));
    await c.auth.requirePlatformAdmin(req.principal);
  };
}

export function principalOf(req: FastifyRequest): UserPrincipal {
  if (!req.principal) throw new DomainError('unauthenticated', 'authentication required');
  return req.principal;
}

/** Strict parsing: unknown keys are rejected, never silently ignored. */
export function parse<S extends z.ZodTypeAny>(schema: S, data: unknown): z.infer<S> {
  const r = schema.safeParse(data ?? {});
  if (!r.success) throw zodToDomain(r.error);
  return r.data;
}

function zodToDomain(e: ZodError): DomainError {
  // Report paths and codes only — never echo submitted values (they may be secrets).
  const issues = e.issues.slice(0, 10).map((i) => `${i.path.join('.') || '(body)'}: ${i.code}`);
  return new DomainError('invalid_request', 'request validation failed', { issues });
}

export function installErrorHandling(app: FastifyInstance): void {
  app.setErrorHandler((err: unknown, req: FastifyRequest, reply: FastifyReply) => {
    const requestId = req.id;
    if (err instanceof DomainError) {
      return reply
        .status(err.status)
        .type('application/problem+json')
        .send({
          code: err.code,
          message: err.message,
          request_id: requestId,
          ...(err.details ? { details: err.details } : {}),
        });
    }
    if (err instanceof ZodError) {
      const d = zodToDomain(err);
      return reply
        .status(400)
        .type('application/problem+json')
        .send({ code: d.code, message: d.message, request_id: requestId, details: d.details });
    }
    const e = err as { statusCode?: number; code?: string };
    if (typeof e.statusCode === 'number' && e.statusCode >= 400 && e.statusCode < 500) {
      const code =
        e.statusCode === 429
          ? 'rate_limited'
          : e.statusCode === 404
            ? 'not_found'
            : 'invalid_request';
      return reply
        .status(e.statusCode)
        .type('application/problem+json')
        .send({
          code,
          message: e.statusCode === 429 ? 'rate limit exceeded' : 'bad request',
          request_id: requestId,
        });
    }
    req.log.error(
      { err: { name: (err as Error)?.name, message: (err as Error)?.message } },
      'unhandled error',
    );
    return reply
      .status(500)
      .type('application/problem+json')
      .send({ code: 'internal', message: 'internal error', request_id: requestId });
  });

  app.setNotFoundHandler((req, reply) =>
    reply
      .status(404)
      .type('application/problem+json')
      .send({ code: 'not_found', message: 'not found', request_id: req.id }),
  );
}

export function installSecurityHeaders(app: FastifyInstance, production: boolean): void {
  app.addHook('onSend', async (req, reply) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('cache-control', 'no-store');
    reply.header('referrer-policy', 'no-referrer');
    reply.header(
      'content-security-policy',
      req.routeOptions.url === '/checkout'
        ? "default-src 'none'; script-src 'self' https://cdn.paddle.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://*.paddle.com; frame-src https://*.paddle.com; img-src 'self' data: https://*.paddle.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        : req.routeOptions.url === '/'
          ? "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
          : "default-src 'none'; frame-ancestors 'none'",
    );
    reply.header('cross-origin-resource-policy', 'same-origin');
    if (production)
      reply.header('strict-transport-security', 'max-age=63072000; includeSubDomains');
  });
}
