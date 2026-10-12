import { readFileSync } from 'node:fs';
import type { FastifyInstance } from 'fastify';

/** Explicit assets only: never map an untrusted path to the filesystem. */
export function registerPortalRoutes(app: FastifyInstance): void {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const css = readFileSync(new URL('../web/portal.css', import.meta.url), 'utf8');
  const js = readFileSync(new URL('../web/portal.mjs', import.meta.url), 'utf8');
  const checkoutHtml = readFileSync(new URL('../web/checkout.html', import.meta.url), 'utf8');
  const checkoutJs = readFileSync(new URL('../web/checkout.mjs', import.meta.url), 'utf8');
  const device = readFileSync(new URL('../web/device.mjs', import.meta.url), 'utf8');
  for (const [url, type, body] of [
    ['/', 'text/html; charset=utf-8', html],
    ['/checkout', 'text/html; charset=utf-8', checkoutHtml],
    ['/checkout.mjs', 'text/javascript; charset=utf-8', checkoutJs],
    ['/portal.css', 'text/css; charset=utf-8', css],
    ['/portal.mjs', 'text/javascript; charset=utf-8', js],
    ['/device.mjs', 'text/javascript; charset=utf-8', device],
  ] as const) {
    app.get(url, async (_req, reply) => reply.type(type).send(body));
  }
}
