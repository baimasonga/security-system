import { readFileSync } from 'node:fs';
import type { FastifyInstance } from 'fastify';
import type { BillingConfig } from '../billing.ts';

/** Explicit assets only: never map an untrusted path to the filesystem. */
export function registerPortalRoutes(app: FastifyInstance, billing?: BillingConfig): void {
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
    app.get(url, async (req, reply) => {
      // Use the actual Host header, not a client-supplied forwarded host, for browser-origin routing.
      const paymentHost = billing ? new URL(billing.paymentUrl).host.toLowerCase() : undefined;
      const host = String(req.headers.host ?? '')
        .toLowerCase()
        .replace(/:443$/, '');
      if (url === '/checkout' && (!paymentHost || host !== paymentHost))
        return reply.status(404).send({ code: 'not_found', message: 'not found' });
      if (paymentHost && host === paymentHost && ['/', '/portal.mjs', '/device.mjs'].includes(url))
        return reply.status(404).send({ code: 'not_found', message: 'not found' });
      return reply.type(type).send(body);
    });
  }
}
