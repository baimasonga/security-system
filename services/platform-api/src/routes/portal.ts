import { readFileSync } from 'node:fs';
import type { FastifyInstance } from 'fastify';
import type { BillingConfig } from '../billing.ts';

/** Explicit assets only: never map an untrusted path to the filesystem. */
export function registerPortalRoutes(
  app: FastifyInstance,
  billing?: BillingConfig,
): { link: string } {
  const html = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
  const css = readFileSync(new URL('../web/portal.css', import.meta.url), 'utf8');
  const js = readFileSync(new URL('../web/portal.mjs', import.meta.url), 'utf8');
  const checkoutHtml = readFileSync(new URL('../web/checkout.html', import.meta.url), 'utf8');
  const checkoutJs = readFileSync(new URL('../web/checkout.mjs', import.meta.url), 'utf8');
  const device = readFileSync(new URL('../web/device.mjs', import.meta.url), 'utf8');
  const icon = readFileSync(new URL('../web/rokela-icon.png', import.meta.url));
  const files = readFileSync(new URL('../web/files.mjs', import.meta.url), 'utf8');
  const shareHtml = readFileSync(new URL('../web/share.html', import.meta.url), 'utf8');
  const shareJs = readFileSync(new URL('../web/share.mjs', import.meta.url), 'utf8');
  const requestHtml = readFileSync(new URL('../web/request.html', import.meta.url), 'utf8');
  const requestJs = readFileSync(new URL('../web/request.mjs', import.meta.url), 'utf8');
  const linkHtml = readFileSync(new URL('../web/link.html', import.meta.url), 'utf8');
  const linkJs = readFileSync(new URL('../web/link.mjs', import.meta.url), 'utf8');
  const uploaderJs = readFileSync(new URL('../web/uploader.mjs', import.meta.url), 'utf8');
  const publicJs = readFileSync(new URL('../web/public.mjs', import.meta.url), 'utf8');
  for (const [url, type, body] of [
    ['/', 'text/html; charset=utf-8', html],
    ['/checkout', 'text/html; charset=utf-8', checkoutHtml],
    ['/checkout.mjs', 'text/javascript; charset=utf-8', checkoutJs],
    ['/portal.css', 'text/css; charset=utf-8', css],
    ['/portal.mjs', 'text/javascript; charset=utf-8', js],
    ['/device.mjs', 'text/javascript; charset=utf-8', device],
    ['/rokela-icon.png', 'image/png', icon],
    ['/files.mjs', 'text/javascript; charset=utf-8', files],
    ['/uploader.mjs', 'text/javascript; charset=utf-8', uploaderJs],
    ['/public.mjs', 'text/javascript; charset=utf-8', publicJs],
    ['/share.mjs', 'text/javascript; charset=utf-8', shareJs],
    ['/request.mjs', 'text/javascript; charset=utf-8', requestJs],
    ['/link.mjs', 'text/javascript; charset=utf-8', linkJs],
    // Public pages: the token stays in the URL path and is read by the page script; the HTML is static.
    ['/s/:token', 'text/html; charset=utf-8', shareHtml],
    ['/r/:token', 'text/html; charset=utf-8', requestHtml],
  ] as const) {
    app.get(url, async (req, reply) => {
      // Use the actual Host header, not a client-supplied forwarded host, for browser-origin routing.
      const paymentHost = billing ? new URL(billing.paymentUrl).host.toLowerCase() : undefined;
      const host = String(req.headers.host ?? '')
        .toLowerCase()
        .replace(/:443$/, '');
      if (url === '/checkout' && (!paymentHost || host !== paymentHost))
        return reply.status(404).send({ code: 'not_found', message: 'not found' });
      if (
        paymentHost &&
        host === paymentHost &&
        ['/', '/portal.mjs', '/device.mjs', '/files.mjs', '/s/:token', '/r/:token'].includes(url)
      )
        return reply.status(404).send({ code: 'not_found', message: 'not found' });
      return reply.type(type).send(body);
    });
  }
  return { link: linkHtml };
}
