import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import { request } from 'node:https';
import { BlockList, isIP } from 'node:net';
import type { LookupFunction } from 'node:net';
import { TextDecoder } from 'node:util';

/**
 * Outbound HTTPS check for Warrior probes (ADR-029 probe amendment). Targets come only from
 * operator configuration. Every resolved address must be public: the guard runs inside the
 * connection's own DNS lookup, so the checked address is the one connected to (no rebinding
 * window). No redirects, proxies, credentials or cookies; bounded time and bytes; no
 * response, header or error ever leaves this function, only pass/fail.
 */
export interface ProbeCheck {
  url: URL;
  contentType: 'json' | 'html';
  contains: string;
}

const V4: [string, number][] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];
const V6: [string, number][] = [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96], // NAT64 can reach private IPv4
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 23], // IETF protocol assignments, including Teredo
  ['2001:db8::', 32],
  ['2002::', 16], // 6to4 embeds IPv4
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
];
export const NON_PUBLIC = new BlockList();
for (const [a, p] of V4) NON_PUBLIC.addSubnet(a, p, 'ipv4');
for (const [a, p] of V6) NON_PUBLIC.addSubnet(a, p, 'ipv6');

export function publicAddress(address: string, blocked: BlockList = NON_PUBLIC): boolean {
  const v = isIP(address);
  if (v === 0) return false;
  // IPv4-mapped IPv6 is never needed for a public HTTPS target. (A BlockList rule for
  // ::ffff:0:0/96 would also match every plain IPv4 address, so refuse it explicitly.)
  if (v === 6 && new URL(`http://[${address}]/`).hostname.startsWith('[::ffff:')) return false;
  return !blocked.check(address, v === 6 ? 'ipv6' : 'ipv4');
}

type Resolve = (
  hostname: string,
  options: { all: true; verbatim: true },
  callback: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void,
) => void;

/** A connection lookup that fails unless every address for the name is public. */
export function guardedLookup(resolve: Resolve, blocked: BlockList = NON_PUBLIC): LookupFunction {
  return (hostname, options, callback) => {
    resolve(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err || !addresses?.length) return callback(err ?? new Error('unresolved'), '', 4);
      if (!addresses.every((a) => publicAddress(a.address, blocked)))
        return callback(new Error('address refused'), '', 4);
      if (options.all)
        return (callback as unknown as (e: null, a: LookupAddress[]) => void)(null, addresses);
      callback(null, addresses[0]!.address, addresses[0]!.family);
    });
  };
}

const TYPES = {
  json: /^application\/json(?:\s*;|$)/i,
  html: /^text\/html(?:\s*;|$)/i,
} as const;

export function checkHttps(
  target: ProbeCheck,
  opts: {
    timeoutMs?: number;
    maxBytes?: number;
    /** Test seams only; production uses system DNS, the public-address list and system CAs. */
    resolve?: Resolve;
    blocked?: BlockList;
    ca?: string;
    port?: number;
  } = {},
): Promise<boolean> {
  const { url } = target;
  // https.request skips the lookup for IP literals, so refuse them here as well as in config.
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    isIP(url.hostname.replace(/^\[|\]$/g, ''))
  )
    return Promise.resolve(false);
  const maxBytes = opts.maxBytes ?? 256 * 1024;
  return new Promise((done) => {
    let settled = false;
    let req: ReturnType<typeof request> | undefined;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req?.destroy();
      done(ok);
    };
    const timer = setTimeout(() => finish(false), opts.timeoutMs ?? 10_000);
    try {
      req = request(
        {
          protocol: 'https:',
          hostname: url.hostname,
          port: opts.port ?? 443,
          path: url.pathname + url.search,
          method: 'GET',
          agent: false,
          lookup: guardedLookup(opts.resolve ?? (dnsLookup as unknown as Resolve), opts.blocked),
          ...(opts.ca ? { ca: opts.ca } : {}),
          headers: {
            accept: target.contentType === 'json' ? 'application/json' : 'text/html',
            'cache-control': 'no-cache',
            'user-agent': 'Warrior-probe/1',
          },
        },
        (res) => {
          if (
            res.statusCode !== 200 ||
            !TYPES[target.contentType].test(String(res.headers['content-type'] ?? '')) ||
            Number(res.headers['age'] ?? '0') !== 0
          )
            return finish(false);
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > maxBytes) return finish(false);
            chunks.push(chunk);
          });
          res.on('end', () => {
            try {
              const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
              if (target.contentType === 'json') JSON.parse(text);
              finish(text.includes(target.contains));
            } catch {
              finish(false);
            }
          });
          res.on('error', () => finish(false));
        },
      );
      req.on('error', () => finish(false));
      req.end();
    } catch {
      finish(false);
    }
  });
}
