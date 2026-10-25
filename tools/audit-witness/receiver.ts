import { createHash, timingSafeEqual } from 'node:crypto';
import { manifestProblem, type AnchorManifest } from '@trust/audit';
import { canonicalJson } from '@trust/crypto';

export interface WitnessRequest {
  method: string;
  path: string;
  authorization: string;
  contentType: string;
  body: string;
  base64?: boolean;
}
const exact = (x: Record<string, unknown>, keys: string[]) =>
  Object.keys(x).length === keys.length && keys.every((k) => Object.hasOwn(x, k));
const object = (x: unknown): x is Record<string, unknown> =>
  x !== null && typeof x === 'object' && !Array.isArray(x);
const hash = (s: string) => createHash('sha256').update(s).digest();

export function createWitnessReceiver(d: {
  token: string;
  store: { retain(body: string): Promise<string> };
}) {
  if (!/^[\x21-\x7e]{32,256}$/.test(d.token)) throw new Error('invalid witness configuration');
  const expected = hash(`Bearer ${d.token}`);
  return async (req: WitnessRequest) => {
    const reply = (statusCode: number, body: string, receipt?: string) => ({
      statusCode,
      body,
      headers: {
        'content-type': 'text/plain',
        'cache-control': 'no-store',
        ...(receipt ? { 'x-witness-receipt': receipt } : {}),
      } as Record<string, string>,
    });
    if (req.path !== '/anchors') return reply(404, 'not found');
    if (req.method !== 'POST') return reply(405, 'method not allowed');
    if (req.authorization.length > 300 || !timingSafeEqual(hash(req.authorization), expected))
      return reply(401, 'unauthorized');
    if (!/^application\/json(?:\s*;|$)/i.test(req.contentType))
      return reply(415, 'unsupported content type');
    if (req.body.length > 1_333_336) return reply(413, 'body too large');
    let m: unknown;
    try {
      const bytes = Buffer.from(req.body, req.base64 ? 'base64' : 'utf8');
      if (bytes.length > 1_000_000) return reply(413, 'body too large');
      m = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (
        !object(m) ||
        !exact(m, ['v', 'created_at', 'anchor', 'chains']) ||
        m.v !== 1 ||
        typeof m.created_at !== 'string' ||
        !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(m.created_at) ||
        !Number.isFinite(Date.parse(m.created_at)) ||
        new Date(m.created_at).toISOString() !== m.created_at ||
        typeof m.anchor !== 'string' ||
        !/^[a-f0-9]{64}$/.test(m.anchor) ||
        !Array.isArray(m.chains) ||
        m.chains.length > 5000
      )
        return reply(400, 'invalid manifest');
      for (const c of m.chains) {
        if (
          !object(c) ||
          !exact(c, ['chain', 'seq', 'hash']) ||
          typeof c.chain !== 'string' ||
          !/^[a-zA-Z0-9:#_-]{1,128}$/.test(c.chain) ||
          !Number.isSafeInteger(c.seq) ||
          (c.seq as number) < 1 ||
          typeof c.hash !== 'string' ||
          !/^[a-f0-9]{64}$/.test(c.hash)
        )
          return reply(400, 'invalid manifest');
      }
      if (manifestProblem(m as unknown as AnchorManifest)) return reply(400, 'invalid manifest');
    } catch {
      return reply(400, 'invalid manifest');
    }
    try {
      const receipt = await d.store.retain(canonicalJson(m));
      if (!/^[\x21-\x7e]{1,256}$/.test(receipt)) throw new Error('invalid receipt');
      return reply(201, 'witnessed', receipt);
    } catch {
      return reply(503, 'storage unavailable');
    }
  };
}
