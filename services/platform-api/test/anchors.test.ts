import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { InMemoryAuditLog, type AnchorManifest } from '@trust/audit';
import {
  AnchorPublisher,
  HttpsAnchorSink,
  InMemoryAnchorStore,
  startAnchoring,
  validateAnchorUrl,
  type AnchorSink,
} from '../src/anchors.ts';
import { Metrics } from '../src/metrics.ts';
import { anchorStoreContract } from './anchor-store-contract.ts';

anchorStoreContract('memory', () => new InMemoryAnchorStore());

const clock = { now: () => new Date('2026-02-02T00:00:00Z') };
const sys = { type: 'system' } as const;

describe('validateAnchorUrl', () => {
  it('requires https; allows loopback http only outside production; refuses credentials and garbage', () => {
    expect(validateAnchorUrl('https://witness.example/a', true).protocol).toBe('https:');
    expect(validateAnchorUrl('http://127.0.0.1:8099/', false).hostname).toBe('127.0.0.1');
    expect(validateAnchorUrl('http://localhost:1/', false).hostname).toBe('localhost');
    expect(() => validateAnchorUrl('http://127.0.0.1:8099/', true)).toThrow(/https/);
    expect(() => validateAnchorUrl('http://witness.example/', false)).toThrow(/https/);
    expect(() => validateAnchorUrl('https://u:p@witness.example/', true)).toThrow(/credentials/);
    expect(() => validateAnchorUrl('ftp://witness.example/', false)).toThrow(/https/);
    expect(() => validateAnchorUrl('not a url', false)).toThrow(/invalid/);
  });
});

describe('HttpsAnchorSink (against a real local server)', () => {
  let server: http.Server | undefined;
  afterEach(async () => {
    await new Promise((r) => (server ? server.close(() => r(null)) : r(null)));
    server = undefined;
  });
  const manifest: AnchorManifest = {
    v: 1,
    created_at: '2026-02-02T00:00:00.000Z',
    anchor: 'a'.repeat(64),
    chains: [],
  };

  async function witness(handler: http.RequestListener) {
    server = http.createServer(handler);
    await new Promise<void>((r) => server!.listen(0, '127.0.0.1', r));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}/anchors?secret=querysecret`;
  }

  it('POSTs the canonical manifest with the bearer token and an idempotency key, and returns the receipt', async () => {
    let seen: { method?: string; auth?: string; idem?: string; ctype?: string; body: string } = {
      body: '',
    };
    const url = await witness((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        seen = {
          method: req.method,
          auth: req.headers.authorization,
          idem: req.headers['idempotency-key'] as string,
          ctype: req.headers['content-type'],
          body,
        };
        res.writeHead(201, { 'x-witness-receipt': 'rcpt-42' });
        res.end('ok');
      });
    });
    const sink = new HttpsAnchorSink(validateAnchorUrl(url, false), { token: 't'.repeat(20) });
    expect(await sink.publish(manifest)).toEqual({ receipt: 'rcpt-42' });
    expect(seen).toMatchObject({
      method: 'POST',
      auth: `Bearer ${'t'.repeat(20)}`,
      idem: manifest.anchor,
      ctype: 'application/json',
    });
    expect(JSON.parse(seen.body)).toEqual(manifest);
    expect(sink.destination).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/anchors$/); // no query string, no credentials
    expect(sink.destination).not.toContain('querysecret');
  });

  it('ignores a malformed receipt header and sends no Authorization header without a token', async () => {
    let auth: string | undefined = 'unset';
    const url = await witness((req, res) => {
      auth = req.headers.authorization;
      res.writeHead(200, { 'x-witness-receipt': 'has space' });
      res.end();
    });
    const sink = new HttpsAnchorSink(validateAnchorUrl(url, false));
    expect(await sink.publish(manifest)).toEqual({ receipt: null });
    expect(auth).toBeUndefined();
  });

  it('failures are short and never leak the token, the URL or the response body', async () => {
    const token = 'supersecrettoken-123456';
    const url500 = await witness((_req, res) => {
      res.writeHead(500);
      res.end(`internal detail with ${token}`);
    });
    const e500 = await new HttpsAnchorSink(validateAnchorUrl(url500, false), { token })
      .publish(manifest)
      .catch((e: Error) => e);
    expect(e500).toBeInstanceOf(Error);
    expect((e500 as Error).message).toBe('witness responded 500');
    await new Promise((r) => server!.close(() => r(null)));

    // A redirect target that would happily accept the manifest: following it would leak the anchor (and token).
    let leaked = 0;
    const elsewhere = http.createServer((_req, res) => {
      leaked++;
      res.writeHead(200);
      res.end();
    });
    await new Promise<void>((r) => elsewhere.listen(0, '127.0.0.1', r));
    const elsewhereUrl = `http://127.0.0.1:${(elsewhere.address() as AddressInfo).port}/collect`;
    const url302 = await witness((_req, res) => {
      res.writeHead(307, { location: elsewhereUrl });
      res.end();
    });
    const e302 = (await new HttpsAnchorSink(validateAnchorUrl(url302, false), { token })
      .publish(manifest)
      .catch((e: Error) => e)) as Error;
    expect(e302).toBeInstanceOf(Error);
    expect(e302.message).toBe('witness unreachable'); // a redirect is never followed
    expect(leaked).toBe(0);
    await new Promise((r) => elsewhere.close(() => r(null)));
    await new Promise((r) => server!.close(() => r(null)));

    const eDown = (await new HttpsAnchorSink(
      validateAnchorUrl('http://127.0.0.1:1/x?k=querysecret', false),
      { token },
    )
      .publish(manifest)
      .catch((e: Error) => e)) as Error;
    for (const e of [e500 as Error, e302, eDown]) {
      expect(e.message).not.toContain(token);
      expect(e.message).not.toContain('querysecret');
      expect(e.message).not.toContain('127.0.0.1');
    }
  });

  it('gives up after the timeout', async () => {
    const url = await witness(() => undefined); // never answers
    const sink = new HttpsAnchorSink(validateAnchorUrl(url, false), { timeoutMs: 150 });
    await expect(sink.publish(manifest)).rejects.toThrow('witness timed out');
    server!.closeAllConnections();
  });
});

describe('AnchorPublisher', () => {
  function setup(sink?: Partial<AnchorSink> & { fail?: () => string | undefined }) {
    const audit = new InMemoryAuditLog(clock);
    const store = new InMemoryAnchorStore();
    const metrics = new Metrics();
    const sent: AnchorManifest[] = [];
    const invalid: Array<{ chain: string; brokenAtSeq: number; reason: string }> = [];
    const fakeSink: AnchorSink = {
      destination: 'https://witness.example/anchors',
      publish: async (m) => {
        const why = sink?.fail?.();
        if (why) throw new Error(why);
        sent.push(m);
        return { receipt: `rcpt-${sent.length}` };
      },
    };
    const publisher = new AnchorPublisher({
      audit,
      store,
      sink: fakeSink,
      clock,
      metrics,
      onChainInvalid: async (f) => void invalid.push(f),
    });
    return { audit, store, metrics, sent, invalid, publisher };
  }
  const ev = (n: number) => ({ actor: sys, action: `a${n}`, orgId: 'org_a' });

  it('witnesses the verified heads, skips an unchanged state, and publishes again after growth or when forced', async () => {
    const t = setup();
    for (let i = 0; i < 3; i++) await t.audit.append(ev(i));
    const first = await t.publisher.publish();
    expect(first).toMatchObject({
      status: 'published',
      record: {
        chains: 1,
        events: 3,
        receipt: 'rcpt-1',
        destination: 'https://witness.example/anchors',
      },
    });
    expect(t.sent[0]!.chains).toEqual([expect.objectContaining({ chain: 'org:org_a', seq: 3 })]);

    expect(await t.publisher.publish()).toMatchObject({
      status: 'unchanged',
      anchor: t.sent[0]!.anchor,
    });
    expect(t.sent).toHaveLength(1);
    expect(await t.publisher.publish({ force: true })).toMatchObject({ status: 'published' });
    expect(t.sent).toHaveLength(2);

    await t.audit.append(ev(9));
    expect(await t.publisher.publish()).toMatchObject({ status: 'published' });
    expect(t.sent).toHaveLength(3);
    expect(t.sent[2]!.anchor).not.toBe(t.sent[0]!.anchor);
    expect((await t.store.list(10)).map((r) => r.status)).toEqual([
      'published',
      'published',
      'published',
    ]);
    // what was witnessed still holds against the live log
    for (const m of t.sent) expect(await t.audit.checkAnchor(m)).toMatchObject({ ok: true });
  });

  it('a failing witness is recorded without secrets, does not count as the last success, and the next run retries', async () => {
    let failing: string | undefined = 'witness responded 503';
    const t = setup({ fail: () => failing });
    await t.audit.append(ev(0));
    const out = await t.publisher.publish();
    expect(out).toMatchObject({
      status: 'failed',
      record: { status: 'failed', error: 'witness responded 503', receipt: null },
    });
    expect(await t.store.latest('published')).toBeUndefined();
    expect(t.metrics.snapshot().gauges['audit_anchor_last_success_age_seconds']).toBe(-1);
    failing = undefined;
    expect(await t.publisher.publish()).toMatchObject({ status: 'published' });
    const snap = t.metrics.snapshot();
    expect(snap.gauges['audit_anchor_last_success_age_seconds']).toBeGreaterThanOrEqual(0);
    expect(snap.counters['audit_anchor_publish_total{outcome="failed"}']).toBe(1);
    expect(snap.counters['audit_anchor_publish_total{outcome="published"}']).toBe(1);
  });

  it('a log that fails verification is NOT published; the alert hook fires with the failure', async () => {
    const t = setup();
    for (let i = 0; i < 3; i++) await t.audit.append(ev(i));
    t.audit.unsafeReplaceForTest(1, { ...(await t.audit.list())[1]!, reason: 'edited' });
    const out = await t.publisher.publish({ force: true });
    expect(out).toMatchObject({ status: 'chain_invalid', chain: 'org:org_a', brokenAtSeq: 2 });
    expect(t.sent).toHaveLength(0);
    expect(await t.store.list(5)).toEqual([]);
    expect(t.invalid).toEqual([expect.objectContaining({ chain: 'org:org_a', brokenAtSeq: 2 })]);
    expect(
      t.metrics.snapshot().counters['audit_anchor_publish_total{outcome="chain_invalid"}'],
    ).toBe(1);
  });

  it('refuses overlapping publications and seeds its last-success gauge from history after a restart', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const audit = new InMemoryAuditLog(clock);
    await audit.append(ev(0));
    const store = new InMemoryAnchorStore();
    const pub = new AnchorPublisher({
      audit,
      store,
      clock,
      sink: {
        destination: 'https://w.example/',
        publish: async () => (await gate, { receipt: null }),
      },
    });
    const first = pub.publish();
    await expect(pub.publish()).rejects.toThrow(/already running/);
    release();
    await first;

    const metrics = new Metrics();
    const restarted = new AnchorPublisher({
      audit,
      store,
      clock,
      metrics,
      sink: { destination: 'x', publish: async () => ({ receipt: null }) },
    });
    expect(metrics.snapshot().gauges['audit_anchor_last_success_age_seconds']).toBe(-1);
    await restarted.init();
    expect(metrics.snapshot().gauges['audit_anchor_last_success_age_seconds']).toBeGreaterThan(-1);
  });
});

describe('startAnchoring', () => {
  it('publishes soon after start and then on the interval; failures reach onOutcome and never throw', async () => {
    const audit = new InMemoryAuditLog(clock);
    const store = new InMemoryAnchorStore();
    let calls = 0;
    const pub = new AnchorPublisher({
      audit,
      store,
      clock,
      sink: {
        destination: 'https://w.example/',
        publish: async () => {
          calls++;
          if (calls === 2) throw new Error('witness unreachable');
          return { receipt: null };
        },
      },
    });
    const outcomes: string[] = [];
    const h = startAnchoring(pub, {
      everyMs: 60,
      firstRunMs: 10,
      onOutcome: (o) => outcomes.push(o.status),
    });
    for (let i = 0; i < 6; i++) {
      await audit.append({ actor: sys, action: `a${i}` });
      await new Promise((r) => setTimeout(r, 40));
    }
    h.stop();
    expect(outcomes[0]).toBe('published');
    expect(outcomes).toContain('failed');
    expect(outcomes.length).toBeGreaterThanOrEqual(3);
  });
});
