import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AnchorManifest, InMemoryAuditLog } from '@trust/audit';
import { makeEnv, type Env } from './harness.ts';

const TOKEN = 'witness-token-0123456789';

describe('audit anchoring through the API (ADR-010)', () => {
  let witness: http.Server;
  let url: string;
  let received: Array<{ auth: string | undefined; manifest: AnchorManifest }>;
  let respondWith = 201;
  let env: Env;

  beforeEach(async () => {
    received = [];
    respondWith = 201;
    witness = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        received.push({ auth: req.headers.authorization, manifest: JSON.parse(body) });
        res.writeHead(respondWith, { 'x-witness-receipt': `r${received.length}` });
        res.end('secret-body-should-never-be-surfaced');
      });
    });
    await new Promise<void>((r) => witness.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(witness.address() as AddressInfo).port}/anchors`;
  });
  afterEach(async () => {
    await env?.app.close();
    witness.closeAllConnections();
    await new Promise((r) => witness.close(() => r(null)));
  });

  const configured = () =>
    makeEnv({ config: { auditAnchor: { url, token: TOKEN, intervalSeconds: 3600 } } });

  it('is off unless configured: publishing answers 409, listing says so', async () => {
    env = await makeEnv();
    const op = await env.operatorToken();
    const r = await env.call('POST', '/v1/admin/audit/anchors', {
      token: op,
      body: { reason: 'try' },
    });
    expect(r.status).toBe(409);
    expect((await env.call('GET', '/v1/admin/audit/anchors', { token: op })).body).toMatchObject({
      configured: false,
      items: [],
    });
  });

  it('the configured URL and token reach the witness; the manifest lists the real chain heads; the action is audited', async () => {
    env = await configured();
    const owner = await env.register('owner@example.test');
    await env.provision(owner.orgId);
    const op = await env.operatorToken();

    const r = await env.call('POST', '/v1/admin/audit/anchors', {
      token: op,
      body: { reason: 'weekly witness check' },
    });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      status: 'published',
      receipt: 'r1',
      chains: expect.any(Number),
      anchor: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(received).toHaveLength(1);
    expect(received[0]!.auth).toBe(`Bearer ${TOKEN}`);
    const m = received[0]!.manifest;
    expect(m.anchor).toBe(r.body.anchor);
    expect(m.chains.map((c) => c.chain)).toContain(`org:${owner.orgId}`);

    const audit = await env.call('GET', '/v1/admin/audit?action=audit.anchor_published', {
      token: op,
    });
    expect(audit.body.items[0]).toMatchObject({
      actor: { type: 'operator' },
      reason: 'weekly witness check',
    });
    const list = await env.call('GET', '/v1/admin/audit/anchors', { token: op });
    expect(list.body).toMatchObject({
      configured: true,
      items: [{ anchor: m.anchor, status: 'published' }],
    });
    expect(JSON.stringify(list.body)).not.toContain(TOKEN);

    // what the witness holds checks out against the live log (which has since grown)
    const chk = await env.call('POST', '/v1/admin/audit/anchors/check', {
      token: op,
      body: { manifest: m },
    });
    expect(chk.body).toEqual({ ok: true, chains: m.chains.length });
  });

  it('check fails when the log no longer matches what was witnessed, and when the log itself is broken', async () => {
    env = await configured();
    const owner = await env.register('owner@example.test');
    await env.provision(owner.orgId);
    const op = await env.operatorToken();
    await env.call('POST', '/v1/admin/audit/anchors', { token: op, body: { reason: 'baseline' } });
    const m = received[0]!.manifest;

    const forged = {
      ...m,
      chains: m.chains.map((c, i) => (i === 0 ? { ...c, hash: 'b'.repeat(64) } : c)),
    };
    // keep it self-consistent so the failure is about the log, not the manifest
    const { computeAnchor } = await import('@trust/audit');
    forged.anchor = computeAnchor(forged.chains);
    const bad = await env.call('POST', '/v1/admin/audit/anchors/check', {
      token: op,
      body: { manifest: forged },
    });
    expect(bad.status).toBe(200);
    expect(bad.body).toMatchObject({
      ok: false,
      stage: 'witness',
      reason: expect.stringContaining('altered'),
    });

    const log = env.c.audit as InMemoryAuditLog;
    const all = await log.list();
    log.unsafeReplaceForTest(0, { ...all[0]!, reason: 'edited after the fact' });
    const broken = await env.call('POST', '/v1/admin/audit/anchors/check', {
      token: op,
      body: { manifest: m },
    });
    expect(broken.body).toMatchObject({ ok: false, stage: 'log' });
  });

  it('a log that fails verification is never sent to the witness; a critical security signal is raised', async () => {
    env = await configured();
    const owner = await env.register('owner@example.test');
    await env.provision(owner.orgId);
    const op = await env.operatorToken();
    const log = env.c.audit as InMemoryAuditLog;
    log.unsafeReplaceForTest(0, { ...(await log.list())[0]!, reason: 'tampered' });

    const r = await env.call('POST', '/v1/admin/audit/anchors', {
      token: op,
      body: { reason: 'after suspected tampering' },
    });
    expect(r.body).toMatchObject({ status: 'chain_invalid', broken_at_seq: expect.any(Number) });
    expect(received).toHaveLength(0);
    expect((await env.signals()).map((s) => [s.kind, s.severity])).toContainEqual([
      'audit_chain_broken',
      'critical',
    ]);
    expect(
      (await env.call('GET', '/v1/admin/audit?action=audit.anchor_refused', { token: op })).body
        .items,
    ).toHaveLength(1);
  });

  it('a witness that rejects the anchor is reported as failed without leaking its response', async () => {
    env = await configured();
    const op = await env.operatorToken();
    respondWith = 503;
    const r = await env.call('POST', '/v1/admin/audit/anchors', {
      token: op,
      body: { reason: 'witness outage drill' },
    });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      status: 'failed',
      error: 'witness responded 503',
      receipt: null,
    });
    expect(JSON.stringify(r.body)).not.toContain('secret-body');
    expect(
      (await env.call('GET', '/v1/admin/audit?action=audit.anchor_failed', { token: op })).body
        .items,
    ).toHaveLength(1);
  });

  it('is operator-only, requires a reason, and rejects unknown fields', async () => {
    env = await configured();
    const user = await env.register('someone@example.test');
    const op = await env.operatorToken();
    const routes: Array<[string, string, unknown]> = [
      ['GET', '/v1/admin/audit/anchors', undefined],
      ['POST', '/v1/admin/audit/anchors', { reason: 'x' }],
      [
        'POST',
        '/v1/admin/audit/anchors/check',
        { manifest: { v: 1, created_at: 'x', anchor: 'a'.repeat(64), chains: [] } },
      ],
    ];
    for (const [method, path, body] of routes) {
      expect((await env.call(method, path, { body })).status, `${path} anonymous`).toBe(401);
      expect(
        (await env.call(method, path, { token: user.token, body })).status,
        `${path} non-operator`,
      ).toBe(403);
    }
    expect(received).toHaveLength(0);
    const post = (body: unknown) =>
      env.call('POST', '/v1/admin/audit/anchors', { token: op, body });
    expect((await post({})).status).toBe(400);
    expect((await post({ reason: '' })).status).toBe(400);
    expect((await post({ reason: 'ok', url: 'https://evil.example/' })).status).toBe(400); // the destination is not caller-controlled
    expect(received).toHaveLength(0);
    const chk = (manifest: unknown) =>
      env.call('POST', '/v1/admin/audit/anchors/check', { token: op, body: { manifest } });
    expect((await chk({ v: 2, created_at: 'x', anchor: 'a'.repeat(64), chains: [] })).status).toBe(
      400,
    );
    expect((await chk({ v: 1, created_at: 'x', anchor: 'nothex', chains: [] })).status).toBe(400);
    expect(
      (await chk({ v: 1, created_at: 'x', anchor: 'a'.repeat(64), chains: [], extra: 1 })).status,
    ).toBe(400);
  });

  it('the verify endpoint returns the digest but not the per-chain list', async () => {
    env = await makeEnv();
    await env.register('a@example.test');
    const op = await env.operatorToken();
    const v = (await env.call('GET', '/v1/admin/audit/verify', { token: op })).body;
    expect(v).toMatchObject({ ok: true, anchor: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(v).not.toHaveProperty('heads');
  });
});
