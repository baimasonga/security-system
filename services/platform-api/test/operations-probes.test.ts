import { afterAll, afterEach, beforeAll, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { IncomingHttpHeaders, ServerResponse } from 'node:http';
import { BlockList, type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeEnv, type Env } from './harness.ts';
import { loadConfig } from '../src/config.ts';
import {
  checkHttps,
  guardedLookup,
  publicAddress,
  type ProbeCheck,
} from '../src/integrations/probe-http.ts';
import { parseProbeTargets, runProbes, type ProbeTarget } from '../src/operations-probes.ts';
import { MemoryMailDelivery } from '../src/integrations/mail.ts';

const HOST = 'probe.example.test';
let dir: string, cert: string, key: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'warrior-probe-'));
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:prime256v1',
      '-nodes',
      '-subj',
      `/CN=${HOST}`,
      '-addext',
      `subjectAltName=DNS:${HOST}`,
      '-days',
      '1',
      '-keyout',
      join(dir, 'key.pem'),
      '-out',
      join(dir, 'cert.pem'),
    ],
    { stdio: 'ignore' },
  );
  cert = readFileSync(join(dir, 'cert.pem'), 'utf8');
  key = readFileSync(join(dir, 'key.pem'), 'utf8');
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** A local HTTPS server standing in for the probed site; records what it receives. */
async function site(handle: (res: ServerResponse) => void) {
  const seen: IncomingHttpHeaders[] = [];
  const server: Server = createServer({ cert, key }, (req, res) => {
    seen.push(req.headers);
    handle(res);
  });
  // TCP connections, counted before TLS: a refused target must not even connect.
  const connections = { count: 0 };
  server.on('connection', () => void connections.count++);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    seen,
    port,
    connections,
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}
const loopback = (
  _h: string,
  _o: unknown,
  cb: (e: null, a: { address: string; family: number }[]) => void,
) => cb(null, [{ address: '127.0.0.1', family: 4 }]);
const target = (over: Partial<ProbeCheck> = {}): ProbeCheck => ({
  url: new URL(`https://${HOST}/api/v1/health`),
  contentType: 'json',
  contains: '"ok":true',
  ...over,
});
/** Test-only: allow the loopback test server while every other control stays in force. */
const testOpts = (port: number, over: Record<string, unknown> = {}) => ({
  port,
  ca: cert,
  resolve: loopback,
  blocked: new BlockList(),
  ...over,
});
const json =
  (body: string, headers: Record<string, string> = {}) =>
  (res: ServerResponse) => {
    res.writeHead(200, { 'content-type': 'application/json', ...headers });
    res.end(body);
  };

it.each([
  '127.0.0.1',
  '10.1.2.3',
  '172.16.0.1',
  '172.31.255.255',
  '192.168.1.1',
  '169.254.169.254',
  '100.64.0.1',
  '0.0.0.0',
  '224.0.0.1',
  '255.255.255.255',
  '198.18.0.1',
  '::1',
  '::',
  'fc00::1',
  'fd12:3456::1',
  'fe80::1',
  '::ffff:127.0.0.1',
  '::ffff:10.0.0.1',
  '::ffff:8.8.8.8',
  '64:ff9b::a00:1',
  '2002:a00:1::1',
  '2001::1',
  'ff02::1',
  'not-an-address',
  '',
])('refuses the non-public address %s', (address) => {
  expect(publicAddress(address)).toBe(false);
});
it.each(['8.8.8.8', '1.1.1.1', '104.21.32.1', '2606:4700::1111', '2001:4860:4860::8888'])(
  'accepts the public address %s',
  (address) => {
    expect(publicAddress(address)).toBe(true);
  },
);

it('refuses a name when any of its addresses is non-public, in both lookup forms', async () => {
  const call = (addresses: { address: string; family: number }[], all: boolean) =>
    new Promise<unknown>((resolve) =>
      guardedLookup((_h, _o, cb) => cb(null, addresses))(HOST, { all }, (err, a) =>
        resolve(err ? 'refused' : a),
      ),
    );
  const pub = { address: '8.8.8.8', family: 4 },
    priv = { address: '10.0.0.1', family: 4 };
  expect(await call([pub, priv], true)).toBe('refused');
  expect(await call([pub, priv], false)).toBe('refused');
  expect(await call([], false)).toBe('refused');
  expect(await call([pub], true)).toEqual([pub]);
  expect(await call([pub], false)).toBe('8.8.8.8');
  expect(
    await new Promise((resolve) =>
      guardedLookup((_h, _o, cb) => cb(Object.assign(new Error('nx'), { code: 'ENOTFOUND' }), []))(
        HOST,
        {},
        (err) => resolve(!!err),
      ),
    ),
  ).toBe(true);
});

it('passes only a direct 200 response of the expected type that contains the expected text', async () => {
  const s = await site(json('{"ok":true}'));
  expect(await checkHttps(target(), testOpts(s.port))).toBe(true);
  // No credentials or cookies are ever sent.
  expect(s.seen[0]).not.toHaveProperty('authorization');
  expect(s.seen[0]).not.toHaveProperty('cookie');
  expect(s.seen[0]!['user-agent']).toBe('Warrior-probe/1');
  expect(await checkHttps(target({ contains: '"ok":false' }), testOpts(s.port))).toBe(false);
  expect(await checkHttps(target({ contentType: 'html' }), testOpts(s.port))).toBe(false);
  await s.close();
});

it.each([
  [
    'server error',
    (res: ServerResponse) => {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    },
  ],
  [
    'redirect',
    (res: ServerResponse) => {
      res.writeHead(307, {
        location: `https://${HOST}/elsewhere`,
        'content-type': 'application/json',
      });
      res.end('{"ok":true}');
    },
  ],
  ['cached', json('{"ok":true}', { age: '30' })],
  ['invalid json', json('{"ok":true')],
  ['oversized', json('{"ok":true}' + ' '.repeat(300 * 1024))],
  [
    'invalid utf-8',
    (res: ServerResponse) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        Buffer.concat([Buffer.from('{"ok":true,"x":"'), Buffer.from([0xff]), Buffer.from('"}')]),
      );
    },
  ],
])('never turns a %s response into a pass', async (_name, handle) => {
  const s = await site(handle);
  expect(await checkHttps(target(), testOpts(s.port))).toBe(false);
  expect(s.seen).toHaveLength(1); // a redirect is not followed
  await s.close();
});

it('bounds a stalled response', async () => {
  const s = await site((res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"ok":');
  });
  const started = Date.now();
  expect(await checkHttps(target(), testOpts(s.port, { timeoutMs: 200 }))).toBe(false);
  expect(Date.now() - started).toBeLessThan(5000);
  await s.close();
});

it('never connects to a non-public address or an IP literal, and requires a trusted certificate', async () => {
  const s = await site(json('{"ok":true}'));
  // The production blocklist refuses loopback before any connection is made.
  expect(await checkHttps(target(), testOpts(s.port, { blocked: undefined }))).toBe(false);
  // https.request skips DNS for IP literals, so they are refused before connecting.
  for (const url of ['https://127.0.0.1/', 'https://[::1]/', 'http://probe.example.test/'])
    expect(await checkHttps(target({ url: new URL(url) }), testOpts(s.port))).toBe(false);
  expect(s.connections.count).toBe(0);
  // Without the test CA the self-signed certificate is not trusted: connected, no request.
  expect(await checkHttps(target(), testOpts(s.port, { ca: undefined }))).toBe(false);
  expect(s.seen).toHaveLength(0);
  await s.close();
});

const ids = {
  org_id: 'org_' + 'a'.repeat(24),
  application_id: 'opa_' + 'b'.repeat(24),
  environment_id: 'ope_' + 'c'.repeat(24),
  component_id: 'opm_' + 'd'.repeat(24),
};
const valid = {
  ...ids,
  url: 'https://www.rokelapdf.com/api/v1/health',
  content_type: 'json',
  contains: '"ok":true',
};
it('parses operator probe targets and refuses anything that could reach a private service', () => {
  expect(parseProbeTargets(JSON.stringify([valid]))).toEqual([
    {
      orgId: ids.org_id,
      applicationId: ids.application_id,
      environmentId: ids.environment_id,
      componentId: ids.component_id,
      url: new URL(valid.url),
      contentType: 'json',
      contains: '"ok":true',
    },
  ]);
  const secret = 'private-secret-value';
  for (const over of [
    { url: `http://www.rokelapdf.com/${secret}` },
    { url: `https://www.rokelapdf.com:8443/${secret}` },
    { url: `https://user:${secret}@www.rokelapdf.com/` },
    { url: `https://www.rokelapdf.com/#${secret}` },
    { url: `https://10.0.0.1/${secret}` },
    { url: `https://[::1]/${secret}` },
    { url: `https://localhost/${secret}` },
    { url: `https://db.railway.internal/${secret}` },
    { url: `https://printer.local/${secret}` },
    { url: `https://intranet/${secret}` },
    { url: `https://2130706433/${secret}` },
    { url: secret },
    { content_type: 'xml' },
    { contains: '' },
    { contains: `bad\n${secret}` },
    { component_id: 'opm_short' },
    { destination: secret },
  ]) {
    let message = '';
    try {
      parseProbeTargets(JSON.stringify([{ ...valid, ...over }]));
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message, JSON.stringify(over)).toMatch(
      /^OPERATIONS_PROBE_TARGETS\[0\]\.\w+ is invalid$/,
    );
    expect(message).not.toContain(secret);
  }
  expect(() => parseProbeTargets(JSON.stringify([valid, valid]))).toThrow('component_id');
  expect(() => parseProbeTargets('[]')).toThrow('1–10 targets');
  expect(() =>
    parseProbeTargets(
      JSON.stringify(
        Array.from({ length: 11 }, (_, i) => ({
          ...valid,
          component_id: 'opm_' + String(i).padStart(24, '0'),
        })),
      ),
    ),
  ).toThrow('1–10 targets');
  expect(() => parseProbeTargets('{')).toThrow('JSON array');
});

it('gates probes behind automation and requires targets only when enabled', () => {
  const base = {
    NODE_ENV: 'test',
    OPERATIONS_INVENTORY_ENABLED: 'true',
    OPERATIONS_INGESTION_ENABLED: 'true',
    OPERATIONS_HEALTH_ENABLED: 'true',
    OPERATIONS_INCIDENTS_ENABLED: 'true',
    OPERATIONS_AUTOMATION_ENABLED: 'true',
  };
  const targets = JSON.stringify([valid]);
  expect(loadConfig(base).operationsProbeTargets).toBeUndefined();
  expect(() =>
    loadConfig({
      NODE_ENV: 'test',
      OPERATIONS_PROBES_ENABLED: 'true',
      OPERATIONS_PROBE_TARGETS: targets,
    }),
  ).toThrow('requires automation');
  expect(() => loadConfig({ ...base, OPERATIONS_PROBES_ENABLED: 'true' })).toThrow(
    'OPERATIONS_PROBE_TARGETS is required',
  );
  expect(() => loadConfig({ ...base, OPERATIONS_PROBE_TARGETS: targets })).toThrow(
    'requires OPERATIONS_PROBES_ENABLED',
  );
  expect(() => loadConfig({ ...base, OPERATIONS_PROBES_ENABLED: 'yes' })).toThrow('true or false');
  expect(
    loadConfig({ ...base, OPERATIONS_PROBES_ENABLED: 'true', OPERATIONS_PROBE_TARGETS: targets })
      .operationsProbeTargets,
  ).toHaveLength(1);
});

let env: Env;
afterEach(async () => env?.app.close());
async function probeEnv(probes: boolean) {
  const mail = new MemoryMailDelivery(),
    identity = new MemoryMailDelivery();
  let up = true;
  const checked: string[] = [];
  const placeholder = parseProbeTargets(JSON.stringify([valid]));
  env = await makeEnv({
    config: {
      operationsInventoryEnabled: true,
      operationsIngestionEnabled: true,
      operationsHealthEnabled: true,
      operationsIncidentsEnabled: true,
      operationsAutomationEnabled: true,
      operationsEmailNotificationsEnabled: true,
      emailDelivery: {
        provider: 'cloudflare',
        accountId: 'a'.repeat(32),
        apiToken: 'synthetic',
        from: 'alerts@example.test',
        publicOrigin: 'https://warrior.example.test',
      },
      ...(probes ? { operationsProbeTargets: placeholder } : {}),
    },
    identityDelivery: identity,
    container: {
      operationsMail: mail,
      probeCheck: async (t) => {
        checked.push(t.url.href);
        return up;
      },
    },
  });
  const owner = await env.register('owner@example.test');
  await env.call('POST', '/v1/auth/email/request', { token: owner.token, body: {} });
  await env.c.auth.flushIdentityMail();
  const token = identity.messages.at(-1)!.text.match(/#verify=(recover_[A-Za-z0-9_-]+)/)![1]!;
  await env.call('POST', '/v1/auth/email/verify', { body: { token } });
  const base = `/v1/organizations/${owner.orgId}/operations/applications`;
  const app = await env.call('POST', base, {
    token: owner.token,
    body: {
      code: 'rokela-pdf',
      owner_user_id: owner.userId,
      criticality: 'high',
      product_id: null,
      reason: 'initial_setup',
    },
  });
  const e = await env.call('POST', `${base}/${app.body.id}/environments`, {
    token: owner.token,
    body: { code: 'production', kind: 'production', reason: 'initial_setup' },
  });
  const envPath = `${base}/${app.body.id}/environments/${e.body.id}`;
  const c = await env.call('POST', envPath + '/components', {
    token: owner.token,
    body: { code: 'public-site', kind: 'service', dependency_ids: [], reason: 'initial_setup' },
  });
  const rule = await env.call('POST', envPath + '/rules', {
    token: owner.token,
    body: {
      component_id: c.body.id,
      kind: 'probe',
      event_type: null,
      threshold: 1,
      window_seconds: 60,
      severity: 'critical',
      runbook: 'investigate_component',
      reason: 'initial_setup',
    },
  });
  expect(rule.status).toBe(201);
  // Bind the configured target to the component just created (IDs are only known now).
  if (probes)
    placeholder[0] = {
      ...placeholder[0]!,
      orgId: owner.orgId,
      applicationId: app.body.id,
      environmentId: e.body.id,
      componentId: c.body.id,
    } satisfies ProbeTarget;
  const cycle = async () => {
    await env.c.operationsProbes?.();
    await env.c.operationsAutomation.tick().catch(() => {});
  };
  return { mail, checked, cycle, setUp: (v: boolean) => void (up = v) };
}

it('opens an incident and emails when Warrior can no longer reach a site, and resolves when it can', async () => {
  const f = await probeEnv(true);
  await f.cycle();
  expect(f.checked).toEqual([valid.url]);
  f.setUp(false);
  await f.cycle();
  env.clock.advance(60000);
  await f.cycle();
  expect(f.mail.messages.map((m) => m.subject)).toEqual([
    'Warrior incident opened: critical on rokela-pdf/production/public-site',
  ]);
  // Probes run a minute apart; recovery needs fresh healthy results for a full window.
  f.setUp(true);
  for (let i = 0; i < 2; i++) {
    env.clock.advance(60000);
    await f.cycle();
  }
  expect(f.mail.messages.map((m) => m.subject).at(-1)).toBe(
    'Warrior incident resolved on rokela-pdf/production/public-site',
  );
});

it('makes no outbound checks unless probes are enabled', async () => {
  const f = await probeEnv(false);
  expect(env.c.operationsProbes).toBeUndefined();
  await f.cycle();
  env.clock.advance(300000);
  await f.cycle();
  expect(f.checked).toEqual([]);
  expect(f.mail.messages).toEqual([]);
});

it('records each run and never records into a wrong or missing scope', async () => {
  const f = await probeEnv(true);
  const [t] = env.c.config.operationsProbeTargets!;
  const other = { ...t!, environmentId: 'ope_' + 'f'.repeat(24) };
  const missing = { ...t!, componentId: 'opm_' + 'f'.repeat(24) };
  env.c.config.operationsProbeTargets!.splice(0, 1, t!, other, missing);
  expect(await env.c.operationsProbes!()).toEqual({ recorded: 1, unrecorded: 2 });
  f.setUp(false);
  expect(await env.c.operationsProbes!()).toEqual({ recorded: 1, unrecorded: 2 });
});

it('records a transport that throws as unavailable', async () => {
  const store = {
    transaction: async (_o: string, fn: (tx: unknown) => Promise<unknown>) => fn(tx),
  };
  const recorded: { status: string }[] = [];
  const tx = {
    find: async () => ({
      applicationId: target0.applicationId,
      environmentId: target0.environmentId,
    }),
    observeHealthTime: async (_o: string, now: Date) => now,
    recordProbeResult: async (r: { status: string }) => void recorded.push(r),
  };
  const target0 = parseProbeTargets(JSON.stringify([valid]))[0]!;
  const result = await runProbes({
    targets: [target0],
    store: store as never,
    clock: { now: () => new Date('2026-10-24T00:00:00Z') },
    check: async () => {
      throw new Error('boom');
    },
  });
  expect(result).toEqual({ recorded: 1, unrecorded: 0 });
  expect(recorded.map((r) => r.status)).toEqual(['unavailable']);
});
