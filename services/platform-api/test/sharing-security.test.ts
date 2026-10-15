import { afterEach, describe, expect, it } from 'vitest';
import { EICAR } from '@trust/sharing';
import { DAY } from './harness.ts';
import {
  BUSINESS,
  UA,
  fetchSigned,
  grantPlan,
  pdf,
  sharingEnv,
  sp,
  tokenOf,
  upload,
  verifyEmail,
  type SharingEnv,
} from './sharing-support.ts';

let env: SharingEnv;
afterEach(async () => env?.app.close());

async function sharedTransfer(e: SharingEnv, email: string, link: Record<string, unknown> = {}) {
  const owner = await e.register(email);
  const P = sp(owner.orgId);
  const tr = await e.call('POST', `${P}/transfers`, {
    token: owner.token,
    body: { title: 'Files', kind: 'temporary' },
  });
  await upload(
    e,
    owner.token,
    owner.orgId,
    { target: 'transfer', transfer_id: tr.body.id, name: 'a.pdf' },
    pdf('secret contents'),
  );
  const l = await e.call('POST', `${P}/links`, {
    token: owner.token,
    body: { target_type: 'transfer', target_id: tr.body.id, permission: 'download', ...link },
  });
  expect(l.status).toBe(201);
  return { owner, P, transferId: tr.body.id as string, link: l.body, token: tokenOf(l.body.url) };
}

describe('sharing: tenant isolation', () => {
  it('returns 404 for every cross-organization reference', async () => {
    env = await sharingEnv();
    const a = await sharedTransfer(env, 'a@example.test');
    const b = await env.register('b@example.test');
    const PB = sp(b.orgId);
    const PA = sp(a.owner.orgId);
    // Reaching into A's organization path as B: not a member → 404.
    expect(
      (await env.call('GET', `${PA}/transfers/${a.transferId}`, { token: b.token })).status,
    ).toBe(404);
    expect((await env.call('GET', `${PA}/overview`, { token: b.token })).status).toBe(404);
    // Using A's ids inside B's own organization: indistinguishable from unknown ids.
    expect(
      (await env.call('GET', `${PB}/transfers/${a.transferId}`, { token: b.token })).status,
    ).toBe(404);
    expect((await env.call('GET', `${PB}/links/${a.link.id}`, { token: b.token })).status).toBe(
      404,
    );
    expect(
      (
        await env.call('POST', `${PB}/links`, {
          token: b.token,
          body: { target_type: 'transfer', target_id: a.transferId, permission: 'download' },
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await env.call('POST', `${PB}/uploads`, {
          token: b.token,
          body: { target: 'transfer', transfer_id: a.transferId, name: 'x.pdf', size: 10 },
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await env.call('POST', `${PB}/links/${a.link.id}/status`, {
          token: b.token,
          body: { action: 'revoke' },
        })
      ).status,
    ).toBe(404);
    const file = (
      await env.call('GET', `${PA}/transfers/${a.transferId}`, { token: a.owner.token })
    ).body.files[0];
    expect(
      (
        await env.call('POST', `${PB}/files/download`, {
          token: b.token,
          body: { type: 'transfer_file', id: file.id },
        })
      ).status,
    ).toBe(404);
    expect((await env.call('GET', `${PB}/transfers`, { token: b.token })).body.items).toEqual([]);
  });

  it('lets members create but only creators or admins manage an item', async () => {
    env = await sharingEnv();
    const owner = await env.register('lead@example.test');
    const member = await env.register('member@example.test');
    const team = await env.call('POST', '/v1/organizations', {
      token: owner.token,
      body: { name: 'Team' },
    });
    await env.call('POST', `/v1/organizations/${team.body.id}/members`, {
      token: owner.token,
      body: { email: 'member@example.test', role: 'member' },
    });
    const P = sp(team.body.id);
    const tr = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: { title: 'Owner files', kind: 'temporary' },
    });
    expect(
      (
        await env.call('POST', `${P}/transfers/${tr.body.id}/revoke`, {
          token: member.token,
          body: {},
        })
      ).status,
    ).toBe(403);
    const mine = await env.call('POST', `${P}/transfers`, {
      token: member.token,
      body: { title: 'Member files', kind: 'temporary' },
    });
    expect(mine.status).toBe(201);
    expect(
      (
        await env.call('POST', `${P}/transfers/${mine.body.id}/revoke`, {
          token: owner.token,
          body: {},
        })
      ).status,
    ).toBe(200);
    expect(
      (await env.call('POST', `${P}/branding`, { token: member.token, body: {} })).status,
    ).toBe(404);
    expect(
      (
        await env.call('POST', `${P}/domains`, {
          token: member.token,
          body: { hostname: 'go.example.com' },
        })
      ).status,
    ).toBe(403);
  });
});

describe('sharing: quarantine, formats and quotas', () => {
  it('never serves bytes before checks pass, and rejects malware and disguised content', async () => {
    env = await sharingEnv();
    const owner = await env.register('q@example.test');
    const P = sp(owner.orgId);
    const tr = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: { title: 'Q', kind: 'temporary' },
    });
    const link = await env.call('POST', `${P}/links`, {
      token: owner.token,
      body: { target_type: 'transfer', target_id: tr.body.id, permission: 'download' },
    });
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: tr.body.id, name: 'pending.pdf' },
      pdf('pending'),
      { process: false },
    );
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: tr.body.id, name: 'eicar.txt' },
      Buffer.concat([Buffer.from('test '), EICAR]),
      { process: false },
    );
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: tr.body.id, name: 'fake.pdf' },
      Buffer.from('MZ\x90\x00 executable', 'latin1'),
      { process: false },
    );
    const tk = tokenOf(link.body.url);
    const open = await env.call('POST', `/v1/public/shares/${tk}/open`, { body: {} });
    expect(
      open.body.files.map((f: { status: string; downloadable: boolean }) => [
        f.status,
        f.downloadable,
      ]),
    ).toEqual([
      ['processing', false],
      ['processing', false],
      ['processing', false],
    ]);
    const tryGet = (fileId: string) =>
      env.call('POST', `/v1/public/shares/${tk}/files/url`, {
        body: { grant: open.body.grant, file_id: fileId, disposition: 'attachment' },
      });
    expect((await tryGet(open.body.files[0].id)).status).toBe(409);
    await env.c.sharing!.processJobs({ limit: 100 });
    const files = (await env.call('GET', `${P}/transfers/${tr.body.id}`, { token: owner.token }))
      .body.files;
    const byName = (n: string) => files.find((f: { name: string }) => f.name === n);
    expect(
      files
        .map((f: { name: string; status: string; reject_reason: string | null }) => [
          f.name,
          f.status,
          f.reject_reason,
        ])
        .sort(),
    ).toEqual([
      ['eicar.txt', 'rejected', 'malware_signature'],
      ['fake.pdf', 'rejected', 'content_does_not_match_type'],
      ['pending.pdf', 'available', null],
    ]);
    expect((await tryGet(byName('eicar.txt').id)).status).toBe(409);
    expect((await tryGet(byName('pending.pdf').id)).status).toBe(200);
    // Rejected bytes are deleted from storage by the next job pass.
    await env.c.sharing!.processJobs({ limit: 100 });
    const audit = await env.c.audit.list({ orgId: owner.orgId, limit: 100 });
    expect(audit.filter((e) => e.action === 'share.file.rejected')).toHaveLength(2);
    expect(JSON.stringify(audit)).not.toContain('eicar.txt');
  });

  it('refuses executables, active content and oversized files before accepting any byte', async () => {
    env = await sharingEnv();
    const owner = await env.register('fmt@example.test');
    const P = sp(owner.orgId);
    const tr = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: { title: 'F', kind: 'temporary' },
    });
    for (const name of ['setup.exe', 'page.html', 'drawing.svg', 'script.js'])
      expect(
        (
          await env.call('POST', `${P}/uploads`, {
            token: owner.token,
            body: { target: 'transfer', transfer_id: tr.body.id, name, size: 10 },
          })
        ).status,
        name,
      ).toBe(400);
    const big = await env.call('POST', `${P}/uploads`, {
      token: owner.token,
      body: {
        target: 'transfer',
        transfer_id: tr.body.id,
        name: 'big.pdf',
        size: 251 * 1024 * 1024,
      },
    });
    expect(big.status).toBe(409);
    expect(big.body.code).toBe('quota_exceeded');
    // Storage: many large reservations cannot exceed the allowance (free plan: 2 GiB).
    const sizes = [240, 240, 240, 240, 240, 240, 240, 240, 240].map((m) => m * 1024 * 1024);
    const results = await Promise.all(
      sizes.map((size, i) =>
        env.call('POST', `${P}/uploads`, {
          token: owner.token,
          body: { target: 'transfer', transfer_id: tr.body.id, name: `f${i}.pdf`, size },
        }),
      ),
    );
    expect(results.filter((r) => r.status === 201)).toHaveLength(8);
    expect(results.filter((r) => r.status === 409)).toHaveLength(1);
    expect(
      (await env.call('GET', `${P}/overview`, { token: owner.token })).body.usage.storage_bytes,
    ).toBeLessThanOrEqual(2 * 1024 ** 3);
    // Drafts accept PDFs only.
    const doc = await env.call('POST', `${P}/documents`, {
      token: owner.token,
      body: { title: 'D' },
    });
    expect(
      (
        await env.call('POST', `${P}/uploads`, {
          token: owner.token,
          body: { target: 'draft', document_id: doc.body.id, name: 'x.docx', size: 10 },
        })
      ).status,
    ).toBe(400);
    // Persistent sharing and long retention need a plan.
    expect(
      (
        await env.call('POST', `${P}/transfers`, {
          token: owner.token,
          body: { title: 'P', kind: 'persistent' },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await env.call('POST', `${P}/transfers`, {
          token: owner.token,
          body: {
            title: 'L',
            kind: 'temporary',
            expires_at: new Date(env.clock.now().getTime() + 30 * DAY).toISOString(),
          },
        })
      ).status,
    ).toBe(409);
  });

  it('meters API mutations and bandwidth separately', async () => {
    env = await sharingEnv();
    const s = await sharedTransfer(env, 'meter@example.test');
    const open = await env.call('POST', `/v1/public/shares/${s.token}/open`, { body: {} });
    await env.call('POST', `/v1/public/shares/${s.token}/files/url`, {
      body: { grant: open.body.grant, file_id: open.body.files[0].id, disposition: 'attachment' },
    });
    const usage = (await env.call('GET', `${s.P}/overview`, { token: s.owner.token })).body.usage;
    expect(usage.api_requests).toBe(3); // transfer, upload, link
    expect(usage.bandwidth_bytes).toBe(pdf('secret contents').length);
    expect(usage.processing_bytes).toBe(pdf('secret contents').length);
    expect(usage.upload_bytes).toBe(pdf('secret contents').length);
  });
});

describe('sharing: access policies', () => {
  it('enforces recipient restrictions on the server, with verified email and on every request', async () => {
    env = await sharingEnv();
    const s = await sharedTransfer(env, 'owner@example.test', {
      restriction: 'recipients',
      recipients: ['client@example.test'],
    });
    const client = await env.register('client@example.test');
    const other = await env.register('other@example.test');
    const open = (token?: string) =>
      env.call('POST', `/v1/public/shares/${s.token}/open`, {
        ...(token ? { token } : {}),
        body: {},
      });
    expect((await open()).status).toBe(401);
    expect((await open(other.token)).status).toBe(403);
    // A matching but unverified email is not enough: anyone can register an address they do not control.
    expect((await open(client.token)).status).toBe(403);
    await verifyEmail(env, client.token);
    const ok = await open(client.token);
    expect(ok.status).toBe(200);
    // A grant bound to the recipient cannot be used without their session, or by someone else.
    const body = { grant: ok.body.grant, file_id: ok.body.files[0].id, disposition: 'attachment' };
    expect(
      (await env.call('POST', `/v1/public/shares/${s.token}/files/url`, { body })).status,
    ).toBe(401);
    expect(
      (
        await env.call('POST', `/v1/public/shares/${s.token}/files/url`, {
          token: other.token,
          body,
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await env.call('POST', `/v1/public/shares/${s.token}/files/url`, {
          token: client.token,
          body,
        })
      ).status,
    ).toBe(200);
    // Removing the recipient takes effect on the next request.
    await env.call('PATCH', `${s.P}/links/${s.link.id}`, {
      token: s.owner.token,
      body: { recipients: ['someone@example.test'] },
    });
    expect(
      (
        await env.call('POST', `/v1/public/shares/${s.token}/files/url`, {
          token: client.token,
          body,
        })
      ).status,
    ).toBe(403); // Revoking the whole transfer also stops an outstanding grant.
    const other2 = await env.call('POST', `${s.P}/links`, {
      token: s.owner.token,
      body: { target_type: 'transfer', target_id: s.transferId, permission: 'download' },
    });
    const g = await env.call('POST', `/v1/public/shares/${tokenOf(other2.body.url)}/open`, {
      body: {},
    });
    await env.call('POST', `${s.P}/transfers/${s.transferId}/revoke`, {
      token: s.owner.token,
      body: {},
    });
    const gone = await env.call('POST', `/v1/public/shares/${tokenOf(other2.body.url)}/files/url`, {
      body: { grant: g.body.grant, file_id: g.body.files[0].id, disposition: 'attachment' },
    });
    expect(gone.status).toBe(410);
    expect(gone.body.details).toEqual({ state: 'unavailable' });
  });

  it('restricts members-only links to the owning organization', async () => {
    env = await sharingEnv();
    const s = await sharedTransfer(env, 'm-owner@example.test', { restriction: 'members' });
    const outsider = await env.register('outsider@example.test');
    expect(
      (
        await env.call('POST', `/v1/public/shares/${s.token}/open`, {
          token: outsider.token,
          body: {},
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await env.call('POST', `/v1/public/shares/${s.token}/open`, {
          token: s.owner.token,
          body: {},
        })
      ).status,
    ).toBe(200);
  });

  it('view-only links never issue attachment downloads; download limits are exact under concurrency', async () => {
    env = await sharingEnv();
    const s = await sharedTransfer(env, 'v@example.test', { permission: 'view' });
    const open = await env.call('POST', `/v1/public/shares/${s.token}/open`, { body: {} });
    expect(open.body.files[0]).toMatchObject({ viewable: true, downloadable: false });
    const req = (
      disposition: string,
      t = s.token,
      grant = open.body.grant,
      fileId = open.body.files[0].id,
    ) =>
      env.call('POST', `/v1/public/shares/${t}/files/url`, {
        body: { grant, file_id: fileId, disposition },
      });
    expect((await req('attachment')).status).toBe(403);
    const inline = await req('inline');
    expect(inline.status).toBe(200);
    const bytes = await fetchSigned(env, inline.body.url);
    expect(bytes.headers['content-disposition']).toMatch(/^inline;/);

    const limited = await env.call('POST', `${s.P}/links`, {
      token: s.owner.token,
      body: {
        target_type: 'transfer',
        target_id: s.transferId,
        permission: 'download',
        max_downloads: 2,
      },
    });
    const lt = tokenOf(limited.body.url);
    const lo = await env.call('POST', `/v1/public/shares/${lt}/open`, { body: {} });
    const results = await Promise.all(
      Array.from({ length: 6 }, () => req('attachment', lt, lo.body.grant, lo.body.files[0].id)),
    );
    expect(results.filter((r) => r.status === 200)).toHaveLength(2);
    expect(
      results
        .filter((r) => r.status === 410)
        .every((r) => r.body.details.state === 'download_limit_reached'),
    ).toBe(true);
    expect(
      (await env.call('GET', `${s.P}/links/${limited.body.id}`, { token: s.owner.token })).body
        .download_count,
    ).toBe(2);
    expect(
      (
        await env.call('PATCH', `${s.P}/links/${limited.body.id}`, {
          token: s.owner.token,
          body: { max_downloads: 1 },
        })
      ).status,
    ).toBe(400);
  });

  it('locks out password guessing per link and never reveals stored hashes', async () => {
    env = await sharingEnv();
    const s = await sharedTransfer(env, 'pw@example.test', { password: 'correct-horse-9' });
    const tries = [];
    for (let i = 0; i < 10; i++)
      tries.push(
        (
          await env.call('POST', `/v1/public/shares/${s.token}/open`, {
            body: { password: `guess-${i}` },
          })
        ).status,
      );
    expect(tries.every((x) => x === 401)).toBe(true);
    const locked = await env.call('POST', `/v1/public/shares/${s.token}/open`, {
      body: { password: 'correct-horse-9' },
    });
    expect(locked.status).toBe(429);
    env.clock.advance(16 * 60_000);
    expect(
      (
        await env.call('POST', `/v1/public/shares/${s.token}/open`, {
          body: { password: 'correct-horse-9' },
        })
      ).status,
    ).toBe(200);
    const act = await env.call('GET', `${s.P}/links/${s.link.id}/activity`, {
      token: await env.login('pw@example.test'),
    });
    expect(act.body.totals.password_failed.count + act.body.totals.password_failed.bots).toBe(10);
    const all = JSON.stringify([
      s.link,
      (await env.call('GET', `${s.P}/links`, { token: s.owner.token })).body,
    ]);
    expect(all).not.toMatch(/scrypt|token_hash|salt/);
  });

  it('rejects malformed, unknown and forged references uniformly', async () => {
    env = await sharingEnv();
    const s = await sharedTransfer(env, 'u@example.test');
    expect(
      (await env.call('POST', `/v1/public/shares/${'A'.repeat(43)}/open`, { body: {} })).status,
    ).toBe(404);
    expect((await env.call('POST', `/v1/public/shares/short/open`, { body: {} })).status).toBe(400);
    const open = await env.call('POST', `/v1/public/shares/${s.token}/open`, { body: {} });
    const [, body, sig] = open.body.grant.split('.');
    const forged = Buffer.from(
      JSON.stringify({
        ...JSON.parse(Buffer.from(body, 'base64url').toString()),
        s: 'lnk_000000000000000000000000',
      }),
    ).toString('base64url');
    expect(
      (
        await env.call('POST', `/v1/public/shares/${s.token}/files/url`, {
          body: {
            grant: `g1.${forged}.${sig}`,
            file_id: open.body.files[0].id,
            disposition: 'attachment',
          },
        })
      ).status,
    ).toBe(401);
    // Strict schemas: unknown fields are rejected everywhere.
    expect(
      (
        await env.call('POST', `/v1/public/shares/${s.token}/open`, {
          body: { password: 'x', admin: true },
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await env.call('POST', `${s.P}/transfers`, {
          token: s.owner.token,
          body: { title: 'x', kind: 'temporary', plan: 'business' },
        })
      ).status,
    ).toBe(400);
  });
});

describe('sharing: isolated content origin', () => {
  it('accepts only valid, unexpired signatures, exact sizes and the portal origin for CORS', async () => {
    env = await sharingEnv();
    const owner = await env.register('co@example.test');
    const P = sp(owner.orgId);
    const tr = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: { title: 'C', kind: 'temporary' },
    });
    const begin = await env.call('POST', `${P}/uploads`, {
      token: owner.token,
      body: { target: 'transfer', transfer_id: tr.body.id, name: 'c.pdf', size: 8 },
    });
    const parts = await env.call('POST', `${P}/uploads/${begin.body.upload_id}/parts`, {
      token: owner.token,
      body: { part_numbers: [1] },
    });
    const url = parts.body.parts[0].url as string;
    const tampered = url.replace(/b=8/, 'b=9');
    expect((await env.content('PUT', tampered, Buffer.alloc(9))).status).toBe(403);
    expect((await env.content('PUT', url, Buffer.alloc(9))).status).toBe(400);
    const pre = await env.content('OPTIONS', url, undefined, {
      origin: 'https://evil.example',
      'access-control-request-method': 'PUT',
    });
    expect(pre.headers['access-control-allow-origin']).toBeUndefined();
    const ok = await env.content('PUT', url, Buffer.from('%PDF-1.7'), {
      origin: env.c.config.sharing!.publicOrigin,
    });
    expect(ok.status).toBe(200);
    expect(ok.headers['access-control-allow-origin']).toBe(env.c.config.sharing!.publicOrigin);
    env.clock.advance(16 * 60_000);
    expect((await env.content('PUT', url, Buffer.from('%PDF-1.7'))).status).toBe(403);
    expect((await env.content('GET', url.replace('/o/part', '/o/get'))).status).toBe(403);
  });

  it('reads only signed parameters (no prototype pollution) and rate-limits the content origin', async () => {
    env = await sharingEnv();
    const store = env.c.sharingLocalStore!;
    const now = env.clock.now().getTime();
    const exp = String(Math.floor(now / 1000) + 60);
    const good = { k: 'o/org_x/blb_x', e: exp, d: 'attachment', t: 'application/pdf' };
    const sig = store.sign(good);
    // Extra or hostile keys are ignored, so they cannot alter the parameters or Object.prototype.
    const v = store.verify(
      { ...good, s: sig, ['__proto__']: 'polluted', constructor: 'x' } as Record<string, unknown>,
      now,
    );
    expect(v && { ...v }).toEqual(good);
    expect(Object.getPrototypeOf(v)).toBeNull();
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    const polluted = await env.content(
      'GET',
      `${store.contentOrigin}/o/get?__proto__[x]=1&k=a&e=${exp}&s=bad`,
    );
    expect(polluted.status).toBe(403);
    expect(({} as Record<string, unknown>)['x']).toBeUndefined();

    const { buildContentApp } = await import('../src/integrations/object-store-local.ts');
    const limited = await buildContentApp(store, {
      allowedOrigin: 'http://127.0.0.1:8080',
      rateLimitPerMinute: 2,
    });
    const codes = [];
    for (let i = 0; i < 3; i++)
      codes.push((await limited.inject({ url: '/o/get?k=a&e=1&s=x' })).statusCode);
    expect(codes).toEqual([403, 403, 429]);
    await limited.close();
  });

  it('keeps the API and portal free of file bytes and serves pages with a strict CSP', async () => {
    env = await sharingEnv();
    const page = await env.app.inject({ url: `/s/${'a'.repeat(43)}` });
    expect(page.statusCode).toBe(200);
    expect(page.headers['content-security-policy']).toContain("script-src 'self'");
    expect(page.headers['content-security-policy']).toContain(
      `connect-src 'self' ${env.c.sharingLocalStore!.contentOrigin}`,
    );
    expect(page.headers['referrer-policy']).toBe('no-referrer');
    expect((await env.app.inject({ url: '/o/get' })).statusCode).toBe(404);
  });
});

describe('sharing: short links and abuse', () => {
  it('separates public and confidential links and validates destinations without fetching them', async () => {
    env = await sharingEnv();
    const s = await sharedTransfer(env, 'sl@example.test');
    const make = (body: Record<string, unknown>) =>
      env.call('POST', `${s.P}/short-links`, { token: s.owner.token, body });
    for (const destination_url of [
      'javascript:alert(1)',
      'http://169.254.169.254/latest/meta-data/',
      'http://localhost:8080/admin',
      'https://intranet.corp/',
      'file:///etc/passwd',
      `${env.c.config.sharing!.shortOrigin}/l/loop`,
    ])
      expect(
        (await make({ kind: 'public', destination_type: 'external', destination_url })).status,
        destination_url,
      ).toBe(400);
    // Confidential links: no alias, no external destination; the code is unpredictable.
    expect(
      (
        await make({
          kind: 'confidential',
          destination_type: 'share',
          target_id: s.link.id,
          alias: 'contract',
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await make({
          kind: 'confidential',
          destination_type: 'external',
          destination_url: 'https://x.example.com',
        })
      ).status,
    ).toBe(400);
    const conf = await make({
      kind: 'confidential',
      destination_type: 'share',
      target_id: s.link.id,
    });
    expect(conf.status).toBe(201);
    const code = conf.body.url.split('/d/')[1];
    expect(code).toMatch(/^[A-Za-z0-9_-]{16}$/);
    const go = await env.app.inject({ url: `/d/${code}` });
    expect(go.statusCode).toBe(302);
    expect(go.headers.location).toBe(s.link.url);
    // A short URL is not an access-control mechanism: the share link's own policy still applies.
    await env.call('POST', `${s.P}/links/${s.link.id}/status`, {
      token: s.owner.token,
      body: { action: 'suspend' },
    });
    expect((await env.call('POST', `/v1/public/shares/${s.token}/open`, { body: {} })).status).toBe(
      410,
    );
    // Aliases are unique per domain and cannot impersonate platform paths.
    expect(
      (
        await make({
          kind: 'public',
          destination_type: 'external',
          destination_url: 'https://a.example.com',
          alias: 'login',
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await make({
          kind: 'public',
          destination_type: 'external',
          destination_url: 'https://a.example.com',
          alias: 'promo',
        })
      ).status,
    ).toBe(201);
    const other = await env.register('sl2@example.test');
    expect(
      (
        await env.call('POST', `${sp(other.orgId)}/short-links`, {
          token: other.token,
          body: {
            kind: 'public',
            destination_type: 'external',
            destination_url: 'https://b.example.com',
            alias: 'promo',
          },
        })
      ).status,
    ).toBe(409);
  });

  it('keeps an audited destination history and supports search and bulk management', async () => {
    env = await sharingEnv();
    const owner = await env.register('bulk@example.test');
    const P = sp(owner.orgId);
    const ids: string[] = [];
    for (const [alias, folder] of [
      ['alpha-one', 'Spring'],
      ['alpha-two', 'Spring'],
      ['beta', 'Autumn'],
    ] as const)
      ids.push(
        (
          await env.call('POST', `${P}/short-links`, {
            token: owner.token,
            body: {
              kind: 'public',
              destination_type: 'external',
              destination_url: `https://${alias}.example.com/`,
              alias,
              folder,
            },
          })
        ).body.id,
      );
    env.clock.advance(1000);
    const edit = await env.call('PATCH', `${P}/short-links/${ids[0]}`, {
      token: owner.token,
      body: { destination_url: 'https://new.example.com/landing', reason: 'campaign moved' },
    });
    expect(edit.body.destination_url).toBe('https://new.example.com/landing');
    const hist = await env.call('GET', `${P}/short-links/${ids[0]}/history`, {
      token: owner.token,
    });
    expect(
      hist.body.items.map((h: { destination_url: string; reason: string }) => [
        h.destination_url,
        h.reason,
      ]),
    ).toEqual([
      ['https://alpha-one.example.com/', 'created'],
      ['https://new.example.com/landing', 'campaign moved'],
    ]);
    const audit = await env.c.audit.list({
      orgId: owner.orgId,
      action: 'short_link.destination_changed',
    });
    expect(audit[0]).toMatchObject({
      reason: 'campaign moved',
      metadata: { from_host: 'alpha-one.example.com', to_host: 'new.example.com' },
    });
    expect(
      (await env.call('GET', `${P}/short-links?q=alpha`, { token: owner.token })).body.items,
    ).toHaveLength(2);
    expect(
      (await env.call('GET', `${P}/short-links?folder=Autumn`, { token: owner.token })).body.items,
    ).toHaveLength(1);
    const bulk = await env.call('POST', `${P}/short-links/bulk`, {
      token: owner.token,
      body: { ids: ids.slice(0, 2), action: 'tag', tag: 'q2' },
    });
    expect(bulk.body.updated).toBe(2);
    expect(
      (await env.call('GET', `${P}/short-links?tag=q2`, { token: owner.token })).body.items,
    ).toHaveLength(2);
    await env.call('POST', `${P}/short-links/bulk`, {
      token: owner.token,
      body: { ids, action: 'suspend' },
    });
    expect((await env.app.inject({ url: '/l/beta' })).statusCode).toBe(410);
    const foreign = await env.register('foreign@example.test');
    const theirs = (
      await env.call('POST', `${sp(foreign.orgId)}/short-links`, {
        token: foreign.token,
        body: {
          kind: 'public',
          destination_type: 'external',
          destination_url: 'https://f.example.com/',
        },
      })
    ).body.id;
    expect(
      (
        await env.call('POST', `${P}/short-links/bulk`, {
          token: owner.token,
          body: { ids: [ids[0], theirs], action: 'revoke' },
        })
      ).status,
    ).toBe(404);
    expect(
      (await env.call('GET', `${P}/short-links/${ids[0]}`, { token: owner.token })).body.status,
    ).toBe('suspended');
  });

  it('password-protected and sign-in public short links require an unlock step', async () => {
    env = await sharingEnv();
    const owner = await env.register('lock@example.test');
    await env.call('POST', `${sp(owner.orgId)}/short-links`, {
      token: owner.token,
      body: {
        kind: 'public',
        destination_type: 'external',
        destination_url: 'https://private.example.com/',
        alias: 'members-area',
        password: 'open-sesame-1',
        require_auth: true,
      },
    });
    const page = await env.app.inject({ url: '/l/members-area' });
    expect(page.statusCode).toBe(200);
    expect(page.headers['content-type']).toContain('text/html');
    expect(page.body).not.toContain('private.example.com');
    expect(
      (
        await env.call('POST', '/v1/public/short-links/members-area/unlock', {
          body: { password: 'open-sesame-1' },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await env.call('POST', '/v1/public/short-links/members-area/unlock', {
          token: owner.token,
          body: { password: 'nope-nope' },
        })
      ).status,
    ).toBe(401);
    const ok = await env.call('POST', '/v1/public/short-links/members-area/unlock', {
      token: owner.token,
      body: { password: 'open-sesame-1' },
    });
    expect(ok.body.location).toBe('https://private.example.com/');
  });

  it('routes abuse reports to operators, whose suspension the owner cannot lift', async () => {
    env = await sharingEnv();
    const owner = await env.register('abuse-owner@example.test');
    const sl = await env.call('POST', `${sp(owner.orgId)}/short-links`, {
      token: owner.token,
      body: {
        kind: 'public',
        destination_type: 'external',
        destination_url: 'https://login-bank.example.net/',
        alias: 'bank-login',
      },
    });
    const unknown = await env.call('POST', '/v1/public/abuse-reports', {
      body: { reference: 'https://elsewhere.example/l/nothing', category: 'phishing' },
    });
    const report = await env.call('POST', '/v1/public/abuse-reports', {
      body: {
        reference: `${env.c.config.sharing!.shortOrigin}/l/bank-login`,
        category: 'phishing',
        details: 'Imitates a bank login.',
      },
    });
    expect(report.status).toBe(202);
    expect(Object.keys(report.body).sort()).toEqual(Object.keys(unknown.body).sort());
    expect(
      (await env.call('GET', '/v1/admin/sharing/abuse-reports', { token: owner.token })).status,
    ).toBe(403);
    const op = await env.operatorToken();
    const list = await env.call('GET', '/v1/admin/sharing/abuse-reports?status=open', {
      token: op,
    });
    const item = list.body.items.find((r: { id: string }) => r.id === report.body.id);
    expect(item).toMatchObject({
      subject_type: 'short',
      subject_id: sl.body.id,
      org_id: owner.orgId,
    });
    expect(
      (
        await env.call('POST', `/v1/admin/sharing/abuse-reports/${item.id}/resolve`, {
          token: op,
          body: { action: 'suspend' },
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await env.call('POST', `/v1/admin/sharing/abuse-reports/${item.id}/resolve`, {
          token: op,
          body: { action: 'suspend', reason: 'confirmed phishing page' },
        })
      ).status,
    ).toBe(200);
    expect((await env.app.inject({ url: '/l/bank-login' })).statusCode).toBe(410);
    const resume = await env.call('POST', `${sp(owner.orgId)}/short-links/${sl.body.id}/status`, {
      token: owner.token,
      body: { action: 'resume' },
    });
    expect(resume.status).toBe(403);
    const audit = await env.c.audit.list({ orgId: owner.orgId, limit: 100 });
    expect(audit.find((e) => e.action === 'share.operator_hold.placed')).toMatchObject({
      actor: { type: 'operator' },
      reason: 'confirmed phishing page',
    });
  });
});

describe('sharing: review, approval and branding', () => {
  it('collects comments and approval through a restricted review link before publication', async () => {
    env = await sharingEnv();
    const author = await env.register('author@example.test');
    const reviewer = await env.register('reviewer@example.test');
    await verifyEmail(env, reviewer.token);
    const P = sp(author.orgId);
    const doc = await env.call('POST', `${P}/documents`, {
      token: author.token,
      body: { title: 'Annual report', require_approval: true },
    });
    await upload(
      env,
      author.token,
      author.orgId,
      { target: 'draft', document_id: doc.body.id, name: 'r.pdf' },
      pdf('report'),
    );
    const v1 = await env.call('POST', `${P}/documents/${doc.body.id}/export`, {
      token: author.token,
      body: {},
    });
    expect(
      (
        await env.call('POST', `${P}/documents/${doc.body.id}/publish`, {
          token: author.token,
          body: { version_id: v1.body.id },
        })
      ).status,
    ).toBe(409);
    // Unapproved versions cannot be shared for viewing; only for review, and only with identified reviewers.
    expect(
      (
        await env.call('POST', `${P}/links`, {
          token: author.token,
          body: {
            target_type: 'document',
            target_id: doc.body.id,
            version_mode: 'fixed',
            version_id: v1.body.id,
            permission: 'download',
          },
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await env.call('POST', `${P}/links`, {
          token: author.token,
          body: {
            target_type: 'document',
            target_id: doc.body.id,
            version_mode: 'fixed',
            version_id: v1.body.id,
            permission: 'review',
          },
        })
      ).status,
    ).toBe(400);
    const review = await env.call('POST', `${P}/links`, {
      token: author.token,
      body: {
        target_type: 'document',
        target_id: doc.body.id,
        version_mode: 'fixed',
        version_id: v1.body.id,
        permission: 'review',
        restriction: 'recipients',
        recipients: ['reviewer@example.test'],
      },
    });
    const rt = tokenOf(review.body.url);
    const open = await env.call('POST', `/v1/public/shares/${rt}/open`, {
      token: reviewer.token,
      body: {},
    });
    expect(open.body.files[0]).toMatchObject({ viewable: true, downloadable: false });
    expect(
      (
        await env.call('POST', `/v1/public/shares/${rt}/comments`, {
          token: reviewer.token,
          body: { grant: open.body.grant, body: 'Page 3 total is wrong.', page: 3 },
        })
      ).status,
    ).toBe(201);
    await env.call('POST', `/v1/public/shares/${rt}/review`, {
      token: reviewer.token,
      body: { grant: open.body.grant, decision: 'changes_requested' },
    });
    expect(
      (
        await env.call('POST', `${P}/documents/${doc.body.id}/publish`, {
          token: author.token,
          body: { version_id: v1.body.id },
        })
      ).status,
    ).toBe(409);
    await env.call('POST', `/v1/public/shares/${rt}/review`, {
      token: reviewer.token,
      body: { grant: open.body.grant, decision: 'approved', note: 'Fine after all.' },
    });
    const thread = await env.call('GET', `/v1/public/shares/${rt}/comments`, {
      token: reviewer.token,
      headers: { 'x-share-grant': open.body.grant },
    });
    expect(thread.body.comments[0]).toMatchObject({ author: 'reviewer@example.test', page: 3 });
    expect(thread.body.reviews).toEqual([expect.objectContaining({ decision: 'approved' })]);
    // The author's own approval would not count; the reviewer's does.
    expect(
      (
        await env.call('POST', `${P}/documents/${doc.body.id}/publish`, {
          token: author.token,
          body: { version_id: v1.body.id },
        })
      ).status,
    ).toBe(200);
    const owner = await env.call(
      'GET',
      `${P}/documents/${doc.body.id}/versions/${v1.body.id}/review`,
      { token: author.token },
    );
    expect(owner.body.comments).toHaveLength(1);
  });

  it('shows branding on download pages only while the plan includes it', async () => {
    env = await sharingEnv();
    const s = await sharedTransfer(env, 'brand@example.test');
    expect(
      (
        await env.call('PUT', `${s.P}/branding`, {
          token: s.owner.token,
          body: { display_name: 'Kamara & Co', accent_color: '#0A7A55' },
        })
      ).status,
    ).toBe(403);
    await grantPlan(env, s.owner.orgId, BUSINESS);
    expect(
      (
        await env.call('PUT', `${s.P}/branding`, {
          token: s.owner.token,
          body: { display_name: 'Kamara & Co', accent_color: '#0A7A55' },
        })
      ).status,
    ).toBe(200);
    const open = await env.call('POST', `/v1/public/shares/${s.token}/open`, {
      body: {},
      headers: { 'user-agent': UA },
    });
    expect(open.body.branding).toEqual({ display_name: 'Kamara & Co', accent_color: '#0a7a55' });
  });

  it('verifies custom-domain ownership by DNS TXT and serves its own short-link namespace', async () => {
    let txt: string[][] = [];
    env = await sharingEnv();
    await env.app.close();
    const { makeEnv } = await import('./harness.ts');
    const { MemoryMailDelivery } = await import('../src/integrations/mail.ts');
    const mail = new MemoryMailDelivery();
    env = Object.assign(
      await makeEnv({ identityDelivery: mail, container: { sharingResolveTxt: async () => txt } }),
      { mail },
    );
    const owner = await env.register('dom@example.test');
    await grantPlan(env, owner.orgId, BUSINESS);
    const P = sp(owner.orgId);
    const dom = await env.call('POST', `${P}/domains`, {
      token: owner.token,
      body: { hostname: 'Go.Kamara.example' },
    });
    expect(dom.body).toMatchObject({ hostname: 'go.kamara.example', status: 'pending' });
    expect(
      (
        await env.call('POST', `${P}/short-links`, {
          token: owner.token,
          body: {
            kind: 'public',
            destination_type: 'external',
            destination_url: 'https://kamara.example/',
            alias: 'offer',
            domain_id: dom.body.id,
          },
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await env.call('POST', `${P}/domains/${dom.body.id}/verify`, {
          token: owner.token,
          body: {},
        })
      ).body.verified,
    ).toBe(false);
    txt = [[dom.body.verification.value]];
    expect(
      (
        await env.call('POST', `${P}/domains/${dom.body.id}/verify`, {
          token: owner.token,
          body: {},
        })
      ).body.verified,
    ).toBe(true);
    const sl = await env.call('POST', `${P}/short-links`, {
      token: owner.token,
      body: {
        kind: 'public',
        destination_type: 'external',
        destination_url: 'https://kamara.example/',
        alias: 'offer',
        domain_id: dom.body.id,
      },
    });
    expect(sl.body.url).toBe('https://go.kamara.example/l/offer');
    expect(
      (await env.app.inject({ url: '/l/offer', headers: { host: 'go.kamara.example' } }))
        .statusCode,
    ).toBe(302);
    expect((await env.app.inject({ url: '/l/offer' })).statusCode).toBe(404);
    const other = await env.register('dom2@example.test');
    await grantPlan(env, other.orgId, BUSINESS, 'business2');
    expect(
      (
        await env.call('POST', `${sp(other.orgId)}/domains`, {
          token: other.token,
          body: { hostname: 'go.kamara.example' },
        })
      ).status,
    ).toBe(409);
    expect(
      (
        await env.call('POST', `${P}/domains/${dom.body.id}/remove`, {
          token: owner.token,
          body: {},
        })
      ).status,
    ).toBe(409);
  });
});
