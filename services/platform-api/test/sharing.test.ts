import jsQRModule from 'jsqr';
import { afterEach, describe, expect, it } from 'vitest';
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

const jsQR = ((jsQRModule as unknown as { default?: unknown }).default ??
  jsQRModule) as unknown as (d: Uint8ClampedArray, w: number, h: number) => { data: string } | null;

let env: SharingEnv;
afterEach(async () => env?.app.close());

/** Rasterizes the downloaded SVG (our own path format) and decodes it independently. */
function decodeSvg(svg: string): string | undefined {
  const dim = Number(/width="(\d+)"/.exec(svg)![1]);
  const px = new Uint8ClampedArray(dim * dim * 4).fill(255);
  for (const m of svg.matchAll(/M(\d+) (\d+)h(\d+)/g)) {
    const [x, y, s] = [Number(m[1]), Number(m[2]), Number(m[3])];
    for (let dy = 0; dy < s; dy++)
      for (let dx = 0; dx < s; dx++) {
        const o = ((y + dy) * dim + x + dx) * 4;
        px[o] = px[o + 1] = px[o + 2] = 0;
      }
  }
  return jsQR(px, dim, dim)?.data;
}

describe('acceptance: file sharing and short links', () => {
  it('1 & 5: edit a PDF, export, share; publish a replacement without exposing unfinished edits', async () => {
    env = await sharingEnv();
    const owner = await env.register('owner@example.test');
    const P = sp(owner.orgId);
    const t = owner.token;
    const doc = await env.call('POST', `${P}/documents`, {
      token: t,
      body: { title: 'Supply contract' },
    });
    expect(doc.status).toBe(201);
    const docId = doc.body.id as string;

    // The editor saves a private draft, then the user exports an immutable version.
    await upload(
      env,
      t,
      owner.orgId,
      { target: 'draft', document_id: docId, name: 'contract.pdf' },
      pdf('draft one'),
    );
    const v1 = await env.call('POST', `${P}/documents/${docId}/export`, {
      token: t,
      body: { note: 'first issue' },
    });
    expect(v1.status).toBe(201);
    expect(v1.body).toMatchObject({ number: 1, published_at: null });

    const latest = await env.call('POST', `${P}/links`, {
      token: t,
      body: {
        target_type: 'document',
        target_id: docId,
        version_mode: 'latest',
        permission: 'download',
      },
    });
    expect(latest.status).toBe(201);
    const latestToken = tokenOf(latest.body.url);
    // An exported but unpublished version is not served by a `latest` link.
    const early = await env.call('POST', `/v1/public/shares/${latestToken}/open`, { body: {} });
    expect(early.status).toBe(410);
    expect(early.body.details).toEqual({ state: 'not_published' });

    expect(
      (
        await env.call('POST', `${P}/documents/${docId}/publish`, {
          token: t,
          body: { version_id: v1.body.id },
        })
      ).status,
    ).toBe(200);
    const fixed = await env.call('POST', `${P}/links`, {
      token: t,
      body: {
        target_type: 'document',
        target_id: docId,
        version_mode: 'fixed',
        version_id: v1.body.id,
        permission: 'download',
      },
    });
    const fixedToken = tokenOf(fixed.body.url);

    const open = await env.call('POST', `/v1/public/shares/${latestToken}/open`, {
      body: {},
      headers: { 'user-agent': UA },
    });
    expect(open.status).toBe(200);
    expect(open.body.version).toMatchObject({ mode: 'latest', number: 1 });
    expect(open.body.version.label).toContain('Latest published version');
    expect(open.body.notices.join(' ')).toContain('cannot prevent screenshots');
    const fileId = open.body.files[0].id;
    const dl = await env.call('POST', `/v1/public/shares/${latestToken}/files/url`, {
      body: { grant: open.body.grant, file_id: fileId, disposition: 'attachment' },
    });
    expect(dl.status).toBe(200);
    expect(new URL(dl.body.url).origin).toBe(env.c.sharingLocalStore!.contentOrigin);
    const bytes = await fetchSigned(env, dl.body.url);
    expect(bytes.status).toBe(200);
    expect(bytes.body.toString('latin1')).toContain('draft one');
    expect(bytes.headers['content-disposition']).toMatch(
      /^attachment; filename="Supply contract v1.pdf"/,
    );
    expect(bytes.headers['x-content-type-options']).toBe('nosniff');
    expect(bytes.headers['content-security-policy']).toContain("default-src 'none'");

    // Unfinished edits: a new draft and even a new export stay private until explicitly published.
    await upload(
      env,
      t,
      owner.orgId,
      { target: 'draft', document_id: docId, name: 'contract.pdf' },
      pdf('draft two (corrected)'),
    );
    const again = await env.call('POST', `/v1/public/shares/${latestToken}/open`, { body: {} });
    expect(again.body.version.number).toBe(1);
    const v2 = await env.call('POST', `${P}/documents/${docId}/export`, { token: t, body: {} });
    expect(v2.body.number).toBe(2);
    const still = await env.call('POST', `/v1/public/shares/${latestToken}/open`, { body: {} });
    expect(still.body.version.number).toBe(1);
    const stillBytes = await env.call('POST', `/v1/public/shares/${latestToken}/files/url`, {
      body: { grant: still.body.grant, file_id: still.body.files[0].id, disposition: 'attachment' },
    });
    expect((await fetchSigned(env, stillBytes.body.url)).body.toString('latin1')).toContain(
      'draft one',
    );

    // Safe replacement: publish v2 with an explanation; the latest link follows, the fixed link does not.
    const pub = await env.call('POST', `${P}/documents/${docId}/publish`, {
      token: t,
      body: { version_id: v2.body.id, replacement_note: 'Corrected the delivery date on page 2.' },
    });
    expect(pub.body).toMatchObject({
      number: 2,
      replacement_note: 'Corrected the delivery date on page 2.',
    });
    const now = await env.call('POST', `/v1/public/shares/${latestToken}/open`, { body: {} });
    expect(now.body.version).toMatchObject({
      number: 2,
      replacement_note: 'Corrected the delivery date on page 2.',
    });
    expect(now.body.history.map((h: { number: number }) => h.number)).toEqual([2, 1]);
    const pinned = await env.call('POST', `/v1/public/shares/${fixedToken}/open`, { body: {} });
    expect(pinned.body.version).toMatchObject({ mode: 'fixed', number: 1 });
    expect(pinned.body.version.label).toContain('Fixed version 1');
    // A grant opened before the replacement cannot fetch the superseded file through the latest link.
    const stale = await env.call('POST', `/v1/public/shares/${latestToken}/files/url`, {
      body: { grant: open.body.grant, file_id: fileId, disposition: 'attachment' },
    });
    expect(stale.status).toBe(409);
    const detail = await env.call('GET', `${P}/documents/${docId}`, { token: t });
    expect(
      detail.body.versions.map((v: { number: number; published: boolean }) => [
        v.number,
        v.published,
      ]),
    ).toEqual([
      [2, true],
      [1, false],
    ]);
  });

  it('2: creates a short link and a matching downloadable QR code', async () => {
    env = await sharingEnv();
    const owner = await env.register('marketer@example.test');
    const P = sp(owner.orgId);
    const created = await env.call('POST', `${P}/short-links`, {
      token: owner.token,
      body: {
        kind: 'public',
        destination_type: 'external',
        destination_url: 'https://shop.example.com/spring?ref=flyer',
        alias: 'Spring-Sale',
        folder: 'Campaigns',
        tags: ['print'],
      },
    });
    expect(created.status).toBe(201);
    expect(created.body.url).toBe(`${env.c.config.sharing!.shortOrigin}/l/spring-sale`);
    const go = await env.app.inject({
      url: '/l/spring-sale',
      headers: { 'user-agent': UA, referer: 'https://news.example/item?id=7' },
    });
    expect(go.statusCode).toBe(302);
    expect(go.headers.location).toBe('https://shop.example.com/spring?ref=flyer');
    expect(go.headers['referrer-policy']).toBe('no-referrer');
    await env.app.inject({
      url: '/l/spring-sale',
      headers: { 'user-agent': 'Slackbot-LinkExpanding 1.0' },
    });
    const qr = await env.app.inject({
      url: `${P}/short-links/${created.body.id}/qr.svg`,
      headers: { authorization: `Bearer ${owner.token}` },
    });
    expect(qr.statusCode).toBe(200);
    expect(qr.headers['content-type']).toContain('image/svg+xml');
    expect(qr.headers['content-disposition']).toContain('attachment');
    expect(decodeSvg(qr.body)).toBe(created.body.url);
    const stats = await env.call('GET', `${P}/short-links/${created.body.id}/stats`, {
      token: owner.token,
    });
    expect(stats.body.totals.visit).toEqual({ count: 1, bots: 1 });
    // Referral hosts are an advanced-analytics (paid) feature.
    expect(stats.body.referrers).toBeNull();
    await grantPlan(env, owner.orgId, BUSINESS);
    const paid = await env.call('GET', `${P}/short-links/${created.body.id}/stats`, {
      token: owner.token,
    });
    expect(paid.body.referrers).toEqual([{ host: 'news.example', count: 1 }]);
    expect(JSON.stringify(stats.body)).not.toContain('id=7');
  });

  it('3 & 4: password and expiry; revocation stops the very next request', async () => {
    env = await sharingEnv();
    const owner = await env.register('sender@example.test');
    const P = sp(owner.orgId);
    const tr = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: { title: 'Board pack', kind: 'temporary' },
    });
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: tr.body.id, name: 'pack.pdf' },
      pdf('pack'),
    );
    const expires = new Date(env.clock.now().getTime() + 2 * DAY).toISOString();
    const link = await env.call('POST', `${P}/links`, {
      token: owner.token,
      body: {
        target_type: 'transfer',
        target_id: tr.body.id,
        permission: 'download',
        password: 'river-stone-42',
        expires_at: expires,
      },
    });
    expect(link.body).toMatchObject({ has_password: true, expires_at: expires, state: 'active' });
    expect(JSON.stringify(link.body)).not.toContain('scrypt');
    const tk = tokenOf(link.body.url);
    const open = (password?: string) =>
      env.call('POST', `/v1/public/shares/${tk}/open`, { body: password ? { password } : {} });
    expect((await open()).status).toBe(401);
    expect((await open('wrong-password')).body.message).toBe('incorrect password');
    const ok = await open('river-stone-42');
    expect(ok.status).toBe(200);
    const file = ok.body.files[0];
    const url = (grant: string) =>
      env.call('POST', `/v1/public/shares/${tk}/files/url`, {
        body: { grant, file_id: file.id, disposition: 'attachment' },
      });
    const signed = await url(ok.body.grant);
    expect(signed.status).toBe(200);
    expect(
      new Date(signed.body.expires_at).getTime() - env.clock.now().getTime(),
    ).toBeLessThanOrEqual(60_000);

    // Revocation applies to the next request even with a still-valid grant.
    expect(
      (
        await env.call('POST', `${P}/links/${link.body.id}/status`, {
          token: owner.token,
          body: { action: 'revoke', reason: 'sent to the wrong board' },
        })
      ).status,
    ).toBe(200);
    const after = await url(ok.body.grant);
    expect(after.status).toBe(410);
    expect(after.body.details).toEqual({ state: 'revoked' });
    expect((await open('river-stone-42')).status).toBe(410);
    const resume = await env.call('POST', `${P}/links/${link.body.id}/status`, {
      token: owner.token,
      body: { action: 'resume' },
    });
    expect(resume.status).toBe(409);

    // A grant does not outlive the link's expiry or the transfer's revocation.
    const third = await env.call('POST', `${P}/links`, {
      token: owner.token,
      body: {
        target_type: 'transfer',
        target_id: tr.body.id,
        permission: 'download',
        expires_at: new Date(env.clock.now().getTime() + 60_000).toISOString(),
      },
    });
    const g3 = await env.call('POST', `/v1/public/shares/${tokenOf(third.body.url)}/open`, {
      body: {},
    });
    env.clock.advance(61_000);
    const late = await env.call('POST', `/v1/public/shares/${tokenOf(third.body.url)}/files/url`, {
      body: { grant: g3.body.grant, file_id: file.id, disposition: 'attachment' },
    });
    expect(late.status).toBe(410);
    expect(late.body.details).toEqual({ state: 'expired' });

    // Expiry.
    const second = await env.call('POST', `${P}/links`, {
      token: owner.token,
      body: {
        target_type: 'transfer',
        target_id: tr.body.id,
        permission: 'view',
        expires_at: expires,
      },
    });
    env.clock.advance(2 * DAY + 1);
    const expired = await env.call('POST', `/v1/public/shares/${tokenOf(second.body.url)}/open`, {
      body: {},
    });
    expect(expired.status).toBe(410);
    expect(expired.body.details).toEqual({ state: 'expired' });
  });

  it('6: receives files through an upload request without exposing other submissions', async () => {
    env = await sharingEnv();
    const owner = await env.register('hr@example.test');
    const P = sp(owner.orgId);
    const body = {
      title: 'Onboarding documents',
      instructions: 'Upload a scan of your ID and the signed contract.',
      requirements: [
        { key: 'id', label: 'Identity document', accept: ['pdf', 'png', 'jpg'], required: true },
        { key: 'contract', label: 'Signed contract', accept: ['pdf'], required: true },
      ],
      deadline: new Date(env.clock.now().getTime() + 7 * DAY).toISOString(),
      max_file_bytes: 1_000_000,
      max_total_bytes: 5_000_000,
      notify: true,
    };
    // Upload requests are a paid feature (phase 2).
    expect(
      (await env.call('POST', `${P}/upload-requests`, { token: owner.token, body })).status,
    ).toBe(403);
    await grantPlan(env, owner.orgId, BUSINESS);
    const req = await env.call('POST', `${P}/upload-requests`, { token: owner.token, body });
    expect(req.status).toBe(201);
    const rt = tokenOf(req.body.url);
    const R = `/v1/public/upload-requests/${rt}`;

    const opened = await env.call('POST', `${R}/open`, { body: {} });
    expect(opened.status).toBe(200);
    expect(opened.body.requirements).toHaveLength(2);
    const start = async (name: string) =>
      (await env.call('POST', `${R}/submissions`, { body: { grant: opened.body.grant, name } }))
        .body.submission_secret as string;
    const alice = await start('Alice');
    const bob = await start('Bob');
    const sendFile = async (secret: string, requirement: string, name: string, bytes: Buffer) => {
      const h = { 'x-submission-secret': secret };
      const begin = await env.call('POST', `${R}/uploads`, {
        headers: h,
        body: { requirement_key: requirement, name, size: bytes.length },
      });
      expect(begin.status).toBe(201);
      const nums = Array.from({ length: begin.body.part_count }, (_, i) => i + 1);
      const parts = await env.call('POST', `${R}/uploads/${begin.body.upload_id}/parts`, {
        headers: h,
        body: { part_numbers: nums },
      });
      for (const p of parts.body.parts) {
        const chunk = bytes.subarray(
          (p.part_number - 1) * begin.body.part_size,
          p.part_number * begin.body.part_size,
        );
        expect((await env.content('PUT', p.url, chunk)).status).toBe(200);
      }
      expect(
        (
          await env.call('POST', `${R}/uploads/${begin.body.upload_id}/complete`, {
            headers: h,
            body: {},
          })
        ).status,
      ).toBe(200);
      return begin.body.upload_id as string;
    };
    const aliceUpload = await sendFile(alice, 'id', 'alice-id.pdf', pdf('alice id'));
    // The wrong type for a requirement is refused before any byte is accepted.
    expect(
      (
        await env.call('POST', `${R}/uploads`, {
          headers: { 'x-submission-secret': alice },
          body: { requirement_key: 'contract', name: 'c.png', size: 10 },
        })
      ).status,
    ).toBe(400);
    // Bob cannot see or touch Alice's upload.
    const bobView = await env.call('GET', `${R}/submission`, {
      headers: { 'x-submission-secret': bob },
    });
    expect(bobView.body.files).toEqual([]);
    expect(
      (
        await env.call('GET', `${R}/uploads/${aliceUpload}`, {
          headers: { 'x-submission-secret': bob },
        })
      ).status,
    ).toBe(404);
    expect(
      (
        await env.call('POST', `${R}/uploads/${aliceUpload}/abort`, {
          headers: { 'x-submission-secret': bob },
          body: {},
        })
      ).status,
    ).toBe(404);
    // Required files are enforced.
    const early = await env.call('POST', `${R}/submission/submit`, {
      headers: { 'x-submission-secret': alice },
      body: {},
    });
    expect(early.status).toBe(409);
    expect(early.body.details).toEqual({ missing: ['contract'] });
    await sendFile(alice, 'contract', 'alice-contract.pdf', pdf('alice contract'));
    expect(
      (
        await env.call('POST', `${R}/submission/submit`, {
          headers: { 'x-submission-secret': alice },
          body: {},
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await env.call('POST', `${R}/uploads`, {
          headers: { 'x-submission-secret': alice },
          body: { requirement_key: 'id', name: 'late.pdf', size: 10 },
        })
      ).status,
    ).toBe(409);
    await env.c.sharing!.processJobs({ limit: 100 });

    const detail = await env.call('GET', `${P}/upload-requests/${req.body.id}`, {
      token: owner.token,
    });
    const sub = detail.body.submissions.find(
      (s: { submitter_name: string }) => s.submitter_name === 'Alice',
    );
    expect(sub).toMatchObject({ status: 'submitted', identity_verified: false });
    expect(
      sub.files.map((f: { name: string; status: string }) => [f.name, f.status]).sort(),
    ).toEqual([
      ['alice-contract.pdf', 'available'],
      ['alice-id.pdf', 'available'],
    ]);
    const dl = await env.call('POST', `${P}/files/download`, {
      token: owner.token,
      body: { type: 'submission_file', id: sub.files[0].id },
    });
    expect(dl.status).toBe(200);
    expect((await fetchSigned(env, dl.body.url)).body.toString('latin1')).toContain('alice');
    const notes = await env.call('GET', `${P}/notifications`, { token: owner.token });
    expect(notes.body.items.some((n: { kind: string }) => n.kind === 'request.submitted')).toBe(
      true,
    );
    // Opt-in email notification is queued for the worker, not sent inline.
    const mailJobs = await env.c.sharing!.processJobs({ limit: 100 });
    expect(mailJobs.failed).toBe(0);
    expect(
      env.mail.messages.some((m) => m.to === 'hr@example.test' && m.text.includes('Alice')),
    ).toBe(true);
  });

  it('7: records visit, authenticated access, download and acknowledgement as distinct events', async () => {
    env = await sharingEnv();
    const owner = await env.register('legal@example.test');
    const recipient = await env.register('client@example.test');
    await verifyEmail(env, recipient.token);
    const P = sp(owner.orgId);
    const tr = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: { title: 'Notice', kind: 'temporary' },
    });
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: tr.body.id, name: 'notice.pdf' },
      pdf('notice'),
    );
    const open = await env.call('POST', `${P}/links`, {
      token: owner.token,
      body: {
        target_type: 'transfer',
        target_id: tr.body.id,
        permission: 'download',
        label: 'Public copy',
      },
    });
    const restricted = await env.call('POST', `${P}/links`, {
      token: owner.token,
      body: {
        target_type: 'transfer',
        target_id: tr.body.id,
        permission: 'download',
        restriction: 'recipients',
        recipients: ['Client@Example.test'],
        notify_on_access: true,
      },
    });
    const ot = tokenOf(open.body.url);
    const rt = tokenOf(restricted.body.url);
    await env.call('POST', `/v1/public/shares/${ot}/open`, {
      body: {},
      headers: { 'user-agent': UA },
    });
    await env.call('POST', `/v1/public/shares/${ot}/open`, {
      body: {},
      headers: { 'user-agent': 'Microsoft Office/16.0 (Windows NT 10.0)' },
    });

    const r = await env.call('POST', `/v1/public/shares/${rt}/open`, {
      token: recipient.token,
      body: {},
      headers: { 'user-agent': UA },
    });
    expect(r.status).toBe(200);
    const dl = await env.call('POST', `/v1/public/shares/${rt}/files/url`, {
      token: recipient.token,
      body: { grant: r.body.grant, file_id: r.body.files[0].id, disposition: 'attachment' },
      headers: { 'user-agent': UA },
    });
    expect(dl.status).toBe(200);
    const ack = await env.call('POST', `/v1/public/shares/${rt}/acknowledge`, {
      token: recipient.token,
      body: { grant: r.body.grant },
      headers: { 'user-agent': UA },
    });
    expect(ack.body).toMatchObject({ verified_identity: true });

    const act = await env.call('GET', `${P}/links/${restricted.body.id}/activity`, {
      token: owner.token,
    });
    expect(act.body.events.map((e: { kind: string }) => e.kind).sort()).toEqual([
      'access',
      'acknowledge',
      'download',
    ]);
    expect(
      act.body.events.every(
        (e: { identity: { email: string } }) => e.identity.email === 'client@example.test',
      ),
    ).toBe(true);
    expect(act.body.totals).toEqual({
      access: { count: 1, bots: 0 },
      download: { count: 1, bots: 0 },
      acknowledge: { count: 1, bots: 0 },
    });
    expect(act.body.notes[0]).toContain('not proof that anyone read');
    const pub = await env.call('GET', `${P}/links/${open.body.id}/activity`, {
      token: owner.token,
    });
    expect(pub.body.totals).toEqual({ visit: { count: 1, bots: 1 } });
    expect(JSON.stringify(pub.body)).not.toContain('notice.pdf');
    const notes = await env.call('GET', `${P}/notifications`, { token: owner.token });
    expect(notes.body.items.map((n: { kind: string }) => n.kind).sort()).toEqual([
      'file.available',
      'share.accessed',
      'share.acknowledged',
      'share.downloaded',
    ]);
  });

  it('8: recovers from an interrupted upload by resuming the missing parts', async () => {
    env = await sharingEnv();
    const owner = await env.register('uploader@example.test');
    const P = sp(owner.orgId);
    const tr = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: { title: 'Scans', kind: 'temporary' },
    });
    const bytes = pdf('a file long enough for several parts of eight bytes');
    const first = await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: tr.body.id, name: 'scan.pdf', folder_path: 'Scans/2026' },
      bytes,
      { skipParts: [2, 3, 4] },
    );
    const id = first.id!;
    const partCount = first.begin.body.part_count as number;
    expect(partCount).toBeGreaterThan(4);
    // The connection dropped. Completion is refused and names exactly what is missing.
    const incomplete = await env.call('POST', `${P}/uploads/${id}/complete`, {
      token: owner.token,
      body: {},
    });
    expect(incomplete.status).toBe(409);
    // On reload, the client asks storage what it already holds and resumes from there.
    const status = await env.call('GET', `${P}/uploads/${id}`, { token: owner.token });
    expect(status.body.status).toBe('uploading');
    expect(status.body.uploaded_parts).toEqual([
      1,
      ...Array.from({ length: partCount - 4 }, (_, i) => i + 5),
    ]);
    const missing = Array.from({ length: partCount }, (_, i) => i + 1).filter(
      (n) => !status.body.uploaded_parts.includes(n),
    );
    expect(missing).toEqual([2, 3, 4]);
    expect(incomplete.body.details.missing_parts).toEqual(missing);
    const signed = await env.call('POST', `${P}/uploads/${id}/parts`, {
      token: owner.token,
      body: { part_numbers: missing },
    });
    for (const p of signed.body.parts) {
      const chunk = bytes.subarray(
        (p.part_number - 1) * first.begin.body.part_size,
        p.part_number * first.begin.body.part_size,
      );
      expect((await env.content('PUT', p.url, chunk)).status).toBe(200);
    }
    const done = await env.call('POST', `${P}/uploads/${id}/complete`, {
      token: owner.token,
      body: {},
    });
    expect(done.body.status).toBe('processing');
    // Visible processing status, then availability after checks.
    let detail = await env.call('GET', `${P}/transfers/${tr.body.id}`, { token: owner.token });
    expect(detail.body.files[0]).toMatchObject({
      name: 'scan.pdf',
      folder_path: 'Scans/2026',
      status: 'processing',
    });
    await env.c.sharing!.processJobs({ limit: 100 });
    detail = await env.call('GET', `${P}/transfers/${tr.body.id}`, { token: owner.token });
    expect(detail.body.files[0].status).toBe('available');
    const dl = await env.call('POST', `${P}/files/download`, {
      token: owner.token,
      body: { type: 'transfer_file', id: detail.body.files[0].id },
    });
    expect((await fetchSigned(env, dl.body.url)).body.equals(bytes)).toBe(true);
  });

  it('9: removes expired temporary files according to the retention policy, keeping referenced objects', async () => {
    env = await sharingEnv();
    const owner = await env.register('temp@example.test');
    await grantPlan(env, owner.orgId, BUSINESS);
    const P = sp(owner.orgId);
    const temp = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: {
        title: 'Temporary',
        kind: 'temporary',
        expires_at: new Date(env.clock.now().getTime() + DAY).toISOString(),
      },
    });
    expect(temp.body.files_deleted_at).toBe(temp.body.expires_at);
    const keep = await env.call('POST', `${P}/transfers`, {
      token: owner.token,
      body: { title: 'Kept', kind: 'persistent' },
    });
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: temp.body.id, name: 't.pdf' },
      pdf('temporary'),
    );
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'transfer', transfer_id: keep.body.id, name: 'k.pdf' },
      pdf('kept'),
    );
    const link = await env.call('POST', `${P}/links`, {
      token: owner.token,
      body: { target_type: 'transfer', target_id: temp.body.id, permission: 'download' },
    });
    const tempFile = (
      await env.call('GET', `${P}/transfers/${temp.body.id}`, { token: owner.token })
    ).body.files[0];
    const before = (await env.call('GET', `${P}/overview`, { token: owner.token })).body.usage
      .storage_bytes;

    // A document whose draft is replaced keeps the old object while an exported version still references it.
    const doc = await env.call('POST', `${P}/documents`, {
      token: owner.token,
      body: { title: 'Report' },
    });
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'draft', document_id: doc.body.id, name: 'r.pdf' },
      pdf('report v1'),
    );
    const v1 = await env.call('POST', `${P}/documents/${doc.body.id}/export`, {
      token: owner.token,
      body: {},
    });
    await upload(
      env,
      owner.token,
      owner.orgId,
      { target: 'draft', document_id: doc.body.id, name: 'r.pdf' },
      pdf('report v2'),
    );
    await env.c.sharing!.processJobs({ limit: 100 });
    const v1url = await env.call('POST', `${P}/files/download`, {
      token: owner.token,
      body: { type: 'version', id: v1.body.id },
    });
    expect((await fetchSigned(env, v1url.body.url)).body.toString('latin1')).toContain('report v1');

    env.clock.advance(DAY + 1);
    owner.token = await env.login('temp@example.test');
    expect(
      (await env.call('POST', `/v1/public/shares/${tokenOf(link.body.url)}/open`, { body: {} }))
        .status,
    ).toBe(410);
    const r = await env.c.sharing!.runRetention();
    expect(r).toMatchObject({ transfersExpired: 1, transfersPurged: 1 });
    await env.c.sharing!.processJobs({ limit: 100 });
    // The object is gone from storage; the persistent transfer is untouched; storage usage dropped.
    const gone = await env.call('POST', `${P}/files/download`, {
      token: owner.token,
      body: { type: 'transfer_file', id: tempFile.id },
    });
    expect(gone.status).toBe(404);
    expect(
      (await env.call('GET', `${P}/transfers/${keep.body.id}`, { token: owner.token })).body
        .files[0].status,
    ).toBe('available');
    expect(
      (await env.call('GET', `${P}/overview`, { token: owner.token })).body.usage.storage_bytes,
    ).toBeLessThan(before + 100);
    expect(
      (await env.call('GET', `${P}/transfers/${temp.body.id}`, { token: owner.token })).status,
    ).toBe(404);
    const audit = await env.c.audit.list({ orgId: owner.orgId, limit: 200 });
    expect(audit.map((e) => e.action)).toContain('share.transfer.purged');
    // Retention is idempotent.
    expect(await env.c.sharing!.runRetention()).toMatchObject({ transfersPurged: 0 });
    // Signed URLs are short-lived; a fresh one still reaches the version-referenced object.
    expect((await fetchSigned(env, v1url.body.url)).status).toBe(403);
    const fresh = await env.call('POST', `${P}/files/download`, {
      token: owner.token,
      body: { type: 'version', id: v1.body.id },
    });
    expect((await fetchSigned(env, fresh.body.url)).body.toString('latin1')).toContain('report v1');
  });
});
