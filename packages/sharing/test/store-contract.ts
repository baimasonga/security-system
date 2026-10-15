import { describe, expect, it } from 'vitest';
import type { SharingStore } from '../src/index.ts';
import * as f from './fixtures.ts';

export interface SharingHarness {
  store: SharingStore;
  /** Creates an organization with one user (foreign keys on PostgreSQL); returns their ids. */
  seed(): Promise<{ orgId: string; userId: string }>;
  /** Actions of durably committed audit events, oldest first. */
  audited(): Promise<string[]>;
}

const { T0 } = f;
const at = (ms: number) => new Date(T0.getTime() + ms);

/** One definition of correct SharingStore behaviour, run against every adapter. */
export function sharingStoreContract(
  name: string,
  make: () => SharingHarness | Promise<SharingHarness>,
) {
  describe(`SharingStore contract: ${name}`, () => {
    it('round-trips rows exactly, including dates, numbers, booleans and JSON', async () => {
      const h = await make();
      const { orgId, userId } = await h.seed();
      const b = f.blob(orgId, { declaredSize: 5_000_000_000, createdBy: userId });
      await h.store.insert('blob', b);
      expect(await h.store.get('blob', orgId, b.id)).toEqual(b);
      const tr = f.transfer(orgId, userId);
      await h.store.insert('transfer', tr);
      const l = f.link(orgId, userId, tr.id, {
        recipients: ['a@x.test', 'b@x.test'],
        maxDownloads: 3,
        notifyOnAccess: true,
      });
      await h.store.insert('link', l);
      expect(await h.store.get('link', orgId, l.id)).toEqual(l);
      const r = f.uploadRequest(orgId, userId);
      await h.store.insert('uploadRequest', r);
      expect(await h.store.get('uploadRequest', orgId, r.id)).toEqual(r);
      const s = f.shortLink(orgId, userId, { tags: ['spring', 'flyer'], folder: 'Campaigns' });
      await h.store.insert('shortLink', s);
      expect(await h.store.get('shortLink', orgId, s.id)).toEqual(s);
      const j = f.job(orgId, { payload: { userId, subject: 'Hello' } });
      await h.store.insert('job', j);
      expect(await h.store.get('job', orgId, j.id)).toEqual(j);
    });

    it('never returns, lists or updates another tenant’s rows', async () => {
      const h = await make();
      const a = await h.seed();
      const b = await h.seed();
      const tr = f.transfer(a.orgId, a.userId);
      await h.store.insert('transfer', tr);
      expect(await h.store.get('transfer', b.orgId, tr.id)).toBeUndefined();
      expect(await h.store.getForUpdate('transfer', b.orgId, tr.id)).toBeUndefined();
      expect(await h.store.list('transfer', b.orgId)).toEqual([]);
      await h.store.update('transfer', b.orgId, tr.id, { title: 'hijacked' });
      expect((await h.store.get('transfer', a.orgId, tr.id))?.title).toBe('Files');
      const j = f.job(a.orgId);
      await h.store.insert('job', j);
      await h.store.remove('job', b.orgId, j.id);
      expect(await h.store.get('job', a.orgId, j.id)).toBeDefined();
    });

    it('filters lists by equality, orders by creation and bounds the result', async () => {
      const h = await make();
      const { orgId, userId } = await h.seed();
      const tr = f.transfer(orgId, userId);
      await h.store.insert('transfer', tr);
      for (let i = 0; i < 5; i++) {
        const b = f.blob(orgId, { createdAt: at(i * 1000) });
        await h.store.insert('blob', b);
        await h.store.insert(
          'transferFile',
          f.transferFile(orgId, tr.id, b.id, {
            createdAt: at(i * 1000),
            status: i === 4 ? 'removed' : 'current',
          }),
        );
      }
      const current = await h.store.list(
        'transferFile',
        orgId,
        { transferId: tr.id, status: 'current' },
        { order: 'oldest' },
      );
      expect(current.map((x) => x.createdAt.getTime())).toEqual(
        [0, 1000, 2000, 3000].map((ms) => T0.getTime() + ms),
      );
      const newest = await h.store.list('transferFile', orgId, { transferId: tr.id }, { limit: 2 });
      expect(newest.map((x) => x.status)).toEqual(['removed', 'current']);
    });

    it('enforces global unique lookups and composite uniqueness as duplicate:<kind>', async () => {
      const h = await make();
      const { orgId, userId } = await h.seed();
      const other = await h.seed();
      const s = f.shortLink(orgId, userId, { code: 'spring-sale', lookupKey: 'p||spring-sale' });
      await h.store.insert('shortLink', s);
      await expect(
        h.store.insert(
          'shortLink',
          f.shortLink(other.orgId, other.userId, {
            code: 'spring-sale',
            lookupKey: 'p||spring-sale',
          }),
        ),
      ).rejects.toThrow('duplicate:shortLink');
      expect((await h.store.findUnique('shortLink', 'lookupKey', 'p||spring-sale'))?.id).toBe(s.id);
      expect(await h.store.findUnique('shortLink', 'lookupKey', 'p||nope')).toBeUndefined();
      const d = f.document(orgId, userId);
      await h.store.insert('document', d);
      const b = f.blob(orgId, { status: 'clean' });
      await h.store.insert('blob', b);
      await h.store.insert('version', f.version(orgId, d.id, b.id, userId, { number: 1 }));
      await expect(
        h.store.insert('version', f.version(orgId, d.id, b.id, userId, { number: 1 })),
      ).rejects.toThrow('duplicate:version');
      await h.store.insert('domain', {
        id: 'dom_a1',
        orgId,
        hostname: 'go.example.com',
        verificationToken: f.hex(32),
        status: 'pending',
        createdAt: T0,
        verifiedAt: null,
        checkedAt: null,
      });
      await expect(
        h.store.insert('domain', {
          id: 'dom_b1',
          orgId: other.orgId,
          hostname: 'go.example.com',
          verificationToken: f.hex(32),
          status: 'pending',
          createdAt: T0,
          verifiedAt: null,
          checkedAt: null,
        }),
      ).rejects.toThrow('duplicate:domain');
    });

    it('counts storage for every blob that is not deleted (declared size until completion)', async () => {
      const h = await make();
      const { orgId } = await h.seed();
      await h.store.insert('blob', f.blob(orgId, { declaredSize: 100 }));
      await h.store.insert(
        'blob',
        f.blob(orgId, { declaredSize: 999, size: 250, status: 'clean' }),
      );
      await h.store.insert(
        'blob',
        f.blob(orgId, { declaredSize: 400, size: 400, status: 'deleted' }),
      );
      expect(await h.store.storageBytes(orgId)).toBe(350);
    });

    it('adds usage atomically under concurrency and reads it per period', async () => {
      const h = await make();
      const { orgId } = await h.seed();
      const results = await Promise.all(
        Array.from({ length: 20 }, () =>
          h.store.transaction((tx) => tx.addUsage(orgId, '2026-03', 'bandwidth_bytes', 10)),
        ),
      );
      expect(Math.max(...results)).toBe(200);
      expect(new Set(results).size).toBe(20);
      await h.store.addUsage(orgId, '2026-04', 'bandwidth_bytes', 1);
      expect(await h.store.usage(orgId, '2026-03')).toEqual({
        bandwidth_bytes: 200,
        api_requests: 0,
        processing_bytes: 0,
        upload_bytes: 0,
      });
    });

    it('treats a blob as referenced only through live drafts, versions, transfer files and submissions', async () => {
      const h = await make();
      const { orgId, userId } = await h.seed();
      const lone = f.blob(orgId, { status: 'clean' });
      const draft = f.blob(orgId, { status: 'clean' });
      const exported = f.blob(orgId, { status: 'clean' });
      const shared = f.blob(orgId, { status: 'clean' });
      const removed = f.blob(orgId, { status: 'clean' });
      const submitted = f.blob(orgId, { status: 'clean' });
      for (const b of [lone, draft, exported, shared, removed, submitted])
        await h.store.insert('blob', b);
      const d = f.document(orgId, userId, { draftBlobId: draft.id });
      await h.store.insert('document', d);
      await h.store.insert('version', f.version(orgId, d.id, exported.id, userId));
      const tr = f.transfer(orgId, userId);
      await h.store.insert('transfer', tr);
      await h.store.insert('transferFile', f.transferFile(orgId, tr.id, shared.id));
      await h.store.insert(
        'transferFile',
        f.transferFile(orgId, tr.id, removed.id, { status: 'removed' }),
      );
      const r = f.uploadRequest(orgId, userId);
      await h.store.insert('uploadRequest', r);
      const sub = f.submission(orgId, r.id);
      await h.store.insert('submission', sub);
      await h.store.insert('submissionFile', f.submissionFile(orgId, r.id, sub.id, submitted.id));
      const ref = (b: { id: string }) => h.store.blobReferenced(orgId, b.id);
      expect(
        await Promise.all([lone, draft, exported, shared, removed, submitted].map(ref)),
      ).toEqual([false, true, true, true, false, true]);
      await h.store.update('document', orgId, d.id, { status: 'deleted' });
      expect(await ref(draft)).toBe(false);
      expect(await ref(exported)).toBe(false);
    });

    it('numbers versions per document', async () => {
      const h = await make();
      const { orgId, userId } = await h.seed();
      const d1 = f.document(orgId, userId);
      const d2 = f.document(orgId, userId);
      await h.store.insert('document', d1);
      await h.store.insert('document', d2);
      const b = f.blob(orgId, { status: 'clean' });
      await h.store.insert('blob', b);
      expect(await h.store.nextVersionNumber(orgId, d1.id)).toBe(1);
      await h.store.insert('version', f.version(orgId, d1.id, b.id, userId, { number: 1 }));
      await h.store.insert('version', f.version(orgId, d1.id, b.id, userId, { number: 2 }));
      expect(await h.store.nextVersionNumber(orgId, d1.id)).toBe(3);
      expect(await h.store.nextVersionNumber(orgId, d2.id)).toBe(1);
    });

    it('searches short links by text, folder, tag and status within the tenant', async () => {
      const h = await make();
      const { orgId, userId } = await h.seed();
      const other = await h.seed();
      await h.store.insert(
        'shortLink',
        f.shortLink(orgId, userId, {
          code: 'spring-flyer',
          lookupKey: 'p||spring-flyer',
          folder: 'Campaigns',
          tags: ['print'],
        }),
      );
      await h.store.insert(
        'shortLink',
        f.shortLink(orgId, userId, {
          code: 'docs',
          lookupKey: 'p||docs',
          label: 'Spring docs',
          status: 'suspended',
        }),
      );
      await h.store.insert(
        'shortLink',
        f.shortLink(other.orgId, other.userId, {
          code: 'spring-other',
          lookupKey: 'p||spring-other',
        }),
      );
      const codes = async (q: Parameters<SharingStore['searchShortLinks']>[1]) =>
        (await h.store.searchShortLinks(orgId, q)).map((s) => s.code).sort();
      expect(await codes({ q: 'SPRING' })).toEqual(['docs', 'spring-flyer']);
      expect(await codes({ folder: 'Campaigns' })).toEqual(['spring-flyer']);
      expect(await codes({ tag: 'print' })).toEqual(['spring-flyer']);
      expect(await codes({ status: 'suspended' })).toEqual(['docs']);
      expect(await codes({ q: '%' })).toEqual([]);
    });

    it('claims due jobs once per lease and frees them when the lease expires', async () => {
      const h = await make();
      const { orgId } = await h.seed();
      await h.store.insert('job', f.job(orgId, { runAfter: T0 }));
      await h.store.insert('job', f.job(orgId, { runAfter: at(60_000) }));
      const first = await h.store.transaction((tx) => tx.claimJobs(T0, 10, 'w1', at(30_000)));
      expect(first.map((j) => j.claim)).toEqual(['w1']);
      expect(
        await h.store.transaction((tx) => tx.claimJobs(at(1000), 10, 'w2', at(31_000))),
      ).toEqual([]);
      const later = await h.store.transaction((tx) =>
        tx.claimJobs(at(60_000), 10, 'w3', at(90_000)),
      );
      expect(later.map((j) => j.claim).sort()).toEqual(['w3', 'w3']);
    });

    it('lists due transfers, upload requests and abandoned uploads across tenants', async () => {
      const h = await make();
      const a = await h.seed();
      const b = await h.seed();
      const expired = f.transfer(a.orgId, a.userId, { expiresAt: at(-1) });
      const live = f.transfer(a.orgId, a.userId, { expiresAt: at(86_400_000) });
      const deleted = f.transfer(b.orgId, b.userId, {
        status: 'deleted',
        expiresAt: null,
        kind: 'persistent',
      });
      const persistentExpired = f.transfer(b.orgId, b.userId, {
        status: 'expired',
        kind: 'persistent',
      });
      for (const t of [expired, live, deleted, persistentExpired])
        await h.store.insert('transfer', t);
      expect((await h.store.dueTransfers(T0, 100)).map((t) => t.id).sort()).toEqual(
        [expired.id, deleted.id].sort(),
      );
      const due = f.uploadRequest(a.orgId, a.userId, { deleteAfter: at(-1) });
      const keep = f.uploadRequest(b.orgId, b.userId, { deleteAfter: null });
      await h.store.insert('uploadRequest', due);
      await h.store.insert('uploadRequest', keep);
      expect((await h.store.dueUploadRequests(T0, 100)).map((r) => r.id)).toEqual([due.id]);
      const stale = f.blob(a.orgId, { uploadExpiresAt: at(-1) });
      await h.store.insert('blob', stale);
      await h.store.insert('blob', f.blob(b.orgId));
      expect((await h.store.staleUploads(T0, 100)).map((x) => x.id)).toEqual([stale.id]);
    });

    it('aggregates daily statistics and purges them by day', async () => {
      const h = await make();
      const { orgId } = await h.seed();
      const base = {
        orgId,
        subjectType: 'short' as const,
        subjectId: 'sln_1',
        kind: 'visit',
        bot: false,
        referrerHost: 'news.example',
      };
      await h.store.bumpStat({ ...base, day: '2026-02-27' }, 1);
      await h.store.bumpStat({ ...base, day: '2026-03-01' }, 2);
      await h.store.bumpStat({ ...base, day: '2026-03-01' }, 3);
      await h.store.bumpStat({ ...base, day: '2026-03-01', bot: true }, 1);
      const rows = await h.store.listStats(orgId, 'short', 'sln_1', '2026-03-01');
      expect(rows.map((r) => [r.day, r.bot, r.count]).sort()).toEqual([
        ['2026-03-01', false, 5],
        ['2026-03-01', true, 1],
      ]);
      expect(await h.store.purgeStats('2026-03-01', 100)).toBe(1);
      expect(await h.store.listStats(orgId, 'short', 'sln_1', '2000-01-01')).toHaveLength(2);
    });

    it('counts password failures atomically with lockout, clears and purges them', async () => {
      const h = await make();
      await Promise.all(
        Array.from({ length: 5 }, () => h.store.recordAttemptFailure('share:x', T0, 5, 60_000)),
      );
      expect(await h.store.findAttempt('share:x')).toEqual({ count: 5, lockedUntil: at(60_000) });
      await h.store.clearAttempt('share:x');
      expect(await h.store.findAttempt('share:x')).toBeUndefined();
      await h.store.recordAttemptFailure('share:y', T0, 5, 60_000);
      expect(await h.store.purgeAttempts(at(1), 100)).toBe(1);
    });

    it('purges events and notifications older than the cutoff', async () => {
      const h = await make();
      const { orgId, userId } = await h.seed();
      const ev = (ms: number) => ({
        id: `evt_${ms}_${Math.random().toString(16).slice(2)}`,
        orgId,
        subjectType: 'share' as const,
        subjectId: 'lnk_1',
        kind: 'visit' as const,
        userId: null,
        email: null,
        fileId: null,
        bot: false,
        referrerHost: '',
        declaredName: null,
        createdAt: at(ms),
      });
      await h.store.insert('event', ev(-10));
      await h.store.insert('event', ev(10));
      expect(await h.store.purgeEvents(T0, 100)).toBe(1);
      expect(await h.store.list('event', orgId)).toHaveLength(1);
      await h.store.insert('notification', {
        id: 'ntf_1',
        orgId,
        userId,
        kind: 'k',
        subjectType: 's',
        subjectId: 'x',
        message: 'm',
        createdAt: at(-10),
        readAt: null,
      });
      expect(await h.store.purgeNotifications(T0, 100)).toBe(1);
    });

    it('rolls back writes and audit events together when a transaction fails', async () => {
      const h = await make();
      const { orgId, userId } = await h.seed();
      const tr = f.transfer(orgId, userId);
      await expect(
        h.store.transaction(async (tx) => {
          await tx.insert('transfer', tr);
          await tx.addUsage(orgId, '2026-03', 'api_requests', 1);
          await tx.audit.append({
            actor: { type: 'user', id: userId },
            action: 'share.transfer.created',
            orgId,
          });
          throw new Error('boom');
        }),
      ).rejects.toThrow('boom');
      expect(await h.store.get('transfer', orgId, tr.id)).toBeUndefined();
      expect((await h.store.usage(orgId, '2026-03')).api_requests).toBe(0);
      expect(await h.audited()).not.toContain('share.transfer.created');
      await h.store.transaction(async (tx) => {
        await tx.lockAccount(orgId, T0);
        await tx.insert('transfer', tr);
        await tx.audit.append({
          actor: { type: 'user', id: userId },
          action: 'share.transfer.created',
          orgId,
        });
      });
      expect(await h.audited()).toContain('share.transfer.created');
    });

    it('lists abuse reports across tenants by status', async () => {
      const h = await make();
      const { orgId } = await h.seed();
      const base = {
        subjectType: 'short' as const,
        subjectId: 'sln_1',
        reference: '/l/x',
        category: 'phishing' as const,
        details: null,
        reporterEmail: null,
        resolvedAt: null,
        resolvedBy: null,
        resolution: null,
      };
      await h.store.insert('abuse', { ...base, id: 'abr_1', orgId, status: 'open', createdAt: T0 });
      await h.store.insert('abuse', {
        ...base,
        id: 'abr_2',
        orgId: '',
        subjectType: 'unknown',
        subjectId: null,
        status: 'dismissed',
        createdAt: at(1),
      });
      expect((await h.store.listAbuse('open', 10)).map((r) => r.id)).toEqual(['abr_1']);
      expect((await h.store.listAbuse(undefined, 10)).map((r) => r.id)).toEqual(['abr_2', 'abr_1']);
      expect((await h.store.getAbuseForUpdate('abr_2'))?.orgId).toBe('');
    });
  });
}
