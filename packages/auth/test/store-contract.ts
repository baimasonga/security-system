import { describe, expect, it } from 'vitest';
import type { AuthStore } from '../src/index.ts';

export interface AuthHarness {
  store: AuthStore;
  /** Actions of audit events that have been durably committed, oldest first. */
  audited(): Promise<string[]>;
}

const T = new Date('2026-03-01T00:00:00Z');
const user = (n: string, over = {}) => ({
  id: `usr_${n}`,
  email: `${n}@x.test`,
  passwordHash: 'h',
  status: 'active' as const,
  platformRole: 'none' as const,
  createdAt: T,
  ...over,
});

/** One definition of correct AuthStore behaviour, run against every adapter. */
export function authStoreContract(name: string, make: () => AuthHarness | Promise<AuthHarness>) {
  describe(`AuthStore contract: ${name}`, () => {
    it('persists MFA state as copies and rolls factor changes back with audit', async () => {
      const h = await make();
      const u = user('mfa');
      await h.store.insertUser(u);
      const factor = {
        sealedSecret: 'ciphertext',
        enabled: true,
        expiresAt: 0,
        lastCounter: 42,
        recoveryHashes: ['digest'],
      };
      await h.store.transaction(async (tx) => {
        await tx.findUserForUpdate(u.id);
        await tx.setMfa(u.id, factor);
        await tx.audit.append({ actor: { type: 'user', id: u.id }, action: 'mfa.enabled' });
      });
      factor.recoveryHashes.push('external');
      const found = (await h.store.findUserById(u.id))!;
      expect(found.mfa?.recoveryHashes).toEqual(['digest']);
      found.mfa!.recoveryHashes.push('reader');
      expect((await h.store.findUserByEmail(u.email))?.mfa?.recoveryHashes).toEqual(['digest']);
      await expect(
        h.store.transaction(async (tx) => {
          await tx.setMfa(u.id, null);
          throw new Error('rollback factor');
        }),
      ).rejects.toThrow('rollback factor');
      expect((await h.store.findUserById(u.id))?.mfa?.enabled).toBe(true);
      await h.store.setMfa(u.id, null);
      expect((await h.store.findUserById(u.id))?.mfa).toBeNull();
    });
    it('holds the user lock until the transaction completes', async () => {
      const { store: s } = await make();
      const u = user('locking');
      await s.insertUser(u);
      let release!: () => void;
      let ready!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const acquired = new Promise<void>((resolve) => (ready = resolve));
      let secondLocked = false;
      const first = s.transaction(async (tx) => {
        await tx.findUserForUpdate(u.id);
        ready();
        await gate;
      });
      await acquired;
      const second = s.transaction(async (tx) => {
        await tx.findUserForUpdate(u.id);
        secondLocked = true;
      });
      try {
        await new Promise((resolve) => setTimeout(resolve, 100));
        expect(secondLocked).toBe(false);
      } finally {
        release();
        await Promise.all([first, second]);
      }
      expect(secondLocked).toBe(true);
    });
    it('rolls back token use, password changes and session revocation together', async () => {
      const { store: s } = await make();
      const u = user('rollback_recovery');
      await s.insertUser(u);
      const token = {
        userId: u.id,
        purpose: 'reset' as const,
        tokenHash: 'd'.repeat(64),
        createdAt: T,
        expiresAt: new Date(T.getTime() + 60000),
        usedAt: null,
      };
      await s.putIdentityToken(token);
      await s.insertSession({
        id: 'ses_recovery_rollback',
        userId: u.id,
        tokenHash: 'e'.repeat(64),
        createdAt: T,
        expiresAt: new Date(T.getTime() + 60000),
        revokedAt: null,
      });
      await expect(
        s.transaction(async (tx) => {
          await tx.findUserForUpdate(u.id);
          await tx.consumeIdentityToken(u.id, 'reset', token.tokenHash, T);
          await tx.setPasswordHash(u.id, 'changed');
          await tx.revokeUserSessions(u.id, T);
          throw new Error('rollback recovery');
        }),
      ).rejects.toThrow('rollback recovery');
      expect((await s.findIdentityToken(token.tokenHash))?.usedAt).toBeNull();
      expect((await s.findUserById(u.id))?.passwordHash).toBe('h');
      expect((await s.findSessionByTokenHash('e'.repeat(64)))?.revokedAt).toBeNull();
    });

    it('identity tokens expire, are bound to purpose/user, and can be consumed only once', async () => {
      const { store: s } = await make();
      await s.insertUser(user('recovery'));
      const u = user('recovery');
      const token = {
        userId: u.id,
        purpose: 'reset' as const,
        tokenHash: 'a'.repeat(64),
        createdAt: T,
        expiresAt: new Date(T.getTime() + 60000),
        usedAt: null,
      };
      await s.putIdentityToken(token);
      expect((await s.findIdentityToken(token.tokenHash))?.userId).toBe(u.id);
      expect(await s.consumeIdentityToken('other', 'reset', token.tokenHash, T)).toBe(false);
      expect(await s.consumeIdentityToken(u.id, 'verify', token.tokenHash, T)).toBe(false);
      expect(await s.consumeIdentityToken(u.id, 'reset', token.tokenHash, token.expiresAt)).toBe(
        false,
      );
      const results = await Promise.all([
        s.consumeIdentityToken(u.id, 'reset', token.tokenHash, T),
        s.consumeIdentityToken(u.id, 'reset', token.tokenHash, T),
      ]);
      expect(results.sort()).toEqual([false, true]);
    });

    it('stores users; email is unique; lookups by id and email; platform role is updatable', async () => {
      const { store: s } = await make();
      await s.insertUser(user('a'));
      await expect(s.insertUser(user('b', { email: 'a@x.test' }))).rejects.toThrow(
        'duplicate_email',
      );
      expect(await s.findUserByEmail('a@x.test')).toMatchObject({
        id: 'usr_a',
        platformRole: 'none',
        createdAt: T,
      });
      expect(await s.findUserById('usr_a')).toMatchObject({ email: 'a@x.test' });
      expect(await s.findUserById('usr_nope')).toBeUndefined();
      await s.setPlatformRole('usr_a', 'platform_admin');
      expect((await s.findUserById('usr_a'))!.platformRole).toBe('platform_admin');
    });

    it('returns copies, not live references', async () => {
      const { store: s } = await make();
      await s.insertUser(user('a'));
      const u = (await s.findUserById('usr_a'))!;
      u.status = 'disabled';
      expect((await s.findUserById('usr_a'))!.status).toBe('active');
    });

    it('stores organizations and memberships; a user joins an org once', async () => {
      const { store: s } = await make();
      await s.insertUser(user('a'));
      await s.insertUser(user('b'));
      await s.insertOrganization({ id: 'org_1', name: 'One', kind: 'team', createdAt: T });
      await s.insertOrganization({ id: 'org_2', name: 'Two', kind: 'personal', createdAt: T });
      await s.insertMembership({ orgId: 'org_1', userId: 'usr_a', role: 'owner', createdAt: T });
      await s.insertMembership({ orgId: 'org_1', userId: 'usr_b', role: 'member', createdAt: T });
      await s.insertMembership({ orgId: 'org_2', userId: 'usr_a', role: 'owner', createdAt: T });
      await expect(
        s.insertMembership({ orgId: 'org_1', userId: 'usr_a', role: 'admin', createdAt: T }),
      ).rejects.toThrow('duplicate_membership');
      expect(await s.findOrganization('org_1')).toMatchObject({ name: 'One', kind: 'team' });
      expect(await s.findOrganization('org_x')).toBeUndefined();
      expect(await s.findMembership('org_1', 'usr_b')).toMatchObject({ role: 'member' });
      expect(await s.findMembership('org_2', 'usr_b')).toBeUndefined();
      expect((await s.listMembershipsForUser('usr_a')).map((m) => m.orgId).sort()).toEqual([
        'org_1',
        'org_2',
      ]);
      expect((await s.listMembershipsForOrg('org_1')).map((m) => m.userId).sort()).toEqual([
        'usr_a',
        'usr_b',
      ]);
      expect(await s.listMembershipsForOrg('org_x')).toEqual([]);
    });

    it('sessions are found by token hash only; revocation is idempotent and keeps the first timestamp', async () => {
      const { store: s } = await make();
      await s.insertUser(user('a'));
      const exp = new Date(T.getTime() + 3600_000);
      await s.insertSession({
        id: 'ses_1',
        userId: 'usr_a',
        tokenHash: 'hash1',
        createdAt: T,
        expiresAt: exp,
        revokedAt: null,
      });
      expect(await s.findSessionByTokenHash('hash1')).toMatchObject({
        id: 'ses_1',
        expiresAt: exp,
        revokedAt: null,
      });
      expect(await s.findSessionByTokenHash('ses_1')).toBeUndefined();
      expect(await s.findSessionById('ses_1')).toMatchObject({ userId: 'usr_a' });
      expect(await s.findSessionById('missing')).toBeUndefined();
      const first = new Date(T.getTime() + 1000);
      await s.revokeSession('ses_1', first);
      await s.revokeSession('ses_1', new Date(T.getTime() + 9000));
      expect((await s.findSessionByTokenHash('hash1'))!.revokedAt).toEqual(first);
      await s.revokeSession('ses_missing', first); // no-op, no throw
    });

    it('findSessionWithUser returns the session with its user (copies); unknown hash gives undefined', async () => {
      const { store: s } = await make();
      await s.insertUser(user('w', { platformRole: 'platform_admin' }));
      await s.insertUser(user('x', { status: 'disabled' as const }));
      const exp = new Date(T.getTime() + 3600_000);
      const ses = (id: string, userId: string) => ({
        id,
        userId,
        tokenHash: `h_${id}`,
        createdAt: T,
        expiresAt: exp,
        revokedAt: null,
      });
      await s.insertSession(ses('ses_w', 'usr_w'));
      await s.insertSession(ses('ses_x', 'usr_x'));
      expect(await s.findSessionWithUser('h_ses_w')).toMatchObject({
        session: { id: 'ses_w', userId: 'usr_w', expiresAt: exp, revokedAt: null },
        user: {
          id: 'usr_w',
          email: 'w@x.test',
          status: 'active',
          platformRole: 'platform_admin',
          createdAt: T,
        },
      });
      expect((await s.findSessionWithUser('h_ses_x'))!.user.status).toBe('disabled'); // the caller decides
      expect(await s.findSessionWithUser('ses_w')).toBeUndefined(); // by token hash only
      await s.revokeSession('ses_w', T);
      expect((await s.findSessionWithUser('h_ses_w'))!.session.revokedAt).toEqual(T);
    });

    describe('login failure counters (shared lockout state, R-7)', () => {
      const t = (ms: number) => new Date(T.getTime() + ms);
      const LOCK = 15 * 60_000;
      const K = (hex: string) => hex.padEnd(64, '0'); // keys are sha256 digests (the table enforces the shape)

      it('counts failures atomically, locks at the threshold and keeps counting; keys are independent', async () => {
        const { store: s } = await make();
        expect(await s.findLoginFailure(K('a1'))).toBeUndefined();
        for (let i = 1; i <= 4; i++)
          expect(await s.recordLoginFailure(K('a1'), t(i), 5, LOCK)).toEqual({
            count: i,
            lockedUntil: null,
          });
        expect(await s.recordLoginFailure(K('a1'), t(10), 5, LOCK)).toEqual({
          count: 5,
          lockedUntil: t(10 + LOCK),
        });
        // still counting after the lock (the next failure after expiry locks again at once)
        expect(await s.recordLoginFailure(K('a1'), t(20), 5, LOCK)).toEqual({
          count: 6,
          lockedUntil: t(20 + LOCK),
        });
        expect(await s.findLoginFailure(K('a1'))).toEqual({ count: 6, lockedUntil: t(20 + LOCK) });
        expect(await s.findLoginFailure(K('a2'))).toBeUndefined();
        expect(await s.recordLoginFailure(K('a2'), t(1), 5, LOCK)).toEqual({
          count: 1,
          lockedUntil: null,
        });
        expect(await s.recordLoginFailure(K('a3'), t(1), 1, LOCK)).toEqual({
          count: 1,
          lockedUntil: t(1 + LOCK),
        });
      });

      it('clear forgets a key; clearing an unknown key is a no-op', async () => {
        const { store: s } = await make();
        await s.recordLoginFailure(K('a1'), t(1), 5, LOCK);
        await s.clearLoginFailure(K('a1'));
        await s.clearLoginFailure(K('ff'));
        expect(await s.findLoginFailure(K('a1'))).toBeUndefined();
        expect(await s.recordLoginFailure(K('a1'), t(2), 5, LOCK)).toEqual({
          count: 1,
          lockedUntil: null,
        });
      });

      it('concurrent failures are not lost: 25 parallel attempts yield counts 1..25 exactly once', async () => {
        const { store: s } = await make();
        const rs = await Promise.all(
          Array.from({ length: 25 }, () => s.recordLoginFailure(K('ab'), t(1), 5, LOCK)),
        );
        expect(rs.map((r) => r.count).sort((a, b) => a - b)).toEqual(
          Array.from({ length: 25 }, (_, i) => i + 1),
        );
        expect((await s.findLoginFailure(K('ab')))!.count).toBe(25);
      });

      it('purge removes only entries last touched before the cutoff, in bounded batches', async () => {
        const { store: s } = await make();
        for (const k of [K('aa'), K('bb'), K('cc')]) await s.recordLoginFailure(k, t(100), 5, LOCK);
        await s.recordLoginFailure(K('fe'), t(10_000), 5, LOCK);
        expect(await s.purgeLoginFailures(t(5_000), 2)).toBe(2);
        expect(await s.purgeLoginFailures(t(5_000), 2)).toBe(1);
        expect(await s.findLoginFailure(K('fe'))).toBeDefined();
        expect(await s.purgeLoginFailures(t(5_000), 2)).toBe(0);
      });
    });

    describe('transactions with atomic audit', () => {
      it('commit persists the change and its audit events, in order', async () => {
        const h = await make();
        await h.store.transaction(async (tx) => {
          await tx.insertUser(user('a'));
          await tx.audit.append({
            actor: { type: 'user', id: 'usr_a' },
            action: 'user.registered',
          });
          await tx.audit.append({ actor: { type: 'system' }, action: 'second' });
        });
        expect(await h.store.findUserById('usr_a')).toBeDefined();
        expect(await h.audited()).toEqual(['user.registered', 'second']);
      });

      it('a throw discards BOTH the writes and the buffered audit events', async () => {
        const h = await make();
        await expect(
          h.store.transaction(async (tx) => {
            await tx.insertUser(user('a'));
            await tx.audit.append({ actor: { type: 'system' }, action: 'should.vanish' });
            throw new Error('boom');
          }),
        ).rejects.toThrow('boom');
        expect(await h.store.findUserById('usr_a')).toBeUndefined();
        expect(await h.audited()).toEqual([]);
      });

      it('if the audit write itself fails, the business change is rolled back (no unaudited change)', async () => {
        const h = await make();
        await expect(
          h.store.transaction(async (tx) => {
            await tx.insertUser(user('a'));
            await tx.audit.append({ actor: { type: 'bogus' as never }, action: 'bad' });
          }),
        ).rejects.toThrow();
        expect(await h.store.findUserById('usr_a')).toBeUndefined();
        expect(await h.audited()).toEqual([]);
      });

      it('a constraint violation inside the transaction leaves earlier writes and audit undone', async () => {
        const h = await make();
        await h.store.insertUser(user('a'));
        await expect(
          h.store.transaction(async (tx) => {
            await tx.insertOrganization({ id: 'org_1', name: 'One', kind: 'team', createdAt: T });
            await tx.audit.append({ actor: { type: 'system' }, action: 'org.created' });
            await tx.insertUser(user('b', { email: 'a@x.test' })); // duplicate email
          }),
        ).rejects.toThrow('duplicate_email');
        expect(await h.store.findOrganization('org_1')).toBeUndefined();
        expect(await h.audited()).toEqual([]);
      });
    });
  });
}
