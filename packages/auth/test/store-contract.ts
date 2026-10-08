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
      const first = new Date(T.getTime() + 1000);
      await s.revokeSession('ses_1', first);
      await s.revokeSession('ses_1', new Date(T.getTime() + 9000));
      expect((await s.findSessionByTokenHash('hash1'))!.revokedAt).toEqual(first);
      await s.revokeSession('ses_missing', first); // no-op, no throw
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
