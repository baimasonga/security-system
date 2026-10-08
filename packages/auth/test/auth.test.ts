import { beforeEach, describe, expect, it } from 'vitest';
import { InMemoryAuditLog } from '@trust/audit';
import { DomainError } from '@trust/shared-types';
import {
  AuthService,
  InMemoryAuthStore,
  canGrantRole,
  roleAllows,
  hashPassword,
  verifyPassword,
} from '../src/index.ts';

let now = new Date('2026-01-01T00:00:00Z');
const clock = { now: () => now };
const FAST = { N: 1024, r: 8, p: 1 };

function make() {
  const audit = new InMemoryAuditLog(clock);
  const store = new InMemoryAuthStore({ audit });
  const auth = new AuthService({ store, clock, audit, config: { scrypt: FAST } });
  return { auth, audit, store };
}
const PW = 'correct horse battery';

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof DomainError) return e.code;
    throw e;
  }
  return 'ok';
}

beforeEach(() => {
  now = new Date('2026-01-01T00:00:00Z');
});

describe('passwords', () => {
  it('hashes with a salt and verifies; rejects tampered or malformed hashes', async () => {
    const h1 = await hashPassword(PW, FAST);
    const h2 = await hashPassword(PW, FAST);
    expect(h1).not.toBe(h2);
    expect(await verifyPassword(PW, h1)).toBe(true);
    expect(await verifyPassword('wrong', h1)).toBe(false);
    expect(await verifyPassword(PW, 'garbage')).toBe(false);
    expect(await verifyPassword(PW, h1.replace('$1024$', '$99999999$'))).toBe(false);
  });
});

describe('registration and login', () => {
  it('registers a user with a personal org, normalizing email', async () => {
    const { auth } = make();
    const { user, personalOrg } = await auth.register({ email: ' Ada@Example.COM ', password: PW });
    expect(user.email).toBe('ada@example.com');
    expect(personalOrg.kind).toBe('personal');
  });

  it.each([
    ['not-an-email', PW],
    ['a@b.co', 'short'],
    ['a@b.co', 'x'.repeat(257)],
    ['a@b.co', 'a@b.co'],
  ])('rejects invalid registration %s', async (email, password) => {
    expect(await code(make().auth.register({ email, password }))).toBe('invalid_request');
  });

  it('rejects duplicate email', async () => {
    const { auth } = make();
    await auth.register({ email: 'a@b.co', password: PW });
    expect(await code(auth.register({ email: 'A@B.co', password: PW }))).toBe('conflict');
  });

  it('login yields a session that authenticates; token is never stored in plaintext', async () => {
    const { auth, store } = make();
    const { user } = await auth.register({ email: 'a@b.co', password: PW });
    const { token } = await auth.login({ email: 'a@b.co', password: PW });
    expect(token).toMatch(/^sess_/);
    expect((await auth.authenticate(token)).userId).toBe(user.id);
    expect(await store.findSessionByTokenHash(token)).toBeUndefined();
  });

  it('gives an identical error for unknown user and wrong password', async () => {
    const { auth } = make();
    await auth.register({ email: 'a@b.co', password: PW });
    const a = await auth
      .login({ email: 'a@b.co', password: 'nope-nope-nope' })
      .catch((e: DomainError) => e);
    const b = await auth
      .login({ email: 'ghost@b.co', password: 'nope-nope-nope' })
      .catch((e: DomainError) => e);
    expect(a).toBeInstanceOf(DomainError);
    expect((a as DomainError).message).toBe((b as DomainError).message);
    expect((a as DomainError).code).toBe((b as DomainError).code);
  });

  it('locks out after repeated failures even for the right password, then recovers', async () => {
    const { auth } = make();
    await auth.register({ email: 'a@b.co', password: PW });
    for (let i = 0; i < 5; i++)
      await code(auth.login({ email: 'a@b.co', password: 'bad-bad-bad-bad' }));
    expect(await code(auth.login({ email: 'a@b.co', password: PW }))).toBe('unauthenticated');
    now = new Date(now.getTime() + 16 * 60 * 1000);
    expect(await code(auth.login({ email: 'a@b.co', password: PW }))).toBe('ok');
  });
});

describe('atomic audit', () => {
  it('if auditing fails, registration leaves nothing behind (no user, no org, no membership)', async () => {
    const audit = new InMemoryAuditLog(clock);
    const store = new InMemoryAuthStore({ audit });
    const auth = new AuthService({ store, clock, audit, config: { scrypt: FAST } });
    audit.appendMany = async () => {
      throw new Error('audit down');
    };
    await expect(auth.register({ email: 'a@b.co', password: PW })).rejects.toThrow('audit down');
    expect(await store.findUserByEmail('a@b.co')).toBeUndefined();
    expect(await store.listMembershipsForOrg('anything')).toEqual([]);
  });

  it('a successful registration commits user, personal org, membership and the audit record together', async () => {
    const { auth, audit, store } = make();
    const { user, personalOrg } = await auth.register({ email: 'a@b.co', password: PW });
    expect(await store.findMembership(personalOrg.id, user.id)).toMatchObject({ role: 'owner' });
    expect((await audit.list({ action: 'user.registered' }))[0]).toMatchObject({
      orgId: personalOrg.id,
    });
  });
});

describe('sessions', () => {
  it('expires, can be revoked by logout, and malformed tokens are rejected', async () => {
    const { auth } = make();
    await auth.register({ email: 'a@b.co', password: PW });
    const { token } = await auth.login({ email: 'a@b.co', password: PW });
    const p = await auth.authenticate(token);
    await auth.logout(p);
    expect(await code(auth.authenticate(token))).toBe('unauthenticated');
    const { token: t2 } = await auth.login({ email: 'a@b.co', password: PW });
    now = new Date(now.getTime() + 13 * 3600 * 1000);
    expect(await code(auth.authenticate(t2))).toBe('unauthenticated');
    for (const bad of [undefined, '', 'Bearer x', 'sess_', 'x'.repeat(500)]) {
      expect(await code(auth.authenticate(bad))).toBe('unauthenticated');
    }
  });
});

describe('organizations and RBAC', () => {
  async function twoUsers() {
    const h = make();
    const a = await h.auth.register({ email: 'a@b.co', password: PW });
    const b = await h.auth.register({ email: 'b@b.co', password: PW });
    const pa = await h.auth.authenticate(
      (await h.auth.login({ email: 'a@b.co', password: PW })).token,
    );
    const pb = await h.auth.authenticate(
      (await h.auth.login({ email: 'b@b.co', password: PW })).token,
    );
    return { ...h, a, b, pa, pb };
  }

  it('non-members get not_found (no existence oracle); members without permission get forbidden', async () => {
    const { auth, pa, pb } = await twoUsers();
    const org = await auth.createOrganization(pa, 'Acme');
    expect(await code(auth.getOrganization(pb, org.id))).toBe('not_found');
    await auth.addMember(pa, org.id, 'b@b.co', 'member');
    expect(await code(auth.getOrganization(pb, org.id))).toBe('ok');
    expect(await code(auth.addMember(pb, org.id, 'a@b.co', 'member'))).toBe('forbidden');
  });

  it('prevents privilege escalation when granting roles', async () => {
    const { auth, pa, pb } = await twoUsers();
    const org = await auth.createOrganization(pa, 'Acme');
    await auth.addMember(pa, org.id, 'b@b.co', 'admin');
    await auth.register({ email: 'c@b.co', password: PW });
    expect(await code(auth.addMember(pb, org.id, 'c@b.co', 'owner'))).toBe('forbidden');
    expect(canGrantRole('admin', 'owner')).toBe(false);
    expect(canGrantRole('owner', 'owner')).toBe(true);
    expect(canGrantRole('member', 'admin')).toBe(false);
    expect(roleAllows('member', 'device:deactivate')).toBe(false);
    expect(roleAllows('admin', 'device:deactivate')).toBe(true);
  });

  it('personal orgs cannot gain members; duplicates are rejected', async () => {
    const { auth, pa, a } = await twoUsers();
    expect(await code(auth.addMember(pa, a.personalOrg.id, 'b@b.co', 'member'))).toBe('forbidden');
    const org = await auth.createOrganization(pa, 'Acme');
    await auth.addMember(pa, org.id, 'b@b.co', 'member');
    expect(await code(auth.addMember(pa, org.id, 'b@b.co', 'member'))).toBe('conflict');
  });

  it('platform admin must be bootstrapped out-of-band and is re-checked on each use', async () => {
    const { auth, pa } = await twoUsers();
    expect(await code(auth.requirePlatformAdmin(pa))).toBe('forbidden');
    await auth.bootstrapPlatformAdmin('a@b.co');
    expect(await code(auth.requirePlatformAdmin(pa))).toBe('ok');
  });

  it('writes audit events for security-relevant actions', async () => {
    const { audit, auth, pa } = await twoUsers();
    await auth.createOrganization(pa, 'Acme');
    const actions = (await audit.list()).map((e) => e.action);
    expect(actions).toEqual(
      expect.arrayContaining(['user.registered', 'user.login_succeeded', 'org.created']),
    );
    expect(JSON.stringify(await audit.list())).not.toMatch(/sess_|scrypt\$/);
  });
});
