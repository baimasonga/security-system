import { createSchemaPool, pgTestEnabled } from '../support/pg.ts';
import { PgAuditLog } from '../../services/platform-api/src/db/pg-audit-log.ts';
import { PgAuthStore } from '../../services/platform-api/src/db/pg-auth-store.ts';
import { randomBytes } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import { InMemoryAuditLog } from '@trust/audit';
import { AuthService, InMemoryAuthStore } from '@trust/auth';
import { IdentityMailOutbox } from '../../packages/auth/src/identity-outbox.ts';
import { IdentityMailCipher } from '@trust/auth';
import { newId, sha256Hex } from '@trust/crypto';

async function queue(s: ReturnType<typeof setup>, suffix = 'one', disabled = false) {
  const user = {
    id: newId('usr'),
    email: `${suffix}@example.test`,
    passwordHash: 'fixture-hash',
    status: disabled ? ('disabled' as const) : ('active' as const),
    platformRole: 'none' as const,
    createdAt: s.clock.now(),
  };
  await s.store.insertUser(user);
  const secret = `recover_${randomBytes(24).toString('base64url')}`;
  const hash = sha256Hex(secret),
    now = s.clock.now();
  const row = {
    userId: user.id,
    purpose: 'reset' as const,
    tokenHash: hash,
    sealed: '',
    createdAt: now,
    expiresAt: new Date(+now + 900000),
    nextAttemptAt: now,
    attempts: 0,
    claim: null,
    lockedUntil: null,
  };
  row.sealed = new IdentityMailCipher(s.key).seal(row, {
    id: hash,
    to: user.email,
    subject: 'Reset',
    text: `https://example.test/#reset=${secret}`,
  });
  await s.store.transaction(async (tx) => {
    await tx.findUserForUpdate(user.id);
    await tx.putIdentityToken({ ...row, usedAt: null });
    await tx.putIdentityMail(row);
  });
  return { row, user, secret };
}

it.each(['expired', 'used', 'superseded', 'disabled', 'tampered', 'wrong-key'])(
  'does not deliver unsafe queued mail (%s)',
  async (mode) => {
    const s = setup(),
      { row, user } = await queue(s, 'one', mode === 'disabled');
    await s.store.transaction(async (tx) => {
      await tx.findUserForUpdate(user.id);
      if (mode === 'used')
        await tx.consumeIdentityToken(user.id, 'reset', row.tokenHash, s.clock.now());
      if (mode === 'superseded')
        await tx.putIdentityToken({ ...row, tokenHash: 'f'.repeat(64), usedAt: null });
      if (mode === 'tampered')
        await tx.putIdentityMail({
          ...row,
          sealed: (row.sealed[0] === 'A' ? 'B' : 'A') + row.sealed.slice(1),
        });
    });
    if (mode === 'expired') s.advance(900001);
    let sent = 0;
    const worker = new IdentityMailOutbox({
      store: s.store,
      clock: s.clock,
      key: mode === 'wrong-key' ? randomBytes(32).toString('hex') : s.key,
      delivery: {
        send: async () => {
          sent++;
          return { id: 'accepted' };
        },
      },
    });
    expect((await worker.runOnce()).discarded).toBe(1);
    expect(sent).toBe(0);
    expect(await s.store.findIdentityMailForUpdate(row.tokenHash)).toBeUndefined();
  },
);

it('fences stale acknowledgements after a worker lease is reclaimed', async () => {
  const s = setup(),
    { row } = await queue(s);
  let releaseA!: () => void, releaseB!: () => void, enteredA!: () => void, enteredB!: () => void;
  const gateA = new Promise<void>((r) => {
      releaseA = r;
    }),
    gateB = new Promise<void>((r) => {
      releaseB = r;
    });
  const readyA = new Promise<void>((r) => {
      enteredA = r;
    }),
    readyB = new Promise<void>((r) => {
      enteredB = r;
    });
  const ids: string[] = [];
  const a = new IdentityMailOutbox({
    store: s.store,
    clock: s.clock,
    key: s.key,
    delivery: {
      send: async (m) => {
        ids.push(m.id);
        enteredA();
        await gateA;
        return { id: 'accepted-a' };
      },
    },
  });
  const b = new IdentityMailOutbox({
    store: s.store,
    clock: s.clock,
    key: s.key,
    delivery: {
      send: async (m) => {
        ids.push(m.id);
        enteredB();
        await gateB;
        return { id: 'accepted-b' };
      },
    },
  });
  const first = a.runOnce();
  await readyA;
  expect(await b.runOnce()).toEqual({ sent: 0, retried: 0, discarded: 0 });
  s.advance(61000);
  const second = b.runOnce();
  await readyB;
  try {
    releaseA();
    await first;
    const leased = await s.store.findIdentityMailForUpdate(row.tokenHash);
    expect(leased?.attempts).toBe(2);
    expect(leased?.claim).not.toBeNull();
    expect(ids).toEqual([row.tokenHash, row.tokenHash]);
  } finally {
    releaseA();
    releaseB();
    await Promise.all([first, second]);
  }
  expect(await s.store.findIdentityMailForUpdate(row.tokenHash)).toBeUndefined();
});

it('stops retrying and removes ciphertext after six failed sends', async () => {
  const s = setup(),
    { row } = await queue(s);
  let sends = 0;
  const worker = new IdentityMailOutbox({
    store: s.store,
    clock: s.clock,
    key: s.key,
    delivery: {
      send: async () => {
        sends++;
        throw new Error('private provider body');
      },
    },
  });
  for (let i = 0; i < 6; i++) {
    await worker.runOnce();
    s.advance(61000);
  }
  expect(sends).toBe(6);
  expect(await s.store.findIdentityMailForUpdate(row.tokenHash)).toBeUndefined();
});

it('authenticates ciphertext metadata bindings and requires a strong key', () => {
  const s = setup(false);
  const row = {
    userId: 'usr_test',
    purpose: 'reset' as const,
    tokenHash: 'a'.repeat(64),
    sealed: '',
    createdAt: s.clock.now(),
    expiresAt: new Date(+s.clock.now() + 900000),
    nextAttemptAt: s.clock.now(),
    attempts: 0,
    claim: null,
    lockedUntil: null,
  };
  const cipher = new IdentityMailCipher(s.key);
  row.sealed = cipher.seal(row, {
    id: row.tokenHash,
    to: 'one@example.test',
    subject: 'Reset',
    text: 'synthetic message',
  });
  for (const change of [
    { userId: 'usr_other' },
    { purpose: 'verify' as const },
    { tokenHash: 'b'.repeat(64) },
    { expiresAt: new Date(+row.expiresAt + 1000) },
  ])
    expect(() => cipher.open({ ...row, ...change })).toThrow();
  expect(() => new IdentityMailCipher('0'.repeat(64))).toThrow();
});

it('does not commit a recovery token or queue entry when its audit fails', async () => {
  const s = setup(false);
  let sends = 0;
  const auth = new AuthService({
    store: s.store,
    clock: s.clock,
    audit: s.audit,
    identityMailEncryptionKey: s.key,
    identityDelivery: {
      send: async () => {
        sends++;
        return { id: 'accepted' };
      },
    },
    config: { scrypt: { N: 1024, r: 8, p: 1 } },
  });
  const { user } = await auth.register({
    email: 'rollback@example.test',
    password: 'a correct test password',
  });
  const failure = vi
    .spyOn(s.audit, 'appendMany')
    .mockRejectedValueOnce(new Error('audit unavailable'));
  try {
    await expect(auth.requestPasswordReset(user.email)).rejects.toThrow('audit unavailable');
  } finally {
    failure.mockRestore();
  }
  expect(await s.store.findUserIdentityToken(user.id, 'reset')).toBeUndefined();
  expect(await s.store.listDueIdentityMail(s.clock.now(), 25)).toEqual([]);
  expect(sends).toBe(0);
});

it('preserves a newer queued message when an older in-flight send finishes', async () => {
  const s = setup(),
    { row, user } = await queue(s);
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>((r) => {
      entered = r;
    }),
    gate = new Promise<void>((r) => {
      release = r;
    });
  const worker = new IdentityMailOutbox({
    store: s.store,
    clock: s.clock,
    key: s.key,
    delivery: {
      send: async () => {
        entered();
        await gate;
        return { id: 'accepted' };
      },
    },
  });
  const first = worker.runOnce();
  await ready;
  const replacement = { ...row, tokenHash: 'd'.repeat(64) };
  replacement.sealed = new IdentityMailCipher(s.key).seal(replacement, {
    id: replacement.tokenHash,
    to: user.email,
    subject: 'Reset',
    text: 'replacement fixture',
  });
  try {
    await s.store.transaction(async (tx) => {
      await tx.findUserForUpdate(user.id);
      await tx.putIdentityToken({ ...replacement, usedAt: null });
      await tx.putIdentityMail(replacement);
    });
  } finally {
    release();
    await first;
  }
  expect(await s.store.findIdentityMailForUpdate(row.tokenHash)).toBeUndefined();
  expect((await s.store.findIdentityMailForUpdate(replacement.tokenHash))?.attempts).toBe(0);
});

it('stops new claims during graceful shutdown and leaves queued work recoverable', async () => {
  const s = setup(),
    { row } = await queue(s);
  let sends = 0;
  const worker = new IdentityMailOutbox({
    store: s.store,
    clock: s.clock,
    key: s.key,
    delivery: {
      send: async () => {
        sends++;
        return { id: 'accepted' };
      },
    },
  });
  await worker.stop();
  expect(await worker.runOnce()).toEqual({ sent: 0, retried: 0, discarded: 0 });
  expect(sends).toBe(0);
  expect(await s.store.findIdentityMailForUpdate(row.tokenHash)).toBeDefined();
});

it('drains a bounded burst across four workers without duplicate sends or lost messages', async () => {
  const s = setup();
  const expected: string[] = [];
  for (let i = 0; i < 30; i++) expected.push((await queue(s, `burst-${i}`)).row.tokenHash);
  const sent: string[] = [];
  const workers = Array.from(
    { length: 4 },
    () =>
      new IdentityMailOutbox({
        store: s.store,
        clock: s.clock,
        key: s.key,
        delivery: {
          send: async (m) => {
            sent.push(m.id);
            await new Promise((r) => setTimeout(r, 1));
            return { id: 'accepted' };
          },
        },
      }),
  );
  for (let pass = 0; pass < 2; pass++) {
    const counts = await Promise.all(workers.map((w) => w.runOnce()));
    expect(counts.every((c) => c.sent + c.discarded + c.retried <= 25)).toBe(true);
  }
  expect(sent.sort()).toEqual(expected.sort());
  expect(new Set(sent).size).toBe(30);
  expect(await s.store.listDueIdentityMail(s.clock.now(), 100)).toEqual([]);
});

function setup(persist = true) {
  let now = new Date('2026-01-01T00:00:00Z');
  const clock = { now: () => now };
  const pool = persist && pgTestEnabled() ? createSchemaPool() : undefined;
  const audit = pool ? new PgAuditLog(pool, clock) : new InMemoryAuditLog(clock);
  const store = pool ? new PgAuthStore(pool, clock) : new InMemoryAuthStore({ audit });
  const key = randomBytes(32).toString('hex');
  return {
    clock,
    audit,
    store,
    key,
    advance: (ms: number) => {
      now = new Date(+now + ms);
    },
  };
}
it('retries encrypted committed recovery mail after recreating the worker without leaking its contents', async () => {
  const { clock, audit, store, key, advance } = setup();
  const auth = new AuthService({
    store,
    clock,
    audit,
    config: { scrypt: { N: 1024, r: 8, p: 1 } },
    identityMailEncryptionKey: key,
    identityDelivery: {
      send: async () => {
        throw new Error('private provider body');
      },
    },
  });
  const { user } = await auth.register({
    email: 'outbox@example.test',
    password: 'a correct test password',
  });
  await auth.requestPasswordReset(user.email);
  await auth.flushIdentityMail();
  const row = await store.findUserIdentityToken(user.id, 'reset');
  expect(row).toBeDefined();
  const queued = await store.findIdentityMailForUpdate(row!.tokenHash);
  expect(queued?.attempts).toBe(1);
  expect(JSON.stringify(queued)).not.toMatch(/outbox@example|recover_/);
  const sent: Array<{ id: string; text: string }> = [];
  const worker = new IdentityMailOutbox({
    store,
    clock,
    key,
    delivery: {
      send: async (message) => {
        sent.push(message);
        return { id: 'provider-id' };
      },
    },
  });
  expect((await worker.runOnce()).sent).toBe(0);
  advance(60000);
  expect((await worker.runOnce()).sent).toBe(1);
  expect(sent[0]?.id).toBe(row!.tokenHash);
  expect(await store.findIdentityMailForUpdate(row!.tokenHash)).toBeUndefined();
  const token = sent[0]!.text.match(/#reset=(recover_[A-Za-z0-9_-]+)/)![1]!;
  await auth.completeIdentityToken(token, 'reset', 'a changed test password');
  expect(JSON.stringify(await audit.list())).not.toMatch(
    /private provider|outbox@example|recover_/,
  );
});
