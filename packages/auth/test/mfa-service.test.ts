import { expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { InMemoryAuditLog } from '@trust/audit';
import { AuthService, InMemoryAuthStore } from '../src/index.ts';
import { MfaCipher, totpCode } from '../src/mfa.ts';
it('fails closed after losing the encryption key, including recovery-code login', async () => {
  let now = new Date('2026-03-01T00:00:00Z');
  const clock = { now: () => now };
  const audit = new InMemoryAuditLog(clock),
    store = new InMemoryAuthStore({ audit });
  const key = randomBytes(32).toString('hex'),
    password = 'correct horse battery staple',
    email = 'lost-key@example.test';
  const service = (mfaEncryptionKey?: string) =>
    new AuthService({
      store,
      audit,
      clock,
      mfaEncryptionKey,
      config: { scrypt: { N: 1024, r: 8, p: 1 } },
    });
  const auth = service(key);
  const { user } = await auth.register({ email, password });
  const login = await auth.login({ email, password });
  const principal = await auth.authenticate(login.token);
  const setup = await auth.beginMfa(principal, password);
  const stored = (await store.findUserById(user.id))!.mfa!;
  const secret = new MfaCipher(key).open(user.id, stored.sealedSecret);
  expect(JSON.stringify(stored)).not.toContain(setup.setupKey);
  const confirmed = await auth.confirmMfa(
    principal,
    password,
    totpCode(secret, Math.floor(now.getTime() / 30000)),
  );
  now = new Date(now.getTime() + 30000);
  for (const broken of [service(), service(randomBytes(32).toString('hex'))]) {
    await expect(
      broken.login({ email, password, code: totpCode(secret, Math.floor(now.getTime() / 30000)) }),
    ).rejects.toMatchObject({ code: 'unauthenticated' });
    await expect(
      broken.login({ email, password, code: confirmed.recoveryCodes[0] }),
    ).rejects.toMatchObject({ code: 'unauthenticated' });
  }
  await expect(
    service().login({ email, password, code: confirmed.recoveryCodes[0] }),
  ).rejects.toMatchObject({ code: 'unauthenticated' });
  for (const code of confirmed.recoveryCodes)
    expect(JSON.stringify(await store.findUserById(user.id))).not.toContain(code);
});
it('rejects management with a revoked session even when password reauthentication succeeds', async () => {
  const clock = { now: () => new Date('2026-03-01T00:00:00Z') },
    audit = new InMemoryAuditLog(clock),
    store = new InMemoryAuthStore({ audit });
  const auth = new AuthService({
    store,
    audit,
    clock,
    mfaEncryptionKey: randomBytes(32).toString('hex'),
    config: { scrypt: { N: 1024, r: 8, p: 1 } },
  });
  const email = 'revoked@example.test',
    password = 'correct horse battery staple';
  await auth.register({ email, password });
  const login = await auth.login({ email, password }),
    principal = await auth.authenticate(login.token);
  await auth.logout(principal);
  await expect(auth.beginMfa(principal, password)).rejects.toMatchObject({
    code: 'unauthenticated',
  });
});
it('rolls factor consumption back when session issuance fails', async () => {
  const clock = { now: () => new Date('2026-03-01T00:00:00Z') },
    audit = new InMemoryAuditLog(clock),
    store = new InMemoryAuthStore({ audit }),
    key = randomBytes(32).toString('hex');
  const auth = new AuthService({
    store,
    audit,
    clock,
    mfaEncryptionKey: key,
    config: { scrypt: { N: 1024, r: 8, p: 1 } },
  });
  const email = 'rollback@example.test',
    password = 'correct horse battery staple';
  const { user } = await auth.register({ email, password });
  const login = await auth.login({ email, password }),
    principal = await auth.authenticate(login.token);
  await auth.beginMfa(principal, password);
  const state = (await store.findUserById(user.id))!.mfa!,
    secret = new MfaCipher(key).open(user.id, state.sealedSecret);
  const codes = await auth.confirmMfa(
    principal,
    password,
    totpCode(secret, Math.floor(clock.now().getTime() / 30000)),
  );
  const original = store.insertSession;
  store.insertSession = async () => {
    throw new Error('synthetic session failure');
  };
  try {
    await expect(auth.login({ email, password, code: codes.recoveryCodes[0] })).rejects.toThrow(
      'synthetic session failure',
    );
  } finally {
    store.insertSession = original;
  }
  expect((await store.findUserById(user.id))!.mfa!.recoveryHashes).toHaveLength(10);
  expect((await auth.login({ email, password, code: codes.recoveryCodes[0] })).token).toMatch(
    /^sess_/,
  );
});
