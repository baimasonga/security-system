import { randomBytes } from 'node:crypto';
import { afterEach, expect, it } from 'vitest';
import { loadConfig } from '../src/config.ts';
import { startIdentityMailWorker } from '../src/identity-mail-worker.ts';
import { MemoryMailDelivery } from '../src/integrations/mail.ts';
import { makeEnv, type Env } from './harness.ts';
let env: Env;
afterEach(async () => env?.app.close());

it('validates opt-in encryption configuration and rejects MFA-key reuse', () => {
  const key = randomBytes(32).toString('hex');
  const base = {
    NODE_ENV: 'test',
    RESEND_API_KEY: 'test-provider',
    EMAIL_FROM: 'noreply@example.test',
    PUBLIC_ORIGIN: 'https://accounts.example.test',
  };
  expect(loadConfig(base).identityMailEncryptionKey).toBeUndefined();
  expect(() => loadConfig({ ...base, MAIL_OUTBOX_ENCRYPTION_KEY: 'weak' })).toThrow(
    /MAIL_OUTBOX_ENCRYPTION_KEY/,
  );
  expect(() => loadConfig({ NODE_ENV: 'test', MAIL_OUTBOX_ENCRYPTION_KEY: key })).toThrow(
    /email provider is required/,
  );
  expect(() =>
    loadConfig({ ...base, MFA_ENCRYPTION_KEY: key, MAIL_OUTBOX_ENCRYPTION_KEY: key }),
  ).toThrow(/separate/);
  expect(loadConfig({ ...base, MAIL_OUTBOX_ENCRYPTION_KEY: key }).identityMailEncryptionKey).toBe(
    key,
  );
});

it('keeps generic HTTP responses during provider failure and resumes via its independent worker with content-free metrics', async () => {
  const sink = new MemoryMailDelivery();
  let unavailable = true;
  env = await makeEnv({
    config: {
      maintenanceIntervalSeconds: 86400,
      identityMailEncryptionKey: randomBytes(32).toString('hex'),
    },
    identityDelivery: {
      send: async (m) => {
        if (unavailable) throw new Error('private message body');
        return sink.send(m);
      },
    },
  });
  await env.register('queued@example.test');
  const known = await env.call('POST', '/v1/auth/password/request', {
    body: { email: 'queued@example.test' },
  });
  const unknown = await env.call('POST', '/v1/auth/password/request', {
    body: { email: 'absent@example.test' },
  });
  expect(known.status).toBe(202);
  expect(known.body).toEqual(unknown.body);
  await env.c.auth.flushIdentityMail();
  expect(sink.messages).toHaveLength(0);
  unavailable = false;
  env.clock.advance(60000);
  const maintenance = startIdentityMailWorker(env.c, { everyMs: 3600000 });
  try {
    await maintenance.runOnce();
  } finally {
    maintenance.stop();
  }
  expect(sink.messages).toHaveLength(1);
  expect(sink.messages[0]!.text).toContain('#reset=recover_');
  expect(JSON.stringify(env.c.metrics.snapshot())).toContain('identity_mail_outcomes_total');
  expect(JSON.stringify(await env.c.audit.list())).not.toMatch(
    /private message|queued@example|recover_/,
  );
  expect((await env.call('GET', '/v1/auth/outbox')).status).toBe(404);
  const secret = sink.messages[0]!.text.match(/#reset=(recover_[A-Za-z0-9_-]+)/)![1]!;
  expect(
    (
      await env.call('POST', '/v1/auth/password/reset', {
        body: { token: secret, password: 'a changed test password' },
      })
    ).status,
  ).toBe(204);
});
