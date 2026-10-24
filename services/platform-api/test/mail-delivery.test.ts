import { expect, it } from 'vitest';
import {
  CloudflareMailDelivery,
  MemoryMailDelivery,
  ResendMailDelivery,
} from '../src/integrations/mail.ts';
const message = {
  id: 'mail_abc',
  to: 'account@example.test',
  subject: 'Account verification',
  text: 'Synthetic test message',
};
it('local email delivery is explicit and idempotent by message id', async () => {
  const mail = new MemoryMailDelivery();
  await mail.send(message);
  await mail.send(message);
  expect(mail.messages).toEqual([message]);
});
it('uses a fixed HTTPS provider, sender and idempotency key', async () => {
  let request: { url: string; options: RequestInit } | undefined;
  const mail = new ResendMailDelivery({
    apiKey: 'synthetic',
    from: 'Trust <trust@example.test>',
    fetch: async (url, options) => {
      request = { url: String(url), options: options! };
      return new Response(JSON.stringify({ id: 'provider_id' }));
    },
  });
  expect(await mail.send(message)).toEqual({ id: 'provider_id' });
  expect(request?.url).toBe('https://api.resend.com/emails');
  expect(request?.options.redirect).toBe('error');
  expect(request?.options.headers).toMatchObject({ 'idempotency-key': 'mail_abc' });
  expect(JSON.parse(String(request?.options.body))).toMatchObject({
    from: 'Trust <trust@example.test>',
    to: [message.to],
  });
});
it('refuses envelope injection before making a request', async () => {
  const mail = new ResendMailDelivery({
    apiKey: 'synthetic',
    from: 'trust@example.test',
    fetch: () => {
      throw new Error('should not call');
    },
  });
  await expect(
    mail.send({ ...message, to: 'victim@example.test\r\nBcc: other@example.test' }),
  ).rejects.toThrow('invalid email envelope');
});
it('never includes provider response bodies or request secrets in failures', async () => {
  const mail = new ResendMailDelivery({
    apiKey: 'secret-key',
    from: 'trust@example.test',
    fetch: async () => new Response('private-body secret-key', { status: 400 }),
  });
  await expect(mail.send(message)).rejects.toThrow('email delivery rejected (HTTP 400)');
  const broken = new ResendMailDelivery({
    apiKey: 'secret-key',
    from: 'trust@example.test',
    fetch: async () => {
      throw new Error('network error secret-key');
    },
  });
  await expect(broken.send(message)).rejects.toThrow(/^email delivery unavailable$/);
});
const ACCOUNT = 'b'.repeat(32);
const accepted = (to = message.to) =>
  new Response(JSON.stringify({ success: true, result: { delivered: [to], queued: [] } }));
function cloudflare(respond: (url: string, options: RequestInit) => Promise<Response> | Response) {
  return new CloudflareMailDelivery({
    apiToken: 'secret-token',
    accountId: ACCOUNT,
    from: 'Warrior <alerts@example.test>',
    fetch: async (url, options) => respond(String(url), options!),
  });
}
it('sends Cloudflare email to the fixed account endpoint without following redirects', async () => {
  let request: { url: string; options: RequestInit } | undefined;
  const mail = cloudflare((url, options) => {
    request = { url, options };
    return accepted();
  });
  expect(await mail.send(message)).toEqual({ id: message.id });
  expect(request?.url).toBe(
    `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/email/sending/send`,
  );
  expect(request?.options.redirect).toBe('error');
  expect(request?.options.method).toBe('POST');
  expect(request?.options.headers).toMatchObject({ authorization: 'Bearer secret-token' });
  expect(JSON.parse(String(request?.options.body))).toEqual({
    from: { address: 'alerts@example.test', name: 'Warrior' },
    to: message.to,
    subject: message.subject,
    text: message.text,
  });
  // A queued recipient (case-insensitive) is accepted too.
  const queued = cloudflare(
    () =>
      new Response(
        JSON.stringify({
          success: true,
          result: { delivered: [], queued: ['ACCOUNT@example.test'] },
        }),
      ),
  );
  await expect(queued.send(message)).resolves.toEqual({ id: message.id });
});
it('rejects Cloudflare settings that could misroute mail before any request', () => {
  for (const opts of [
    { apiToken: '', accountId: ACCOUNT, from: 'alerts@example.test' },
    { apiToken: 'x', accountId: '../../zones', from: 'alerts@example.test' },
    { apiToken: 'x', accountId: ACCOUNT, from: 'alerts@example.test\r\nBcc: x@example.test' },
  ])
    expect(() => new CloudflareMailDelivery(opts)).toThrow();
});
it('refuses Cloudflare envelope injection and invalid ids before making a request', async () => {
  const mail = cloudflare(() => {
    throw new Error('should not call');
  });
  await expect(
    mail.send({ ...message, to: 'victim@example.test\r\nBcc: other@example.test' }),
  ).rejects.toThrow('invalid email envelope');
  await expect(mail.send({ ...message, subject: 'a\nb' })).rejects.toThrow(
    'invalid email envelope',
  );
  await expect(mail.send({ ...message, id: 'bad id' })).rejects.toThrow('invalid message id');
});
it('treats a Cloudflare response that does not accept this recipient as a failure', async () => {
  for (const body of [
    { success: false, result: { delivered: [message.to] } },
    { success: true, result: { delivered: [], queued: [] } },
    { success: true, result: { delivered: ['other@example.test'] } },
    { success: true, result: { delivered: [message.to], permanent_bounces: [message.to] } },
    { success: true },
    null,
  ])
    await expect(
      cloudflare(() => new Response(JSON.stringify(body))).send(message),
    ).rejects.toThrow(/^email delivery not accepted$/);
  await expect(cloudflare(() => new Response('not json')).send(message)).rejects.toThrow(
    /^invalid email delivery response$/,
  );
});
it('never includes Cloudflare response bodies, recipients or the token in failures', async () => {
  const rejected = cloudflare(
    () => new Response(`private ${message.to} secret-token`, { status: 403 }),
  );
  await expect(rejected.send(message)).rejects.toThrow(/^email delivery rejected \(HTTP 403\)$/);
  const broken = cloudflare(() => {
    throw new Error(`network error secret-token ${message.to}`);
  });
  await expect(broken.send(message)).rejects.toThrow(/^email delivery unavailable$/);
});
