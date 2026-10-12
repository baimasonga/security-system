import { expect, it } from 'vitest';
import { MemoryMailDelivery, ResendMailDelivery } from '../src/integrations/mail.ts';
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
