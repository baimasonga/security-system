import { createHmac, randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { PaddleWebhookVerifier } from '../src/integrations/billing.ts';
const secret = randomBytes(32).toString('hex');
const now = Date.parse('2026-10-12T12:00:00Z');
const ts = String(now / 1000);
const body = JSON.stringify({
  event_id: 'evt_01test',
  event_type: 'subscription.updated',
  occurred_at: '2026-10-12T12:00:00Z',
  data: { id: 'sub_provider' },
});
const sign = (raw = body, time = ts) =>
  `ts=${time};h1=${createHmac('sha256', secret).update(`${time}:${raw}`).digest('hex')}`;
const verifier = () => new PaddleWebhookVerifier({ secret, now: () => now });
it('verifies original signed bytes before returning provider data', () =>
  expect(verifier().verify(body, sign())).toMatchObject({
    id: 'evt_01test',
    type: 'subscription.updated',
  }));
it('supports multiple provider signatures without trusting mismatches', () =>
  expect(verifier().verify(body, sign() + `;h1=${'0'.repeat(64)}`).id).toBe('evt_01test'));
it.each([
  () => sign(body, String(now / 1000 - 301)),
  () => sign(body, String(now / 1000 + 301)),
  () => `ts=${ts};h1=${'0'.repeat(64)}`,
  () => sign() + `;ts=${ts}`,
  () => `ts=${ts};h1=bad`,
])('rejects stale, future, forged and malformed signatures', (signature) =>
  expect(() => verifier().verify(body, signature())).toThrow('invalid billing webhook'),
);
it('rejects body tampering and malformed signed payloads', () => {
  expect(() => verifier().verify(body + ' ', sign())).toThrow('invalid billing webhook');
  expect(() => verifier().verify('null', sign('null'))).toThrow('invalid billing webhook');
});
