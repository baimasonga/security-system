import { expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { MfaCipher, totpCode, matchingCounter } from '../src/mfa.ts';
it('matches RFC 6238 SHA-1 test vectors truncated to six digits', () => {
  const secret = Buffer.from('12345678901234567890');
  for (const [seconds, code] of [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
  ] as const)
    expect(totpCode(secret, Math.floor(seconds / 30))).toBe(code);
});
it('rejects malformed, expired and replayed codes, tolerating only adjacent steps', () => {
  const secret = randomBytes(20),
    now = 3000000,
    counter = 100;
  const code = totpCode(secret, counter);
  expect(matchingCounter(secret, code, now, -1)).toBe(counter);
  expect(matchingCounter(secret, code, now, counter)).toBeUndefined();
  expect(matchingCounter(secret, totpCode(secret, counter - 2), now, -1)).toBeUndefined();
  for (const code of ['12345', '0000000', ' 123456', 'abcdef'])
    expect(matchingCounter(secret, code, now, -1)).toBeUndefined();
});
it('encrypts secrets and rejects tampering, wrong users and wrong keys', () => {
  const cipher = new MfaCipher(randomBytes(32).toString('hex')),
    secret = randomBytes(20);
  const sealed = cipher.seal('usr_one', secret);
  expect(sealed).not.toContain(secret.toString('hex'));
  expect(cipher.open('usr_one', sealed)).toEqual(secret);
  expect(() => cipher.open('usr_two', sealed)).toThrow('MFA secret unavailable');
  expect(() => new MfaCipher(randomBytes(32).toString('hex')).open('usr_one', sealed)).toThrow(
    'MFA secret unavailable',
  );
  expect(() => cipher.open('usr_one', sealed.slice(0, -3) + 'AAA')).toThrow(
    'MFA secret unavailable',
  );
  expect(() => new MfaCipher('weak')).toThrow();
});
