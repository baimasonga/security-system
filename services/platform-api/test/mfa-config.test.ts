import { expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../src/config.ts';
it('requires a stable random encryption key before operator MFA enforcement', () => {
  expect(() => loadConfig({ NODE_ENV: 'test', REQUIRE_OPERATOR_MFA: 'true' })).toThrow(
    /MFA_ENCRYPTION_KEY/,
  );
  expect(() => loadConfig({ NODE_ENV: 'test', MFA_ENCRYPTION_KEY: 'weak' })).toThrow(
    /MFA_ENCRYPTION_KEY/,
  );
  expect(() => loadConfig({ NODE_ENV: 'test', REQUIRE_OPERATOR_MFA: 'tru' })).toThrow(
    /REQUIRE_OPERATOR_MFA/,
  );
  const key = randomBytes(32).toString('hex');
  expect(
    loadConfig({ NODE_ENV: 'test', MFA_ENCRYPTION_KEY: key, REQUIRE_OPERATOR_MFA: 'true' }),
  ).toMatchObject({ mfaEncryptionKey: key, requireOperatorMfa: true });
  expect(loadConfig({ NODE_ENV: 'test' }).requireOperatorMfa).toBe(false);
});
