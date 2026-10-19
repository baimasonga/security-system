import { ESLint } from 'eslint';
import { expect, it } from 'vitest';

it('the installed lint toolchain still rejects unsafe regular expressions in production code', async () => {
  const eslint = new ESLint();
  const results = await eslint.lintText('export const unsafe = /(a+)+$/;\n', {
    filePath: 'packages/crypto/src/toolchain-fixture.ts',
  });
  expect(results).toHaveLength(1);
  expect(results[0]!.fatalErrorCount).toBe(0);
  expect(results[0]!.messages.some((m) => m.ruleId === 'security/detect-unsafe-regex')).toBe(true);
});
