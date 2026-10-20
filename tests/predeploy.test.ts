import { basename } from 'node:path';
import { expect, it, vi } from 'vitest';
import { runPredeploy } from '../tools/predeploy.ts';
it('runs migration, grants and profile checks explicitly in order, without shell operators', () => {
  const execute = vi.fn<
    (
      file: string,
      args: string[],
      options: { stdio: 'inherit' },
    ) => { status: number; signal: null }
  >(() => ({ status: 0, signal: null }));
  expect(runPredeploy(execute)).toBe(0);
  expect(execute.mock.calls.map((call) => basename(call[1][0]!))).toEqual([
    'migrate.ts',
    'db-grants.ts',
    'db-check.ts',
  ]);
  for (const [file, args, options] of execute.mock.calls) {
    expect(file).toBe(process.execPath);
    expect(args).toHaveLength(1);
    expect(args[0]).not.toContain('&&');
    expect(options).toEqual({ stdio: 'inherit' });
  }
});
it.each([0, 1, 2])(
  'stops after failed deployment step %s and preserves its failure status',
  (index) => {
    let n = 0;
    const execute = vi.fn(() => ({ status: n++ === index ? 2 : 0, signal: null }));
    expect(runPredeploy(execute)).toBe(2);
    expect(execute).toHaveBeenCalledTimes(index + 1);
  },
);
it.each([
  { status: null, signal: 'SIGTERM' },
  { status: null, signal: null, error: new Error('not executable') },
])('fails closed when a deployment step cannot complete', (result) => {
  const execute = vi.fn(() => result);
  expect(runPredeploy(execute)).toBe(1);
  expect(execute).toHaveBeenCalledTimes(1);
});
