import { describe, expect, it } from 'vitest';
import { DomainError } from '@trust/shared-types';
import { withTransaction, type PgPool } from '../src/db/pg.ts';

/** A scripted fake pool: records every statement and releases. No database needed. */
function fakePool(opts: { failRollback?: boolean } = {}) {
  const log: string[] = [];
  let released = 0;
  const client = {
    async query(text: string) {
      log.push(text);
      if (text === 'ROLLBACK' && opts.failRollback) throw new Error('connection reset');
      return { rows: [], rowCount: 0 };
    },
    release() {
      released++;
    },
  };
  const pool = {
    async connect() {
      return client;
    },
    async query() {
      return { rows: [], rowCount: 0 };
    },
  } as unknown as PgPool;
  return { pool, log, released: () => released };
}
const pgError = (code: string) => Object.assign(new Error(`pg ${code}`), { code });
const noSleep = { sleep: async () => {} };

describe('withTransaction retry policy (R-14)', () => {
  it.each(['40P01', '40001'])(
    're-runs the whole attempt after %s and then commits',
    async (code) => {
      const f = fakePool();
      let runs = 0;
      const out = await withTransaction(
        f.pool,
        async () => {
          if (++runs < 3) throw pgError(code);
          return 'done';
        },
        noSleep,
      );
      expect(out).toBe('done');
      expect(runs).toBe(3);
      expect(f.log).toEqual(['BEGIN', 'ROLLBACK', 'BEGIN', 'ROLLBACK', 'BEGIN', 'COMMIT']);
      expect(f.released()).toBe(1); // one connection for all attempts, released once
    },
  );

  it('gives up after maxAttempts and surfaces the ORIGINAL error', async () => {
    const f = fakePool();
    let runs = 0;
    await expect(
      withTransaction(
        f.pool,
        async () => {
          runs++;
          throw pgError('40P01');
        },
        { ...noSleep, maxAttempts: 3 },
      ),
    ).rejects.toMatchObject({ code: '40P01' });
    expect(runs).toBe(3);
    expect(f.log.filter((q) => q === 'ROLLBACK')).toHaveLength(3);
    expect(f.log).not.toContain('COMMIT');
    expect(f.released()).toBe(1);
  });

  it.each([
    ['unique violation', pgError('23505')],
    ['foreign key violation', pgError('23503')],
    ['domain error', new DomainError('conflict', 'nope')],
    ['plain error', new Error('boom')],
  ])('does NOT retry a %s', async (_n, err) => {
    const f = fakePool();
    let runs = 0;
    await expect(
      withTransaction(
        f.pool,
        async () => {
          runs++;
          throw err;
        },
        noSleep,
      ),
    ).rejects.toBe(err);
    expect(runs).toBe(1);
    expect(f.log).toEqual(['BEGIN', 'ROLLBACK']);
    expect(f.released()).toBe(1);
  });

  it('backs off with a bounded, growing delay between attempts', async () => {
    const f = fakePool();
    const delays: number[] = [];
    let runs = 0;
    await withTransaction(
      f.pool,
      async () => {
        if (++runs < 4) throw pgError('40001');
      },
      { sleep: async (ms) => void delays.push(ms) },
    );
    expect(delays).toHaveLength(3);
    delays.forEach((d, i) => {
      expect(d).toBeGreaterThanOrEqual(5 * (i + 1));
      expect(d).toBeLessThan(25 * (i + 1));
    });
  });

  it('a failing ROLLBACK does not mask the original error or leak the connection', async () => {
    const f = fakePool({ failRollback: true });
    await expect(
      withTransaction(
        f.pool,
        async () => {
          throw new Error('original');
        },
        noSleep,
      ),
    ).rejects.toThrow('original');
    expect(f.released()).toBe(1);
  });

  it('commits immediately when nothing fails (no spurious retry)', async () => {
    const f = fakePool();
    expect(await withTransaction(f.pool, async () => 42, noSleep)).toBe(42);
    expect(f.log).toEqual(['BEGIN', 'COMMIT']);
  });
});
