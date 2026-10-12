import { createServer } from 'node:http';
import { expect, it } from 'vitest';
import { createSchemaPool, pgTestEnabled } from '../support/pg.ts';
import { startServer, type Server } from '../../tools/loadtest/world.ts';
it.skipIf(!pgTestEnabled())(
  'load server startup rejects another process occupying its port even if health is OK',
  async () => {
    const pool = createSchemaPool();
    await pool.query('SELECT 1');
    const schema = (await pool.query('SHOW search_path')).rows[0]!.search_path as string;
    const url = new URL(process.env['DATABASE_URL']!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    const occupied = createServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end('{"status":"ok"}');
    });
    await new Promise<void>((resolve) => occupied.listen(0, '127.0.0.1', resolve));
    const address = occupied.address();
    if (!address || typeof address === 'string') throw new Error('missing test port');
    let started: Server | undefined;
    try {
      await expect(
        startServer(url.toString(), {
          port: address.port,
          pool: 2,
          logLevel: 'silent',
          extraEnv: { DB_SCHEMA: schema },
        }).then((value) => {
          started = value;
          return value;
        }),
      ).rejects.toThrow(/server exited|readiness/);
    } finally {
      await started?.stop();
      await new Promise<void>((resolve, reject) =>
        occupied.close((error) => (error ? reject(error) : resolve())),
      );
    }
  },
);
