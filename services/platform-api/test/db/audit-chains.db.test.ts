import { copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GENESIS_HASH, computeEventHash } from '@trust/audit';
import { createSchemaPool } from '../../../../tests/support/pg.ts';
import { applyMigrations } from '../../src/db/migrate.ts';
import { PgAuditLog } from '../../src/db/pg-audit-log.ts';

const url = process.env['DATABASE_URL'];
const migrationsDir = fileURLToPath(new URL('../../migrations', import.meta.url));
const clock = { now: () => new Date('2026-01-01T00:00:00Z') };
const sys = { type: 'system' } as const;

describe.skipIf(!url)('partitioned audit chains on PostgreSQL (ADR-008)', () => {
  it('an appender holding org A’s chain lock blocks A but not B', async () => {
    const pool = createSchemaPool();
    const log = new PgAuditLog(pool, clock);
    await log.append({ actor: sys, action: 'seed', orgId: 'org_a' });
    await log.append({ actor: sys, action: 'seed', orgId: 'org_b' });
    const holder = await pool.connect();
    try {
      await holder.query('BEGIN');
      await holder.query("SELECT 1 FROM audit_chains WHERE chain_id = 'org:org_a' FOR UPDATE");
      const settled = (p: Promise<unknown>) =>
        Promise.race([
          p.then(() => 'done'),
          new Promise((r) => setTimeout(() => r('waiting'), 400)),
        ]);
      expect(await settled(log.append({ actor: sys, action: 'b', orgId: 'org_b' }))).toBe('done');
      const blocked = log.append({ actor: sys, action: 'a', orgId: 'org_a' });
      expect(await settled(blocked)).toBe('waiting');
      await holder.query('COMMIT');
      await blocked;
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 4, chains: 2 });
    } finally {
      holder.release();
    }
  });

  it('concurrent appends across pools, orgs and a hot sharded org stay verifiable and gap-free', async () => {
    const first = createSchemaPool();
    await first.query('SELECT 1');
    const schema = (await first.query('SHOW search_path')).rows[0]!.search_path as string;
    const extra = Array.from(
      { length: 2 },
      () => new pg.Pool({ connectionString: url, max: 8, options: `-c search_path=${schema}` }),
    );
    try {
      const logs = [first, ...extra].map((p) => new PgAuditLog(p as never, clock, { shards: 4 }));
      await Promise.all(
        Array.from({ length: 240 }, (_, i) =>
          logs[i % 3]!.appendMany([
            {
              actor: sys,
              action: 'x',
              orgId: `org_${i % 5}`,
              target: { type: 'device', id: `d${i % 16}` },
            },
            { actor: sys, action: 'y', orgId: `org_${(i + 1) % 5}` },
          ]),
        ),
      );
      const v = await logs[0]!.verifyChain();
      expect(v).toMatchObject({ ok: true, count: 480 });
      const gaps = await first.query(
        'SELECT chain_id FROM audit_events GROUP BY chain_id HAVING max(seq) <> count(*) OR min(seq) <> 1',
      );
      expect(gaps.rows).toEqual([]);
      const shardChains = await first.query(
        "SELECT DISTINCT chain_id FROM audit_events WHERE chain_id LIKE 'org:org_0#%'",
      );
      expect(shardChains.rows.length).toBeGreaterThan(1);
    } finally {
      await Promise.all(extra.map((p) => p.end()));
    }
  }, 60_000);

  describe('tamper evidence', () => {
    async function seeded() {
      const pool = createSchemaPool();
      const log = new PgAuditLog(pool, clock);
      for (let i = 0; i < 5; i++) await log.append({ actor: sys, action: `a${i}`, orgId: 'org_a' });
      for (let i = 0; i < 3; i++) await log.append({ actor: sys, action: `b${i}`, orgId: 'org_b' });
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 8 });
      return { pool, log };
    }
    const unguarded = async (
      pool: { query: (s: string) => Promise<unknown> },
      t: string,
      tg: string,
      sql: string,
    ) => {
      await pool.query(`ALTER TABLE ${t} DISABLE TRIGGER ${tg}`);
      await pool.query(sql);
      await pool.query(`ALTER TABLE ${t} ENABLE TRIGGER ${tg}`);
    };

    it('detects deleting the tail event of a chain (head cross-check)', async () => {
      const { pool, log } = await seeded();
      await unguarded(
        pool,
        'audit_events',
        'audit_events_no_update',
        "DELETE FROM audit_events WHERE chain_id='org:org_a' AND seq=5",
      );
      expect(await log.verifyChain()).toMatchObject({ ok: false });
      expect(await log.verifyChain({ orgId: 'org_b' })).toMatchObject({ ok: true, count: 3 });
      expect(await log.verifyChain({ orgId: 'org_a' })).toMatchObject({ ok: false });
    });

    it('detects moving an event into another chain', async () => {
      const { pool, log } = await seeded();
      await unguarded(
        pool,
        'audit_events',
        'audit_events_no_update',
        "UPDATE audit_events SET chain_id='org:org_b', seq=4 WHERE chain_id='org:org_a' AND seq=5",
      );
      expect(await log.verifyChain()).toMatchObject({ ok: false });
    });

    it('detects a chain whose head row was removed, and a head with no events', async () => {
      const { pool, log } = await seeded();
      await unguarded(
        pool,
        'audit_chains',
        'audit_chains_no_regress',
        "DELETE FROM audit_chains WHERE chain_id='org:org_b'",
      );
      expect(await log.verifyChain()).toMatchObject({ ok: false });
      await unguarded(
        pool,
        'audit_chains',
        'audit_chains_no_regress',
        "INSERT INTO audit_chains (chain_id, head_seq, head_hash) VALUES ('org:ghost', 3, 'h')",
      );
      expect(await log.verifyChain({ orgId: 'ghost' })).toMatchObject({ ok: false });
    });

    it('the database refuses to rename, rewind, delete or truncate head rows', async () => {
      const { pool } = await seeded();
      await expect(
        pool.query("UPDATE audit_chains SET chain_id='x' WHERE chain_id='org:org_a'"),
      ).rejects.toThrow(/immutable/);
      await expect(
        pool.query("UPDATE audit_chains SET head_seq=1 WHERE chain_id='org:org_a'"),
      ).rejects.toThrow(/backwards/);
      await expect(pool.query('DELETE FROM audit_chains')).rejects.toThrow(/cannot be deleted/);
      await expect(pool.query('TRUNCATE audit_chains')).rejects.toThrow(/append-only/);
    });
  });

  describe('upgrade from the single global chain (0001+0002 → 0003)', () => {
    let admin: pg.Client;
    let db: pg.Client;
    let pool: pg.Pool;
    const dbName = `aud_${Date.now()}`;
    beforeAll(async () => {
      admin = new pg.Client({ connectionString: url });
      await admin.connect();
      await admin.query(`CREATE DATABASE ${dbName}`);
      const u = new URL(url!);
      u.pathname = `/${dbName}`;
      db = new pg.Client({ connectionString: u.toString() });
      await db.connect();
      pool = new pg.Pool({ connectionString: u.toString(), max: 4 });
    });
    afterAll(async () => {
      await pool?.end();
      await db?.end();
      await admin?.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
      await admin?.end();
    });

    it('legacy events keep verifying, are never extended, and new events use their own chains', async () => {
      const old = mkdtempSync(join(tmpdir(), 'mig-old-'));
      for (const f of ['0001_init.sql', '0002_retention_indexes.sql'])
        copyFileSync(join(migrationsDir, f), join(old, f));
      expect((await applyMigrations(db, old)).applied).toHaveLength(2);

      // write three events exactly as the pre-ADR-008 code hashed them (no chain field)
      let prev = GENESIS_HASH;
      for (let seq = 1; seq <= 3; seq++) {
        const base = {
          seq,
          id: `aud_old${seq}`,
          occurredAt: '2026-01-01T00:00:00.000Z',
          actor: { type: 'system', id: null },
          action: `old${seq}`,
          target: null,
          orgId: null,
          reason: null,
          metadata: {},
          prevHash: prev,
        };
        const hash = computeEventHash(base as never);
        await db.query(
          `INSERT INTO audit_events (seq,id,occurred_at,actor_type,action,metadata,prev_hash,hash)
           VALUES ($1,$2,$3,'system',$4,'{}',$5,$6)`,
          [seq, base.id, base.occurredAt, base.action, prev, hash],
        );
        prev = hash;
      }

      expect((await applyMigrations(db, migrationsDir)).applied).toEqual([
        '0003_partitioned_audit',
      ]);
      const head = (
        await db.query("SELECT head_seq, head_hash FROM audit_chains WHERE chain_id='legacy'")
      ).rows[0];
      expect({ seq: Number(head.head_seq), hash: head.head_hash }).toEqual({ seq: 3, hash: prev });

      const log = new PgAuditLog(pool as never, clock);
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 3, chains: 1 });
      await log.append({ actor: sys, action: 'new', orgId: 'org_z' });
      await log.append({ actor: sys, action: 'login' });
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 5, chains: 3 });
      const chains = (
        await db.query(
          'SELECT chain_id, max(seq)::int AS n FROM audit_events GROUP BY 1 ORDER BY 1',
        )
      ).rows;
      expect(chains).toEqual([
        { chain_id: 'legacy', n: 3 },
        { chain_id: 'org:org_z', n: 1 },
        { chain_id: 'system', n: 1 },
      ]);
      await expect(
        db.query("UPDATE audit_events SET action='t' WHERE chain_id='legacy'"),
      ).rejects.toThrow(/append-only/);
    });
  });
});
