import { copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GENESIS_HASH, computeEventHash, createAnchor } from '@trust/audit';
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

  it('does not lock a later existing head while waiting for an earlier head being created', async () => {
    const pool = createSchemaPool();
    const log = new PgAuditLog(pool, clock);
    await log.append({ actor: sys, action: 'seed', orgId: 'org_z' });
    const creator = await pool.connect();
    const probe = await pool.connect();
    const appendClient = await pool.connect();
    let started!: () => void;
    const firstRead = new Promise<void>((resolve) => {
      started = resolve;
    });
    let signalled = false;
    const wrapped = {
      connect: async () => ({
        query: async (...args: Parameters<typeof appendClient.query>) => {
          const result = await appendClient.query(...args);
          if (!signalled && String(args[0]).includes('SELECT chain_id, head_seq, head_hash')) {
            signalled = true;
            started();
          }
          return result;
        },
        release: () => undefined,
      }),
    };
    let pending: Promise<unknown> | undefined;
    try {
      await creator.query('BEGIN');
      await creator.query(
        'INSERT INTO audit_chains(chain_id,head_seq,head_hash) VALUES ($1,0,$2)',
        ['org:org_a', GENESIS_HASH],
      );
      pending = new PgAuditLog(wrapped as never, clock).appendMany([
        { actor: sys, action: 'a', orgId: 'org_a' },
        { actor: sys, action: 'z', orgId: 'org_z' },
      ]);
      await firstRead;
      await probe.query('BEGIN');
      // Appender waits for uncommitted A. It must not already hold the later Z lock.
      await expect(
        probe.query("SELECT 1 FROM audit_chains WHERE chain_id='org:org_z' FOR UPDATE NOWAIT"),
      ).resolves.toBeDefined();
    } finally {
      await probe.query('ROLLBACK').catch(() => undefined);
      await creator.query('COMMIT');
      await pending;
      creator.release();
      probe.release();
      appendClient.release();
    }
    expect(await log.verifyChain()).toMatchObject({ ok: true, count: 3, chains: 2 });
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

  describe('external anchor (ADR-010)', () => {
    const at = new Date('2026-02-02T00:00:00Z');

    it('a perfect, self-consistent rewrite passes verifyChain but fails the witnessed anchor; growth does not', async () => {
      const pool = createSchemaPool();
      const log = new PgAuditLog(pool, clock);
      for (let i = 0; i < 4; i++) await log.append({ actor: sys, action: `a${i}`, orgId: 'org_a' });
      await log.append({ actor: sys, action: 'b', orgId: 'org_b' });
      const r = await createAnchor(log, at);
      if (!r.ok) throw new Error('expected an anchor');
      expect(r.manifest.chains.map((c) => [c.chain, c.seq])).toEqual([
        ['org:org_a', 4],
        ['org:org_b', 1],
      ]);

      await log.append({ actor: sys, action: 'later', orgId: 'org_a' });
      expect(await log.checkAnchor(r.manifest)).toEqual({ ok: true, chains: 2 });

      // A superuser disables the triggers and rewrites event 2 of org_a, recomputing every later hash and the head.
      const evs = (await log.list({ orgId: 'org_a' })).filter((e) => e.chain === 'org:org_a');
      await pool.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update');
      let prev = evs[0]!.hash;
      for (const e of evs.slice(1)) {
        const { hash: _h, ...rest } = {
          ...e,
          prevHash: prev,
          reason: e.seq === 2 ? 'forged' : e.reason,
        };
        void _h;
        const hash = computeEventHash(rest);
        await pool.query(
          'UPDATE audit_events SET reason = $3, prev_hash = $4, hash = $5 WHERE chain_id = $1 AND seq = $2',
          ['org:org_a', e.seq, rest.reason, prev, hash],
        );
        prev = hash;
      }
      await pool.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update');
      await pool.query("UPDATE audit_chains SET head_hash = $1 WHERE chain_id = 'org:org_a'", [
        prev,
      ]);

      expect(await log.verifyChain()).toMatchObject({ ok: true }); // self-consistent: only a witness can tell
      expect(await log.checkAnchor(r.manifest)).toMatchObject({ ok: false, chain: 'org:org_a' });
    });

    it('detects a chain removed together with its head row, and a rolled-back log', async () => {
      const pool = createSchemaPool();
      const log = new PgAuditLog(pool, clock);
      await log.append({ actor: sys, action: 'a', orgId: 'org_a' });
      await log.append({ actor: sys, action: 'b', orgId: 'org_b' });
      await log.append({ actor: sys, action: 'b2', orgId: 'org_b' });
      const r = await createAnchor(log, at);
      if (!r.ok) throw new Error('expected an anchor');
      await pool.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update');
      await pool.query('ALTER TABLE audit_chains DISABLE TRIGGER audit_chains_no_regress');
      await pool.query("DELETE FROM audit_events WHERE chain_id = 'org:org_a'");
      await pool.query("DELETE FROM audit_chains WHERE chain_id = 'org:org_a'");
      expect(await log.verifyChain()).toMatchObject({ ok: true });
      expect(await log.checkAnchor(r.manifest)).toMatchObject({ ok: false, chain: 'org:org_a' });
      // roll org_b back to its first event (events and head)
      await pool.query("DELETE FROM audit_events WHERE chain_id = 'org:org_b' AND seq = 2");
      const first = (
        await pool.query("SELECT hash FROM audit_events WHERE chain_id='org:org_b' AND seq=1")
      ).rows[0]!.hash;
      await pool.query(
        "UPDATE audit_chains SET head_seq = 1, head_hash = $1 WHERE chain_id = 'org:org_b'",
        [first],
      );
      expect(await log.verifyChain()).toMatchObject({ ok: true });
      const only_b = {
        ...r.manifest,
        chains: r.manifest.chains.filter((c) => c.chain === 'org:org_b'),
      };
      only_b.anchor = (await import('@trust/audit')).computeAnchor(only_b.chains);
      expect(await log.checkAnchor(only_b)).toMatchObject({
        ok: false,
        chain: 'org:org_b',
        seq: 2,
      });
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
    }, 60_000); // Database removal can wait for a checkpoint; match the shared PG harness.

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
        '0004_audit_anchors',
        '0005_shared_rate_state',
        '0006_identity_recovery',
        '0007_authenticator_mfa',
        '0008_monthly_quotas',
        '0009_billing_checkout',
        '0010_identity_mail_outbox',
        '0011_file_sharing',
        '0012_privileged_operations',
        '0013_passkeys',
        '0014_capability_challenges',
        '0015_license_seats',
        '0016_device_trust',
        '0017_operations_inventory',
        '0018_operations_credentials',
        '0019_operations_events',
        '0020_operations_health',
        '0021_operations_health_clock',
        '0022_operations_incidents',
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

describe.skipIf(!url)('anchor publication and the offline checker on PostgreSQL (ADR-010)', () => {
  it('publishes through the real container wiring, records it, and tools/verify-anchor.ts agrees — then catches a forgery', async () => {
    const { createContainer } = await import('../../src/container.ts');
    const { loadConfig } = await import('../../src/config.ts');
    const { spawnSync } = await import('node:child_process');
    const { mkdtempSync, writeFileSync } = await import('node:fs');
    const { computeAnchor } = await import('@trust/audit');
    const { generateEd25519 } = await import('@trust/crypto');

    const pool = createSchemaPool();
    await pool.query('SELECT 1');
    const schema = (await pool.query('SHOW search_path')).rows[0]!.search_path as string;
    const witnessed: unknown[] = [];
    const c = await createContainer(
      {
        ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv),
        signingKeyPem: generateEd25519()
          .privateKey.export({ type: 'pkcs8', format: 'pem' })
          .toString(),
        scrypt: { N: 1024, r: 8, p: 1 },
      },
      {
        pool,
        anchorSink: {
          destination: 'https://witness.example/anchors',
          publish: async (m) => (witnessed.push(m), { receipt: 'rcpt-1' }),
        },
      },
    );
    try {
      await c.auth.register({ email: 'a@example.test', password: 'correct horse battery' });
      await c.auth.register({ email: 'b@example.test', password: 'correct horse battery' });
      const out = await c.anchors!.publish();
      expect(out).toMatchObject({ status: 'published', record: { receipt: 'rcpt-1' } });
      expect(
        (await pool.query('SELECT status, chains, events, destination FROM audit_anchors')).rows,
      ).toEqual([
        {
          status: 'published',
          chains: expect.any(Number),
          events: expect.stringMatching(/^\d+$/),
          destination: 'https://witness.example/anchors',
        },
      ]);
      const manifest = witnessed[0] as {
        anchor: string;
        chains: Array<{ chain: string; seq: number; hash: string }>;
      };
      expect(manifest.chains.length).toBeGreaterThanOrEqual(2);

      const dir = mkdtempSync(join(tmpdir(), 'anchor-'));
      const file = join(dir, 'manifest.json');
      writeFileSync(file, JSON.stringify(manifest));
      const run = (path: string) =>
        spawnSync('node', ['tools/verify-anchor.ts', path], {
          env: { ...process.env, DATABASE_URL: url!, PGOPTIONS: `-c search_path=${schema}` },
          encoding: 'utf8',
        });
      const ok = run(file);
      expect(ok.status, ok.stderr).toBe(0);
      expect(ok.stdout).toMatch(/OK: .* 1 witnessed anchor/);

      // A forged manifest (as if the history had been replaced) must fail the checker.
      const forged = {
        ...manifest,
        chains: manifest.chains.map((x, i) => (i === 0 ? { ...x, hash: 'c'.repeat(64) } : x)),
      };
      forged.anchor = computeAnchor(forged.chains);
      writeFileSync(file, JSON.stringify(forged));
      const bad = run(file);
      expect(bad.status).toBe(1);
      expect(bad.stderr).toMatch(/FAIL anchor #1/);

      // JSON Lines (as the reference witness writes it): every manifest in the file is checked.
      writeFileSync(
        file,
        [JSON.stringify({ manifest }), JSON.stringify({ manifest: forged })].join('\n'),
      );
      expect(run(file).status).toBe(1);
      expect(run(join(dir, 'missing.json')).status).toBe(2);
    } finally {
      await c.close();
    }
  }, 60_000);
});
