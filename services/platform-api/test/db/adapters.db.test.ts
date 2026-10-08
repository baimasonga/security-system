import { describe, expect, it } from 'vitest';
import pg from 'pg';
import { generateEd25519 } from '@trust/crypto';
import { Telemetry } from '@trust/telemetry';
import { anchorStoreContract } from '../anchor-store-contract.ts';
import { PgAnchorStore } from '../../src/db/pg-anchor-store.ts';
import { auditLogContract } from '../../../../packages/audit/test/log-contract.ts';
import { authStoreContract } from '../../../../packages/auth/test/store-contract.ts';
import { licensingStoreContract } from '../../../../packages/licensing/test/store-contract.ts';
import { createSchemaPool } from '../../../../tests/support/pg.ts';
import { loadConfig } from '../../src/config.ts';
import { createContainer } from '../../src/container.ts';
import type { PgPool } from '../../src/db/pg.ts';
import { PgAuditLog } from '../../src/db/pg-audit-log.ts';
import { PgAuthStore } from '../../src/db/pg-auth-store.ts';
import { PgKeyStore } from '../../src/db/pg-key-store.ts';
import { PgLicensingStore } from '../../src/db/pg-licensing-store.ts';
import { PgTelemetrySink } from '../../src/db/pg-telemetry-sink.ts';

const url = process.env['DATABASE_URL'];

describe.skipIf(!url)('PostgreSQL adapters', () => {
  // ---- the same contracts the in-memory adapters satisfy -------------------------------------
  const clock = { now: () => new Date('2026-01-01T00:00:00Z') };
  const auditedOf = (pool: PgPool) => async () =>
    (await pool.query('SELECT action FROM audit_events ORDER BY gseq')).rows.map(
      (r) => r.action as string,
    );
  authStoreContract('postgres', () => {
    const pool = createSchemaPool();
    return { store: new PgAuthStore(pool, clock), audited: auditedOf(pool) };
  });
  anchorStoreContract('postgres', () => new PgAnchorStore(createSchemaPool()));
  auditLogContract('postgres', (clock, opts) => new PgAuditLog(createSchemaPool(), clock, opts));
  licensingStoreContract('postgres', () => {
    const pool = createSchemaPool();
    return {
      store: new PgLicensingStore(pool, clock),
      audited: auditedOf(pool),
      seedOrg: async (id) =>
        void (await pool.query("INSERT INTO organizations (id, name, kind) VALUES ($1,$1,'team')", [
          id,
        ])),
      seedUser: async (id) =>
        void (await pool.query(
          "INSERT INTO users (id, email, password_hash) VALUES ($1, $1 || '@x.test', 'x')",
          [id],
        )),
    };
  });

  // ---- audit: things only a real multi-connection database can prove --------------------------
  describe('audit log', () => {
    const clock = { now: () => new Date('2026-01-01T00:00:00Z') };

    it('stays one linear chain when appended from independent connection pools', async () => {
      const a = createSchemaPool();
      await a.query('SELECT 1'); // schema ready
      const schema = (await a.query('SHOW search_path')).rows[0]!.search_path as string;
      const other = new pg.Pool({
        connectionString: url,
        max: 4,
        options: `-c search_path=${schema}`,
      });
      try {
        const logA = new PgAuditLog(a, clock);
        const logB = new PgAuditLog(other, clock);
        await Promise.all(
          Array.from({ length: 60 }, (_, i) =>
            (i % 2 ? logA : logB).append({ actor: { type: 'system' }, action: `e${i}` }),
          ),
        );
        expect(await logA.verifyChain()).toMatchObject({ ok: true, count: 60 });
      } finally {
        await other.end();
      }
    });

    it('verifies logs larger than one page (paging boundary) and reports the exact break', async () => {
      const pool = createSchemaPool();
      const log = new PgAuditLog(pool, clock);
      for (let i = 0; i < 1030; i++)
        await log.append({ actor: { type: 'system' }, action: 'bulk' });
      expect(await log.verifyChain()).toMatchObject({ ok: true, count: 1030 });
      // An attacker with superuser access disables the trigger and edits an old row.
      await pool.query('ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update');
      await pool.query("UPDATE audit_events SET reason = 'edited' WHERE seq = 1001");
      await pool.query('ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update');
      expect(await log.verifyChain()).toMatchObject({
        ok: false,
        brokenAtSeq: 1001,
        reason: expect.stringContaining('hash mismatch'),
      });
    }, 60_000);

    it('the database itself refuses to rewrite history', async () => {
      const pool = createSchemaPool();
      const log = new PgAuditLog(pool, clock);
      await log.append({ actor: { type: 'system' }, action: 'x' });
      await expect(pool.query("UPDATE audit_events SET action = 'y'")).rejects.toThrow(
        /append-only/,
      );
      await expect(pool.query('DELETE FROM audit_events')).rejects.toThrow(/append-only/);
    });
  });

  it('audit_anchors is append-only at the database level', async () => {
    const pool = createSchemaPool();
    const store = new PgAnchorStore(pool);
    await store.record({
      id: 'anc_1',
      createdAt: new Date('2026-01-01T00:00:00Z'),
      anchor: 'a'.repeat(64),
      chains: 1,
      events: 3,
      destination: 'https://w.example/a',
      status: 'published',
      receipt: null,
      error: null,
    });
    await expect(pool.query("UPDATE audit_anchors SET status = 'failed'")).rejects.toThrow(
      /append-only/,
    );
    await expect(pool.query('DELETE FROM audit_anchors')).rejects.toThrow(/append-only/);
    await expect(pool.query('TRUNCATE audit_anchors')).rejects.toThrow(/append-only/);
    await expect(
      pool.query(
        "INSERT INTO audit_anchors (id, created_at, anchor, chains, events, destination, status) VALUES ('x', now(), 'not-hex', 0, 0, 'd', 'published')",
      ),
    ).rejects.toThrow();
  });

  // ---- telemetry --------------------------------------------------------------------------
  it('telemetry sink persists only allow-listed attributes and pseudonymized security subjects', async () => {
    const pool = createSchemaPool();
    const sink = new PgTelemetrySink(pool);
    const t = new Telemetry({
      sink,
      clock: { now: () => new Date('2026-01-01T00:00:00Z') },
      pseudonymKey: 'k'.repeat(32),
    });
    await t.track('app.started', {
      app_version: '5.0.0',
      platform: 'windows',
      document_text: 'secret salary table',
    });
    await t.signal('canary_license_activated', {
      orgId: 'org_1',
      subject: 'inst_rawinstallationid',
      attributes: { license_key: 'LK-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE', ip_class: 'dc' },
    });
    await sink.flush();
    const tel = (await pool.query('SELECT * FROM telemetry_events')).rows;
    const sec = (await pool.query('SELECT * FROM security_events')).rows;
    expect(tel).toHaveLength(1);
    expect(tel[0]!.attributes).toEqual({ app_version: '5.0.0', platform: 'windows' });
    expect(sec[0]).toMatchObject({
      kind: 'canary_license_activated',
      severity: 'high',
      org_id: 'org_1',
    });
    expect(sec[0]!.subject).toMatch(/^ps_/);
    expect(JSON.stringify([tel, sec])).not.toMatch(/salary|LK-AAAAA|inst_rawinstallationid/);
  });

  it('product telemetry is batched off the request path; security signals are written immediately', async () => {
    const pool = createSchemaPool();
    const sink = new PgTelemetrySink(pool, { flushMs: 60_000, maxBatch: 5 });
    const rec = (i: number) => ({
      id: `tel_${i}`,
      occurredAt: '2026-01-01T00:00:00.000Z',
      name: 'app.started' as const,
      attributes: { n: i },
    });
    const count = async () =>
      (await pool.query('SELECT count(*)::int AS n FROM telemetry_events')).rows[0]!.n as number;
    for (let i = 0; i < 4; i++) await sink.recordTelemetry(rec(i));
    expect(await count()).toBe(0); // buffered, not yet a round trip
    await sink.recordSecurity({
      id: 'sec_1',
      occurredAt: '2026-01-01T00:00:00.000Z',
      kind: 'challenge_replay',
      severity: 'medium',
      orgId: null,
      subject: null,
      attributes: {},
    } as never);
    expect((await pool.query('SELECT count(*)::int AS n FROM security_events')).rows[0]!.n).toBe(1);
    await sink.recordTelemetry(rec(4)); // reaches maxBatch: flushed
    await sink.flush();
    expect(await count()).toBe(5);
    await sink.recordTelemetry(rec(5));
    await sink.flush(); // shutdown drain
    expect(await count()).toBe(6);
    expect(sink.dropped).toBe(0);
  });

  it('a failing telemetry batch is counted and dropped; it never fails a caller', async () => {
    const pool = createSchemaPool();
    const sink = new PgTelemetrySink(pool, { flushMs: 60_000 });
    await sink.recordTelemetry({
      id: 'tel_dup',
      occurredAt: '2026-01-01T00:00:00.000Z',
      name: 'app.started',
      attributes: {},
    } as never);
    await sink.recordTelemetry({
      id: 'tel_dup',
      occurredAt: '2026-01-01T00:00:00.000Z',
      name: 'app.started',
      attributes: {},
    } as never); // PK violation
    await expect(sink.flush()).resolves.toBeUndefined();
    expect(sink.dropped).toBe(2);
  });

  // ---- keys & durability across restarts ------------------------------------------------------
  describe('container restart (durability)', () => {
    const pem = () =>
      generateEd25519().privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const cfg = (signingKeyPem: string) => ({
      ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv),
      signingKeyPem,
      scrypt: { N: 1024, r: 8, p: 1 },
    });

    it('accounts, licenses, activations, audit chain and the signing key survive a restart; old leases still verify', async () => {
      const pool = createSchemaPool();
      const key = pem();
      const c1 = await createContainer(cfg(key), { pool });
      await c1.auth.register({ email: 'a@example.test', password: 'correct horse battery' });
      const kid1 = c1.keyring.activeKeyId('license');
      const auditBefore = (await c1.audit.verifyChain()) as { count: number };
      await c1.close();

      const c2 = await createContainer(cfg(key), { pool });
      expect(c2.keyring.activeKeyId('license')).toBe(kid1); // same key, same kid
      expect(
        (await c2.auth.login({ email: 'a@example.test', password: 'correct horse battery' }))
          .userId,
      ).toMatch(/^usr_/);
      expect(await c2.audit.verifyChain()).toMatchObject({ ok: true });
      expect(((await c2.audit.verifyChain()) as { count: number }).count).toBeGreaterThan(
        auditBefore.count,
      );
      expect(await new PgKeyStore(pool).list()).toHaveLength(1);
      await c2.close();
    });

    it('rotating the configured key persists the old one as deprecated (verify-only) and the new one as active', async () => {
      const pool = createSchemaPool();
      const k1 = pem();
      const k2 = pem();
      const c1 = await createContainer(cfg(k1), { pool });
      const kid1 = c1.keyring.activeKeyId('license');
      await c1.close();
      const c2 = await createContainer(cfg(k2), { pool });
      const kid2 = c2.keyring.activeKeyId('license');
      expect(kid2).not.toBe(kid1);
      expect(c2.keyring.get(kid1)?.state).toBe('deprecated');
      expect(
        c2.keyring
          .trustBundle('license')
          .keys.map((k) => k.kid)
          .sort(),
      ).toEqual([kid1, kid2].sort());
      await c2.close();
      const states = Object.fromEntries(
        (await new PgKeyStore(pool).list()).map((r) => [r.kid, r.state]),
      );
      expect(states).toEqual({ [kid1]: 'deprecated', [kid2]: 'active' });
      // Restarting with the OLD key configured must refuse: it was rotated out.
      await expect(createContainer(cfg(k1), { pool })).rejects.toThrow(/rotated out/);
    });

    it('refuses to start with a signing key that was revoked', async () => {
      const pool = createSchemaPool();
      const k1 = pem();
      const c1 = await createContainer(cfg(k1), { pool });
      c1.keyring.revoke(c1.keyring.activeKeyId('license'), 'compromise drill');
      await c1.close(); // flushes the persisted state
      await expect(createContainer(cfg(k1), { pool })).rejects.toThrow(/is revoked/);
      expect(
        (
          await pool.query(
            "SELECT count(*)::int AS n FROM audit_events WHERE action = 'key.revoke'",
          )
        ).rows[0]!.n,
      ).toBe(1);
    });

    it('does not start against a database whose migrations are missing', async () => {
      const bare = new pg.Pool({ connectionString: url, max: 1 });
      try {
        await expect(
          createContainer({ ...cfg(pem()), persistence: 'postgres', databaseUrl: url }, {}),
        ).rejects.toThrow(/migrat/);
      } finally {
        await bare.end();
      }
    });
  });

  // ---- R-14: deadlocks are retried; R-10: audit is atomic with the change -------------------------------
  describe('shared license lock and retention indexes (found by load testing)', () => {
    async function oneLicense() {
      const pool = createSchemaPool();
      const store = new PgLicensingStore(pool, { now: () => new Date('2026-01-01T00:00:00Z') });
      await pool.query("INSERT INTO organizations (id,name,kind) VALUES ('org_s','S','team')");
      await pool.query("INSERT INTO products (id,code,name) VALUES ('prd_s','prod-s','P')");
      await pool.query(
        "INSERT INTO plans (id,product_id,code,tier,device_limit) VALUES ('pln_s','prd_s','plan-s','professional',3)",
      );
      await pool.query(
        "INSERT INTO licenses (id,org_id,product_id,plan_id,kind,key_hash) VALUES ('lic_s','org_s','prd_s','pln_s','perpetual','h')",
      );
      return { pool, store };
    }

    it.each([
      ['findLicenseForShare / findLicenseForUpdate', 'legacy'],
      ['findLicenseContext(share) / findLicenseContext(update)', 'context'],
    ] as const)(
      'FOR SHARE holders coexist; an exclusive (FOR UPDATE) locker waits for all of them: %s',
      async (_n, api) => {
        const { store } = await oneLicense();
        type Tx = Parameters<Parameters<typeof store.transaction>[0]>[0];
        const share = (tx: Tx) =>
          api === 'legacy'
            ? tx.findLicenseForShare('org_s', 'lic_s')
            : tx.findLicenseContext('org_s', 'lic_s', 'share');
        const exclusive = (tx: Tx) =>
          api === 'legacy'
            ? tx.findLicenseForUpdate('org_s', 'lic_s')
            : tx.findLicenseContext('org_s', 'lic_s', 'update');
        const order: string[] = [];
        let releaseA!: () => void;
        const aHolds = new Promise<void>((r) => (releaseA = r));
        let aLocked!: () => void;
        const aReady = new Promise<void>((r) => (aLocked = r));

        const a = store.transaction(async (tx) => {
          await share(tx);
          order.push('A:locked');
          aLocked();
          await aHolds;
          order.push('A:done');
        });
        await aReady;
        // B shares the lock while A still holds it: must complete without waiting for A.
        await store.transaction(async (tx) => {
          await share(tx);
          order.push('B:shared-ok');
        });
        // C wants it exclusively: must NOT get it while A holds its shared lock.
        let cGotIt = false;
        const c = store.transaction(async (tx) => {
          await exclusive(tx);
          cGotIt = true;
          order.push('C:exclusive');
        });
        await new Promise((r) => setTimeout(r, 300));
        expect(cGotIt).toBe(false);
        releaseA();
        await Promise.all([a, c]);
        expect(order).toEqual(['A:locked', 'B:shared-ok', 'A:done', 'C:exclusive']);
      },
      20_000,
    );

    it('the retention DELETE uses the expires_at index instead of scanning the table', async () => {
      const { pool } = await oneLicense();
      await pool.query(
        `INSERT INTO challenges (nonce_hash, purpose, installation_id, expires_at, consumed_at)
         SELECT 'n' || g, 'refresh', 'inst_x', now() + interval '1 day' + (g || ' seconds')::interval, now()
         FROM generate_series(1, 30000) g`,
      );
      await pool.query('ANALYZE challenges');
      const plan = (
        await pool.query(
          "EXPLAIN DELETE FROM challenges WHERE ctid IN (SELECT ctid FROM challenges WHERE expires_at < now() - interval '1 hour' LIMIT 5000)",
        )
      ).rows
        .map((r) => r['QUERY PLAN'])
        .join('\n');
      expect(plan).toMatch(/challenges_expires_idx/);
      expect(plan).not.toMatch(/Seq Scan on challenges\s+challenges_1/);
    });
  });

  describe('deadlock retry and atomic audit', () => {
    const NOW = new Date('2026-01-01T00:00:00Z');
    const clock2 = { now: () => NOW };

    async function twoLicenses() {
      const pool = createSchemaPool();
      const store = new PgLicensingStore(pool, clock2);
      await pool.query("INSERT INTO organizations (id,name,kind) VALUES ('org_d','D','team')");
      await pool.query("INSERT INTO products (id,code,name) VALUES ('prd_d','prod-d','P')");
      await pool.query(
        "INSERT INTO plans (id,product_id,code,tier,device_limit) VALUES ('pln_d','prd_d','plan-d','professional',3)",
      );
      for (const id of ['lic_d1', 'lic_d2']) {
        await pool.query(
          "INSERT INTO licenses (id,org_id,product_id,plan_id,kind,key_hash) VALUES ($1,'org_d','prd_d','pln_d','perpetual',$1)",
          [id],
        );
      }
      return { pool, store };
    }

    it('a real PostgreSQL deadlock (opposite lock order) is retried and BOTH transactions succeed', async () => {
      const { pool, store } = await twoLicenses();
      let arrived = 0;
      let release!: () => void;
      const bothHoldFirstLock = new Promise<void>((r) => (release = r));
      const attempts = { a: 0, b: 0 };

      const run = (name: 'a' | 'b', first: string, second: string) =>
        store.transaction(async (tx) => {
          attempts[name]++;
          await tx.findLicenseForUpdate('org_d', first);
          if (attempts[name] === 1) {
            // Only on the first attempt: wait until the other side holds ITS first lock => guaranteed deadlock.
            if (++arrived === 2) release();
            await bothHoldFirstLock;
          }
          await tx.findLicenseForUpdate('org_d', second);
          await tx.audit.append({ actor: { type: 'system' }, action: `tx.${name}` });
          return name;
        });

      const res = await Promise.all([run('a', 'lic_d1', 'lic_d2'), run('b', 'lic_d2', 'lic_d1')]);
      expect(res.sort()).toEqual(['a', 'b']);
      expect(attempts.a + attempts.b).toBeGreaterThanOrEqual(3); // the deadlock victim ran again
      // Audit from the aborted attempt did not leak: exactly one event per transaction.
      const audited = (await pool.query('SELECT action FROM audit_events ORDER BY gseq')).rows
        .map((r) => r.action)
        .sort();
      expect(audited).toEqual(['tx.a', 'tx.b']);
      expect(await new PgAuditLog(pool, clock2).verifyChain()).toMatchObject({
        ok: true,
        count: 2,
      });
    }, 30_000);

    it('without retry the same scenario fails with SQLSTATE 40P01 (proves the test really deadlocks)', async () => {
      const { pool } = await twoLicenses();
      const a = await pool.connect();
      const b = await pool.connect();
      try {
        await a.query('BEGIN');
        await b.query('BEGIN');
        await a.query("SELECT 1 FROM licenses WHERE id='lic_d1' FOR UPDATE");
        await b.query("SELECT 1 FROM licenses WHERE id='lic_d2' FOR UPDATE");
        const pa = a.query("SELECT 1 FROM licenses WHERE id='lic_d2' FOR UPDATE");
        const pb = b.query("SELECT 1 FROM licenses WHERE id='lic_d1' FOR UPDATE");
        const settled = await Promise.allSettled([pa, pb]);
        const codes = settled.map((r) =>
          r.status === 'rejected' ? (r.reason as { code?: string }).code : 'ok',
        );
        expect(codes).toContain('40P01');
      } finally {
        await a.query('ROLLBACK').catch(() => undefined);
        await b.query('ROLLBACK').catch(() => undefined);
        a.release();
        b.release();
      }
    }, 30_000);

    it('if the audit insert fails, the service-level change does not happen (no unaudited changes)', async () => {
      const pool = createSchemaPool();
      const c = await createContainer(
        {
          ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv),
          scrypt: { N: 1024, r: 8, p: 1 },
        },
        { pool },
      );
      try {
        await c.auth.register({ email: 'op@example.test', password: 'correct horse battery' });
        // Break auditing at the database level.
        await pool.query(
          `CREATE FUNCTION fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$`,
        );
        await pool.query(
          'CREATE TRIGGER fail_audit_t BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_audit()',
        );

        await expect(
          c.licensing.createProduct(
            { code: 'unaudited', name: 'X' },
            { id: 'usr_op', reason: 'test change' },
          ),
        ).rejects.toThrow(/audit unavailable/);
        expect(
          (await pool.query("SELECT count(*)::int AS n FROM products WHERE code='unaudited'"))
            .rows[0]!.n,
        ).toBe(0);

        const before = (await pool.query('SELECT count(*)::int AS n FROM users')).rows[0]!.n;
        await expect(
          c.auth.register({ email: 'new@example.test', password: 'correct horse battery' }),
        ).rejects.toThrow(/audit unavailable/);
        // register is atomic: no user, no personal org, no membership left behind
        expect((await pool.query('SELECT count(*)::int AS n FROM users')).rows[0]!.n).toBe(before);
        expect(
          (await pool.query("SELECT count(*)::int AS n FROM organizations WHERE kind='personal'"))
            .rows[0]!.n,
        ).toBe(1);
        expect((await pool.query('SELECT count(*)::int AS n FROM memberships')).rows[0]!.n).toBe(1);
      } finally {
        await c.close();
      }
    });
  });
});

describe.skipIf(!url)(
  'audit chain under heavy cross-connection contention (guards the one-round-trip lock+head read)',
  () => {
    it('240 concurrent appends from 4 independent pools produce one gap-free, fork-free chain', async () => {
      const first = createSchemaPool();
      await first.query('SELECT 1');
      const schema = (await first.query('SHOW search_path')).rows[0]!.search_path as string;
      const extra = Array.from(
        { length: 3 },
        () => new pg.Pool({ connectionString: url, max: 8, options: `-c search_path=${schema}` }),
      );
      const pools = [first, ...extra];
      const clock = { now: () => new Date('2026-01-01T00:00:00Z') };
      try {
        const logs = pools.map((p) => new PgAuditLog(p as never, clock));
        await Promise.all(
          Array.from({ length: 240 }, (_, i) =>
            logs[i % 4]!.appendMany([
              { actor: { type: 'system' }, action: `e${i}.a` },
              { actor: { type: 'system' }, action: `e${i}.b` },
            ]),
          ),
        );
        expect(await logs[0]!.verifyChain()).toMatchObject({ ok: true, count: 480 });
        const seqs = (await first.query('SELECT seq FROM audit_events ORDER BY gseq')).rows.map(
          (r) => Number(r.seq),
        );
        expect(seqs).toEqual(Array.from({ length: 480 }, (_, i) => i + 1));
        // each appendMany run stayed contiguous
        const acts = (await first.query('SELECT action FROM audit_events ORDER BY gseq')).rows.map(
          (r) => r.action as string,
        );
        for (let i = 0; i < 240; i++) expect(acts[acts.indexOf(`e${i}.a`) + 1]).toBe(`e${i}.b`);
      } finally {
        await Promise.all(extra.map((p) => p.end()));
      }
    }, 60_000);
  },
);
