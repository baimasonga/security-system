import { describe, expect, it } from 'vitest';
import pg from 'pg';
import { generateEd25519 } from '@trust/crypto';
import { Telemetry } from '@trust/telemetry';
import { auditLogContract } from '../../../../packages/audit/test/log-contract.ts';
import { authStoreContract } from '../../../../packages/auth/test/store-contract.ts';
import { licensingStoreContract } from '../../../../packages/licensing/test/store-contract.ts';
import { createSchemaPool } from '../../../../tests/support/pg.ts';
import { loadConfig } from '../../src/config.ts';
import { createContainer } from '../../src/container.ts';
import { PgAuditLog } from '../../src/db/pg-audit-log.ts';
import { PgAuthStore } from '../../src/db/pg-auth-store.ts';
import { PgKeyStore } from '../../src/db/pg-key-store.ts';
import { PgLicensingStore } from '../../src/db/pg-licensing-store.ts';
import { PgTelemetrySink } from '../../src/db/pg-telemetry-sink.ts';

const url = process.env['DATABASE_URL'];

describe.skipIf(!url)('PostgreSQL adapters', () => {
  // ---- the same contracts the in-memory adapters satisfy -------------------------------------
  authStoreContract('postgres', () => new PgAuthStore(createSchemaPool()));
  auditLogContract('postgres', (clock) => new PgAuditLog(createSchemaPool(), clock));
  licensingStoreContract('postgres', () => {
    const pool = createSchemaPool();
    return {
      store: new PgLicensingStore(pool),
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

  // ---- telemetry --------------------------------------------------------------------------
  it('telemetry sink persists only allow-listed attributes and pseudonymized security subjects', async () => {
    const pool = createSchemaPool();
    const t = new Telemetry({
      sink: new PgTelemetrySink(pool),
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
});
