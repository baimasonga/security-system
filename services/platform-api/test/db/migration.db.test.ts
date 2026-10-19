import { copyFileSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { applyMigrations } from '../../src/db/migrate.ts';

const url = process.env['DATABASE_URL'];
const migrationsDir = fileURLToPath(new URL('../../migrations', import.meta.url));

describe.skipIf(!url)('PostgreSQL schema (migration 0001)', () => {
  let admin: pg.Client;
  let db: pg.Client;
  const dbName = `mig_${Date.now()}`;

  const q = (sql: string, params: unknown[] = []) => db.query(sql, params);
  /** Run a statement expecting a specific SQLSTATE (or any error when omitted). */
  async function fails(sql: string, params: unknown[] = [], code?: string) {
    // autocommit: a failed statement leaves the session usable
    try {
      await q(sql, params);
    } catch (e) {
      if (code) expect((e as { code?: string }).code).toBe(code);
      return;
    }
    throw new Error(`expected failure (${code ?? 'any'}) for: ${sql}`);
  }

  beforeAll(async () => {
    admin = new pg.Client({ connectionString: url });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    const u = new URL(url!);
    u.pathname = `/${dbName}`;
    db = new pg.Client({ connectionString: u.toString() });
    // DROP DATABASE … WITH (FORCE) in afterAll terminates sessions; a late FATAL 57P01 on a client that is
    // already closing is expected teardown noise, not a failure.
    db.on('error', () => undefined);
    await db.connect();
  });
  afterAll(async () => {
    await db?.end();
    await admin?.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin?.end();
  });

  it('applies from an empty database, then is idempotent', async () => {
    const first = await applyMigrations(db, migrationsDir);
    expect(first.applied).toEqual([
      '0001_init',
      '0002_retention_indexes',
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
    ]);
    const second = await applyMigrations(db, migrationsDir);
    expect(second).toEqual({
      applied: [],
      skipped: [
        '0001_init',
        '0002_retention_indexes',
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
      ],
    });
  });

  it('refuses to run when an applied migration file has been modified (immutable history)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'mig-'));
    for (const f of readdirSync(migrationsDir)) copyFileSync(join(migrationsDir, f), join(dir, f));
    writeFileSync(join(dir, '0001_init.sql'), '-- tampered\n', { flag: 'a' });
    await expect(applyMigrations(db, dir)).rejects.toThrow(/modified after being applied/);
  });

  // ---- fixtures -------------------------------------------------------------------------
  async function seed() {
    const s = Math.random().toString(16).slice(2, 10);
    const ids = {
      prd: `prd_${s}`,
      pln: `pln_${s}`,
      orgA: `org_a${s}`,
      orgB: `org_b${s}`,
      usr: `usr_${s}`,
    };
    await q(`INSERT INTO users (id,email,password_hash) VALUES ($1,$2,'x')`, [
      ids.usr,
      `${s}@x.test`,
    ]);
    await q(`INSERT INTO organizations (id,name,kind) VALUES ($1,'A','team'),($2,'B','team')`, [
      ids.orgA,
      ids.orgB,
    ]);
    await q(`INSERT INTO products (id,code,name) VALUES ($1,$2,'P')`, [ids.prd, `p-${s}`]);
    await q(
      `INSERT INTO plans (id,product_id,code,tier,device_limit) VALUES ($1,$2,'pro','professional',3)`,
      [ids.pln, ids.prd],
    );
    return { s, ...ids };
  }
  async function sub(id: string, org: string, plan: string) {
    await q(
      `INSERT INTO subscriptions (id,org_id,plan_id,status,current_period_end) VALUES ($1,$2,$3,'active', now()+interval '30 days')`,
      [id, org, plan],
    );
  }
  async function lic(
    id: string,
    org: string,
    f: { prd: string; pln: string },
    subId: string | null,
    hash: string,
    kind = 'subscription',
  ) {
    await q(
      `INSERT INTO licenses (id,org_id,product_id,plan_id,subscription_id,kind,key_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, org, f.prd, f.pln, subId, kind, hash],
    );
  }
  async function dev(id: string, org: string, tp: string) {
    await q(`INSERT INTO devices (id,org_id,thumbprint,public_key_jwk) VALUES ($1,$2,$3,'{}')`, [
      id,
      org,
      tp,
    ]);
  }
  const act = (id: string, org: string, l: string, d: string, status = 'active') =>
    q(
      `INSERT INTO activations (id,org_id,license_id,device_id,installation_id,activated_by,status) VALUES ($1,$2,$3,$4,'inst_x',(SELECT id FROM users LIMIT 1),$5)`,
      [id, org, l, d, status],
    );

  describe('tenant isolation by construction', () => {
    it('rejects a license in org B that references org A’s subscription', async () => {
      const f = await seed();
      await sub(`sub_${f.s}`, f.orgA, f.pln);
      await fails(
        `INSERT INTO licenses (id,org_id,product_id,plan_id,subscription_id,kind,key_hash) VALUES ('lic_x${f.s}',$1,$2,$3,$4,'subscription','h_x${f.s}')`,
        [f.orgB, f.prd, f.pln, `sub_${f.s}`],
        '23503',
      );
    });

    it('rejects an activation joining org A’s license with org B’s device (and vice versa)', async () => {
      const f = await seed();
      await sub(`sub_${f.s}`, f.orgA, f.pln);
      await lic(`lic_${f.s}`, f.orgA, f, `sub_${f.s}`, `h_${f.s}`);
      await dev(`dev_b${f.s}`, f.orgB, `tp_b${f.s}`);
      await fails(
        `INSERT INTO activations (id,org_id,license_id,device_id,installation_id,activated_by) VALUES ('act_1${f.s}',$1,$2,$3,'i',$4)`,
        [f.orgA, `lic_${f.s}`, `dev_b${f.s}`, f.usr],
        '23503',
      );
      await fails(
        `INSERT INTO activations (id,org_id,license_id,device_id,installation_id,activated_by) VALUES ('act_2${f.s}',$1,$2,$3,'i',$4)`,
        [f.orgB, `lic_${f.s}`, `dev_b${f.s}`, f.usr],
        '23503',
      );
    });

    it('rejects a lease row whose org differs from its activation’s org', async () => {
      const f = await seed();
      await sub(`sub_${f.s}`, f.orgA, f.pln);
      await lic(`lic_${f.s}`, f.orgA, f, `sub_${f.s}`, `h_${f.s}`);
      await dev(`dev_${f.s}`, f.orgA, `tp_${f.s}`);
      await act(`act_${f.s}`, f.orgA, `lic_${f.s}`, `dev_${f.s}`);
      await fails(
        `INSERT INTO leases (jti,org_id,activation_id,plan_version,issued_at,expires_at) VALUES ('lse_${f.s}',$1,$2,1,now(),now()+interval '1 day')`,
        [f.orgB, `act_${f.s}`],
        '23503',
      );
    });
  });

  describe('licensing integrity', () => {
    it('license key digests and device thumbprints are globally unique', async () => {
      const f = await seed();
      await sub(`sub_${f.s}`, f.orgA, f.pln);
      await lic(`lic_${f.s}`, f.orgA, f, `sub_${f.s}`, `h_${f.s}`);
      await fails(
        `INSERT INTO licenses (id,org_id,product_id,plan_id,subscription_id,kind,key_hash) VALUES ('lic_dup${f.s}',$1,$2,$3,$4,'subscription',$5)`,
        [f.orgA, f.prd, f.pln, `sub_${f.s}`, `h_${f.s}`],
        '23505',
      );
      await dev(`dev_${f.s}`, f.orgA, `tp_${f.s}`);
      await fails(
        `INSERT INTO devices (id,org_id,thumbprint,public_key_jwk) VALUES ('dev_dup${f.s}',$1,$2,'{}')`,
        [f.orgB, `tp_${f.s}`],
        '23505',
      ); // same key, other org
    });

    it('subscription-backed licenses must reference a subscription; perpetual/canary need none', async () => {
      const f = await seed();
      await fails(
        `INSERT INTO licenses (id,org_id,product_id,plan_id,kind,key_hash) VALUES ('lic_n${f.s}',$1,$2,$3,'subscription','h_n${f.s}')`,
        [f.orgA, f.prd, f.pln],
        '23514',
      );
      await lic(`lic_p${f.s}`, f.orgA, f, null, `h_p${f.s}`, 'perpetual');
      await lic(`lic_c${f.s}`, f.orgA, f, null, `h_c${f.s}`, 'canary');
    });

    it('allows only one ACTIVE activation per (license, device), but history and re-activation are fine', async () => {
      const f = await seed();
      await sub(`sub_${f.s}`, f.orgA, f.pln);
      await lic(`lic_${f.s}`, f.orgA, f, `sub_${f.s}`, `h_${f.s}`);
      await dev(`dev_${f.s}`, f.orgA, `tp_${f.s}`);
      await act(`act_1${f.s}`, f.orgA, `lic_${f.s}`, `dev_${f.s}`);
      await fails(
        `INSERT INTO activations (id,org_id,license_id,device_id,installation_id,activated_by) VALUES ('act_2${f.s}',$1,$2,$3,'i',$4)`,
        [f.orgA, `lic_${f.s}`, `dev_${f.s}`, f.usr],
        '23505',
      );
      await q(`UPDATE activations SET status='deactivated' WHERE id=$1`, [`act_1${f.s}`]);
      await act(`act_3${f.s}`, f.orgA, `lic_${f.s}`, `dev_${f.s}`); // re-activation after deactivation
      expect(
        (await q(`SELECT count(*)::int AS n FROM activations WHERE license_id=$1`, [`lic_${f.s}`]))
          .rows[0].n,
      ).toBe(2);
    });

    it('trial history cannot be duplicated per (product, org) or (product, user)', async () => {
      const f = await seed();
      await sub(`sub_${f.s}`, f.orgA, f.pln);
      await lic(`lic_${f.s}`, f.orgA, f, `sub_${f.s}`, `h_${f.s}`, 'trial');
      await q(
        `INSERT INTO trial_claims (product_id,org_id,user_id,license_id) VALUES ($1,$2,$3,$4)`,
        [f.prd, f.orgA, f.usr, `lic_${f.s}`],
      );
      await fails(
        `INSERT INTO trial_claims (product_id,org_id,user_id,license_id) VALUES ($1,$2,'usr_other',$3)`,
        [f.prd, f.orgA, `lic_${f.s}`],
        '23505',
      );
      await fails(
        `INSERT INTO trial_claims (product_id,org_id,user_id,license_id) VALUES ($1,$2,$3,$4)`,
        [f.prd, f.orgB, f.usr, `lic_${f.s}`],
        '23505',
      );
    });

    it('enforces value domains (tiers, statuses, purposes, lowercase emails, positive limits)', async () => {
      const f = await seed();
      await fails(
        `INSERT INTO plans (id,product_id,code,tier,device_limit) VALUES ('pln_b${f.s}',$1,'x-1','platinum',1)`,
        [f.prd],
        '23514',
      );
      await fails(
        `INSERT INTO plans (id,product_id,code,tier,device_limit) VALUES ('pln_c${f.s}',$1,'x-2','standard',0)`,
        [f.prd],
        '23514',
      );
      await fails(
        `INSERT INTO users (id,email,password_hash) VALUES ('usr_u${f.s}','UPPER@X.TEST','x')`,
        [],
        '23514',
      );
      await fails(
        `INSERT INTO challenges (nonce_hash,purpose,installation_id,expires_at) VALUES ('n${f.s}','bogus','i',now())`,
        [],
        '23514',
      );
      await fails(
        `INSERT INTO subscriptions (id,org_id,plan_id,status) VALUES ('sub_z${f.s}',$1,$2,'free-forever')`,
        [f.orgA, f.pln],
        '23514',
      );
    });

    it('permits at most one active signing key per purpose', async () => {
      const ins = (kid: string, state: string) =>
        q(
          `INSERT INTO signing_keys (kid,purpose,state,public_key_jwk) VALUES ($1,'license',$2,'{}')`,
          [kid, state],
        );
      await ins('k1', 'active');
      await fails(
        `INSERT INTO signing_keys (kid,purpose,state,public_key_jwk) VALUES ('k2','license','active','{}')`,
        [],
        '23505',
      );
      await ins('k3', 'deprecated');
      await ins('k4', 'revoked');
    });
  });

  describe('audit log is append-only', () => {
    const ev = (seq: number) =>
      q(
        `INSERT INTO audit_events (chain_id,seq,id,occurred_at,actor_type,action,prev_hash,hash) VALUES ('c',$1,$2,now(),'system','x',$3,$4)`,
        [seq, `aud_${seq}`, 'p', 'h'],
      );

    it('rejects UPDATE, DELETE and TRUNCATE', async () => {
      await ev(1);
      await ev(2);
      await fails(`UPDATE audit_events SET action='tampered' WHERE seq=1`, [], 'P0001');
      await fails(`DELETE FROM audit_events WHERE seq=1`, [], 'P0001');
      await fails(`TRUNCATE audit_events`, [], 'P0001');
      expect((await q(`SELECT count(*)::int AS n FROM audit_events`)).rows[0].n).toBe(2);
    });
  });

  describe('concurrency patterns the PostgreSQL adapter must use', () => {
    it('SELECT … FOR UPDATE on the license row makes “count then insert” respect the device limit', async () => {
      const f = await seed();
      await sub(`sub_${f.s}`, f.orgA, f.pln);
      await lic(`lic_${f.s}`, f.orgA, f, `sub_${f.s}`, `h_${f.s}`);
      const pool = new pg.Pool({
        connectionString: new URL(`/${dbName}`, url!).toString(),
        max: 12,
      });
      pool.on('error', () => undefined); // teardown noise, see afterAll
      const LIMIT = 3;
      const attempt = async (i: number): Promise<'ok' | 'limit'> => {
        const c = await pool.connect();
        try {
          await c.query('BEGIN');
          await c.query('SELECT id FROM licenses WHERE id=$1 AND org_id=$2 FOR UPDATE', [
            `lic_${f.s}`,
            f.orgA,
          ]);
          const n = (
            await c.query(
              `SELECT count(*)::int AS n FROM activations WHERE license_id=$1 AND status='active'`,
              [`lic_${f.s}`],
            )
          ).rows[0].n as number;
          if (n >= LIMIT) {
            await c.query('ROLLBACK');
            return 'limit';
          }
          await c.query(
            `INSERT INTO devices (id,org_id,thumbprint,public_key_jwk) VALUES ($1,$2,$3,'{}')`,
            [`dev_c${i}${f.s}`, f.orgA, `tp_c${i}${f.s}`],
          );
          await c.query(
            `INSERT INTO activations (id,org_id,license_id,device_id,installation_id,activated_by) VALUES ($1,$2,$3,$4,'i',$5)`,
            [`act_c${i}${f.s}`, f.orgA, `lic_${f.s}`, `dev_c${i}${f.s}`, f.usr],
          );
          await c.query('COMMIT');
          return 'ok';
        } catch (e) {
          await c.query('ROLLBACK');
          throw e;
        } finally {
          c.release();
        }
      };
      const res = await Promise.all(Array.from({ length: 12 }, (_, i) => attempt(i)));
      await pool.end();
      expect(res.filter((r) => r === 'ok')).toHaveLength(LIMIT);
      expect(res.filter((r) => r === 'limit')).toHaveLength(12 - LIMIT);
    });

    it('atomic single-use challenge consumption: exactly one concurrent UPDATE wins', async () => {
      await q(
        `INSERT INTO challenges (nonce_hash,purpose,installation_id,expires_at) VALUES ('nh_race','activate','inst_x', now()+interval '5 minutes')`,
      );
      const pool = new pg.Pool({
        connectionString: new URL(`/${dbName}`, url!).toString(),
        max: 10,
      });
      pool.on('error', () => undefined);
      const consume = () =>
        pool.query(
          `UPDATE challenges SET consumed_at=now() WHERE nonce_hash='nh_race' AND consumed_at IS NULL AND expires_at > now() RETURNING nonce_hash`,
        );
      const results = await Promise.all(Array.from({ length: 10 }, consume));
      await pool.end();
      expect(results.filter((r) => r.rowCount === 1)).toHaveLength(1);
    });
  });
});
