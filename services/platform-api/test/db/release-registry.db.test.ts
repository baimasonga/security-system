import { randomBytes, randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { KeyRing } from '@trust/crypto';
import { createSchemaPool } from '../../../../tests/support/pg.ts';
import { PgRegistryStore } from '../../src/db/pg-release-registry.ts';
import { ReleaseRegistryService } from '../../src/release-registry.ts';

it('keeps reservations durable across independent coordinators and rejects database history mutation', async () => {
  const pool = createSchemaPool();
  const productId = 'prd_' + randomBytes(12).toString('hex');
  await pool.query('INSERT INTO products(id,code,name) VALUES($1,$2,$3)', [
    productId,
    'registry-db',
    'Registry DB',
  ]);
  const clock = { now: () => new Date('2026-03-01T00:00:00Z') };
  const ring = new KeyRing();
  const a = ring.generate('license'),
    b = ring.generate('license');
  const make = () =>
    new ReleaseRegistryService(new PgRegistryStore(pool, clock), clock, async () => ({
      code: 'registry-db',
      status: 'active',
    }));
  const first = make();
  await first.register(
    productId,
    {
      root: {
        schema: 1,
        version: 1,
        expires: 1_800_000_000,
        root: { threshold: 1, keys: [{ kid: a.kid, jwk: a.publicJwk }] },
        release: { threshold: 1, keys: [{ kid: b.kid, jwk: b.publicJwk }] },
        artifact_origins: ['https://updates.example'],
      },
      reason: 'Initial root',
    },
    'operator',
  );
  const target = { platform: 'windows-x64', channel: 'stable', reason: 'Prepare release' };
  await first.addTarget(productId, target, 'operator');
  const services = [first, make(), make(), make()];
  const rows = await Promise.all(
    Array.from({ length: 24 }, (_, i) =>
      services[i % 4]!.reserve(productId, { ...target, request_id: randomUUID() }, 'operator'),
    ),
  );
  expect(rows.map((r) => r.sequence).sort((a, b) => a - b)).toEqual(
    Array.from({ length: 24 }, (_, i) => i + 1),
  );
  const request = { ...target, request_id: randomUUID() };
  expect((await make().reserve(productId, request, 'operator')).sequence).toBe(25);
  expect((await make().reserve(productId, request, 'operator')).sequence).toBe(25);
  await expect(
    pool.query('UPDATE update_reservations SET sequence=99 WHERE product_id=$1', [productId]),
  ).rejects.toMatchObject({ code: '23514' });
  await expect(
    pool.query('DELETE FROM update_reservations WHERE product_id=$1', [productId]),
  ).rejects.toMatchObject({ code: '23514' });
  await expect(
    pool.query("UPDATE update_registries SET targets='[]'::jsonb WHERE product_id=$1", [productId]),
  ).rejects.toMatchObject({ code: '23514' });
  const count = await pool.query(
    'SELECT count(*)::int AS n FROM update_reservations WHERE product_id=$1',
    [productId],
  );
  expect(count.rows[0]!.n).toBe(25);
  // Simulate failure in the audit append AFTER the counter/receipt statements.
  await pool.query(`CREATE FUNCTION fail_reservation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.action='updates.sequence_reserved' THEN RAISE EXCEPTION 'synthetic audit failure' USING ERRCODE='23514'; END IF;
    RETURN NEW; END; $$`);
  await pool.query(
    'CREATE TRIGGER fail_reservation_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_reservation_audit()',
  );
  const retry = { ...target, request_id: randomUUID() };
  await expect(make().reserve(productId, retry, 'operator')).rejects.toMatchObject({
    code: '23514',
  });
  expect((await make().read(productId)).targets[0]!.reservedSequence).toBe(25);
  await pool.query('DROP TRIGGER fail_reservation_audit ON audit_events');
  expect((await make().reserve(productId, retry, 'operator')).sequence).toBe(26);
});
