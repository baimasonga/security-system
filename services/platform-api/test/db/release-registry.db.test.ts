import { randomBytes, randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { KeyRing, signJws } from '@trust/crypto';
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
  ring.activate(b.kid);
  const now = Math.floor(clock.now().getTime() / 1000);
  const manifest = {
    schema: 1,
    product: 'registry-db',
    platform: target.platform,
    channel: target.channel,
    sequence: 26,
    version: '1.0',
    minimum_sequence: 0,
    paused: false,
    issued_at: now,
    expires: now + 300,
    artifact: {
      url: 'https://updates.example/setup.exe',
      size: 5,
      sha256: 'a'.repeat(64),
      sbom_sha256: 'b'.repeat(64),
      provenance_sha256: 'c'.repeat(64),
    },
  };
  const envelope = {
    signatures: [
      await signJws(manifest, { kid: b.kid, typ: 'trust-update-manifest+jws' }, ring.custody),
    ],
  };
  const input = { ...target, request_id: retry.request_id, envelope };
  await pool.query(`CREATE FUNCTION fail_publication_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.action='updates.release_published' THEN RAISE EXCEPTION 'synthetic publication failure' USING ERRCODE='23514'; END IF;
    RETURN NEW; END; $$`);
  await pool.query(
    'CREATE TRIGGER fail_publication_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_publication_audit()',
  );
  await expect(make().publish(productId, input, 'operator')).rejects.toMatchObject({
    code: '23514',
  });
  expect(
    await make().history(productId, {
      platform: target.platform,
      channel: target.channel,
      limit: 20,
    }),
  ).toEqual([]);
  await pool.query('DROP TRIGGER fail_publication_audit ON audit_events');
  await Promise.all(Array.from({ length: 8 }, () => make().publish(productId, input, 'operator')));
  expect(
    await make().current(productId, { platform: target.platform, channel: target.channel }),
  ).toEqual(envelope);
  expect(
    await make().history(productId, {
      platform: target.platform,
      channel: target.channel,
      limit: 20,
    }),
  ).toHaveLength(1);
  await expect(
    pool.query('UPDATE update_publications SET sequence=99 WHERE product_id=$1', [productId]),
  ).rejects.toMatchObject({ code: '23514' });
  await expect(
    pool.query('DELETE FROM update_publications WHERE product_id=$1', [productId]),
  ).rejects.toMatchObject({ code: '23514' });
});
