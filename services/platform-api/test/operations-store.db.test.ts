import { expect, it } from 'vitest';
import { PgInventoryStore } from '../src/db/pg-operations-store.ts';
import {
  inventoryStoreContract,
  application,
} from '../../../packages/operations/test/store-contract.ts';
import { createSchemaPool, appRoleMode } from '../../../tests/support/pg.ts';
const clock = { now: () => new Date('2026-10-19T00:00:00Z') };
async function seeded() {
  const pool = createSchemaPool();
  const row = application();
  await pool.query(
    "INSERT INTO users (id,email,password_hash,status,platform_role,created_at) VALUES ($1,'owner@example.test','test-only','active','none',now())",
    [row.ownerUserId],
  );
  await pool.query("INSERT INTO organizations (id,name,kind) VALUES ($1,'test','team')", [
    row.orgId,
  ]);
  await pool.query("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", [
    row.orgId,
    row.ownerUserId,
  ]);
  return { pool, row, store: new PgInventoryStore(pool, clock) };
}
inventoryStoreContract(async () => (await seeded()).store);
it('database enforces ancestor foreign keys and app role cannot delete tombstones', async () => {
  const { pool, row, store } = await seeded();
  await store.transaction(row.orgId, (tx) => tx.insert('application', row));
  await expect(
    pool.query(
      "INSERT INTO operations_environments (id,org_id,application_id,code,state,version,created_at,updated_at,kind) VALUES ('ope_invalid',$1,'opa_missing','production','active',1,now(),now(),'production')",
      [row.orgId],
    ),
  ).rejects.toThrow();
  if (appRoleMode()) {
    await expect(
      pool.query('DELETE FROM operations_applications WHERE id=$1', [row.id]),
    ).rejects.toThrow(/permission denied/);
    await expect(pool.query('TRUNCATE operations_applications CASCADE')).rejects.toThrow(
      /permission denied/,
    );
  }
});
it('failed audit append rolls back inventory and no audit record commits', async () => {
  const { pool, row } = await seeded();
  const failing = {
    query: pool.query.bind(pool),
    async connect() {
      const client = await pool.connect();
      const query = client.query.bind(client);
      return new Proxy(client, {
        get(target, key) {
          if (key === 'query')
            return async (sql: string, params?: unknown[]) => {
              if (sql.includes('INSERT INTO audit_events'))
                throw new Error('simulated_audit_failure');
              return query(sql, params);
            };
          const value = Reflect.get(target, key);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
  };
  const store = new PgInventoryStore(failing, clock);
  await expect(
    store.transaction(row.orgId, async (tx) => {
      await tx.insert('application', row);
      await tx.audit.append({
        actor: { type: 'system' },
        orgId: row.orgId,
        action: 'operations.application.created',
      });
    }),
  ).rejects.toThrow('simulated_audit_failure');
  expect(await store.find('application', row.orgId, row.id)).toBeUndefined();
  expect((await pool.query('SELECT count(*)::int AS n FROM audit_events')).rows[0]).toEqual({
    n: 0,
  });
});
it('transaction authority checks actual membership, active ownership and freeze on its own connection', async () => {
  const { pool, row, store } = await seeded();
  const principal = {
    kind: 'user' as const,
    userId: row.ownerUserId,
    sessionId: 'test',
    platformRole: 'none' as const,
  };
  await store.transaction(row.orgId, async (tx) => {
    expect(tx.authority).toBeDefined();
    await tx.authority!.authorize(principal, row.orgId, 'ops:manage_inventory');
    await expect(
      tx.authority!.authorize({ ...principal, userId: 'usr_missing' }, row.orgId, 'ops:read'),
    ).rejects.toMatchObject({ code: 'not_found' });
    expect(await tx.authority!.activeMember(row.orgId, row.ownerUserId)).toBe(true);
    expect(await tx.authority!.activeProduct('prd_missing')).toBe(false);
  });
  await pool.query("UPDATE users SET status='disabled' WHERE id=$1", [row.ownerUserId]);
  await store.transaction(row.orgId, async (tx) =>
    expect(await tx.authority!.activeMember(row.orgId, row.ownerUserId)).toBe(false),
  );
  await pool.query(
    "INSERT INTO privileged_freezes (scope,reason,frozen_by,frozen_at) VALUES ($1,'test freeze',$2,now())",
    ['org:' + row.orgId, row.ownerUserId],
  );
  await expect(
    store.transaction(row.orgId, (tx) => tx.authority!.assertWritable(row.orgId)),
  ).rejects.toMatchObject({ code: 'forbidden' });
});
