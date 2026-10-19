import { expect, it } from 'vitest';
import { createSchemaPool, appRoleMode } from '../../../tests/support/pg.ts';
import { credentialStoreContract } from '../../../packages/operations/test/credential-store-contract.ts';
import { application } from '../../../packages/operations/test/store-contract.ts';
import { CredentialService, type CredentialRecord, type CredentialScope } from '@trust/operations';
import { PgInventoryStore } from '../src/db/pg-operations-store.ts';
const clock = { now: () => new Date('2026-10-19T00:00:00Z') };
async function seeded() {
  const pool = createSchemaPool();
  const app = application();
  await pool.query(
    "INSERT INTO users (id,email,password_hash,status,platform_role) VALUES ($1,'owner@example.test','test-only','active','none')",
    [app.ownerUserId],
  );
  await pool.query("INSERT INTO organizations (id,name,kind) VALUES ($1,'test','team')", [
    app.orgId,
  ]);
  await pool.query("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')", [
    app.orgId,
    app.ownerUserId,
  ]);
  await pool.query(
    "INSERT INTO sessions (id,user_id,token_hash,created_at,expires_at) VALUES ('test-session',$1,'test-only',$2,$3)",
    [app.ownerUserId, clock.now(), new Date(+clock.now() + 86400000)],
  );
  const store = new PgInventoryStore(pool, clock);
  const scope: CredentialScope = {
    orgId: app.orgId,
    applicationId: app.id,
    environmentId: 'ope_' + 'a'.repeat(24),
  };
  await store.transaction(app.orgId, async (tx) => {
    await tx.insert('application', app);
    await tx.insert('environment', {
      id: scope.environmentId,
      orgId: app.orgId,
      applicationId: app.id,
      code: 'staging',
      kind: 'staging',
      state: 'active',
      version: 1,
      createdAt: clock.now(),
      updatedAt: clock.now(),
    });
  });
  return { pool, store, scope, app };
}
credentialStoreContract(seeded);
it('credential rows enforce immutable ancestry and app role cannot delete verification evidence', async () => {
  const { pool, store, scope } = await seeded();
  const row: CredentialRecord = {
    ...scope,
    id: 'opc_' + 'a'.repeat(32),
    purpose: 'events:write',
    source: 'backend_report',
    secretHash: 'b'.repeat(64),
    createdAt: clock.now(),
    expiresAt: new Date(+clock.now() + 86400000),
    revokedAt: null,
    rotatedAt: null,
  };
  await expect(
    store.transaction(scope.orgId, (tx) =>
      tx.insertCredential({ ...row, environmentId: 'ope_' + 'f'.repeat(24) }),
    ),
  ).rejects.toThrow();
  await store.transaction(scope.orgId, (tx) => tx.insertCredential(row));
  await expect(
    pool.query("UPDATE operations_credentials SET source='independent_probe' WHERE id=$1", [
      row.id,
    ]),
  ).rejects.toThrow();
  if (appRoleMode())
    await expect(
      pool.query('DELETE FROM operations_credentials WHERE id=$1', [row.id]),
    ).rejects.toThrow(/permission denied/);
});
it('uses one connection for guarded verification and does not persist plaintext or a failed audit mutation', async () => {
  const { pool, store, scope, app } = await seeded();
  let failAudit = false;
  const failing = {
    query: pool.query.bind(pool),
    async connect() {
      const client = await pool.connect();
      const query = client.query.bind(client);
      return new Proxy(client, {
        get(target, key) {
          if (key === 'query')
            return async (sql: string, params?: unknown[]) => {
              if (failAudit && sql.includes('INSERT INTO audit_events'))
                throw new Error('simulated_audit_failure');
              return query(sql, params);
            };
          const v = Reflect.get(target, key);
          return typeof v === 'function' ? v.bind(target) : v;
        },
      });
    },
  };
  const guarded = new PgInventoryStore(failing, clock);
  const principal = {
    kind: 'user' as const,
    userId: app.ownerUserId,
    sessionId: 'test-session',
    platformRole: 'none' as const,
  };
  const service = new CredentialService({
    store: guarded,
    clock,
    enabled: () => true,
    authorize: async () => {},
    assertWritable: async () => {},
    stepUp: async () => {},
    sessionActive: async () => true,
  });
  const input = {
    purpose: 'events:write' as const,
    ttlSeconds: 86400,
    reason: 'initial_setup' as const,
    mfaCode: '123456',
  };
  failAudit = true;
  await expect(service.issue(principal, scope, input)).rejects.toThrow('simulated_audit_failure');
  expect(await store.listCredentials(scope, { limit: 100 })).toEqual([]);
  failAudit = false;
  const one = await service.issue(principal, scope, input);
  const raw = (await pool.query('SELECT * FROM operations_credentials')).rows;
  expect(raw).toHaveLength(1);
  expect(JSON.stringify(raw)).not.toContain(one.token.split('.')[2]);
  expect(raw[0]!.secret_hash).toHaveLength(64);
  const identity = await service.withCredential(
    one.token,
    scope,
    async (_tx, identity) => identity,
  );
  expect(identity.environmentId).toBe(scope.environmentId);
  failAudit = true;
  await expect(
    service.rotate(principal, scope, one.credential.id, { ...input, overlapSeconds: 0 }),
  ).rejects.toThrow('simulated_audit_failure');
  expect(await store.listCredentials(scope, { limit: 100 })).toHaveLength(1);
  await service.withCredential(one.token, scope, async () => true);
  await expect(service.revoke(principal, scope, one.credential.id, input)).rejects.toThrow(
    'simulated_audit_failure',
  );
  failAudit = false;
  await service.withCredential(one.token, scope, async () => true);
  await pool.query("UPDATE sessions SET revoked_at=$1 WHERE id='test-session'", [clock.now()]);
  await expect(service.issue(principal, scope, input)).rejects.toMatchObject({
    code: 'unauthenticated',
  });
});
