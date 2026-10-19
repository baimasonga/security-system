import { roleAllows } from '@trust/auth';
import { DomainError, type OrgRole } from '@trust/shared-types';
import { AuditBuffer } from '@trust/audit';
import type {
  InventoryAuthority,
  InventoryEntities,
  InventoryRepo,
  InventoryScope,
  InventoryStore,
  InventoryTx,
  InventoryType,
} from '@trust/operations';
import type { Clock } from '@trust/shared-types';
import { appendAuditInTx } from './pg-audit-log.ts';
import {
  pgErr,
  UNIQUE_VIOLATION,
  serialized,
  withTransaction,
  type PgPool,
  type Queryable,
} from './pg.ts';

const TABLES = {
  application: 'operations_applications',
  environment: 'operations_environments',
  component: 'operations_components',
} as const;
const common = ['id', 'orgId', 'code', 'state', 'version', 'createdAt', 'updatedAt'];
const FIELDS = {
  application: [...common, 'ownerUserId', 'criticality', 'productId'],
  environment: [...common, 'applicationId', 'kind'],
  component: [...common, 'applicationId', 'environmentId', 'kind', 'dependencyIds'],
};
const column = (s: string) => s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
function fromRow<K extends InventoryType>(
  type: K,
  row: Record<string, unknown>,
): InventoryEntities[K] {
  const out = Object.fromEntries(FIELDS[type].map((field) => [field, row[column(field)]]));
  out.version = Number(out.version);
  out.createdAt = new Date(out.createdAt as string | Date);
  out.updatedAt = new Date(out.updatedAt as string | Date);
  return out as unknown as InventoryEntities[K];
}
function values(type: InventoryType, row: unknown) {
  const r = row as Record<string, unknown>;
  return FIELDS[type].map((field) =>
    field === 'dependencyIds' ? JSON.stringify(r[field]) : r[field],
  );
}
function authorityFor(q: Queryable): InventoryAuthority {
  return {
    async authorize(p, orgId, permission) {
      const result = await q.query(
        "SELECT m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND m.user_id=$2 AND u.status='active'",
        [orgId, p.userId],
      );
      const row = result.rows[0] as { role: OrgRole } | undefined;
      if (!row) throw new DomainError('not_found', 'not found');
      if (!roleAllows(row.role, permission)) throw new DomainError('forbidden', 'request rejected');
    },
    async assertWritable(orgId) {
      const result = await q.query(
        "SELECT 1 FROM privileged_freezes WHERE scope IN ('platform',$1)",
        ['org:' + orgId],
      );
      if (result.rows.length) throw new DomainError('forbidden', 'request rejected');
    },
    async activeMember(orgId, userId) {
      return (
        (
          await q.query(
            "SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND m.user_id=$2 AND u.status='active'",
            [orgId, userId],
          )
        ).rows.length > 0
      );
    },
    async activeProduct(productId) {
      return (
        (await q.query("SELECT 1 FROM products WHERE id=$1 AND status='active'", [productId])).rows
          .length > 0
      );
    },
  };
}
class Repo implements InventoryRepo {
  readonly #q: Queryable;
  constructor(q: Queryable) {
    this.#q = q;
  }
  async find<K extends InventoryType>(type: K, orgId: string, id: string) {
    const result = await this.#q.query(`SELECT * FROM ${TABLES[type]} WHERE org_id=$1 AND id=$2`, [
      orgId,
      id,
    ]);
    return result.rows[0] ? fromRow(type, result.rows[0] as Record<string, unknown>) : undefined;
  }
  async list<K extends InventoryType>(type: K, scope: InventoryScope) {
    const params = [scope.orgId];
    let where = 'org_id=$1';
    if (scope.applicationId) {
      params.push(scope.applicationId);
      where += ` AND application_id=$${params.length}`;
    }
    if (scope.environmentId) {
      params.push(scope.environmentId);
      where += ` AND environment_id=$${params.length}`;
    }
    const result = await this.#q.query(
      `SELECT * FROM ${TABLES[type]} WHERE ${where} ORDER BY id COLLATE "C"`,
      params,
    );
    return result.rows.map((row) => fromRow(type, row as Record<string, unknown>));
  }
  async insert<K extends InventoryType>(type: K, row: InventoryEntities[K]) {
    try {
      await this.#q.query(
        `INSERT INTO ${TABLES[type]} (${FIELDS[type].map(column).join(',')}) VALUES (${FIELDS[type].map((_, i) => `$${i + 1}`).join(',')})`,
        values(type, row),
      );
    } catch (e) {
      if (pgErr(e).code === UNIQUE_VIOLATION) throw new Error('duplicate_inventory');
      throw e;
    }
  }
  async update<K extends InventoryType>(
    type: K,
    row: InventoryEntities[K],
    expectedVersion: number,
  ) {
    const fields = FIELDS[type];
    const params = [...values(type, row), expectedVersion];
    const result = await this.#q.query(
      `UPDATE ${TABLES[type]} SET ${fields.map((f, i) => `${column(f)}=$${i + 1}`).join(',')} WHERE id=$1 AND org_id=$2 AND version=$${params.length}`,
      params,
    );
    if (result.rowCount !== 1) throw new Error('inventory_version');
  }
}
export class PgInventoryStore extends Repo implements InventoryStore {
  readonly #pool: PgPool;
  readonly #clock: Clock;
  readonly #shards: number;
  constructor(pool: PgPool, clock: Clock, options?: { auditShards?: number }) {
    super(pool);
    this.#pool = pool;
    this.#clock = clock;
    this.#shards = options?.auditShards ?? 1;
  }
  transaction<T>(orgId: string, fn: (tx: InventoryTx) => Promise<T>): Promise<T> {
    return withTransaction(this.#pool, async (client) => {
      // One lock per organization serializes graph edits, quotas and all ancestor state transitions.
      await client.query(
        'INSERT INTO operations_accounts (org_id) VALUES ($1) ON CONFLICT DO NOTHING',
        [orgId],
      );
      await client.query('SELECT org_id FROM operations_accounts WHERE org_id=$1 FOR UPDATE', [
        orgId,
      ]);
      const buffer = new AuditBuffer();
      const q = serialized(client);
      const result = await fn(
        Object.assign(new Repo(q), { audit: buffer, authority: authorityFor(q) }),
      );
      await appendAuditInTx(client, this.#clock, buffer.drain(), this.#shards);
      return result;
    });
  }
}
