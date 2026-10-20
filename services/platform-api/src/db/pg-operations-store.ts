import { PgPostureRepo } from './pg-operations-posture.ts';
import { roleAllows } from '@trust/auth';
import { DomainError, type OrgRole } from '@trust/shared-types';
import { AuditBuffer } from '@trust/audit';
import type {
  CredentialRecord,
  CredentialScope,
  CredentialListOptions,
  InventoryAuthority,
  InventoryEntities,
  InventoryRepo,
  InventoryScope,
  InventoryStore,
  InventoryTx,
  InventoryType,
  Incident,
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
    async sessionActive(p, now) {
      return (
        (
          await q.query(
            'SELECT 1 FROM sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>$3',
            [p.sessionId, p.userId, now],
          )
        ).rows.length > 0
      );
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
const credentialFrom = (r: Record<string, unknown>): CredentialRecord => ({
  id: r.id as string,
  orgId: r.org_id as string,
  applicationId: r.application_id as string,
  environmentId: r.environment_id as string,
  purpose: r.purpose as 'events:write',
  source: r.source as 'backend_report',
  secretHash: r.secret_hash as string,
  createdAt: new Date(r.created_at as Date),
  expiresAt: new Date(r.expires_at as Date),
  revokedAt: r.revoked_at ? new Date(r.revoked_at as Date) : null,
  rotatedAt: r.rotated_at ? new Date(r.rotated_at as Date) : null,
});
const incidentFields = [
  'id',
  'orgId',
  'applicationId',
  'environmentId',
  'componentId',
  'source',
  'ruleId',
  'severity',
  'state',
  'assigneeUserId',
  'createdByUserId',
  'version',
  'createdAt',
  'updatedAt',
  'acknowledgedAt',
  'resolvedAt',
] as const;
function incidentFrom(r: Record<string, unknown>): Incident {
  const row = Object.fromEntries(incidentFields.map((f) => [f, r[column(f)]]));
  for (const f of ['createdAt', 'updatedAt', 'acknowledgedAt', 'resolvedAt'])
    if (row[f]) row[f] = new Date(row[f] as Date);
  if (!row.ruleId) delete row.ruleId;
  row.version = Number(row.version);
  return row as unknown as Incident;
}
class Repo extends PgPostureRepo implements InventoryRepo {
  readonly #q: Queryable;
  constructor(q: Queryable) {
    super(q);
    this.#q = q;
  }
  async findIncident(orgId: string, id: string) {
    const r = await this.#q.query('SELECT * FROM operations_incidents WHERE org_id=$1 AND id=$2', [
      orgId,
      id,
    ]);
    return r.rows[0] ? incidentFrom(r.rows[0]) : undefined;
  }
  async listIncidents(scope: CredentialScope, options: { limit: number; after?: string }) {
    const r = await this.#q.query(
      'SELECT * FROM operations_incidents WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND ($4::text IS NULL OR id>$4) ORDER BY id LIMIT $5',
      [scope.orgId, scope.applicationId, scope.environmentId, options.after ?? null, options.limit],
    );
    return r.rows.map(incidentFrom);
  }
  async insertIncident(row: Incident) {
    await this.#q.query(
      `INSERT INTO operations_incidents (${incidentFields.map(column).join(',')}) VALUES (${incidentFields.map((_, i) => '$' + (i + 1)).join(',')})`,
      incidentFields.map((f) => row[f]),
    );
  }
  async updateIncident(row: Incident, expectedVersion: number) {
    const params = [...incidentFields.map((f) => row[f]), expectedVersion];
    const r = await this.#q.query(
      `UPDATE operations_incidents SET ${incidentFields.map((f, i) => `${column(f)}=$${i + 1}`).join(',')} WHERE id=$1 AND org_id=$2 AND version=$${params.length}`,
      params,
    );
    if (r.rowCount !== 1) throw new Error('incident_version');
  }
  async findCredential(id: string) {
    const result = await this.#q.query('SELECT * FROM operations_credentials WHERE id=$1', [id]);
    return result.rows[0] ? credentialFrom(result.rows[0] as Record<string, unknown>) : undefined;
  }
  async listCredentials(scope: CredentialScope, options: CredentialListOptions) {
    const result = await this.#q.query(
      'SELECT * FROM operations_credentials WHERE org_id=$1 AND application_id=$2 AND environment_id=$3 AND ($4::text IS NULL OR id>$4) AND ($5::timestamptz IS NULL OR (revoked_at IS NULL AND expires_at>$5)) ORDER BY id COLLATE "C" LIMIT $6',
      [
        scope.orgId,
        scope.applicationId,
        scope.environmentId,
        options.after ?? null,
        options.activeAt ?? null,
        options.limit,
      ],
    );
    return result.rows.map((r) => credentialFrom(r as Record<string, unknown>));
  }
  async insertCredential(row: CredentialRecord) {
    await this.#q.query(
      'INSERT INTO operations_credentials (id,org_id,application_id,environment_id,purpose,source,secret_hash,created_at,expires_at,revoked_at,rotated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [
        row.id,
        row.orgId,
        row.applicationId,
        row.environmentId,
        row.purpose,
        row.source,
        row.secretHash,
        row.createdAt,
        row.expiresAt,
        row.revokedAt,
        row.rotatedAt,
      ],
    );
  }
  async updateCredential(row: CredentialRecord) {
    const result = await this.#q.query(
      'UPDATE operations_credentials SET org_id=$2,application_id=$3,environment_id=$4,purpose=$5,source=$6,secret_hash=$7,created_at=$8,expires_at=$9,revoked_at=$10,rotated_at=$11 WHERE id=$1',
      [
        row.id,
        row.orgId,
        row.applicationId,
        row.environmentId,
        row.purpose,
        row.source,
        row.secretHash,
        row.createdAt,
        row.expiresAt,
        row.revokedAt,
        row.rotatedAt,
      ],
    );
    if (result.rowCount !== 1) throw new Error('credential_missing');
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
      // eslint-disable-next-line preserve-caught-error -- Constraint details may contain tenant data; expose only the stable code.
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
