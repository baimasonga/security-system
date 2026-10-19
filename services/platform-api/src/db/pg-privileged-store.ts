import { AuditBuffer } from '@trust/audit';
import type {
  Freeze,
  PrivilegedRepo,
  PrivilegedRequest,
  PrivilegedStore,
  PrivilegedTx,
  StoredStatus,
} from '@trust/privileged';
import type { Clock } from '@trust/shared-types';
import { appendAuditInTx } from './pg-audit-log.ts';
import {
  UNIQUE_VIOLATION,
  pgErr,
  serialized,
  withTransaction,
  type PgPool,
  type Queryable,
} from './pg.ts';

// Privileged operations (ADR-022). SQL is built only from these constants, never from request input.
const COLS = [
  'id',
  'operation',
  'org_id',
  'target_id',
  'reason',
  'requested_by',
  'created_at',
  'expires_at',
  'status',
  'decided_by',
  'decided_at',
  'decision_reason',
  'break_glass',
  'witnessed_at',
  'witness_anchor',
  'execute_before',
  'executed_at',
  'failure',
] as const;
const MUTABLE = COLS.filter(
  (c) =>
    ![
      'id',
      'operation',
      'org_id',
      'target_id',
      'reason',
      'requested_by',
      'created_at',
      'expires_at',
    ].includes(c),
);

type Row = Record<(typeof COLS)[number], unknown>;
const d = (v: unknown) => (v === null ? null : new Date(v as string | Date));

function fromRow(r: Row): PrivilegedRequest {
  return {
    id: r.id as string,
    operation: r.operation as PrivilegedRequest['operation'],
    orgId: (r.org_id as string | null) ?? null,
    targetId: (r.target_id as string | null) ?? null,
    reason: r.reason as string,
    requestedBy: r.requested_by as string,
    createdAt: d(r.created_at)!,
    expiresAt: d(r.expires_at)!,
    status: r.status as StoredStatus,
    decidedBy: (r.decided_by as string | null) ?? null,
    decidedAt: d(r.decided_at),
    decisionReason: (r.decision_reason as string | null) ?? null,
    breakGlass: r.break_glass as boolean,
    witnessedAt: d(r.witnessed_at),
    witnessAnchor: (r.witness_anchor as string | null) ?? null,
    executeBefore: d(r.execute_before),
    executedAt: d(r.executed_at),
    failure: (r.failure as string | null) ?? null,
  };
}

function toValues(r: PrivilegedRequest): Row {
  return {
    id: r.id,
    operation: r.operation,
    org_id: r.orgId,
    target_id: r.targetId,
    reason: r.reason,
    requested_by: r.requestedBy,
    created_at: r.createdAt,
    expires_at: r.expiresAt,
    status: r.status,
    decided_by: r.decidedBy,
    decided_at: r.decidedAt,
    decision_reason: r.decisionReason,
    break_glass: r.breakGlass,
    witnessed_at: r.witnessedAt,
    witness_anchor: r.witnessAnchor,
    execute_before: r.executeBefore,
    executed_at: r.executedAt,
    failure: r.failure,
  };
}

const freezeOf = (r: Record<string, unknown>): Freeze => ({
  scope: r['scope'] as string,
  reason: r['reason'] as string,
  frozenBy: r['frozen_by'] as string,
  frozenAt: new Date(r['frozen_at'] as string | Date),
});

class PgPrivilegedRepo implements PrivilegedRepo {
  readonly #q: Queryable;
  constructor(q: Queryable) {
    this.#q = q;
  }

  async insertRequest(r: PrivilegedRequest) {
    const v = toValues(r);
    await this.#q.query(
      `INSERT INTO privileged_requests (${COLS.join(',')}) VALUES (${COLS.map((_, i) => `$${i + 1}`).join(',')})`,
      COLS.map((c) => v[c]),
    );
  }
  async findRequest(id: string) {
    const r = await this.#q.query(
      `SELECT ${COLS.join(',')} FROM privileged_requests WHERE id = $1`,
      [id],
    );
    return r.rows[0] ? fromRow(r.rows[0] as Row) : undefined;
  }
  async findRequestForUpdate(id: string) {
    const r = await this.#q.query(
      `SELECT ${COLS.join(',')} FROM privileged_requests WHERE id = $1 FOR UPDATE`,
      [id],
    );
    return r.rows[0] ? fromRow(r.rows[0] as Row) : undefined;
  }
  async updateRequest(r: PrivilegedRequest) {
    const v = toValues(r);
    await this.#q.query(
      `UPDATE privileged_requests SET ${MUTABLE.map((c, i) => `${c} = $${i + 2}`).join(', ')} WHERE id = $1`,
      [r.id, ...MUTABLE.map((c) => v[c])],
    );
  }
  async listRequests(filter: { status?: StoredStatus; limit: number }) {
    const limit = Math.max(1, Math.min(200, Math.floor(filter.limit)));
    const r = filter.status
      ? await this.#q.query(
          `SELECT ${COLS.join(',')} FROM privileged_requests WHERE status = $1 ORDER BY created_at DESC, id DESC LIMIT ${limit}`,
          [filter.status],
        )
      : await this.#q.query(
          `SELECT ${COLS.join(',')} FROM privileged_requests ORDER BY created_at DESC, id DESC LIMIT ${limit}`,
        );
    return r.rows.map((x) => fromRow(x as Row));
  }
  async countBreakGlassSince(userId: string, since: Date) {
    const r = await this.#q.query(
      'SELECT count(*)::int AS n FROM privileged_requests WHERE break_glass AND decided_by = $1 AND decided_at >= $2',
      [userId, since],
    );
    return (r.rows[0] as { n: number }).n;
  }
  async getFreeze(scope: string) {
    const r = await this.#q.query('SELECT * FROM privileged_freezes WHERE scope = $1', [scope]);
    return r.rows[0] ? freezeOf(r.rows[0] as Record<string, unknown>) : undefined;
  }
  async insertFreeze(f: Freeze) {
    try {
      await this.#q.query(
        'INSERT INTO privileged_freezes (scope, reason, frozen_by, frozen_at) VALUES ($1,$2,$3,$4)',
        [f.scope, f.reason, f.frozenBy, f.frozenAt],
      );
    } catch (e) {
      // eslint-disable-next-line preserve-caught-error -- Constraint details may contain tenant data; expose only the stable code.
      if (pgErr(e).code === UNIQUE_VIOLATION) throw new Error('duplicate_freeze');
      throw e;
    }
  }
  async deleteFreeze(scope: string) {
    await this.#q.query('DELETE FROM privileged_freezes WHERE scope = $1', [scope]);
  }
  async listFreezes() {
    const r = await this.#q.query('SELECT * FROM privileged_freezes ORDER BY frozen_at, scope');
    return r.rows.map((x) => freezeOf(x as Record<string, unknown>));
  }
}

export class PgPrivilegedStore extends PgPrivilegedRepo implements PrivilegedStore {
  readonly #pool: PgPool;
  readonly #clock: Clock;
  readonly #auditShards: number;
  constructor(pool: PgPool, clock: Clock, opts?: { auditShards?: number }) {
    super(pool);
    this.#pool = pool;
    this.#clock = clock;
    this.#auditShards = opts?.auditShards ?? 1;
  }

  transaction<T>(fn: (tx: PrivilegedTx) => Promise<T>): Promise<T> {
    return withTransaction(this.#pool, async (client) => {
      const buffer = new AuditBuffer(); // fresh per attempt (see withTransaction retry contract)
      const tx = Object.assign(new PgPrivilegedRepo(serialized(client)), {
        audit: buffer,
      }) as unknown as PrivilegedTx;
      const out = await fn(tx);
      await appendAuditInTx(client, this.#clock, buffer.drain(), this.#auditShards);
      return out;
    });
  }
}
