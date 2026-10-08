import {
  ChainVerifier,
  GENESIS_HASH,
  buildEvent,
  type AuditEvent,
  type AuditEventInput,
  type AuditLog,
  type ChainVerification,
} from '@trust/audit';
import type { Clock, Json } from '@trust/shared-types';
import { withTransaction, type PgPool, type Queryable } from './pg.ts';

type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

// Serializes appends so the hash chain cannot fork. Transaction-scoped: released on commit/rollback.
const AUDIT_APPEND_LOCK = 727275;
const PAGE = 1000;

function toEvent(r: Row): AuditEvent {
  return {
    seq: Number(r.seq), // bigint arrives as string
    id: r.id,
    occurredAt: (r.occurred_at as Date).toISOString(),
    actor: { type: r.actor_type, id: r.actor_id },
    action: r.action,
    target: r.target_type ? { type: r.target_type, id: r.target_id } : null,
    orgId: r.org_id,
    reason: r.reason,
    metadata: r.metadata as Record<string, Json>,
    prevHash: r.prev_hash,
    hash: r.hash,
  };
}

/**
 * Appends events to the chain using the CALLER's transaction. Takes the chain lock last (call it
 * right before COMMIT) so the lock is held as briefly as possible; it is released automatically at
 * commit/rollback. Used both by `PgAuditLog` and by store transactions (change + audit are atomic).
 */
export async function appendAuditInTx(
  q: Queryable,
  clock: Clock,
  inputs: readonly AuditEventInput[],
): Promise<AuditEvent[]> {
  if (inputs.length === 0) return [];
  await q.query('SELECT pg_advisory_xact_lock($1)', [AUDIT_APPEND_LOCK]);
  const last = (await q.query('SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1'))
    .rows[0];
  let prev = last
    ? { seq: Number(last.seq), hash: last.hash as string }
    : { seq: 0, hash: GENESIS_HASH };
  const out: AuditEvent[] = [];
  for (const input of inputs) {
    const ev = buildEvent(input, prev, clock.now());
    await q.query(
      `INSERT INTO audit_events (seq, id, occurred_at, actor_type, actor_id, action, target_type, target_id, org_id, reason, metadata, prev_hash, hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        ev.seq,
        ev.id,
        ev.occurredAt,
        ev.actor.type,
        ev.actor.id,
        ev.action,
        ev.target?.type ?? null,
        ev.target?.id ?? null,
        ev.orgId,
        ev.reason,
        ev.metadata,
        ev.prevHash,
        ev.hash,
      ],
    );
    prev = { seq: ev.seq, hash: ev.hash };
    out.push(ev);
  }
  return out;
}

export class PgAuditLog implements AuditLog {
  readonly #pool: PgPool;
  readonly #clock: Clock;
  constructor(pool: PgPool, clock: Clock) {
    this.#pool = pool;
    this.#clock = clock;
  }

  async append(input: AuditEventInput): Promise<AuditEvent> {
    return (await this.appendMany([input]))[0]!;
  }

  appendMany(inputs: readonly AuditEventInput[]): Promise<AuditEvent[]> {
    return withTransaction(this.#pool, (c) => appendAuditInTx(c, this.#clock, inputs));
  }

  async list(filter?: { orgId?: string; action?: string; limit?: number }): Promise<AuditEvent[]> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (filter?.orgId !== undefined) where.push(`org_id = $${params.push(filter.orgId)}`);
    if (filter?.action !== undefined) where.push(`action = $${params.push(filter.action)}`);
    const limit = Math.min(Math.max(filter?.limit ?? 10_000, 1), 10_000);
    // Newest `limit` events, returned oldest-first (same contract as the in-memory adapter).
    const sql = `SELECT * FROM (SELECT * FROM audit_events ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY seq DESC LIMIT ${limit}) t ORDER BY seq`;
    return (await this.#pool.query(sql, params)).rows.map(toEvent);
  }

  /** Streams the whole chain in pages; memory use is bounded regardless of log size. */
  async verifyChain(): Promise<ChainVerification> {
    const v = new ChainVerifier();
    let after = 0;
    for (;;) {
      const rows = (
        await this.#pool.query('SELECT * FROM audit_events WHERE seq > $1 ORDER BY seq LIMIT $2', [
          after,
          PAGE,
        ])
      ).rows;
      for (const r of rows) {
        const failure = v.push(toEvent(r));
        if (failure) return failure;
      }
      if (rows.length < PAGE) return v.result();
      after = Number(rows[rows.length - 1]!.seq);
    }
  }
}
