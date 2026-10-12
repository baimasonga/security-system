import {
  ChainVerifier,
  GENESIS_HASH,
  LEGACY_CHAIN,
  buildRun,
  checkHead,
  checkManifest,
  manifestProblem,
  orgChainPrefix,
  planAppend,
  summarize,
  type AnchorCheck,
  type AnchorManifest,
  type AuditEvent,
  type AuditEventInput,
  type AuditLog,
  type ChainHead,
  type ChainVerification,
  type VerifyOptions,
} from '@trust/audit';
import type { Clock, Json } from '@trust/shared-types';
import { observer, withTransaction, type PgPool, type Queryable } from './pg.ts';

type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const PAGE = 1000;

function toEvent(r: Row): AuditEvent {
  return {
    // Legacy (pre-partitioning) events hash WITHOUT a chain field; keep them byte-identical.
    ...(r.chain_id === LEGACY_CHAIN ? {} : { chain: r.chain_id as string }),
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

const headOf = (r: Row): ChainHead => ({ seq: Number(r.head_seq), hash: r.head_hash as string });

/**
 * Acquire each head completely in the same binary chain-id order, including creation races.
 * Locking all existing heads first and then missing heads violates that order and can deadlock.
 * Single-head appends keep their one-read fast path; multi-head batches pay one read per head.
 */
async function lockHeads(q: Queryable, chains: readonly string[]): Promise<Map<string, ChainHead>> {
  const heads = new Map<string, ChainHead>();
  for (const chain of chains) {
    const existing = await q.query(
      'SELECT chain_id, head_seq, head_hash FROM audit_chains WHERE chain_id = $1 FOR UPDATE',
      [chain],
    );
    if (existing.rows[0]) {
      heads.set(chain, headOf(existing.rows[0]));
      continue;
    }
    const ins = await q.query(
      'INSERT INTO audit_chains (chain_id, head_seq, head_hash) VALUES ($1, 0, $2) ON CONFLICT (chain_id) DO NOTHING RETURNING chain_id',
      [chain, GENESIS_HASH],
    );
    if (ins.rowCount === 1) heads.set(chain, { seq: 0, hash: GENESIS_HASH });
    else {
      // The competing creator committed. Lock its newest head before moving to the next chain.
      const current = await q.query(
        'SELECT chain_id, head_seq, head_hash FROM audit_chains WHERE chain_id = $1 FOR UPDATE',
        [chain],
      );
      heads.set(chain, headOf(current.rows[0]!));
    }
  }
  return heads;
}

/** One statement: insert every event and advance every touched head. */
const WRITE_RUN = `
WITH ins AS (
  INSERT INTO audit_events (chain_id, seq, id, occurred_at, actor_type, actor_id, action, target_type,
                            target_id, org_id, reason, metadata, prev_hash, hash)
  SELECT chain_id, seq, id, occurred_at::timestamptz, actor_type, actor_id, action, target_type,
         target_id, org_id, reason, metadata::jsonb, prev_hash, hash
  FROM unnest($1::text[], $2::bigint[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[],
              $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[])
       AS t(chain_id, seq, id, occurred_at, actor_type, actor_id, action, target_type, target_id,
            org_id, reason, metadata, prev_hash, hash)
  RETURNING 1
)
UPDATE audit_chains c
   SET head_seq = h.seq, head_hash = h.hash, updated_at = $18::timestamptz
  FROM unnest($15::text[], $16::bigint[], $17::text[]) AS h(chain_id, seq, hash)
 WHERE c.chain_id = h.chain_id`;

/**
 * Appends events to their chains using the CALLER's transaction (ADR-006/ADR-008). Call it right before COMMIT:
 * the chain locks are held only from here to the end of the transaction, and only appenders to the SAME chain
 * wait for each other. Unrelated organizations proceed in parallel.
 */
export async function appendAuditInTx(
  q: Queryable,
  clock: Clock,
  inputs: readonly AuditEventInput[],
  shards = 1,
): Promise<AuditEvent[]> {
  if (inputs.length === 0) return [];
  const plan = planAppend(inputs, shards); // validates before any lock is taken
  const chains = [...new Set(plan.map((p) => p.chain))].sort();

  const waitStart = performance.now();
  const heads = await lockHeads(q, chains);
  observer.onAuditLockWait?.(performance.now() - waitStart);

  const at = clock.now();
  const { events, newHeads } = buildRun(plan, heads, at);
  const col = <T>(f: (e: AuditEvent) => T) => events.map(f);
  const headChains = [...newHeads.keys()];
  const res = await q.query(WRITE_RUN, [
    col((e) => e.chain!),
    col((e) => e.seq),
    col((e) => e.id),
    col((e) => e.occurredAt),
    col((e) => e.actor.type),
    col((e) => e.actor.id),
    col((e) => e.action),
    col((e) => e.target?.type ?? null),
    col((e) => e.target?.id ?? null),
    col((e) => e.orgId),
    col((e) => e.reason),
    col((e) => JSON.stringify(e.metadata)),
    col((e) => e.prevHash),
    col((e) => e.hash),
    headChains,
    headChains.map((c) => newHeads.get(c)!.seq),
    headChains.map((c) => newHeads.get(c)!.hash),
    at.toISOString(),
  ]);
  if (res.rowCount !== headChains.length) throw new Error('audit head update failed');
  return events;
}

export class PgAuditLog implements AuditLog {
  readonly #pool: PgPool;
  readonly #clock: Clock;
  readonly #shards: number;
  constructor(pool: PgPool, clock: Clock, opts?: { shards?: number }) {
    this.#pool = pool;
    this.#clock = clock;
    this.#shards = opts?.shards ?? 1;
  }

  async append(input: AuditEventInput): Promise<AuditEvent> {
    return (await this.appendMany([input]))[0]!;
  }

  appendMany(inputs: readonly AuditEventInput[]): Promise<AuditEvent[]> {
    return withTransaction(this.#pool, (c) =>
      appendAuditInTx(c, this.#clock, inputs, this.#shards),
    );
  }

  async list(filter?: { orgId?: string; action?: string; limit?: number }): Promise<AuditEvent[]> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (filter?.orgId !== undefined) where.push(`org_id = $${params.push(filter.orgId)}`);
    if (filter?.action !== undefined) where.push(`action = $${params.push(filter.action)}`);
    const limit = Math.min(Math.max(filter?.limit ?? 10_000, 1), 10_000);
    // Newest `limit` events, returned oldest-first, in global insertion order (same contract as in-memory).
    const sql = `SELECT * FROM (SELECT * FROM audit_events ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY gseq DESC LIMIT ${limit}) t ORDER BY gseq`;
    return (await this.#pool.query(sql, params)).rows.map(toEvent);
  }

  /** One indexed lookup per witnessed `(chain, seq)` (primary key), done in a single statement. */
  async checkAnchor(manifest: AnchorManifest): Promise<AnchorCheck> {
    const bad = manifestProblem(manifest);
    if (bad) return { ok: false, chain: null, seq: null, reason: bad };
    const rows = (
      await this.#pool.query(
        `SELECT e.chain_id, e.seq, e.hash
           FROM unnest($1::text[], $2::bigint[]) AS w(chain_id, seq)
           JOIN audit_events e ON e.chain_id = w.chain_id AND e.seq = w.seq`,
        [manifest.chains.map((c) => c.chain), manifest.chains.map((c) => c.seq)],
      )
    ).rows;
    const stored = new Map<string, string>(
      rows.map((r) => [`${r.chain_id}\u0000${Number(r.seq)}`, r.hash as string]),
    );
    return checkManifest(manifest, (chain, seq) => stored.get(`${chain}\u0000${seq}`));
  }

  /**
   * Verifies every chain (or one organization's) AND that each chain's tail equals its stored head.
   * Runs in one REPEATABLE READ snapshot: heads and events must be read consistently while writers continue,
   * otherwise an append landing between the two reads would look like tampering. Streams in pages.
   */
  async verifyChain(opts?: VerifyOptions): Promise<ChainVerification> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      let scopeSql = '';
      const scopeParams: unknown[] = [];
      if (opts?.orgId !== undefined) {
        const base = orgChainPrefix(opts.orgId);
        scopeSql = 'WHERE (chain_id = $1 OR starts_with(chain_id, $2))';
        scopeParams.push(base, `${base}#`);
      }
      const headRows = (
        await client.query(
          `SELECT chain_id, head_seq, head_hash FROM audit_chains ${scopeSql}`,
          scopeParams,
        )
      ).rows;
      const heads = new Map<string, ChainHead>(
        headRows.map((r) => [r.chain_id as string, headOf(r)]),
      );
      const present = (
        await client.query(
          `SELECT chain_id FROM audit_events ${scopeSql} GROUP BY chain_id`,
          scopeParams,
        )
      ).rows.map((r) => r.chain_id as string);
      const chains = [...new Set([...heads.keys(), ...present])].sort();

      const verified: Array<{ chain: string; seq: number; hash: string }> = [];
      for (const chain of chains) {
        const v = new ChainVerifier(chain);
        let after = 0;
        for (;;) {
          const rows = (
            await client.query(
              'SELECT * FROM audit_events WHERE chain_id = $1 AND seq > $2 ORDER BY seq LIMIT $3',
              [chain, after, PAGE],
            )
          ).rows;
          for (const r of rows) {
            const f = v.push(toEvent(r));
            if (f) return { ok: false, ...f };
          }
          if (rows.length < PAGE) break;
          after = Number(rows[rows.length - 1]!.seq);
        }
        const bad = checkHead(chain, v.tail, heads.get(chain));
        if (bad) return { ok: false, ...bad };
        verified.push({ chain, ...v.tail });
      }
      return summarize(verified);
    } finally {
      await client.query('ROLLBACK').catch(() => undefined);
      client.release();
    }
  }
}
