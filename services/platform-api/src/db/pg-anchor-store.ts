import type { AnchorRecord, AnchorStore } from '../anchors.ts';
import type { PgPool } from './pg.ts';

type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const record = (r: Row): AnchorRecord => ({
  id: r.id,
  createdAt: r.created_at,
  anchor: r.anchor,
  chains: r.chains,
  events: Number(r.events), // bigint arrives as string
  destination: r.destination,
  status: r.status,
  receipt: r.receipt,
  error: r.error,
});

export class PgAnchorStore implements AnchorStore {
  readonly #pool: PgPool;
  constructor(pool: PgPool) {
    this.#pool = pool;
  }
  async record(r: AnchorRecord) {
    await this.#pool.query(
      'INSERT INTO audit_anchors (id, created_at, anchor, chains, events, destination, status, receipt, error) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [
        r.id,
        r.createdAt,
        r.anchor,
        r.chains,
        r.events,
        r.destination,
        r.status,
        r.receipt,
        r.error,
      ],
    );
  }
  async latest(status?: AnchorRecord['status']) {
    const res = await this.#pool.query(
      `SELECT * FROM audit_anchors ${status ? 'WHERE status = $1' : ''} ORDER BY created_at DESC, id DESC LIMIT 1`,
      status ? [status] : [],
    );
    return res.rows[0] ? record(res.rows[0]) : undefined;
  }
  async list(limit: number) {
    return (
      await this.#pool.query(
        'SELECT * FROM audit_anchors ORDER BY created_at DESC, id DESC LIMIT $1',
        [limit],
      )
    ).rows.map(record);
  }
}
