import type { Clock } from '@trust/shared-types';
import { DomainError } from '@trust/shared-types';
import type {
  RegistryStore,
  RegistryTx,
  ReleaseRegistry,
  ReleaseReservation,
} from '../release-registry.ts';
import { appendAuditInTx } from './pg-audit-log.ts';
import { withTransaction, type PgPool } from './pg.ts';

function registry(row: Record<string, unknown>): ReleaseRegistry {
  return {
    productId: row.product_id as string,
    product: row.product_code as string,
    root: row.root as ReleaseRegistry['root'],
    targets: row.targets as ReleaseRegistry['targets'],
    createdAt: row.created_at as Date,
    updatedAt: row.updated_at as Date,
  };
}
function receipt(row: Record<string, unknown>): ReleaseReservation {
  return {
    productId: row.product_id as string,
    requestId: row.request_id as string,
    platform: row.platform as string,
    channel: row.channel as string,
    sequence: Number(row.sequence),
    createdAt: row.created_at as Date,
  };
}
export class PgRegistryStore implements RegistryStore {
  readonly #pool: PgPool;
  readonly #clock: Clock;
  readonly #shards: number;
  constructor(pool: PgPool, clock: Clock, shards = 1) {
    this.#pool = pool;
    this.#clock = clock;
    this.#shards = shards;
  }
  async read(productId: string) {
    const r = await this.#pool.query('SELECT * FROM update_registries WHERE product_id=$1', [
      productId,
    ]);
    return r.rows[0] ? registry(r.rows[0]) : undefined;
  }
  transaction<T>(productId: string, work: (tx: RegistryTx) => Promise<T>): Promise<T> {
    return withTransaction(this.#pool, async (q) => {
      // Product-scoped advisory lock also covers the first insert; the product table
      // deliberately grants no UPDATE privilege to the app role. Hash collisions only serialize.
      await q.query('SELECT pg_advisory_xact_lock(hashtextextended($1,32027))', [productId]);
      const product = await q.query('SELECT id FROM products WHERE id=$1', [productId]);
      if (!product.rows[0]) throw new DomainError('not_found', 'not found');
      return work({
        get: async () => {
          const r = await q.query('SELECT * FROM update_registries WHERE product_id=$1', [
            productId,
          ]);
          return r.rows[0] ? registry(r.rows[0]) : undefined;
        },
        put: async (row) => {
          await q.query(
            `INSERT INTO update_registries(product_id,product_code,root,targets,created_at,updated_at)
            VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(product_id) DO UPDATE
            SET targets=EXCLUDED.targets,updated_at=EXCLUDED.updated_at`,
            [
              productId,
              row.product,
              JSON.stringify(row.root),
              JSON.stringify(row.targets),
              row.createdAt,
              row.updatedAt,
            ],
          );
        },
        receipt: async (id) => {
          const r = await q.query(
            'SELECT * FROM update_reservations WHERE product_id=$1 AND request_id=$2',
            [productId, id],
          );
          return r.rows[0] ? receipt(r.rows[0]) : undefined;
        },
        appendReceipt: async (row) => {
          await q.query(
            `INSERT INTO update_reservations(product_id,request_id,platform,channel,sequence,created_at)
            VALUES($1,$2,$3,$4,$5,$6)`,
            [productId, row.requestId, row.platform, row.channel, row.sequence, row.createdAt],
          );
        },
        audit: async (event) => {
          await appendAuditInTx(q, this.#clock, [event], this.#shards);
        },
      });
    });
  }
}
