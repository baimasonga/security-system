import type { KeyPurpose, KeyRecord, PublicJwk } from '@trust/crypto';
import type { PgPool } from './pg.ts';

type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Persists signing-key METADATA only (public key + lifecycle). Private material never touches the DB. */
export class PgKeyStore {
  readonly #pool: PgPool;
  constructor(pool: PgPool) {
    this.#pool = pool;
  }

  async list(): Promise<KeyRecord[]> {
    const rows = (await this.#pool.query('SELECT * FROM signing_keys ORDER BY created_at, kid'))
      .rows as Row[];
    return rows.map((r) => ({
      kid: r.kid,
      purpose: r.purpose as KeyPurpose,
      state: r.state,
      publicJwk: r.public_key_jwk as PublicJwk,
      createdAt: r.created_at,
      ...(r.activated_at ? { activatedAt: r.activated_at } : {}),
      ...(r.deprecated_at ? { deprecatedAt: r.deprecated_at } : {}),
      ...(r.revoked_at ? { revokedAt: r.revoked_at } : {}),
    }));
  }

  /**
   * Upserts one record. A rotation changes two records (old → deprecated, new → active); the partial
   * unique index allows one active key per purpose, so callers persist the demotion first.
   */
  async upsert(r: KeyRecord): Promise<void> {
    await this.#pool.query(
      `INSERT INTO signing_keys (kid, purpose, state, public_key_jwk, created_at, activated_at, deprecated_at, revoked_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (kid) DO UPDATE SET state=EXCLUDED.state, activated_at=EXCLUDED.activated_at,
         deprecated_at=EXCLUDED.deprecated_at, revoked_at=EXCLUDED.revoked_at`,
      [
        r.kid,
        r.purpose,
        r.state,
        r.publicJwk,
        r.createdAt,
        r.activatedAt ?? null,
        r.deprecatedAt ?? null,
        r.revokedAt ?? null,
      ],
    );
  }
}
