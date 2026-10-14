import { AuditBuffer } from '@trust/audit';
import type {
  AuthRepo,
  MfaState,
  AuthStore,
  IdentityToken,
  IdentityMail,
  AuthTx,
  Membership,
  Organization,
  Session,
  User,
} from '@trust/auth';
import type { Clock, OrgRole, PlatformRole } from '@trust/shared-types';
import { appendAuditInTx } from './pg-audit-log.ts';
import {
  UNIQUE_VIOLATION,
  pgErr,
  serialized,
  withTransaction,
  type PgPool,
  type Queryable,
} from './pg.ts';

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  email_verified_at?: Date | null;
  mfa_state?: MfaState | null;
  status: 'active' | 'disabled';
  platform_role: PlatformRole;
  created_at: Date;
}
interface OrgRow {
  id: string;
  name: string;
  kind: 'personal' | 'team';
  created_at: Date;
}
interface MembershipRow {
  org_id: string;
  user_id: string;
  role: OrgRole;
  created_at: Date;
}
interface SessionRow {
  id: string;
  user_id: string;
  token_hash: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
}

const user = (r: UserRow): User => ({
  id: r.id,
  email: r.email,
  passwordHash: r.password_hash,
  emailVerifiedAt: r.email_verified_at,
  mfa: r.mfa_state,
  status: r.status,
  platformRole: r.platform_role,
  createdAt: r.created_at,
});
const org = (r: OrgRow): Organization => ({
  id: r.id,
  name: r.name,
  kind: r.kind,
  createdAt: r.created_at,
});
const membership = (r: MembershipRow): Membership => ({
  orgId: r.org_id,
  userId: r.user_id,
  role: r.role,
  createdAt: r.created_at,
});
const session = (r: SessionRow): Session => ({
  id: r.id,
  userId: r.user_id,
  tokenHash: r.token_hash,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  revokedAt: r.revoked_at,
});

const mailRow = (r: {
  user_id: string;
  purpose: IdentityMail['purpose'];
  token_hash: string;
  sealed: string;
  created_at: Date;
  expires_at: Date;
  next_attempt_at: Date;
  attempts: number;
  claim: string | null;
  locked_until: Date | null;
}): IdentityMail => ({
  userId: r.user_id,
  purpose: r.purpose,
  tokenHash: r.token_hash,
  sealed: r.sealed,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
  nextAttemptAt: r.next_attempt_at,
  attempts: r.attempts,
  claim: r.claim,
  lockedUntil: r.locked_until,
});
class PgAuthRepo implements AuthRepo {
  readonly #db: Queryable;
  constructor(db: Queryable) {
    this.#db = db;
  }

  async setMfa(userId: string, state: MfaState | null) {
    await this.#db.query('UPDATE users SET mfa_state=$2::jsonb WHERE id=$1', [
      userId,
      state ? JSON.stringify(state) : null,
    ]);
  }
  async findUserForUpdate(id: string) {
    const result = await this.#db.query<UserRow>('SELECT * FROM users WHERE id=$1 FOR UPDATE', [
      id,
    ]);
    return result.rows[0] ? user(result.rows[0]) : undefined;
  }
  async putIdentityToken(t: IdentityToken) {
    await this.#db.query(
      `INSERT INTO identity_tokens (user_id,purpose,token_hash,created_at,expires_at,used_at) VALUES ($1,$2,$3,$4,$5,NULL) ON CONFLICT(user_id,purpose) DO UPDATE SET token_hash=EXCLUDED.token_hash,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at,used_at=NULL`,
      [t.userId, t.purpose, t.tokenHash, t.createdAt, t.expiresAt],
    );
  }
  async putIdentityMail(r: IdentityMail) {
    await this.#db.query(
      `INSERT INTO identity_mail_outbox(user_id,purpose,token_hash,sealed,created_at,expires_at,next_attempt_at,attempts,claim,locked_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(user_id,purpose) DO UPDATE SET token_hash=EXCLUDED.token_hash,sealed=EXCLUDED.sealed,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at,next_attempt_at=EXCLUDED.next_attempt_at,attempts=EXCLUDED.attempts,claim=EXCLUDED.claim,locked_until=EXCLUDED.locked_until`,
      [
        r.userId,
        r.purpose,
        r.tokenHash,
        r.sealed,
        r.createdAt,
        r.expiresAt,
        r.nextAttemptAt,
        r.attempts,
        r.claim,
        r.lockedUntil,
      ],
    );
  }
  async listDueIdentityMail(now: Date, limit: number): Promise<IdentityMail[]> {
    const r = await this.#db.query<Parameters<typeof mailRow>[0]>(
      'SELECT * FROM identity_mail_outbox WHERE next_attempt_at<=$1 AND (locked_until IS NULL OR locked_until<=$1) ORDER BY next_attempt_at,token_hash LIMIT $2',
      [now, Math.max(1, Math.min(100, Math.floor(limit)))],
    );
    return r.rows.map(mailRow);
  }
  async findIdentityMailForUpdate(hash: string): Promise<IdentityMail | undefined> {
    const r = await this.#db.query<Parameters<typeof mailRow>[0]>(
      'SELECT * FROM identity_mail_outbox WHERE token_hash=$1 FOR UPDATE',
      [hash],
    );
    return r.rows[0] ? mailRow(r.rows[0]) : undefined;
  }
  async deleteIdentityMail(hash: string) {
    await this.#db.query('DELETE FROM identity_mail_outbox WHERE token_hash=$1', [hash]);
  }
  async findUserIdentityToken(
    userId: string,
    purpose: IdentityToken['purpose'],
  ): Promise<IdentityToken | undefined> {
    const result = await this.#db.query(
      'SELECT * FROM identity_tokens WHERE user_id=$1 AND purpose=$2',
      [userId, purpose],
    );
    const r = result.rows[0];
    return r
      ? {
          userId: r.user_id,
          purpose: r.purpose,
          tokenHash: r.token_hash,
          createdAt: r.created_at,
          expiresAt: r.expires_at,
          usedAt: r.used_at,
        }
      : undefined;
  }
  async findIdentityToken(hash: string): Promise<IdentityToken | undefined> {
    const result = await this.#db.query('SELECT * FROM identity_tokens WHERE token_hash=$1', [
      hash,
    ]);
    const r = result.rows[0];
    return r
      ? {
          userId: r.user_id,
          purpose: r.purpose,
          tokenHash: r.token_hash,
          createdAt: r.created_at,
          expiresAt: r.expires_at,
          usedAt: r.used_at,
        }
      : undefined;
  }
  async consumeIdentityToken(
    userId: string,
    purpose: IdentityToken['purpose'],
    hash: string,
    now: Date,
  ) {
    const result = await this.#db.query(
      'UPDATE identity_tokens SET used_at=$4 WHERE user_id=$1 AND purpose=$2 AND token_hash=$3 AND used_at IS NULL AND expires_at>$4 RETURNING user_id',
      [userId, purpose, hash, now],
    );
    return !!result.rowCount;
  }
  async setPasswordHash(userId: string, hash: string) {
    await this.#db.query('UPDATE users SET password_hash=$2 WHERE id=$1', [userId, hash]);
  }
  async markEmailVerified(userId: string, now: Date) {
    await this.#db.query('UPDATE users SET email_verified_at=$2 WHERE id=$1', [userId, now]);
  }
  async revokeUserSessions(userId: string, now: Date) {
    await this.#db.query(
      'UPDATE sessions SET revoked_at=$2 WHERE user_id=$1 AND revoked_at IS NULL',
      [userId, now],
    );
  }
  async insertUser(u: User): Promise<void> {
    try {
      await this.#db.query(
        'INSERT INTO users (id, email, password_hash, status, platform_role, created_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [u.id, u.email, u.passwordHash, u.status, u.platformRole, u.createdAt],
      );
    } catch (e) {
      if (pgErr(e).code === UNIQUE_VIOLATION) throw new Error('duplicate_email');
      throw e;
    }
  }
  async findUserByEmail(email: string) {
    const r = await this.#db.query<UserRow>('SELECT * FROM users WHERE email = $1', [email]);
    return r.rows[0] ? user(r.rows[0]) : undefined;
  }
  async findUserById(id: string) {
    const r = await this.#db.query<UserRow>('SELECT * FROM users WHERE id = $1', [id]);
    return r.rows[0] ? user(r.rows[0]) : undefined;
  }
  async setPlatformRole(userId: string, role: PlatformRole) {
    await this.#db.query('UPDATE users SET platform_role = $2 WHERE id = $1', [userId, role]);
  }

  async insertOrganization(o: Organization) {
    await this.#db.query(
      'INSERT INTO organizations (id, name, kind, created_at) VALUES ($1,$2,$3,$4)',
      [o.id, o.name, o.kind, o.createdAt],
    );
  }
  async findOrganization(id: string) {
    const r = await this.#db.query<OrgRow>('SELECT * FROM organizations WHERE id = $1', [id]);
    return r.rows[0] ? org(r.rows[0]) : undefined;
  }

  async insertMembership(m: Membership) {
    try {
      await this.#db.query(
        'INSERT INTO memberships (org_id, user_id, role, created_at) VALUES ($1,$2,$3,$4)',
        [m.orgId, m.userId, m.role, m.createdAt],
      );
    } catch (e) {
      if (pgErr(e).code === UNIQUE_VIOLATION) throw new Error('duplicate_membership');
      throw e;
    }
  }
  async findMembership(orgId: string, userId: string) {
    const r = await this.#db.query<MembershipRow>(
      'SELECT * FROM memberships WHERE org_id = $1 AND user_id = $2',
      [orgId, userId],
    );
    return r.rows[0] ? membership(r.rows[0]) : undefined;
  }
  async listMembershipsForUser(userId: string) {
    return (
      await this.#db.query<MembershipRow>(
        'SELECT * FROM memberships WHERE user_id = $1 ORDER BY created_at, org_id',
        [userId],
      )
    ).rows.map(membership);
  }
  async listMembershipsForOrg(orgId: string) {
    return (
      await this.#db.query<MembershipRow>(
        'SELECT * FROM memberships WHERE org_id = $1 ORDER BY created_at, user_id',
        [orgId],
      )
    ).rows.map(membership);
  }

  async insertSession(s: Session) {
    await this.#db.query(
      'INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, revoked_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [s.id, s.userId, s.tokenHash, s.createdAt, s.expiresAt, s.revokedAt],
    );
  }
  async findSessionById(id: string) {
    const r = await this.#db.query<SessionRow>('SELECT * FROM sessions WHERE id=$1', [id]);
    return r.rows[0] ? session(r.rows[0]) : undefined;
  }
  async findSessionByTokenHash(hash: string) {
    const r = await this.#db.query<SessionRow>('SELECT * FROM sessions WHERE token_hash = $1', [
      hash,
    ]);
    return r.rows[0] ? session(r.rows[0]) : undefined;
  }
  async findSessionWithUser(hash: string) {
    const r = await this.#db.query(
      `SELECT s.id AS s_id, s.user_id AS s_user_id, s.token_hash AS s_token_hash, s.created_at AS s_created_at,
              s.expires_at AS s_expires_at, s.revoked_at AS s_revoked_at,
              u.id AS u_id, u.email AS u_email, u.password_hash AS u_password_hash, u.status AS u_status,
              u.platform_role AS u_platform_role, u.created_at AS u_created_at
         FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1`,
      [hash],
    );
    const x = r.rows[0];
    if (!x) return undefined;
    return {
      session: session({
        id: x.s_id,
        user_id: x.s_user_id,
        token_hash: x.s_token_hash,
        created_at: x.s_created_at,
        expires_at: x.s_expires_at,
        revoked_at: x.s_revoked_at,
      }),
      user: user({
        id: x.u_id,
        email: x.u_email,
        password_hash: x.u_password_hash,
        status: x.u_status,
        platform_role: x.u_platform_role,
        created_at: x.u_created_at,
      }),
    };
  }
  async findLoginFailure(key: string) {
    const r = await this.#db.query(
      'SELECT count, locked_until FROM login_failures WHERE key = $1',
      [key],
    );
    const row = r.rows[0];
    return row
      ? { count: row.count as number, lockedUntil: row.locked_until as Date | null }
      : undefined;
  }
  async recordLoginFailure(key: string, now: Date, maxFailures: number, lockoutMs: number) {
    const lock = new Date(now.getTime() + lockoutMs);
    // One atomic statement: concurrent failures (from any instance) are never lost.
    const r = await this.#db.query(
      `INSERT INTO login_failures (key, count, locked_until, updated_at)
       VALUES ($1, 1, CASE WHEN 1 >= $3 THEN $4::timestamptz END, $2)
       ON CONFLICT (key) DO UPDATE
          SET count = login_failures.count + 1,
              locked_until = CASE WHEN login_failures.count + 1 >= $3 THEN $4::timestamptz END,
              updated_at = $2
       RETURNING count, locked_until`,
      [key, now, maxFailures, lock],
    );
    const row = r.rows[0]!;
    return { count: row.count as number, lockedUntil: row.locked_until as Date | null };
  }
  async clearLoginFailure(key: string) {
    await this.#db.query('DELETE FROM login_failures WHERE key = $1', [key]);
  }
  async purgeLoginFailures(before: Date, limit = 5000) {
    const r = await this.#db.query(
      'DELETE FROM login_failures WHERE key IN (SELECT key FROM login_failures WHERE updated_at < $1 LIMIT $2)',
      [before, limit],
    );
    return r.rowCount ?? 0;
  }
  async revokeSession(id: string, at: Date) {
    await this.#db.query(
      'UPDATE sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL',
      [id, at],
    );
  }
}

export class PgAuthStore extends PgAuthRepo implements AuthStore {
  readonly #pool: PgPool;
  readonly #clock: Clock;
  readonly #auditShards: number;
  constructor(pool: PgPool, clock: Clock, opts?: { auditShards?: number }) {
    super(pool);
    this.#pool = pool;
    this.#clock = clock;
    this.#auditShards = opts?.auditShards ?? 1;
  }

  transaction<T>(fn: (tx: AuthTx) => Promise<T>): Promise<T> {
    return withTransaction(this.#pool, async (client) => {
      const buffer = new AuditBuffer(); // fresh per attempt (see withTransaction retry contract)
      const tx = Object.assign(new PgAuthRepo(serialized(client)), {
        audit: buffer,
      }) as unknown as AuthTx;
      const out = await fn(tx);
      await appendAuditInTx(client, this.#clock, buffer.drain(), this.#auditShards);
      return out;
    });
  }
}
