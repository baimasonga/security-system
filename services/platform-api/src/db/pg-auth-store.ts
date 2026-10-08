import type { AuthStore, Membership, Organization, Session, User } from '@trust/auth';
import type { OrgRole, PlatformRole } from '@trust/shared-types';
import { UNIQUE_VIOLATION, pgErr, type PgPool } from './pg.ts';

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
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

export class PgAuthStore implements AuthStore {
  readonly #db: PgPool;
  constructor(db: PgPool) {
    this.#db = db;
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
  async findSessionByTokenHash(hash: string) {
    const r = await this.#db.query<SessionRow>('SELECT * FROM sessions WHERE token_hash = $1', [
      hash,
    ]);
    return r.rows[0] ? session(r.rows[0]) : undefined;
  }
  async revokeSession(id: string, at: Date) {
    await this.#db.query(
      'UPDATE sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL',
      [id, at],
    );
  }
}
