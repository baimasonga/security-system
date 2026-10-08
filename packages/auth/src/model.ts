import type { OrgRole, PlatformRole } from '@trust/shared-types';

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  status: 'active' | 'disabled';
  platformRole: PlatformRole;
  createdAt: Date;
}

export interface Organization {
  id: string;
  name: string;
  kind: 'personal' | 'team';
  createdAt: Date;
}

export interface Membership {
  orgId: string;
  userId: string;
  role: OrgRole;
  createdAt: Date;
}

export interface Session {
  id: string;
  userId: string;
  tokenHash: string;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

/** Persistence port for identity. Adapters: in-memory (tests/dev), PostgreSQL (next slice). */
export interface AuthStore {
  insertUser(u: User): Promise<void>;
  findUserByEmail(email: string): Promise<User | undefined>;
  findUserById(id: string): Promise<User | undefined>;
  setPlatformRole(userId: string, role: PlatformRole): Promise<void>;
  insertOrganization(o: Organization): Promise<void>;
  findOrganization(id: string): Promise<Organization | undefined>;
  insertMembership(m: Membership): Promise<void>;
  findMembership(orgId: string, userId: string): Promise<Membership | undefined>;
  listMembershipsForUser(userId: string): Promise<Membership[]>;
  listMembershipsForOrg(orgId: string): Promise<Membership[]>;
  insertSession(s: Session): Promise<void>;
  findSessionByTokenHash(hash: string): Promise<Session | undefined>;
  revokeSession(id: string, at: Date): Promise<void>;
}

export class InMemoryAuthStore implements AuthStore {
  readonly #users = new Map<string, User>();
  readonly #orgs = new Map<string, Organization>();
  readonly #memberships = new Map<string, Membership>();
  readonly #sessions = new Map<string, Session>();

  async insertUser(u: User) {
    if ([...this.#users.values()].some((x) => x.email === u.email))
      throw new Error('duplicate_email');
    this.#users.set(u.id, { ...u });
  }
  async findUserByEmail(email: string) {
    const u = [...this.#users.values()].find((x) => x.email === email);
    return u ? { ...u } : undefined;
  }
  async findUserById(id: string) {
    const u = this.#users.get(id);
    return u ? { ...u } : undefined;
  }
  async setPlatformRole(userId: string, role: 'none' | 'platform_admin') {
    const u = this.#users.get(userId);
    if (u) u.platformRole = role;
  }
  async insertOrganization(o: Organization) {
    this.#orgs.set(o.id, { ...o });
  }
  async findOrganization(id: string) {
    const o = this.#orgs.get(id);
    return o ? { ...o } : undefined;
  }
  async insertMembership(m: Membership) {
    const k = `${m.orgId}|${m.userId}`;
    if (this.#memberships.has(k)) throw new Error('duplicate_membership');
    this.#memberships.set(k, { ...m });
  }
  async findMembership(orgId: string, userId: string) {
    const m = this.#memberships.get(`${orgId}|${userId}`);
    return m ? { ...m } : undefined;
  }
  async listMembershipsForUser(userId: string) {
    return [...this.#memberships.values()]
      .filter((m) => m.userId === userId)
      .map((m) => ({ ...m }));
  }
  async listMembershipsForOrg(orgId: string) {
    return [...this.#memberships.values()].filter((m) => m.orgId === orgId).map((m) => ({ ...m }));
  }
  async insertSession(s: Session) {
    this.#sessions.set(s.id, { ...s });
  }
  async findSessionByTokenHash(hash: string) {
    const s = [...this.#sessions.values()].find((x) => x.tokenHash === hash);
    return s ? { ...s } : undefined;
  }
  async revokeSession(id: string, at: Date) {
    const s = this.#sessions.get(id);
    if (s && !s.revokedAt) s.revokedAt = at;
  }
}
