import type { AuditEventInput, AuditLog, AuditWriter } from '@trust/audit';
import { AuditBuffer } from '@trust/audit';
import type { OrgRole, PlatformRole } from '@trust/shared-types';

export interface MfaState {
  sealedSecret: string;
  enabled: boolean;
  expiresAt: number;
  lastCounter: number;
  recoveryHashes: string[];
}
export interface User {
  id: string;
  email: string;
  passwordHash: string;
  emailVerifiedAt?: Date | null;
  mfa?: MfaState | null;
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

export interface IdentityToken {
  userId: string;
  purpose: 'reset' | 'verify';
  tokenHash: string;
  createdAt: Date;
  expiresAt: Date;
  usedAt: Date | null;
}
/** A registered WebAuthn credential (ADR-023). The key is public; nothing secret is stored. */
export interface Passkey {
  /** base64url credential id, globally unique. */
  credentialId: string;
  userId: string;
  name: string;
  /** COSE algorithm (-8 EdDSA, -7 ES256, -257 RS256). */
  alg: number;
  publicKeyJwk: Record<string, string>;
  signCount: number;
  backupEligible: boolean;
  backedUp: boolean;
  createdAt: Date;
  lastUsedAt: Date | null;
}

/** A pending WebAuthn ceremony; only the challenge digest is stored. */
export interface WebauthnChallenge {
  challengeHash: string;
  purpose: 'register' | 'login';
  /** Registration: the signed-in user and session the challenge is bound to. Login: null. */
  userId: string | null;
  sessionId: string | null;
  createdAt: Date;
  expiresAt: Date;
}

/** Identity data access. */
export interface IdentityMail {
  userId: string;
  purpose: IdentityToken['purpose'];
  tokenHash: string;
  sealed: string;
  createdAt: Date;
  expiresAt: Date;
  nextAttemptAt: Date;
  attempts: number;
  claim: string | null;
  lockedUntil: Date | null;
}
export interface AuthRepo {
  /** Fails when the credential id is already registered (to anyone). */
  insertPasskey(p: Passkey): Promise<void>;
  findPasskey(credentialId: string): Promise<Passkey | undefined>;
  /** As `findPasskey`, plus a row lock until the transaction ends (PostgreSQL). */
  findPasskeyForUpdate(credentialId: string): Promise<Passkey | undefined>;
  /** Oldest first. */
  listPasskeys(userId: string): Promise<Passkey[]>;
  updatePasskeyUse(
    credentialId: string,
    signCount: number,
    backedUp: boolean,
    at: Date,
  ): Promise<void>;
  /** Removes the user's own credential; false when it does not exist or belongs to someone else. */
  deletePasskey(userId: string, credentialId: string): Promise<boolean>;
  putWebauthnChallenge(c: WebauthnChallenge): Promise<void>;
  /** Atomically removes and returns an unexpired challenge of that purpose (single use); expired ones stay for purge. */
  consumeWebauthnChallenge(
    hash: string,
    purpose: WebauthnChallenge['purpose'],
    now: Date,
  ): Promise<WebauthnChallenge | undefined>;
  /** Deletes up to `limit` challenges that expired before `before`. */
  purgeWebauthnChallenges(before: Date, limit?: number): Promise<number>;
  putIdentityMail(row: IdentityMail): Promise<void>;
  listDueIdentityMail(now: Date, limit: number): Promise<IdentityMail[]>;
  /** Inside a transaction, acquire the user's lock before the message lock. */
  findIdentityMailForUpdate(tokenHash: string): Promise<IdentityMail | undefined>;
  deleteIdentityMail(tokenHash: string): Promise<void>;
  setMfa(userId: string, state: MfaState | null): Promise<void>;
  findUserForUpdate(id: string): Promise<User | undefined>;
  putIdentityToken(token: IdentityToken): Promise<void>;
  findUserIdentityToken(
    userId: string,
    purpose: IdentityToken['purpose'],
  ): Promise<IdentityToken | undefined>;
  findIdentityToken(hash: string): Promise<IdentityToken | undefined>;
  consumeIdentityToken(
    userId: string,
    purpose: IdentityToken['purpose'],
    hash: string,
    now: Date,
  ): Promise<boolean>;
  setPasswordHash(userId: string, hash: string): Promise<void>;
  markEmailVerified(userId: string, now: Date): Promise<void>;
  revokeUserSessions(userId: string, now: Date): Promise<void>;
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
  findSessionById(id: string): Promise<Session | undefined>;
  findSessionByTokenHash(hash: string): Promise<Session | undefined>;
  /** `findSessionByTokenHash` plus the session's user in one read (one round trip per authenticated request). */
  findSessionWithUser(hash: string): Promise<{ session: Session; user: User } | undefined>;
  revokeSession(id: string, at: Date): Promise<void>;

  /** Consecutive failed logins for an account key (a digest of the normalized email, never the email). */
  findLoginFailure(key: string): Promise<LoginFailure | undefined>;
  /**
   * Atomically adds one failure (concurrent callers never lose a count, across processes). The count keeps
   * growing after a lock; `lockedUntil` is `now + lockoutMs` whenever the new count is `>= maxFailures`.
   */
  recordLoginFailure(
    key: string,
    now: Date,
    maxFailures: number,
    lockoutMs: number,
  ): Promise<LoginFailure>;
  clearLoginFailure(key: string): Promise<void>;
  /** Deletes up to `limit` entries last updated before `before`. Returns the number deleted. */
  purgeLoginFailures(before: Date, limit?: number): Promise<number>;
}

export interface LoginFailure {
  count: number;
  lockedUntil: Date | null;
}

/** A transaction: every repository method, plus an audit writer that commits atomically with them. */
export interface AuthTx extends AuthRepo {
  audit: AuditWriter;
}

/** Persistence port for identity. Adapters: in-memory (tests/dev), PostgreSQL. */
export interface AuthStore extends AuthRepo {
  /**
   * Unit of work: writes and audit events appended via `tx.audit` commit together or not at all.
   * `fn` must be safe to re-run (the PostgreSQL adapter retries after deadlocks).
   */
  transaction<T>(fn: (tx: AuthTx) => Promise<T>): Promise<T>;
}

interface State {
  passkeys: Map<string, Passkey>;
  webauthnChallenges: Map<string, WebauthnChallenge>;
  identityMail: Map<string, IdentityMail>;
  identityTokens: Map<string, IdentityToken>;
  loginFailures: Map<string, LoginFailure & { updatedAt: Date }>;
  users: Map<string, User>;
  orgs: Map<string, Organization>;
  memberships: Map<string, Membership>;
  sessions: Map<string, Session>;
}

class MemoryRepo implements AuthRepo {
  readonly s: State = {
    passkeys: new Map(),
    webauthnChallenges: new Map(),
    identityMail: new Map(),
    identityTokens: new Map(),
    loginFailures: new Map(),
    users: new Map(),
    orgs: new Map(),
    memberships: new Map(),
    sessions: new Map(),
  };

  async insertPasskey(p: Passkey) {
    if (!this.s.users.has(p.userId)) throw new Error('user_not_found');
    if (this.s.passkeys.has(p.credentialId)) throw new Error('duplicate_passkey');
    this.s.passkeys.set(p.credentialId, structuredClone(p));
  }
  async findPasskey(credentialId: string) {
    const p = this.s.passkeys.get(credentialId);
    return p ? structuredClone(p) : undefined;
  }
  async findPasskeyForUpdate(credentialId: string) {
    return this.findPasskey(credentialId);
  }
  async listPasskeys(userId: string) {
    return [...this.s.passkeys.values()]
      .filter((p) => p.userId === userId)
      .sort((a, b) => +a.createdAt - +b.createdAt || a.credentialId.localeCompare(b.credentialId))
      .map((p) => structuredClone(p));
  }
  async updatePasskeyUse(credentialId: string, signCount: number, backedUp: boolean, at: Date) {
    const p = this.s.passkeys.get(credentialId);
    if (p) Object.assign(p, { signCount, backedUp, lastUsedAt: at });
  }
  async deletePasskey(userId: string, credentialId: string) {
    const p = this.s.passkeys.get(credentialId);
    if (!p || p.userId !== userId) return false;
    this.s.passkeys.delete(credentialId);
    return true;
  }
  async putWebauthnChallenge(c: WebauthnChallenge) {
    this.s.webauthnChallenges.set(c.challengeHash, structuredClone(c));
  }
  async consumeWebauthnChallenge(hash: string, purpose: WebauthnChallenge['purpose'], now: Date) {
    const c = this.s.webauthnChallenges.get(hash);
    if (!c || c.purpose !== purpose || c.expiresAt <= now) return undefined;
    this.s.webauthnChallenges.delete(hash);
    return structuredClone(c);
  }
  async purgeWebauthnChallenges(before: Date, limit = 5000) {
    let n = 0;
    for (const [k, c] of this.s.webauthnChallenges) {
      if (n >= limit) break;
      if (c.expiresAt < before) {
        this.s.webauthnChallenges.delete(k);
        n++;
      }
    }
    return n;
  }

  async putIdentityMail(row: IdentityMail) {
    if (!this.s.users.has(row.userId)) throw new Error('user_not_found');
    this.s.identityMail.set(`${row.userId}|${row.purpose}`, structuredClone(row));
  }
  async listDueIdentityMail(now: Date, limit: number) {
    return [...this.s.identityMail.values()]
      .filter((r) => r.nextAttemptAt <= now && (!r.lockedUntil || r.lockedUntil <= now))
      .sort((a, b) => +a.nextAttemptAt - +b.nextAttemptAt || a.tokenHash.localeCompare(b.tokenHash))
      .slice(0, Math.max(1, Math.min(100, Math.floor(limit))))
      .map((r) => structuredClone(r));
  }
  async findIdentityMailForUpdate(hash: string) {
    const row = [...this.s.identityMail.values()].find((r) => r.tokenHash === hash);
    return row ? structuredClone(row) : undefined;
  }
  async deleteIdentityMail(hash: string) {
    const row = [...this.s.identityMail.values()].find((r) => r.tokenHash === hash);
    if (row) this.s.identityMail.delete(`${row.userId}|${row.purpose}`);
  }

  async setMfa(userId: string, state: MfaState | null) {
    const user = this.s.users.get(userId);
    if (user) user.mfa = structuredClone(state);
  }
  async findUserForUpdate(id: string) {
    return this.findUserById(id);
  }
  async putIdentityToken(token: IdentityToken) {
    if (!this.s.users.has(token.userId)) throw new Error('user_not_found');
    this.s.identityTokens.set(`${token.userId}|${token.purpose}`, structuredClone(token));
  }
  async findUserIdentityToken(userId: string, purpose: IdentityToken['purpose']) {
    const token = this.s.identityTokens.get(`${userId}|${purpose}`);
    return token ? structuredClone(token) : undefined;
  }
  async findIdentityToken(hash: string) {
    const token = [...this.s.identityTokens.values()].find((t) => t.tokenHash === hash);
    return token ? structuredClone(token) : undefined;
  }
  async consumeIdentityToken(
    userId: string,
    purpose: IdentityToken['purpose'],
    hash: string,
    now: Date,
  ) {
    const token = this.s.identityTokens.get(`${userId}|${purpose}`);
    if (
      !token ||
      token.tokenHash !== hash ||
      token.usedAt ||
      token.expiresAt.getTime() <= now.getTime()
    )
      return false;
    token.usedAt = now;
    return true;
  }
  async setPasswordHash(userId: string, hash: string) {
    const user = this.s.users.get(userId);
    if (user) user.passwordHash = hash;
  }
  async markEmailVerified(userId: string, now: Date) {
    const user = this.s.users.get(userId);
    if (user) user.emailVerifiedAt = now;
  }
  async revokeUserSessions(userId: string, now: Date) {
    for (const session of this.s.sessions.values())
      if (session.userId === userId && !session.revokedAt) session.revokedAt = now;
  }
  async insertUser(u: User) {
    if ([...this.s.users.values()].some((x) => x.email === u.email))
      throw new Error('duplicate_email');
    this.s.users.set(u.id, structuredClone(u));
  }
  async findUserByEmail(email: string) {
    const u = [...this.s.users.values()].find((x) => x.email === email);
    return u ? structuredClone(u) : undefined;
  }
  async findUserById(id: string) {
    const u = this.s.users.get(id);
    return u ? structuredClone(u) : undefined;
  }
  async setPlatformRole(userId: string, role: 'none' | 'platform_admin') {
    const u = this.s.users.get(userId);
    if (u) u.platformRole = role;
  }
  async insertOrganization(o: Organization) {
    this.s.orgs.set(o.id, { ...o });
  }
  async findOrganization(id: string) {
    const o = this.s.orgs.get(id);
    return o ? { ...o } : undefined;
  }
  async insertMembership(m: Membership) {
    const k = `${m.orgId}|${m.userId}`;
    if (this.s.memberships.has(k)) throw new Error('duplicate_membership');
    this.s.memberships.set(k, { ...m });
  }
  async findMembership(orgId: string, userId: string) {
    const m = this.s.memberships.get(`${orgId}|${userId}`);
    return m ? { ...m } : undefined;
  }
  async listMembershipsForUser(userId: string) {
    return [...this.s.memberships.values()]
      .filter((m) => m.userId === userId)
      .map((m) => ({ ...m }));
  }
  async listMembershipsForOrg(orgId: string) {
    return [...this.s.memberships.values()].filter((m) => m.orgId === orgId).map((m) => ({ ...m }));
  }
  async insertSession(s: Session) {
    this.s.sessions.set(s.id, { ...s });
  }
  async findSessionById(id: string) {
    const s = this.s.sessions.get(id);
    return s ? structuredClone(s) : undefined;
  }
  async findSessionByTokenHash(hash: string) {
    const s = [...this.s.sessions.values()].find((x) => x.tokenHash === hash);
    return s ? { ...s } : undefined;
  }
  async findSessionWithUser(hash: string) {
    const s = [...this.s.sessions.values()].find((x) => x.tokenHash === hash);
    const u = s && this.s.users.get(s.userId);
    return s && u ? { session: { ...s }, user: structuredClone(u) } : undefined;
  }
  async findLoginFailure(key: string) {
    const f = this.s.loginFailures.get(key);
    return f ? { count: f.count, lockedUntil: f.lockedUntil } : undefined;
  }
  async recordLoginFailure(key: string, now: Date, maxFailures: number, lockoutMs: number) {
    const count = (this.s.loginFailures.get(key)?.count ?? 0) + 1;
    const lockedUntil = count >= maxFailures ? new Date(now.getTime() + lockoutMs) : null;
    this.s.loginFailures.set(key, { count, lockedUntil, updatedAt: now });
    return { count, lockedUntil };
  }
  async clearLoginFailure(key: string) {
    this.s.loginFailures.delete(key);
  }
  async purgeLoginFailures(before: Date, limit = 5000) {
    let n = 0;
    for (const [k, f] of this.s.loginFailures) {
      if (n >= limit) break;
      if (f.updatedAt < before) {
        this.s.loginFailures.delete(k);
        n++;
      }
    }
    return n;
  }
  async revokeSession(id: string, at: Date) {
    const s = this.s.sessions.get(id);
    if (s && !s.revokedAt) s.revokedAt = at;
  }
}

/** In-memory adapter: serialized transactions with snapshot rollback; audit flushed only on commit. */
export class InMemoryAuthStore extends MemoryRepo implements AuthStore {
  #lock: Promise<unknown> = Promise.resolve();
  readonly #audit: AuditLog | undefined;
  readonly committedAudit: AuditEventInput[] = [];

  constructor(opts?: { audit?: AuditLog }) {
    super();
    this.#audit = opts?.audit;
  }

  transaction<T>(fn: (tx: AuthTx) => Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      const snapshot = structuredClone(this.s);
      const buffer = new AuditBuffer();
      const tx = Object.assign(Object.create(this) as MemoryRepo, {
        audit: buffer,
      }) as unknown as AuthTx;
      try {
        const out = await fn(tx);
        const events = buffer.drain();
        if (this.#audit) await this.#audit.appendMany(events);
        else this.committedAudit.push(...events);
        return out;
      } catch (e) {
        Object.assign(this.s, snapshot);
        throw e;
      }
    };
    const p = this.#lock.then(run, run);
    this.#lock = p.catch(() => undefined);
    return p;
  }
}
