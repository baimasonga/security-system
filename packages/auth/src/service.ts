import { newId, newSecretToken, sha256Hex } from '@trust/crypto';
import type { AuditLog } from '@trust/audit';
import { DomainError, type Clock, type OrgRole, type UserPrincipal } from '@trust/shared-types';
import { hashPassword, verifyPassword, DEFAULT_SCRYPT, type ScryptParams } from './password.ts';
import { canGrantRole, roleAllows, type Permission } from './rbac.ts';
import type { AuthStore, Membership, Organization, User } from './model.ts';

export interface AuthConfig {
  sessionTtlMs: number;
  maxFailedLogins: number;
  lockoutMs: number;
  scrypt: ScryptParams;
}

export const DEFAULT_AUTH_CONFIG: AuthConfig = {
  sessionTtlMs: 12 * 60 * 60 * 1000,
  maxFailedLogins: 5,
  lockoutMs: 15 * 60 * 1000,
  scrypt: DEFAULT_SCRYPT,
};

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,63}$/;
const BAD_LOGIN = 'invalid email or password';

export class AuthService {
  readonly #store: AuthStore;
  readonly #clock: Clock;
  readonly #audit: AuditLog;
  readonly #cfg: AuthConfig;
  #dummyHash: Promise<string> | undefined;

  constructor(deps: {
    store: AuthStore;
    clock: Clock;
    audit: AuditLog;
    config?: Partial<AuthConfig>;
  }) {
    this.#store = deps.store;
    this.#clock = deps.clock;
    this.#audit = deps.audit;
    this.#cfg = { ...DEFAULT_AUTH_CONFIG, ...deps.config };
  }

  async register(input: {
    email: string;
    password: string;
  }): Promise<{ user: User; personalOrg: Organization }> {
    const email = input.email.trim().toLowerCase();
    if (email.length > 254 || !EMAIL.test(email))
      throw new DomainError('invalid_request', 'invalid email');
    if (input.password.length < 12 || input.password.length > 256) {
      throw new DomainError('invalid_request', 'password must be 12-256 characters');
    }
    if (input.password.toLowerCase() === email) {
      throw new DomainError('invalid_request', 'password must not equal the email');
    }
    if (await this.#store.findUserByEmail(email))
      throw new DomainError('conflict', 'email already registered');

    const now = this.#clock.now();
    const user: User = {
      id: newId('usr'),
      email,
      passwordHash: await hashPassword(input.password, this.#cfg.scrypt),
      status: 'active',
      platformRole: 'none',
      createdAt: now,
    };
    const org: Organization = {
      id: newId('org'),
      name: 'Personal',
      kind: 'personal',
      createdAt: now,
    };
    try {
      // User, personal org, membership and audit record: all or nothing.
      await this.#store.transaction(async (tx) => {
        await tx.insertUser(user);
        await tx.insertOrganization(org);
        await tx.insertMembership({
          orgId: org.id,
          userId: user.id,
          role: 'owner',
          createdAt: now,
        });
        await tx.audit.append({
          actor: { type: 'user', id: user.id },
          action: 'user.registered',
          target: { type: 'user', id: user.id },
          orgId: org.id,
        });
      });
    } catch (e) {
      if (e instanceof Error && e.message === 'duplicate_email') {
        throw new DomainError('conflict', 'email already registered');
      }
      throw e;
    }
    return { user, personalOrg: org };
  }

  async login(input: {
    email: string;
    password: string;
  }): Promise<{ token: string; expiresAt: Date; userId: string }> {
    const email = input.email.trim().toLowerCase();
    const now = this.#clock.now();
    // Lockout state lives in the store, shared by every instance and surviving restarts (R-7). The key is a
    // digest, so unknown accounts are tracked identically and no address is stored.
    const failKey = sha256Hex(email);
    const fail = await this.#store.findLoginFailure(failKey);
    if (fail?.lockedUntil && fail.lockedUntil.getTime() > now.getTime()) {
      await this.#audit.append({
        actor: { type: 'anonymous' },
        action: 'user.login_blocked',
        metadata: { email_hash: sha256Hex(email).slice(0, 16) },
      });
      throw new DomainError('unauthenticated', BAD_LOGIN);
    }
    const user = await this.#store.findUserByEmail(email);
    // Always run one password derivation so timing does not reveal account existence.
    const ok = await verifyPassword(
      input.password.slice(0, 256),
      user?.passwordHash ?? (await this.#dummy()),
    );
    if (!user || !ok || user.status !== 'active') {
      const { count } = await this.#store.recordLoginFailure(
        failKey,
        now,
        this.#cfg.maxFailedLogins,
        this.#cfg.lockoutMs,
      );
      await this.#audit.append({
        actor: user ? { type: 'user', id: user.id } : { type: 'anonymous' },
        action: 'user.login_failed',
        metadata: { email_hash: sha256Hex(email).slice(0, 16), consecutive_failures: count },
      });
      throw new DomainError('unauthenticated', BAD_LOGIN);
    }
    if (fail) await this.#store.clearLoginFailure(failKey);
    const token = newSecretToken('sess');
    const expiresAt = new Date(now.getTime() + this.#cfg.sessionTtlMs);
    const sessionId = newId('ses');
    await this.#store.transaction(async (tx) => {
      await tx.insertSession({
        id: sessionId,
        userId: user.id,
        tokenHash: sha256Hex(token),
        createdAt: now,
        expiresAt,
        revokedAt: null,
      });
      await tx.audit.append({
        actor: { type: 'user', id: user.id },
        action: 'user.login_succeeded',
        metadata: { session_id: sessionId },
      });
    });
    return { token, expiresAt, userId: user.id };
  }

  async authenticate(token: string | undefined): Promise<UserPrincipal> {
    if (!token || token.length > 128 || !token.startsWith('sess_')) {
      throw new DomainError('unauthenticated', 'authentication required');
    }
    const found = await this.#store.findSessionWithUser(sha256Hex(token));
    const now = this.#clock.now();
    if (!found || found.session.revokedAt || found.session.expiresAt.getTime() <= now.getTime()) {
      throw new DomainError('unauthenticated', 'authentication required');
    }
    const { session, user } = found;
    if (user.status !== 'active')
      throw new DomainError('unauthenticated', 'authentication required');
    return {
      kind: 'user',
      userId: user.id,
      sessionId: session.id,
      platformRole: user.platformRole,
    };
  }

  async logout(principal: UserPrincipal): Promise<void> {
    await this.#store.transaction(async (tx) => {
      await tx.revokeSession(principal.sessionId, this.#clock.now());
      await tx.audit.append({
        actor: { type: 'user', id: principal.userId },
        action: 'user.logout',
        metadata: { session_id: principal.sessionId },
      });
    });
  }

  /**
   * Authorize an org-scoped action. Non-members get `not_found` (no existence oracle); members
   * lacking the permission get `forbidden`.
   */
  async requireOrgPermission(
    p: UserPrincipal,
    orgId: string,
    permission: Permission,
  ): Promise<Membership> {
    const m = await this.#store.findMembership(orgId, p.userId);
    if (!m) throw new DomainError('not_found', 'not found');
    if (!roleAllows(m.role, permission))
      throw new DomainError('forbidden', 'insufficient permissions');
    return m;
  }

  async createOrganization(p: UserPrincipal, name: string): Promise<Organization> {
    const trimmed = name.trim();
    if (trimmed.length < 1 || trimmed.length > 200)
      throw new DomainError('invalid_request', 'invalid organization name');
    const org: Organization = {
      id: newId('org'),
      name: trimmed,
      kind: 'team',
      createdAt: this.#clock.now(),
    };
    await this.#store.transaction(async (tx) => {
      await tx.insertOrganization(org);
      await tx.insertMembership({
        orgId: org.id,
        userId: p.userId,
        role: 'owner',
        createdAt: org.createdAt,
      });
      await tx.audit.append({
        actor: { type: 'user', id: p.userId },
        action: 'org.created',
        target: { type: 'org', id: org.id },
        orgId: org.id,
      });
    });
    return org;
  }

  async listOrganizations(p: UserPrincipal): Promise<Array<Organization & { role: OrgRole }>> {
    const out: Array<Organization & { role: OrgRole }> = [];
    for (const m of await this.#store.listMembershipsForUser(p.userId)) {
      const o = await this.#store.findOrganization(m.orgId);
      if (o) out.push({ ...o, role: m.role });
    }
    return out;
  }

  async getOrganization(p: UserPrincipal, orgId: string) {
    const m = await this.requireOrgPermission(p, orgId, 'org:read');
    const org = await this.#store.findOrganization(orgId);
    if (!org) throw new DomainError('not_found', 'not found');
    return { ...org, role: m.role };
  }

  async listMembers(p: UserPrincipal, orgId: string) {
    await this.requireOrgPermission(p, orgId, 'org:read');
    const out = [];
    for (const m of await this.#store.listMembershipsForOrg(orgId)) {
      const u = await this.#store.findUserById(m.userId);
      if (u) out.push({ userId: u.id, email: u.email, role: m.role });
    }
    return out;
  }

  async addMember(
    p: UserPrincipal,
    orgId: string,
    email: string,
    role: OrgRole,
  ): Promise<Membership> {
    const actor = await this.requireOrgPermission(p, orgId, 'org:manage_members');
    const org = await this.#store.findOrganization(orgId);
    if (!org || org.kind === 'personal')
      throw new DomainError('forbidden', 'personal organizations cannot have additional members');
    if (!canGrantRole(actor.role, role))
      throw new DomainError('forbidden', 'cannot grant a role above your own');
    const target = await this.#store.findUserByEmail(email.trim().toLowerCase());
    if (!target) throw new DomainError('not_found', 'user not found');
    if (await this.#store.findMembership(orgId, target.id))
      throw new DomainError('conflict', 'already a member');
    const m: Membership = { orgId, userId: target.id, role, createdAt: this.#clock.now() };
    try {
      await this.#store.transaction(async (tx) => {
        await tx.insertMembership(m);
        await tx.audit.append({
          actor: { type: 'user', id: p.userId },
          action: 'member.added',
          target: { type: 'user', id: target.id },
          orgId,
          metadata: { role },
        });
      });
    } catch (e) {
      // Lost a race with a concurrent add of the same member.
      if (e instanceof Error && e.message === 'duplicate_membership') {
        throw new DomainError('conflict', 'already a member');
      }
      throw e;
    }
    return m;
  }

  async orgExists(orgId: string): Promise<boolean> {
    return (await this.#store.findOrganization(orgId)) !== undefined;
  }

  /** Operator bootstrap. Deliberately NOT exposed over HTTP: invoked by deployment tooling only. */
  async bootstrapPlatformAdmin(email: string): Promise<void> {
    const u = await this.#store.findUserByEmail(email.trim().toLowerCase());
    if (!u) throw new Error('user not found');
    await this.#store.transaction(async (tx) => {
      await tx.setPlatformRole(u.id, 'platform_admin');
      await tx.audit.append({
        actor: { type: 'system' },
        action: 'operator.bootstrapped',
        target: { type: 'user', id: u.id },
      });
    });
  }

  /** Operator offboarding. Out-of-band like bootstrap; takes effect on the very next request. */
  async revokePlatformAdmin(email: string, reason: string): Promise<void> {
    const u = await this.#store.findUserByEmail(email.trim().toLowerCase());
    if (!u) throw new Error('user not found');
    await this.#store.transaction(async (tx) => {
      await tx.setPlatformRole(u.id, 'none');
      await tx.audit.append({
        actor: { type: 'system' },
        action: 'operator.revoked',
        target: { type: 'user', id: u.id },
        reason,
      });
    });
  }

  async requirePlatformAdmin(p: UserPrincipal): Promise<void> {
    // Re-read from the store: a revoked operator loses access without waiting for session expiry.
    const u = await this.#store.findUserById(p.userId);
    if (!u || u.status !== 'active' || u.platformRole !== 'platform_admin') {
      await this.#audit.append({
        actor: { type: 'user', id: p.userId },
        action: 'admin.access_denied',
      });
      throw new DomainError('forbidden', 'insufficient permissions');
    }
  }

  /**
   * Retention for the failed-login counters, off the request path. An account that has not failed for a day
   * (and at least twice the lockout period) starts again from zero.
   */
  async runMaintenance(opts?: {
    batch?: number;
    maxBatches?: number;
  }): Promise<{ loginFailures: number }> {
    const batch = opts?.batch ?? 5000;
    const keep = Math.max(24 * 60 * 60 * 1000, this.#cfg.lockoutMs * 2);
    const cutoff = new Date(this.#clock.now().getTime() - keep);
    let total = 0;
    for (let i = 0; i < (opts?.maxBatches ?? 20); i++) {
      const n = await this.#store.purgeLoginFailures(cutoff, batch);
      total += n;
      if (n < batch) break;
    }
    return { loginFailures: total };
  }

  #dummy(): Promise<string> {
    this.#dummyHash ??= hashPassword('dummy-password-for-timing', this.#cfg.scrypt);
    return this.#dummyHash;
  }
}
