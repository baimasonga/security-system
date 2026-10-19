import { IdentityMailOutbox } from './identity-outbox.ts';
import { randomBytes } from 'node:crypto';
import { MfaCipher, base32, matchingCounter } from './mfa.ts';
import { newId, newSecretToken, sha256Hex } from '@trust/crypto';
import type { AuditLog } from '@trust/audit';
import {
  DomainError,
  type Clock,
  type OrgRole,
  type PlatformRole,
  type UserPrincipal,
} from '@trust/shared-types';
import { hashPassword, verifyPassword, DEFAULT_SCRYPT, type ScryptParams } from './password.ts';
import { canGrantRole, roleAllows, type Permission } from './rbac.ts';
import type { AuthStore, AuthTx, MfaState, Membership, Organization, User } from './model.ts';
import {
  COSE_ALGS,
  checkClientData,
  counterAcceptable,
  verifyAssertion,
  verifyRegistration,
  type CoseAlg,
  type RelyingParty,
} from './webauthn.ts';

const PASSKEY_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const PASSKEY_FAILED = 'passkey sign-in failed';

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

export interface IdentityDelivery {
  send(message: { id: string; to: string; subject: string; text: string }): Promise<{ id: string }>;
}
export class AuthService {
  readonly #mfa: MfaCipher | undefined;
  readonly #rp: (RelyingParty & { rpName: string }) | undefined;
  readonly #signal:
    | ((
        kind: 'passkey_counter_regression',
        ctx: { subject: string; attributes: Record<string, unknown> },
      ) => void)
    | undefined;
  readonly #requireOperatorMfa: boolean;
  readonly #mail: IdentityDelivery | undefined;
  readonly #outbox: IdentityMailOutbox | undefined;
  readonly #publicOrigin: string;
  readonly #deliveries = new Set<Promise<void>>();
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
    identityDelivery?: IdentityDelivery;
    identityMailEncryptionKey?: string;
    identityMailOutcome?: (outcome: 'sent' | 'retried' | 'discarded') => void;
    publicOrigin?: string;
    mfaEncryptionKey?: string;
    requireOperatorMfa?: boolean;
    /** Passkeys (ADR-023): validated relying party; undefined disables them. */
    webauthn?: RelyingParty & { rpName: string };
    /** Security signals the identity context raises (e.g. a cloned authenticator). */
    onSecuritySignal?: (
      kind: 'passkey_counter_regression',
      ctx: { subject: string; attributes: Record<string, unknown> },
    ) => void;
  }) {
    this.#rp = deps.webauthn;
    this.#signal = deps.onSecuritySignal;
    this.#store = deps.store;
    this.#mfa = deps.mfaEncryptionKey ? new MfaCipher(deps.mfaEncryptionKey) : undefined;
    this.#requireOperatorMfa = deps.requireOperatorMfa ?? false;
    if (this.#requireOperatorMfa && !this.#mfa)
      throw new Error('MFA key required for operator enforcement');
    this.#mail = deps.identityDelivery;
    if (deps.identityMailEncryptionKey && !this.#mail)
      throw new Error('identity mail delivery required for durable outbox');
    this.#outbox =
      deps.identityMailEncryptionKey && this.#mail
        ? new IdentityMailOutbox({
            store: deps.store,
            clock: deps.clock,
            delivery: this.#mail,
            key: deps.identityMailEncryptionKey,
            onOutcome: deps.identityMailOutcome,
          })
        : undefined;
    this.#publicOrigin = deps.publicOrigin ?? 'http://localhost:8080';
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
    code?: string;
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
    const token = newSecretToken('sess');
    const expiresAt = new Date(now.getTime() + this.#cfg.sessionTtlMs);
    const sessionId = newId('ses');
    const issued = await this.#store.transaction(async (tx) => {
      const current = await tx.findUserForUpdate(user.id);
      if (!current || current.status !== 'active' || current.passwordHash !== user.passwordHash)
        return false;
      const locked = await tx.findLoginFailure(failKey);
      if (locked?.lockedUntil && locked.lockedUntil > this.#clock.now()) return false;
      if (current.mfa?.enabled) {
        const updated = this.#consumeFactor(current, input.code ?? '', this.#clock.now());
        if (!updated) {
          await this.#recordFactorFailure(tx, user.id, failKey);
          return false;
        }
        await tx.setMfa(user.id, updated);
      }
      await tx.clearLoginFailure(failKey);
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
      return true;
    });
    if (!issued) throw new DomainError('unauthenticated', BAD_LOGIN);
    return { token, expiresAt, userId: user.id };
  }

  get deliveryConfigured() {
    return !!this.#mail;
  }

  async account(principal: UserPrincipal) {
    const user = await this.#store.findUserById(principal.userId);
    if (!user) throw new DomainError('unauthenticated', 'authentication required');
    return {
      userId: user.id,
      email: user.email,
      emailVerified: !!user.emailVerifiedAt,
      platformRole: user.platformRole,
      recoveryConfigured: !!this.#mail,
      mfaConfigured: !!this.#mfa,
      mfaEnabled: !!user.mfa?.enabled,
      operatorMfaRequired: this.#requireOperatorMfa,
    };
  }

  #consumeFactor(user: User, code: string, now: Date): MfaState | undefined {
    const factor = user.mfa;
    if (!factor?.enabled || !this.#mfa) return undefined;
    let secret: Buffer;
    try {
      secret = this.#mfa.open(user.id, factor.sealedSecret);
    } catch {
      return undefined;
    }
    const recoveryHash = sha256Hex(code);
    if (/^[0-9a-f]{32}$/.test(code) && factor.recoveryHashes.includes(recoveryHash))
      return { ...factor, recoveryHashes: factor.recoveryHashes.filter((h) => h !== recoveryHash) };
    const counter = matchingCounter(secret, code, now.getTime(), factor.lastCounter);
    return counter === undefined ? undefined : { ...factor, lastCounter: counter };
  }
  async #recordFactorFailure(tx: AuthTx, userId: string, key: string) {
    const { count } = await tx.recordLoginFailure(
      key,
      this.#clock.now(),
      this.#cfg.maxFailedLogins,
      this.#cfg.lockoutMs,
    );
    await tx.audit.append({
      actor: { type: 'user', id: userId },
      action: 'identity.factor_failed',
      metadata: { consecutive_failures: count },
    });
  }
  async #failedFactor(userId: string, key: string) {
    await this.#store.transaction(async (tx) => {
      await tx.findUserForUpdate(userId);
      await this.#recordFactorFailure(tx, userId, key);
    });
  }
  async #mfaChange<T>(
    principal: UserPrincipal,
    password: string,
    change: (tx: AuthTx, user: User, now: Date) => Promise<T>,
  ): Promise<T> {
    if (!this.#mfa) throw new DomainError('conflict', 'MFA is not configured');
    return this.#reauthenticated(principal, password, change);
  }
  /** Password re-authentication for account-security changes, under the user lock with a live-session check. */
  async #reauthenticated<T>(
    principal: UserPrincipal,
    password: string,
    change: (tx: AuthTx, user: User, now: Date) => Promise<T>,
  ): Promise<T> {
    const user = await this.#store.findUserById(principal.userId);
    if (!user) throw new DomainError('unauthenticated', 'authentication required');
    const key = sha256Hex(user.email);
    const fail = await this.#store.findLoginFailure(key);
    const ok = await verifyPassword(password.slice(0, 256), user.passwordHash);
    if (!ok || (fail?.lockedUntil && fail.lockedUntil > this.#clock.now())) {
      await this.#failedFactor(user.id, key);
      throw new DomainError('unauthenticated', 'invalid credentials or code');
    }
    const result = await this.#store.transaction(
      async (tx): Promise<{ ok: true; value: T } | { ok: false }> => {
        const current = await tx.findUserForUpdate(user.id);
        // Holding the user lock serializes management with reset, enrollment and login.
        const session = await tx.findSessionById(principal.sessionId);
        if (
          !session ||
          session.userId !== user.id ||
          session.revokedAt ||
          session.expiresAt <= this.#clock.now()
        )
          throw new DomainError('unauthenticated', 'authentication required');
        if (!current || current.status !== 'active' || current.passwordHash !== user.passwordHash)
          throw new DomainError('unauthenticated', 'invalid credentials or code');
        const locked = await tx.findLoginFailure(key);
        if (locked?.lockedUntil && locked.lockedUntil > this.#clock.now())
          throw new DomainError('unauthenticated', 'invalid credentials or code');
        try {
          return { ok: true, value: await change(tx, current, this.#clock.now()) };
        } catch (e) {
          if (!(e instanceof DomainError) || e.code !== 'unauthenticated') throw e;
          await this.#recordFactorFailure(tx, user.id, key);
          return { ok: false };
        }
      },
    );
    if (!result.ok) throw new DomainError('unauthenticated', 'invalid credentials or code');
    return result.value;
  }
  async beginMfa(principal: UserPrincipal, password: string) {
    const secret = randomBytes(20);
    const sealedSecret = this.#mfa?.seal(principal.userId, secret);
    return this.#mfaChange(principal, password, async (tx, user, now) => {
      if (user.mfa?.enabled) throw new DomainError('conflict', 'MFA is already enabled');
      await tx.setMfa(user.id, {
        sealedSecret: sealedSecret!,
        enabled: false,
        expiresAt: now.getTime() + 600000,
        lastCounter: -1,
        recoveryHashes: [],
      });
      await tx.audit.append({
        actor: { type: 'user', id: user.id },
        action: 'identity.mfa_enrollment_started',
      });
      return { setupKey: base32(secret), expiresAt: new Date(now.getTime() + 600000) };
    });
  }
  async confirmMfa(principal: UserPrincipal, password: string, code: string) {
    const recoveryCodes = Array.from({ length: 10 }, () => randomBytes(16).toString('hex'));
    return this.#mfaChange(principal, password, async (tx, user, now) => {
      const factor = user.mfa;
      if (!factor || factor.enabled || factor.expiresAt <= now.getTime())
        throw new DomainError('unauthenticated', 'invalid credentials or code');
      const counter = matchingCounter(
        this.#mfa!.open(user.id, factor.sealedSecret),
        code,
        now.getTime(),
        -1,
      );
      if (counter === undefined)
        throw new DomainError('unauthenticated', 'invalid credentials or code');
      await tx.setMfa(user.id, {
        ...factor,
        enabled: true,
        expiresAt: 0,
        lastCounter: counter,
        recoveryHashes: recoveryCodes.map(sha256Hex),
      });
      await tx.revokeUserSessions(user.id, now);
      await tx.clearLoginFailure(sha256Hex(user.email));
      await tx.audit.append({
        actor: { type: 'user', id: user.id },
        action: 'identity.mfa_enabled',
      });
      return { recoveryCodes };
    });
  }
  async disableMfa(principal: UserPrincipal, password: string, code: string, reason: string) {
    if (reason.trim().length < 3 || reason.length > 500)
      throw new DomainError('invalid_request', 'a reason is required');
    return this.#mfaChange(principal, password, async (tx, user, now) => {
      if (!this.#consumeFactor(user, code, now))
        throw new DomainError('unauthenticated', 'invalid credentials or code');
      await tx.setMfa(user.id, null);
      await tx.revokeUserSessions(user.id, now);
      await tx.clearLoginFailure(sha256Hex(user.email));
      await tx.audit.append({
        actor: { type: 'user', id: user.id },
        action: 'identity.mfa_disabled',
        reason: reason.trim(),
      });
    });
  }

  // ---- passkeys (ADR-023) -------------------------------------------------------------------------------------

  get passkeysConfigured(): boolean {
    return this.#rp !== undefined;
  }
  #relyingParty(): RelyingParty & { rpName: string } {
    if (!this.#rp) throw new DomainError('conflict', 'passkeys are not configured');
    return this.#rp;
  }

  /** Password re-authentication, then creation options bound to this user and session (5 minutes, single use). */
  async beginPasskeyRegistration(principal: UserPrincipal, password: string) {
    const rp = this.#relyingParty();
    const challenge = randomBytes(32).toString('base64url');
    return this.#reauthenticated(principal, password, async (tx, user, now) => {
      await tx.putWebauthnChallenge({
        challengeHash: sha256Hex(challenge),
        purpose: 'register',
        userId: user.id,
        sessionId: principal.sessionId,
        createdAt: now,
        expiresAt: new Date(now.getTime() + PASSKEY_CHALLENGE_TTL_MS),
      });
      const existing = await tx.listPasskeys(user.id);
      return {
        challenge,
        rp: { id: rp.rpId, name: rp.rpName },
        user: {
          id: Buffer.from(user.id).toString('base64url'),
          name: user.email,
          displayName: user.email,
        },
        pubKeyCredParams: COSE_ALGS.map((alg) => ({ type: 'public-key', alg })),
        timeout: PASSKEY_CHALLENGE_TTL_MS,
        attestation: 'none',
        authenticatorSelection: {
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'required',
        },
        excludeCredentials: existing.map((p) => ({ type: 'public-key', id: p.credentialId })),
      };
    });
  }

  async finishPasskeyRegistration(
    principal: UserPrincipal,
    input: { name: string; clientDataJSON: Uint8Array; attestationObject: Uint8Array },
  ): Promise<{ id: string; name: string; createdAt: Date }> {
    const rp = this.#relyingParty();
    const name = input.name.trim();
    if (name.length < 1 || name.length > 100)
      throw new DomainError('invalid_request', 'a passkey name is required');
    const failed = () => new DomainError('invalid_request', 'passkey registration failed');
    let challenge: string;
    try {
      challenge = checkClientData(input.clientDataJSON, 'webauthn.create', rp);
    } catch {
      throw failed();
    }
    // Consumed on its own first: a failed verification still burns the challenge.
    const c = await this.#store.consumeWebauthnChallenge(
      sha256Hex(challenge),
      'register',
      this.#clock.now(),
    );
    if (!c || c.userId !== principal.userId || c.sessionId !== principal.sessionId) throw failed();
    let reg: ReturnType<typeof verifyRegistration>;
    try {
      reg = verifyRegistration(input, rp);
    } catch {
      throw failed();
    }
    return this.#store.transaction(async (tx) => {
      const now = this.#clock.now();
      const user = await tx.findUserForUpdate(principal.userId);
      const session = await tx.findSessionById(principal.sessionId);
      if (
        !user ||
        user.status !== 'active' ||
        !session ||
        session.userId !== user.id ||
        session.revokedAt ||
        session.expiresAt <= now
      )
        throw new DomainError('unauthenticated', 'authentication required');
      if (await tx.findPasskey(reg.credentialId))
        throw new DomainError('conflict', 'this passkey is already registered');
      await tx.insertPasskey({
        credentialId: reg.credentialId,
        userId: user.id,
        name,
        alg: reg.key.alg,
        publicKeyJwk: reg.key.jwk,
        signCount: reg.signCount,
        backupEligible: reg.backupEligible,
        backedUp: reg.backedUp,
        createdAt: now,
        lastUsedAt: null,
      });
      await tx.audit.append({
        actor: { type: 'user', id: user.id },
        action: 'identity.passkey_added',
        metadata: { credential: sha256Hex(reg.credentialId).slice(0, 16), alg: reg.key.alg },
      });
      return { id: reg.credentialId, name, createdAt: now };
    });
  }

  /** A sign-in challenge (5 minutes, single use) for discoverable credentials. */
  async beginPasskeyLogin() {
    const rp = this.#relyingParty();
    const challenge = randomBytes(32).toString('base64url');
    const now = this.#clock.now();
    await this.#store.putWebauthnChallenge({
      challengeHash: sha256Hex(challenge),
      purpose: 'login',
      userId: null,
      sessionId: null,
      createdAt: now,
      expiresAt: new Date(now.getTime() + PASSKEY_CHALLENGE_TTL_MS),
    });
    return {
      challenge,
      rpId: rp.rpId,
      timeout: PASSKEY_CHALLENGE_TTL_MS,
      userVerification: 'required',
      allowCredentials: [] as never[],
    };
  }

  async finishPasskeyLogin(input: {
    credentialId: string;
    clientDataJSON: Uint8Array;
    authenticatorData: Uint8Array;
    signature: Uint8Array;
    userHandle?: Uint8Array | undefined;
  }): Promise<{ token: string; expiresAt: Date; userId: string }> {
    const rp = this.#relyingParty();
    const failed = () => new DomainError('unauthenticated', PASSKEY_FAILED);
    let challenge: string;
    try {
      challenge = checkClientData(input.clientDataJSON, 'webauthn.get', rp);
    } catch {
      throw failed();
    }
    const c = await this.#store.consumeWebauthnChallenge(
      sha256Hex(challenge),
      'login',
      this.#clock.now(),
    );
    const pk = c ? await this.#store.findPasskey(input.credentialId) : undefined;
    const handleOk =
      !input.userHandle || (pk && Buffer.from(input.userHandle).toString('utf8') === pk.userId);
    let verified: ReturnType<typeof verifyAssertion> | undefined;
    if (pk && handleOk) {
      try {
        verified = verifyAssertion(input, { alg: pk.alg as CoseAlg, jwk: pk.publicKeyJwk }, rp);
      } catch {
        verified = undefined;
      }
    }
    if (!pk || !verified) {
      await this.#audit.append({
        actor: pk ? { type: 'user', id: pk.userId } : { type: 'anonymous' },
        action: 'user.passkey_login_failed',
        metadata: { credential: sha256Hex(input.credentialId).slice(0, 16) },
      });
      throw failed();
    }
    const assertion = verified;
    const token = newSecretToken('sess');
    const sessionId = newId('ses');
    const result = await this.#store.transaction(async (tx) => {
      const now = this.#clock.now();
      const user = await tx.findUserForUpdate(pk.userId);
      const current = await tx.findPasskeyForUpdate(pk.credentialId);
      if (!user || user.status !== 'active' || !current) return { ok: false as const };
      if (!counterAcceptable(current.signCount, assertion.signCount)) {
        await tx.audit.append({
          actor: { type: 'user', id: user.id },
          action: 'identity.passkey_counter_regression',
          metadata: {
            credential: sha256Hex(pk.credentialId).slice(0, 16),
            stored: current.signCount,
            presented: assertion.signCount,
          },
        });
        return {
          ok: false as const,
          regression: { stored: current.signCount, presented: assertion.signCount },
        };
      }
      await tx.updatePasskeyUse(pk.credentialId, assertion.signCount, assertion.backedUp, now);
      const expiresAt = new Date(now.getTime() + this.#cfg.sessionTtlMs);
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
        metadata: { session_id: sessionId, method: 'passkey' },
      });
      return { ok: true as const, expiresAt, userId: user.id };
    });
    if (!result.ok) {
      if ('regression' in result && result.regression)
        this.#signal?.('passkey_counter_regression', {
          subject: pk.userId,
          attributes: result.regression,
        });
      throw failed();
    }
    return { token, expiresAt: result.expiresAt, userId: result.userId };
  }

  async listPasskeys(principal: UserPrincipal) {
    return (await this.#store.listPasskeys(principal.userId)).map((p) => ({
      id: p.credentialId,
      name: p.name,
      createdAt: p.createdAt,
      lastUsedAt: p.lastUsedAt,
      backedUp: p.backedUp,
    }));
  }

  async deletePasskey(principal: UserPrincipal, credentialId: string, password: string) {
    return this.#reauthenticated(principal, password, async (tx, user) => {
      if (!(await tx.deletePasskey(user.id, credentialId)))
        throw new DomainError('not_found', 'passkey not found');
      await tx.audit.append({
        actor: { type: 'user', id: user.id },
        action: 'identity.passkey_removed',
        metadata: { credential: sha256Hex(credentialId).slice(0, 16) },
      });
    });
  }

  async requestPasswordReset(email: string): Promise<void> {
    await this.#requestIdentityToken(email, 'reset');
  }
  async requestEmailVerification(principal: UserPrincipal): Promise<void> {
    const user = await this.#store.findUserById(principal.userId);
    if (!user) throw new DomainError('unauthenticated', 'authentication required');
    if (user.emailVerifiedAt) return;
    await this.#requestIdentityToken(user.email, 'verify');
  }
  async #requestIdentityToken(email: string, purpose: 'reset' | 'verify') {
    if (!this.#mail) throw new DomainError('conflict', 'email recovery is not configured');
    const user = await this.#store.findUserByEmail(email.trim().toLowerCase());
    if (!user || user.status !== 'active') return;
    const token = newSecretToken('recover');
    const tokenHash = sha256Hex(token);
    const now = this.#clock.now();
    const message = {
      id: tokenHash,
      to: user.email,
      subject:
        purpose === 'reset'
          ? 'Reset your Rokela Bai Bureh Warrior password'
          : 'Verify your Rokela Bai Bureh Warrior email',
      text: `Open ${this.#publicOrigin}/#${purpose}=${token} within 15 minutes. If you did not request this, ignore this message.`,
    };
    const row = {
      userId: user.id,
      purpose,
      tokenHash,
      sealed: '',
      createdAt: now,
      expiresAt: new Date(+now + 15 * 60000),
      nextAttemptAt: now,
      attempts: 0,
      claim: null,
      lockedUntil: null,
    };
    if (this.#outbox) row.sealed = this.#outbox.cipher.seal(row, message);
    const issued = await this.#store.transaction(async (tx) => {
      const current = await tx.findUserForUpdate(user.id);
      if (!current || current.status !== 'active') return false;
      const prior = await tx.findUserIdentityToken(user.id, purpose);
      if (prior && now.getTime() - prior.createdAt.getTime() < 60000) return false;
      await tx.putIdentityToken({
        userId: user.id,
        purpose,
        tokenHash,
        createdAt: now,
        expiresAt: new Date(now.getTime() + 15 * 60000),
        usedAt: null,
      });
      if (this.#outbox) await tx.putIdentityMail(row);
      await tx.audit.append({
        actor: { type: 'anonymous' },
        action: `identity.${purpose}_requested`,
        target: { type: 'user', id: user.id },
      });
      return true;
    });
    if (!issued) return;
    if (this.#outbox) {
      const pending = this.#outbox
        .runOnce()
        .then(() => undefined)
        .catch(() => undefined);
      this.#deliveries.add(pending);
      void pending.finally(() => this.#deliveries.delete(pending));
      return;
    }
    // Delivery is outside retryable transactions and the public response does not await provider latency.
    const pending = this.#mail
      .send(message)
      .then(() => undefined)
      .catch(async () => {
        await this.#audit
          .append({
            actor: { type: 'system' },
            action: 'identity.delivery_failed',
            target: { type: 'user', id: user.id },
            metadata: { purpose },
          })
          .catch(() => undefined);
      });
    this.#deliveries.add(pending);
    void pending.finally(() => this.#deliveries.delete(pending));
  }
  async flushIdentityMail() {
    await Promise.all([...this.#deliveries]);
    await this.#outbox?.runOnce();
  }
  async processIdentityMail() {
    return this.#outbox ? this.#outbox.runOnce() : { sent: 0, retried: 0, discarded: 0 };
  }
  async closeIdentityMail() {
    await this.#outbox?.stop();
    await Promise.all([...this.#deliveries]);
  }
  async completeIdentityToken(token: string, purpose: 'reset' | 'verify', password?: string) {
    if (token.length > 128)
      throw new DomainError('invalid_request', 'invalid or expired recovery link');
    const tokenHash = sha256Hex(token);
    const found = await this.#store.findIdentityToken(tokenHash);
    const refuse = () => new DomainError('invalid_request', 'invalid or expired recovery link');
    if (!found || found.purpose !== purpose) throw refuse();
    const user = await this.#store.findUserById(found.userId);
    if (!user || user.status !== 'active') throw refuse();
    if (
      purpose === 'reset' &&
      (!password ||
        password.length < 12 ||
        password.length > 256 ||
        password.toLowerCase() === user.email)
    )
      throw new DomainError(
        'invalid_request',
        'password must be 12-256 characters and not equal the email',
      );
    const hash = purpose === 'reset' ? await hashPassword(password!, this.#cfg.scrypt) : undefined;
    const now = this.#clock.now();
    await this.#store.transaction(async (tx) => {
      const current = await tx.findUserForUpdate(user.id);
      if (
        !current ||
        current.status !== 'active' ||
        !(await tx.consumeIdentityToken(user.id, purpose, tokenHash, now))
      )
        throw refuse();
      if (hash) {
        await tx.setPasswordHash(user.id, hash);
        if (current.mfa && !current.mfa.enabled) await tx.setMfa(user.id, null);
        await tx.revokeUserSessions(user.id, now);
        await tx.clearLoginFailure(sha256Hex(user.email));
      } else await tx.markEmailVerified(user.id, now);
      await tx.audit.append({
        actor: { type: 'user', id: user.id },
        action: purpose === 'reset' ? 'identity.password_reset' : 'identity.email_verified',
        target: { type: 'user', id: user.id },
      });
    });
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
      await tx.findUserForUpdate(principal.userId);
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

  /** Contact facts for an active user (internal; used by sharing receipts and recipient checks). */
  async contact(userId: string): Promise<{ email: string; emailVerified: boolean } | undefined> {
    const u = await this.#store.findUserById(userId);
    return u && u.status === 'active'
      ? { email: u.email, emailVerified: !!u.emailVerifiedAt }
      : undefined;
  }

  async isMember(orgId: string, userId: string): Promise<boolean> {
    return (await this.#store.findMembership(orgId, userId)) !== undefined;
  }

  async orgExists(orgId: string): Promise<boolean> {
    return (await this.#store.findOrganization(orgId)) !== undefined;
  }

  /** Operator bootstrap. Deliberately NOT exposed over HTTP: invoked by deployment tooling only. */
  async bootstrapPlatformAdmin(email: string, reason: string): Promise<void> {
    if (reason.trim().length < 3) throw new Error('a reason is required');
    const u = await this.#store.findUserByEmail(email.trim().toLowerCase());
    if (!u) throw new Error('user not found');
    await this.#store.transaction(async (tx) => {
      await tx.setPlatformRole(u.id, 'platform_admin');
      await tx.audit.append({
        actor: { type: 'system' },
        action: 'operator.bootstrapped',
        target: { type: 'user', id: u.id },
        reason: reason.trim(),
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

  /**
   * Fresh second factor for a privileged decision (ADR-022). The live session's user must have authenticator MFA
   * enabled and submit a current six-digit code; recovery codes are not accepted here. The code is consumed under
   * the user lock with the same replay protection as login, and a failure counts toward the account lockout.
   */
  async stepUp(p: { userId: string; sessionId: string }, code: string): Promise<void> {
    if (!this.#mfa || !/^\d{6}$/.test(code))
      throw new DomainError('unauthenticated', 'invalid credentials or code');
    const user = await this.#store.findUserById(p.userId);
    if (!user) throw new DomainError('unauthenticated', 'authentication required');
    const key = sha256Hex(user.email);
    const ok = await this.#store.transaction(async (tx) => {
      const now = this.#clock.now();
      const current = await tx.findUserForUpdate(user.id);
      const session = await tx.findSessionById(p.sessionId);
      if (!session || session.userId !== user.id || session.revokedAt || session.expiresAt <= now)
        throw new DomainError('unauthenticated', 'authentication required');
      if (!current || current.status !== 'active' || !current.mfa?.enabled)
        throw new DomainError('forbidden', 'authenticator MFA is required for this action');
      const locked = await tx.findLoginFailure(key);
      if (locked?.lockedUntil && locked.lockedUntil > now)
        throw new DomainError('unauthenticated', 'invalid credentials or code');
      const updated = this.#consumeFactor(current, code, now);
      if (!updated) {
        await this.#recordFactorFailure(tx, user.id, key);
        return false;
      }
      await tx.setMfa(user.id, updated);
      await tx.audit.append({
        actor: { type: 'user', id: user.id },
        action: 'identity.step_up_succeeded',
        metadata: { session_id: p.sessionId },
      });
      return true;
    });
    if (!ok) throw new DomainError('unauthenticated', 'invalid credentials or code');
  }

  /** For privileged requests: whether a user exists, is active, and their platform role. */
  async operatorTarget(
    userId: string,
  ): Promise<{ active: boolean; platformRole: PlatformRole } | undefined> {
    const u = await this.#store.findUserById(userId);
    return u ? { active: u.status === 'active', platformRole: u.platformRole } : undefined;
  }

  /** Executes an approved `operator.grant` / `operator.revoke` request (ADR-022). Takes effect on the next request. */
  async setOperatorRole(
    userId: string,
    role: PlatformRole,
    actor: { id: string; reason: string; requestId: string },
  ): Promise<void> {
    await this.#store.transaction(async (tx) => {
      const u = await tx.findUserForUpdate(userId);
      if (!u || u.status !== 'active') throw new DomainError('not_found', 'user not found');
      if (u.platformRole === role) throw new DomainError('conflict', 'role is already set');
      await tx.setPlatformRole(userId, role);
      await tx.audit.append({
        actor: { type: 'operator', id: actor.id },
        action: role === 'platform_admin' ? 'operator.granted' : 'operator.revoked',
        target: { type: 'user', id: userId },
        reason: actor.reason,
        metadata: { request_id: actor.requestId },
      });
    });
  }

  async requirePlatformAdmin(p: UserPrincipal): Promise<void> {
    // Re-read from the store: a revoked operator loses access without waiting for session expiry.
    const u = await this.#store.findUserById(p.userId);
    if (
      !u ||
      u.status !== 'active' ||
      u.platformRole !== 'platform_admin' ||
      (this.#requireOperatorMfa && !u.mfa?.enabled)
    ) {
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
  }): Promise<{ loginFailures: number; webauthnChallenges: number }> {
    const batch = opts?.batch ?? 5000;
    const keep = Math.max(24 * 60 * 60 * 1000, this.#cfg.lockoutMs * 2);
    const cutoff = new Date(this.#clock.now().getTime() - keep);
    let total = 0;
    for (let i = 0; i < (opts?.maxBatches ?? 20); i++) {
      const n = await this.#store.purgeLoginFailures(cutoff, batch);
      total += n;
      if (n < batch) break;
    }
    let challenges = 0;
    for (let i = 0; i < (opts?.maxBatches ?? 20); i++) {
      const n = await this.#store.purgeWebauthnChallenges(this.#clock.now(), batch);
      challenges += n;
      if (n < batch) break;
    }
    return { loginFailures: total, webauthnChallenges: challenges };
  }

  #dummy(): Promise<string> {
    this.#dummyHash ??= hashPassword('dummy-password-for-timing', this.#cfg.scrypt);
    return this.#dummyHash;
  }
}
