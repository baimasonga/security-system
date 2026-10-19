import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sha256Hex } from '@trust/crypto';
import { DomainError, type Clock, type UserPrincipal } from '@trust/shared-types';
import type {
  CredentialRecord,
  CredentialScope,
  InventoryAuthority,
  InventoryRepo,
  InventoryStore,
  InventoryTx,
} from './model.ts';
import { INVENTORY_REASONS, type InventoryReason } from './service.ts';

export type CredentialMetadata = Omit<CredentialRecord, 'secretHash' | 'rotatedAt'>;
export interface CredentialIdentity extends CredentialScope {
  credentialId: string;
  purpose: 'events:write';
  source: 'backend_report';
}
export interface CredentialDependencies {
  store: InventoryStore;
  clock: Clock;
  enabled(): boolean;
  authorize(p: UserPrincipal, orgId: string, permission: 'ops:manage_credentials'): Promise<void>;
  assertWritable(orgId: string): Promise<void>;
  stepUp(p: UserPrincipal, code: string): Promise<void>;
  sessionActive(p: UserPrincipal, now: Date): Promise<boolean>;
}
export interface CredentialMutation {
  reason: InventoryReason;
  mfaCode: string;
}
export interface IssueCredential extends CredentialMutation {
  purpose: 'events:write';
  ttlSeconds: number;
}
export interface RotateCredential extends CredentialMutation {
  ttlSeconds: number;
  overlapSeconds: number;
}
const missing = () => new DomainError('not_found', 'not found');
const refused = () => new DomainError('unauthenticated', 'authentication required');
const conflict = () => new DomainError('conflict', 'request rejected');
const invalid = () => new DomainError('invalid_request', 'request rejected');
const metadata = (row: CredentialRecord): CredentialMetadata => ({
  id: row.id,
  orgId: row.orgId,
  applicationId: row.applicationId,
  environmentId: row.environmentId,
  purpose: row.purpose,
  source: row.source,
  createdAt: row.createdAt,
  expiresAt: row.expiresAt,
  revokedAt: row.revokedAt,
});
const sameScope = (row: CredentialRecord, scope: CredentialScope) =>
  row.orgId === scope.orgId &&
  row.applicationId === scope.applicationId &&
  row.environmentId === scope.environmentId;
const DUMMY_HASH = sha256Hex('warrior-operations-unknown-credential');
export class CredentialService {
  readonly #d: CredentialDependencies;
  constructor(d: CredentialDependencies) {
    this.#d = d;
  }
  #enabled() {
    if (!this.#d.enabled()) throw missing();
  }
  async #parents(repo: InventoryRepo, scope: CredentialScope, active: boolean) {
    const app = await repo.find('application', scope.orgId, scope.applicationId);
    const env = await repo.find('environment', scope.orgId, scope.environmentId);
    if (!app || !env || env.applicationId !== app.id) throw missing();
    if (active && (app.state !== 'active' || env.state !== 'active')) throw conflict();
  }
  async #authorize(p: UserPrincipal, scope: CredentialScope, authority?: InventoryAuthority) {
    const a = authority ?? this.#d;
    await a.authorize(p, scope.orgId, 'ops:manage_credentials');
    const active = authority?.sessionActive
      ? await authority.sessionActive(p, this.#d.clock.now())
      : await this.#d.sessionActive(p, this.#d.clock.now());
    if (!active) throw refused();
  }
  async #writable(orgId: string, authority: Pick<InventoryAuthority, 'assertWritable'> = this.#d) {
    try {
      await authority.assertWritable(orgId);
    } catch (e) {
      if (e instanceof DomainError && e.code === 'frozen')
        throw new DomainError('forbidden', 'request rejected');
      throw e;
    }
  }
  async #prepare(
    p: UserPrincipal,
    scope: CredentialScope,
    input: CredentialMutation,
    action: 'issue' | 'rotate' | 'revoke',
    id?: string,
  ) {
    this.#enabled();
    await this.#authorize(p, scope);
    await this.#parents(this.#d.store, scope, false);
    if (id) {
      const row = await this.#d.store.findCredential(id);
      if (!row || !sameScope(row, scope)) throw missing();
    }
    if (!INVENTORY_REASONS.includes(input.reason) || !/^[0-9]{6}$/.test(input.mfaCode))
      throw invalid();
    if (action !== 'revoke') await this.#writable(scope.orgId);
    // The auth transaction consumes this factor before any operations lock is acquired.
    // Failure/ambiguity later NEVER restores the factor; retry requires a fresh code.
    await this.#d.stepUp(p, input.mfaCode);
  }
  async #checkManagement(
    tx: InventoryTx,
    p: UserPrincipal,
    scope: CredentialScope,
    write: boolean,
  ) {
    this.#enabled();
    await this.#authorize(p, scope, tx.authority);
    await this.#parents(tx, scope, write);
    if (write) await this.#writable(scope.orgId, tx.authority);
  }
  #ttl(ttl: number) {
    if (!Number.isInteger(ttl) || ttl < 86400 || ttl > 7776000) throw invalid();
  }
  async #mint(tx: InventoryTx, scope: CredentialScope, ttl: number, now: Date) {
    const id = 'opc_' + randomBytes(16).toString('hex');
    const secret = randomBytes(32).toString('hex');
    const row: CredentialRecord = {
      ...scope,
      id,
      purpose: 'events:write',
      source: 'backend_report',
      secretHash: sha256Hex(secret),
      createdAt: now,
      expiresAt: new Date(+now + ttl * 1000),
      revokedAt: null,
      rotatedAt: null,
    };
    await tx.insertCredential(row);
    return { credential: metadata(row), token: `ops_v1.${id}.${secret}` };
  }
  async #audit(
    tx: InventoryTx,
    p: UserPrincipal,
    row: CredentialMetadata,
    action: string,
    reason: InventoryReason,
  ) {
    await tx.audit.append({
      actor: { type: 'user', id: p.userId },
      orgId: row.orgId,
      action: `operations.credential.${action}`,
      target: { type: 'operations_credential', id: row.id },
      reason,
      metadata: {
        application_id: row.applicationId,
        environment_id: row.environmentId,
        purpose: row.purpose,
      },
    });
  }
  async issue(p: UserPrincipal, scope: CredentialScope, input: IssueCredential) {
    this.#ttl(input.ttlSeconds);
    if (input.purpose !== 'events:write') throw invalid();
    await this.#prepare(p, scope, input, 'issue');
    return this.#d.store.transaction(scope.orgId, async (tx) => {
      await this.#checkManagement(tx, p, scope, true);
      const now = this.#d.clock.now();
      if ((await tx.listCredentials(scope, { limit: 3, activeAt: now })).length >= 2)
        throw conflict();
      const issued = await this.#mint(tx, scope, input.ttlSeconds, now);
      await this.#audit(tx, p, issued.credential, 'issued', input.reason);
      return issued;
    });
  }
  async rotate(p: UserPrincipal, scope: CredentialScope, id: string, input: RotateCredential) {
    this.#ttl(input.ttlSeconds);
    if (
      !Number.isInteger(input.overlapSeconds) ||
      input.overlapSeconds < 0 ||
      input.overlapSeconds > 3600
    )
      throw invalid();
    await this.#prepare(p, scope, input, 'rotate', id);
    return this.#d.store.transaction(scope.orgId, async (tx) => {
      await this.#checkManagement(tx, p, scope, true);
      const now = this.#d.clock.now();
      const old = await tx.findCredential(id);
      if (!old || !sameScope(old, scope)) throw missing();
      const active = await tx.listCredentials(scope, { limit: 3, activeAt: now });
      if (
        old.revokedAt ||
        old.expiresAt <= now ||
        old.rotatedAt ||
        active.length > 2 ||
        active.some((row) => row.id !== old.id && row.rotatedAt !== null) ||
        (input.overlapSeconds > 0 && active.length >= 2)
      )
        throw conflict();
      await tx.updateCredential({
        ...old,
        rotatedAt: now,
        expiresAt: new Date(Math.min(+old.expiresAt, +now + input.overlapSeconds * 1000)),
        revokedAt: input.overlapSeconds === 0 ? now : null,
      });
      const issued = await this.#mint(tx, scope, input.ttlSeconds, now);
      await this.#audit(tx, p, issued.credential, 'rotated', input.reason);
      // Link the predecessor by a public ID only; never a digest or secret.
      await tx.audit.append({
        actor: { type: 'user', id: p.userId },
        orgId: scope.orgId,
        action: 'operations.credential.overlap_started',
        target: { type: 'operations_credential', id: old.id },
        reason: input.reason,
        metadata: { successor_id: issued.credential.id, overlap_seconds: input.overlapSeconds },
      });
      return issued;
    });
  }
  async revoke(p: UserPrincipal, scope: CredentialScope, id: string, input: CredentialMutation) {
    await this.#prepare(p, scope, input, 'revoke', id);
    return this.#d.store.transaction(scope.orgId, async (tx) => {
      // Emergency revocation remains possible during freeze and after ancestor archival.
      await this.#checkManagement(tx, p, scope, false);
      const row = await tx.findCredential(id);
      if (!row || !sameScope(row, scope)) throw missing();
      if (!row.revokedAt) {
        row.revokedAt = this.#d.clock.now();
        await tx.updateCredential(row);
        await this.#audit(tx, p, metadata(row), 'revoked', input.reason);
      }
      return { credential: metadata(row) };
    });
  }
  async list(
    p: UserPrincipal,
    scope: CredentialScope,
    options: { limit?: number; cursor?: string } = {},
  ) {
    this.#enabled();
    await this.#authorize(p, scope);
    await this.#parents(this.#d.store, scope, false);
    const limit = options.limit ?? 50;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw invalid();
    const scopeKey = JSON.stringify([scope.orgId, scope.applicationId, scope.environmentId]);
    let after: string | undefined;
    if (options.cursor) {
      try {
        if (options.cursor.length > 512 || !/^[A-Za-z0-9_-]+$/.test(options.cursor))
          throw invalid();
        const cursor = JSON.parse(Buffer.from(options.cursor, 'base64url').toString('utf8')) as {
          scope?: string;
          id?: string;
        };
        if (cursor.scope !== scopeKey || typeof cursor.id !== 'string') throw invalid();
        const row = await this.#d.store.findCredential(cursor.id);
        if (!row || !sameScope(row, scope)) throw invalid();
        after = row.id;
      } catch {
        throw invalid();
      }
    }
    const rows = await this.#d.store.listCredentials(scope, {
      limit: limit + 1,
      ...(after ? { after } : {}),
    });
    const items = rows.slice(0, limit).map(metadata);
    const nextCursor =
      rows.length > limit
        ? Buffer.from(JSON.stringify({ scope: scopeKey, id: items.at(-1)!.id })).toString(
            'base64url',
          )
        : null;
    return { items, nextCursor };
  }
  #secretMatches(row: CredentialRecord | undefined, secret: string) {
    const sane = !!row && /^[a-f0-9]{64}$/.test(row.secretHash);
    const equal = timingSafeEqual(
      Buffer.from(sane ? row.secretHash : DUMMY_HASH, 'hex'),
      Buffer.from(sha256Hex(secret), 'hex'),
    );
    return sane && equal;
  }
  /** The callback MUST be retry-safe and have no network side effects. OPS-004 ingestion uses this
   * transaction rather than caching a detached authentication result across a revoke/commit race. */
  async withCredential<T>(
    token: string | undefined,
    expected: Partial<CredentialScope> & { purpose?: string; source?: string },
    fn: (tx: InventoryTx, identity: CredentialIdentity) => Promise<T>,
  ): Promise<T> {
    if (!this.#d.enabled()) throw refused();
    const match =
      typeof token === 'string' ? /^ops_v1\.(opc_[a-f0-9]{32})\.([a-f0-9]{64})$/.exec(token) : null;
    if (!match) throw refused();
    const id = match[1]!,
      secret = match[2]!;
    const observed = await this.#d.store.findCredential(id);
    if (!this.#secretMatches(observed, secret) || !observed) throw refused();
    return this.#d.store.transaction(observed.orgId, async (tx) => {
      const row = await tx.findCredential(id);
      if (!this.#secretMatches(row, secret) || !row) throw refused();
      const check = async () => {
        if (
          !this.#d.enabled() ||
          row.revokedAt ||
          row.expiresAt <= this.#d.clock.now() ||
          row.purpose !== 'events:write' ||
          row.source !== 'backend_report' ||
          (expected.orgId !== undefined && expected.orgId !== row.orgId) ||
          (expected.applicationId !== undefined && expected.applicationId !== row.applicationId) ||
          (expected.environmentId !== undefined && expected.environmentId !== row.environmentId) ||
          (expected.purpose !== undefined && expected.purpose !== row.purpose) ||
          (expected.source !== undefined && expected.source !== row.source)
        )
          throw refused();
        try {
          await this.#parents(tx, row, true);
        } catch (e) {
          if (e instanceof DomainError) throw refused();
          throw e;
        }
      };
      await check();
      const identity: CredentialIdentity = {
        credentialId: row.id,
        orgId: row.orgId,
        applicationId: row.applicationId,
        environmentId: row.environmentId,
        purpose: row.purpose,
        source: row.source,
      };
      const out = await fn(tx, identity);
      await check();
      return out;
    });
  }
}
