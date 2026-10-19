import { newId } from '@trust/crypto';
import { DomainError, type Clock } from '@trust/shared-types';
import {
  effectiveStatus,
  orgScope,
  platformScope,
  type Freeze,
  type Operation,
  type PrivilegedRequest,
  type PrivilegedStore,
  type PrivilegedTx,
  type RequestStatus,
} from './model.ts';

const HOUR = 3_600_000;
export const PENDING_TTL_MS = 24 * HOUR;
export const GRANT_TTL_MS = HOUR;
export const BREAK_GLASS_GRANT_TTL_MS = 15 * 60_000;
export const BREAK_GLASS_WINDOW_MS = 24 * HOUR;

/** Operations whose state lives in this module and change atomically with the request. */
type LocalOperation = 'org.unfreeze' | 'platform.unfreeze';
/** Operations owned by another bounded context (claimed, run, then settled). */
export type ExternalOperation = Exclude<Operation, LocalOperation>;

export interface StepUpPrincipal {
  userId: string;
  sessionId: string;
}

export interface PrivilegedDeps {
  store: PrivilegedStore;
  clock: Clock;
  config: {
    /** `PRIVILEGED_DUAL_CONTROL`: the direct license-revoke endpoint refuses; revocation needs approval. */
    dualControlLicenseRevoke: boolean;
    /** External audit anchoring is configured (break-glass needs an independent witness). */
    witnessConfigured: boolean;
  };
  /**
   * Fresh second factor for this live session: consumes one authenticator code (replay-protected) or throws
   * `unauthenticated`. Requires MFA to be enabled.
   */
  stepUp(p: StepUpPrincipal, code: string): Promise<void>;
  /** Throws `not_found` / `conflict` when the target cannot be used for the operation. */
  validateTarget(op: Operation, orgId: string | null, targetId: string | null): Promise<void>;
  orgExists(orgId: string): Promise<boolean>;
  /** Runs an external operation in its own audited transaction, attributing it to the request. */
  run: Record<ExternalOperation, (r: PrivilegedRequest) => Promise<void>>;
}

export interface RequestView extends Omit<PrivilegedRequest, 'status'> {
  status: RequestStatus;
}

export interface CreateRequest {
  operation: Operation;
  orgId?: string | undefined;
  targetId?: string | undefined;
  reason: string;
}

const SHAPE: Record<Operation, { org: boolean; target: boolean }> = {
  'license.revoke': { org: true, target: true },
  'operator.grant': { org: false, target: true },
  'operator.revoke': { org: false, target: true },
  'org.unfreeze': { org: true, target: false },
  'platform.unfreeze': { org: false, target: false },
};

function reasonOf(reason: string): string {
  const r = reason.trim();
  if (r.length < 3 || r.length > 500)
    throw new DomainError('invalid_request', 'a reason is required');
  return r;
}

/**
 * Dual control, JIT grants, freeze and break-glass (ADR-022).
 *
 * Invariants:
 *  - a request executes only the operation and target stored when it was created;
 *  - the requester never approves or rejects their own request (break-glass is the bounded, witnessed exception);
 *  - approval consumes a fresh authenticator code of a distinct MFA-enabled operator;
 *  - every transition happens under the request's row lock with its audit event in the same transaction, so an
 *    approval or execution cannot be replayed;
 *  - external operations are claimed (`executing`) before they run: at most once, never retried by a request.
 */
export class PrivilegedService {
  readonly #d: PrivilegedDeps;
  constructor(deps: PrivilegedDeps) {
    this.#d = deps;
  }

  get dualControlLicenseRevoke(): boolean {
    return this.#d.config.dualControlLicenseRevoke;
  }

  #view(r: PrivilegedRequest): RequestView {
    return { ...r, status: effectiveStatus(r, this.#d.clock.now()) };
  }

  async create(actorId: string, input: CreateRequest): Promise<RequestView> {
    const reason = reasonOf(input.reason);
    const shape = SHAPE[input.operation];
    if (!shape) throw new DomainError('invalid_request', 'unknown operation');
    const orgId = input.orgId ?? null;
    const targetId = input.targetId ?? null;
    if (shape.org !== (orgId !== null) || shape.target !== (targetId !== null))
      throw new DomainError('invalid_request', `invalid target for ${input.operation}`);
    if (input.operation === 'org.unfreeze' && !(await this.#d.store.getFreeze(orgScope(orgId!))))
      throw new DomainError('conflict', 'organization is not frozen');
    if (input.operation === 'platform.unfreeze' && !(await this.#d.store.getFreeze(platformScope)))
      throw new DomainError('conflict', 'platform is not frozen');
    await this.#d.validateTarget(input.operation, orgId, targetId);
    const now = this.#d.clock.now();
    const r: PrivilegedRequest = {
      id: newId('prq'),
      operation: input.operation,
      orgId,
      targetId,
      reason,
      requestedBy: actorId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + PENDING_TTL_MS),
      status: 'pending',
      decidedBy: null,
      decidedAt: null,
      decisionReason: null,
      breakGlass: false,
      witnessedAt: null,
      witnessAnchor: null,
      executeBefore: null,
      executedAt: null,
      failure: null,
    };
    await this.#d.store.transaction(async (tx) => {
      await tx.insertRequest(r);
      await this.#audit(tx, actorId, 'privileged.requested', r, reason);
    });
    return this.#view(r);
  }

  async get(id: string): Promise<RequestView> {
    const r = await this.#d.store.findRequest(id);
    if (!r) throw new DomainError('not_found', 'request not found');
    return this.#view(r);
  }

  async list(status?: RequestStatus, limit = 50): Promise<RequestView[]> {
    const stored = status === 'expired' ? undefined : status;
    const rows = await this.#d.store.listRequests({ ...(stored ? { status: stored } : {}), limit });
    return rows.map((r) => this.#view(r)).filter((v) => !status || v.status === status);
  }

  /** A distinct operator approves with a fresh authenticator code. */
  async approve(
    p: StepUpPrincipal,
    id: string,
    reason: string,
    code: string,
  ): Promise<RequestView> {
    const why = reasonOf(reason);
    const pre = await this.get(id);
    this.#decidable(pre, p.userId);
    await this.#d.stepUp(p, code); // consumes the code; failures count toward the account lockout
    return this.#transition(id, async (tx, r, now) => {
      this.#decidable(this.#view(r), p.userId);
      const next: PrivilegedRequest = {
        ...r,
        status: 'approved',
        decidedBy: p.userId,
        decidedAt: now,
        decisionReason: why,
        executeBefore: new Date(now.getTime() + GRANT_TTL_MS),
      };
      await tx.updateRequest(next);
      await this.#audit(tx, p.userId, 'privileged.approved', next, why);
      return next;
    });
  }

  async reject(actorId: string, id: string, reason: string): Promise<RequestView> {
    const why = reasonOf(reason);
    return this.#transition(id, async (tx, r, now) => {
      this.#decidable(this.#view(r), actorId);
      const next: PrivilegedRequest = {
        ...r,
        status: 'rejected',
        decidedBy: actorId,
        decidedAt: now,
        decisionReason: why,
      };
      await tx.updateRequest(next);
      await this.#audit(tx, actorId, 'privileged.rejected', next, why);
      return next;
    });
  }

  async cancel(actorId: string, id: string, reason: string): Promise<RequestView> {
    const why = reasonOf(reason);
    return this.#transition(id, async (tx, r) => {
      if (r.requestedBy !== actorId)
        throw new DomainError('forbidden', 'only the requester can cancel a request');
      const s = effectiveStatus(r, this.#d.clock.now());
      if (s !== 'pending' && s !== 'approved')
        throw new DomainError('conflict', `cannot cancel a request in state ${s}`);
      const next: PrivilegedRequest = { ...r, status: 'cancelled' };
      await tx.updateRequest(next);
      await this.#audit(tx, actorId, 'privileged.cancelled', next, why);
      return next;
    });
  }

  /**
   * The requester approves their own request when no second operator is available. Bounded (fresh code, one use
   * per operator per 24 h, 15-minute grant) and unusable until `markWitnessed` records the external anchor.
   */
  async breakGlass(
    p: StepUpPrincipal,
    id: string,
    reason: string,
    code: string,
  ): Promise<RequestView> {
    const why = reasonOf(reason);
    if (!this.#d.config.witnessConfigured)
      throw new DomainError(
        'conflict',
        'break-glass requires external audit anchoring (an independent witness) to be configured',
      );
    const check = async (r: RequestView, count: () => Promise<number>) => {
      if (r.requestedBy !== p.userId)
        throw new DomainError('forbidden', 'only the requester can use break-glass');
      if (r.status !== 'pending')
        throw new DomainError('conflict', `cannot approve a request in state ${r.status}`);
      if ((await count()) > 0)
        throw new DomainError('conflict', 'break-glass was already used in the last 24 hours');
    };
    const since = () => new Date(this.#d.clock.now().getTime() - BREAK_GLASS_WINDOW_MS);
    await check(await this.get(id), () => this.#d.store.countBreakGlassSince(p.userId, since()));
    await this.#d.stepUp(p, code);
    return this.#transition(id, async (tx, r, now) => {
      await check(this.#view(r), () => tx.countBreakGlassSince(p.userId, since()));
      const next: PrivilegedRequest = {
        ...r,
        status: 'approved',
        breakGlass: true,
        decidedBy: p.userId,
        decidedAt: now,
        decisionReason: why,
        executeBefore: new Date(now.getTime() + BREAK_GLASS_GRANT_TTL_MS),
      };
      await tx.updateRequest(next);
      await this.#audit(tx, p.userId, 'privileged.break_glass', next, why);
      return next;
    });
  }

  /** Records the external anchor published after a break-glass approval; only then can it execute. */
  async markWitnessed(id: string, anchor: string): Promise<RequestView> {
    return this.#transition(id, async (tx, r, now) => {
      if (!r.breakGlass || r.status !== 'approved' || r.witnessedAt)
        throw new DomainError('conflict', 'request is not awaiting a witness');
      const next: PrivilegedRequest = { ...r, witnessedAt: now, witnessAnchor: anchor };
      await tx.updateRequest(next);
      await tx.audit.append({
        actor: { type: 'system' },
        action: 'privileged.break_glass_witnessed',
        target: { type: 'privileged_request', id: r.id },
        orgId: r.orgId ?? undefined,
        metadata: { anchor },
      });
      return next;
    });
  }

  /** The requester uses the grant: the stored operation runs once. */
  async execute(actorId: string, id: string, reason: string): Promise<RequestView> {
    const why = reasonOf(reason);
    const claimed = await this.#transition(id, async (tx, r, now) => {
      if (r.requestedBy !== actorId)
        throw new DomainError('forbidden', 'only the requester can execute a request');
      const s = effectiveStatus(r, now);
      if (s !== 'approved')
        throw new DomainError('conflict', `cannot execute a request in state ${s}`);
      if (r.breakGlass && !r.witnessedAt)
        throw new DomainError('conflict', 'break-glass approval has not been witnessed');
      if (r.operation === 'operator.grant' && (await tx.getFreeze(platformScope)))
        throw new DomainError('frozen', 'the platform is frozen');
      if (r.operation === 'org.unfreeze' || r.operation === 'platform.unfreeze') {
        const scope = r.operation === 'platform.unfreeze' ? platformScope : orgScope(r.orgId!);
        await tx.deleteFreeze(scope);
        const done: PrivilegedRequest = { ...r, status: 'executed', executedAt: now };
        await tx.updateRequest(done);
        await this.#audit(tx, actorId, 'privileged.executed', done, why);
        await tx.audit.append({
          actor: { type: 'operator', id: actorId },
          action: 'privileged.unfrozen',
          target: { type: 'freeze', id: scope },
          orgId: r.orgId ?? undefined,
          reason: why,
          metadata: { request_id: r.id },
        });
        return done;
      }
      const next: PrivilegedRequest = { ...r, status: 'executing' };
      await tx.updateRequest(next);
      await this.#audit(tx, actorId, 'privileged.execution_started', next, why);
      return next;
    });
    if (claimed.status !== 'executing') return this.#view(claimed);

    let failure: unknown;
    try {
      await this.#d.run[claimed.operation as ExternalOperation](claimed);
    } catch (e) {
      failure = e;
    }
    const settled = await this.#transition(id, async (tx, r, now) => {
      if (r.status !== 'executing') throw new DomainError('conflict', 'request is not executing');
      const code = failure instanceof DomainError ? failure.code : failure ? 'error' : null;
      const next: PrivilegedRequest = failure
        ? { ...r, status: 'failed', failure: code }
        : { ...r, status: 'executed', executedAt: now };
      await tx.updateRequest(next);
      await this.#audit(
        tx,
        actorId,
        failure ? 'privileged.execution_failed' : 'privileged.executed',
        next,
        why,
        failure ? { failure: code } : undefined,
      );
      return next;
    });
    if (failure) throw failure;
    return this.#view(settled);
  }

  // ---- freeze ---------------------------------------------------------------------------------

  /** Immediate: freezing only restricts. Lifting needs a privileged request (`*.unfreeze`). */
  async freeze(actorId: string, orgId: string | null, reason: string): Promise<Freeze> {
    const why = reasonOf(reason);
    if (orgId !== null && !(await this.#d.orgExists(orgId)))
      throw new DomainError('not_found', 'organization not found');
    const f: Freeze = {
      scope: orgId === null ? platformScope : orgScope(orgId),
      reason: why,
      frozenBy: actorId,
      frozenAt: this.#d.clock.now(),
    };
    await this.#d.store.transaction(async (tx) => {
      if (await tx.getFreeze(f.scope)) throw new DomainError('conflict', 'already frozen');
      await tx.insertFreeze(f);
      await tx.audit.append({
        actor: { type: 'operator', id: actorId },
        action: 'privileged.frozen',
        target: { type: 'freeze', id: f.scope },
        orgId: orgId ?? undefined,
        reason: why,
      });
    });
    return f;
  }

  listFreezes(): Promise<Freeze[]> {
    return this.#d.store.listFreezes();
  }

  /**
   * Refuses writes that grant or extend access while the platform, or the given organization, is frozen.
   * Pass `null` for platform-wide writes (catalog, operator grants).
   */
  async assertWritable(orgId: string | null): Promise<void> {
    if (await this.#d.store.getFreeze(platformScope))
      throw new DomainError('frozen', 'the platform is frozen');
    if (orgId !== null && (await this.#d.store.getFreeze(orgScope(orgId))))
      throw new DomainError('frozen', 'this organization is frozen');
  }

  // ---- internals ------------------------------------------------------------------------------

  #decidable(r: RequestView, deciderId: string): void {
    if (r.requestedBy === deciderId)
      throw new DomainError('forbidden', 'a request cannot be decided by its requester');
    if (r.status !== 'pending')
      throw new DomainError('conflict', `cannot decide a request in state ${r.status}`);
  }

  async #transition(
    id: string,
    fn: (tx: PrivilegedTx, r: PrivilegedRequest, now: Date) => Promise<PrivilegedRequest>,
  ): Promise<PrivilegedRequest> {
    return this.#d.store.transaction(async (tx) => {
      const r = await tx.findRequestForUpdate(id);
      if (!r) throw new DomainError('not_found', 'request not found');
      return fn(tx, r, this.#d.clock.now());
    });
  }

  async #audit(
    tx: PrivilegedTx,
    actorId: string,
    action: string,
    r: PrivilegedRequest,
    reason: string,
    extra?: Record<string, unknown>,
  ): Promise<void> {
    await tx.audit.append({
      actor: { type: 'operator', id: actorId },
      action,
      target: { type: 'privileged_request', id: r.id },
      orgId: r.orgId ?? undefined,
      reason,
      metadata: {
        operation: r.operation,
        ...(r.targetId ? { target_id: r.targetId } : {}),
        ...(r.breakGlass ? { break_glass: true } : {}),
        ...extra,
      },
    });
  }
}
