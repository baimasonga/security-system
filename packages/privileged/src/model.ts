import type { AuditEventInput, AuditLog, AuditWriter } from '@trust/audit';
import { AuditBuffer } from '@trust/audit';

// Privileged operations (ADR-022): dual control, just-in-time grants, freeze and break-glass.

/** The closed list of operations that go through a privileged request. */
export const OPERATIONS = [
  'license.revoke',
  'operator.grant',
  'operator.revoke',
  'org.unfreeze',
  'platform.unfreeze',
] as const;
export type Operation = (typeof OPERATIONS)[number];

/** Stored states. `expired` is never stored: it is derived from the clock (see `effectiveStatus`). */
export type StoredStatus =
  'pending' | 'approved' | 'executing' | 'executed' | 'rejected' | 'cancelled' | 'failed';
export type RequestStatus = StoredStatus | 'expired';

export interface PrivilegedRequest {
  id: string;
  operation: Operation;
  /** Organization the operation targets (license.revoke, org.unfreeze); null otherwise. */
  orgId: string | null;
  /** License id (license.revoke) or user id (operator.*); null otherwise. */
  targetId: string | null;
  reason: string;
  requestedBy: string;
  createdAt: Date;
  /** A pending request expires at this time. */
  expiresAt: Date;
  status: StoredStatus;
  decidedBy: string | null;
  decidedAt: Date | null;
  decisionReason: string | null;
  /** Approved by the requester through break-glass. */
  breakGlass: boolean;
  /** Break-glass only: when the external witness acknowledged the anchor that covers the approval. */
  witnessedAt: Date | null;
  witnessAnchor: string | null;
  /** The JIT grant: an approved request can be executed until this time. */
  executeBefore: Date | null;
  executedAt: Date | null;
  /** Short machine-readable outcome of a failed execution (never free text from the operation). */
  failure: string | null;
}

/** `platform`, or `org:<id>`. One row per frozen scope. */
export interface Freeze {
  scope: string;
  reason: string;
  frozenBy: string;
  frozenAt: Date;
}

export const platformScope = 'platform';
export const orgScope = (orgId: string) => `org:${orgId}`;

export function effectiveStatus(r: PrivilegedRequest, now: Date): RequestStatus {
  if (r.status === 'pending' && r.expiresAt <= now) return 'expired';
  if (r.status === 'approved' && r.executeBefore && r.executeBefore <= now) return 'expired';
  return r.status;
}

export interface PrivilegedRepo {
  insertRequest(r: PrivilegedRequest): Promise<void>;
  findRequest(id: string): Promise<PrivilegedRequest | undefined>;
  /** As `findRequest`, plus an exclusive row lock until the transaction ends (PostgreSQL). */
  findRequestForUpdate(id: string): Promise<PrivilegedRequest | undefined>;
  /** Replaces the stored row with the same id (all mutable columns). */
  updateRequest(r: PrivilegedRequest): Promise<void>;
  /** Newest first, at most `limit` (1..200). */
  listRequests(filter: { status?: StoredStatus; limit: number }): Promise<PrivilegedRequest[]>;
  /** Break-glass approvals by `userId` decided at or after `since`. */
  countBreakGlassSince(userId: string, since: Date): Promise<number>;
  getFreeze(scope: string): Promise<Freeze | undefined>;
  /** Fails with `duplicate_freeze` when the scope is already frozen. */
  insertFreeze(f: Freeze): Promise<void>;
  deleteFreeze(scope: string): Promise<void>;
  listFreezes(): Promise<Freeze[]>;
}

/** A transaction: every repository method, plus an audit writer that commits atomically with them. */
export interface PrivilegedTx extends PrivilegedRepo {
  audit: AuditWriter;
}

/** Persistence port. Adapters: in-memory (tests/dev), PostgreSQL. */
export interface PrivilegedStore extends PrivilegedRepo {
  /** `fn` must be safe to re-run (the PostgreSQL adapter retries after deadlocks). */
  transaction<T>(fn: (tx: PrivilegedTx) => Promise<T>): Promise<T>;
}

interface State {
  requests: Map<string, PrivilegedRequest>;
  freezes: Map<string, Freeze>;
}

class MemoryRepo implements PrivilegedRepo {
  readonly s: State = { requests: new Map(), freezes: new Map() };

  async insertRequest(r: PrivilegedRequest) {
    if (this.s.requests.has(r.id)) throw new Error('duplicate_request');
    this.s.requests.set(r.id, structuredClone(r));
  }
  async findRequest(id: string) {
    const r = this.s.requests.get(id);
    return r ? structuredClone(r) : undefined;
  }
  async findRequestForUpdate(id: string) {
    return this.findRequest(id);
  }
  async updateRequest(r: PrivilegedRequest) {
    if (this.s.requests.has(r.id)) this.s.requests.set(r.id, structuredClone(r));
  }
  async listRequests(filter: { status?: StoredStatus; limit: number }) {
    return [...this.s.requests.values()]
      .filter((r) => !filter.status || r.status === filter.status)
      .sort((a, b) => +b.createdAt - +a.createdAt || b.id.localeCompare(a.id))
      .slice(0, Math.max(1, Math.min(200, Math.floor(filter.limit))))
      .map((r) => structuredClone(r));
  }
  async countBreakGlassSince(userId: string, since: Date) {
    return [...this.s.requests.values()].filter(
      (r) => r.breakGlass && r.decidedBy === userId && r.decidedAt && r.decidedAt >= since,
    ).length;
  }
  async getFreeze(scope: string) {
    const f = this.s.freezes.get(scope);
    return f ? structuredClone(f) : undefined;
  }
  async insertFreeze(f: Freeze) {
    if (this.s.freezes.has(f.scope)) throw new Error('duplicate_freeze');
    this.s.freezes.set(f.scope, structuredClone(f));
  }
  async deleteFreeze(scope: string) {
    this.s.freezes.delete(scope);
  }
  async listFreezes() {
    return [...this.s.freezes.values()]
      .sort((a, b) => +a.frozenAt - +b.frozenAt || a.scope.localeCompare(b.scope))
      .map((f) => structuredClone(f));
  }
}

/** In-memory adapter: serialized transactions with snapshot rollback; audit flushed only on commit. */
export class InMemoryPrivilegedStore extends MemoryRepo implements PrivilegedStore {
  #lock: Promise<unknown> = Promise.resolve();
  readonly #audit: AuditLog | undefined;
  readonly committedAudit: AuditEventInput[] = [];

  constructor(opts?: { audit?: AuditLog }) {
    super();
    this.#audit = opts?.audit;
  }

  transaction<T>(fn: (tx: PrivilegedTx) => Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      const snapshot = structuredClone(this.s);
      const buffer = new AuditBuffer();
      const tx = Object.assign(Object.create(this) as MemoryRepo, {
        audit: buffer,
      }) as unknown as PrivilegedTx;
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
