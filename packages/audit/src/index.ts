import { canonicalJson, newId, sha256Hex } from '@trust/crypto';
import { redact, type Clock, type Json } from '@trust/shared-types';

export const GENESIS_HASH = '0'.repeat(64);

export const ACTOR_TYPES = ['user', 'device', 'system', 'operator', 'anonymous'] as const;
export type ActorType = (typeof ACTOR_TYPES)[number];

export interface AuditEventInput {
  actor: { type: ActorType; id?: string | undefined };
  /** Dotted verb, e.g. `license.revoked`. */
  action: string;
  target?: { type: string; id: string } | undefined;
  orgId?: string | undefined;
  /** Mandatory for operator mutations; free text must not contain secrets. */
  reason?: string | undefined;
  metadata?: Record<string, unknown> | undefined;
}

export interface AuditEvent {
  seq: number;
  id: string;
  occurredAt: string;
  actor: { type: ActorType; id: string | null };
  action: string;
  target: { type: string; id: string } | null;
  orgId: string | null;
  reason: string | null;
  metadata: Record<string, Json>;
  prevHash: string;
  hash: string;
}

export type ChainVerification =
  | { ok: true; count: number; headHash: string }
  | { ok: false; brokenAtSeq: number; reason: string };

/**
 * Write-only audit handle given to a store transaction. Events are buffered and written by the
 * adapter inside the SAME unit of work as the business change, so a change and its audit record
 * commit or roll back together. (If the audit write fails, the change does not happen.)
 */
export interface AuditWriter {
  append(input: AuditEventInput): Promise<void>;
}

/** Shared buffering implementation used by every transactional adapter. */
export class AuditBuffer implements AuditWriter {
  #events: AuditEventInput[] = [];
  async append(input: AuditEventInput): Promise<void> {
    this.#events.push(input);
  }
  /** Returns and clears the buffered events, oldest first. */
  drain(): AuditEventInput[] {
    const out = this.#events;
    this.#events = [];
    return out;
  }
}

export interface AuditLog {
  append(input: AuditEventInput): Promise<AuditEvent>;
  /** Appends all events as one contiguous run of the chain (no other event can interleave). */
  appendMany(inputs: readonly AuditEventInput[]): Promise<AuditEvent[]>;
  list(filter?: { orgId?: string; action?: string; limit?: number }): Promise<AuditEvent[]>;
  verifyChain(): Promise<ChainVerification>;
}

export function computeEventHash(e: Omit<AuditEvent, 'hash'>): string {
  return sha256Hex(canonicalJson(e));
}

/**
 * Incremental chain verifier: feed events in `seq` order, in batches if the log is large.
 * Shared by every storage adapter so "valid chain" has exactly one definition.
 */
export class ChainVerifier {
  #prev = GENESIS_HASH;
  #expectedSeq = 1;
  #count = 0;
  #failure: Extract<ChainVerification, { ok: false }> | undefined;

  /** Returns the failure as soon as one is found (and keeps returning it). */
  push(e: AuditEvent): Extract<ChainVerification, { ok: false }> | undefined {
    if (this.#failure) return this.#failure;
    const fail = (reason: string) => (this.#failure = { ok: false, brokenAtSeq: e.seq, reason });
    if (e.seq !== this.#expectedSeq) return fail('sequence gap or reorder');
    if (e.prevHash !== this.#prev) return fail('prev_hash mismatch');
    const { hash, ...rest } = e;
    // Public, non-secret chain values: constant-time comparison is not required here.
    // eslint-disable-next-line security/detect-possible-timing-attacks
    if (computeEventHash(rest) !== hash) return fail('hash mismatch (content altered)');
    this.#prev = hash;
    this.#expectedSeq++;
    this.#count++;
    return undefined;
  }

  result(): ChainVerification {
    return this.#failure ?? { ok: true, count: this.#count, headHash: this.#prev };
  }
}

/** Pure chain verifier for an in-memory list. */
export function verifyEvents(events: readonly AuditEvent[]): ChainVerification {
  const v = new ChainVerifier();
  for (const e of events) if (v.push(e)) break;
  return v.result();
}

export function buildEvent(
  input: AuditEventInput,
  prev: { seq: number; hash: string },
  at: Date,
): AuditEvent {
  if (!(ACTOR_TYPES as readonly string[]).includes(input.actor.type)) {
    throw new Error('invalid audit actor type');
  }
  const base: Omit<AuditEvent, 'hash'> = {
    seq: prev.seq + 1,
    id: newId('aud'),
    occurredAt: at.toISOString(),
    actor: { type: input.actor.type, id: input.actor.id ?? null },
    action: input.action,
    target: input.target ?? null,
    orgId: input.orgId ?? null,
    reason: input.reason ?? null,
    metadata: redact(input.metadata ?? {}) as Record<string, Json>,
    prevHash: prev.hash,
  };
  return { ...base, hash: computeEventHash(base) };
}

/** In-memory adapter (tests, local dev). Appends are serialized so the chain cannot fork. */
export class InMemoryAuditLog implements AuditLog {
  readonly #events: AuditEvent[] = [];
  readonly #clock: Clock;
  #tail: Promise<unknown> = Promise.resolve();

  constructor(clock: Clock) {
    this.#clock = clock;
  }

  append(input: AuditEventInput): Promise<AuditEvent> {
    return this.appendMany([input]).then((r) => r[0]!);
  }

  appendMany(inputs: readonly AuditEventInput[]): Promise<AuditEvent[]> {
    const run = async (): Promise<AuditEvent[]> => {
      // Build the whole run first: if any event is invalid, nothing is written (all-or-nothing).
      const out: AuditEvent[] = [];
      let prev = this.#events.at(-1);
      for (const input of inputs) {
        const ev = buildEvent(
          input,
          prev ? { seq: prev.seq, hash: prev.hash } : { seq: 0, hash: GENESIS_HASH },
          this.#clock.now(),
        );
        out.push(ev);
        prev = ev;
      }
      for (const ev of out) this.#events.push(Object.freeze(ev) as AuditEvent);
      return out;
    };
    const p = this.#tail.then(run, run);
    this.#tail = p.catch(() => undefined);
    return p;
  }

  async list(filter?: { orgId?: string; action?: string; limit?: number }): Promise<AuditEvent[]> {
    let out = this.#events.filter(
      (e) =>
        (filter?.orgId === undefined || e.orgId === filter.orgId) &&
        (filter?.action === undefined || e.action === filter.action),
    );
    if (filter?.limit) out = out.slice(-filter.limit);
    return out.map((e) => structuredClone(e));
  }

  async verifyChain(): Promise<ChainVerification> {
    return verifyEvents(this.#events);
  }

  /** Test seam: simulates an attacker with direct storage access. Not exposed via the port. */
  unsafeReplaceForTest(index: number, e: AuditEvent): void {
    this.#events[index] = e;
  }
  unsafeDeleteForTest(index: number): void {
    this.#events.splice(index, 1);
  }
}
