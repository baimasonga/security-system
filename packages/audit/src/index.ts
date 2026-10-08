import { canonicalJson, newId, sha256Hex } from '@trust/crypto';
import { redact, type Clock, type Json } from '@trust/shared-types';

export const GENESIS_HASH = '0'.repeat(64);

/** Chain for events that carry no organization (human logins, key lifecycle, unknown-key rejections…). */
export const SYSTEM_CHAIN = 'system';
/** The single global chain that existed before partitioning (ADR-008). Verified, never extended. */
export const LEGACY_CHAIN = 'legacy';

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
  /** Chain this event belongs to. Absent only on pre-partitioning (`legacy`) events. */
  chain?: string;
  /** Position within its chain, from 1. */
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

export interface ChainHead {
  seq: number;
  hash: string;
}

export type ChainVerification =
  | { ok: true; count: number; chains: number; anchor: string }
  | { ok: false; chain: string; brokenAtSeq: number; reason: string };

export interface VerifyOptions {
  /** Verify only this organization's chains (all of its shards). The `system`/`legacy` chains are skipped. */
  orgId?: string | undefined;
}

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
  /**
   * Appends all events atomically. Events of the same chain form one contiguous run in input order; a batch
   * that spans chains is all-or-nothing.
   */
  appendMany(inputs: readonly AuditEventInput[]): Promise<AuditEvent[]>;
  /** Oldest-first among the newest `limit`, in global insertion order (a display order, not a trust claim). */
  list(filter?: { orgId?: string; action?: string; limit?: number }): Promise<AuditEvent[]>;
  /** Verifies every chain (or one organization's) including that each chain's tail equals its stored head. */
  verifyChain(opts?: VerifyOptions): Promise<ChainVerification>;
}

// ---------------------------------------------------------------------------------------------------
// Chain assignment
// ---------------------------------------------------------------------------------------------------

export const MAX_SHARDS = 64;

/** Base chain id of an organization (its shards append `#<k>`). */
export const orgChainPrefix = (orgId: string) => `org:${encodeURIComponent(orgId)}`;

/** True if `chain` is one of the organization's chains (`org:<id>` or `org:<id>#<shard>`). */
export function isOrgChain(chain: string, orgId: string): boolean {
  const p = orgChainPrefix(orgId);
  return chain === p || chain.startsWith(`${p}#`);
}

function shardOf(key: string, shards: number): number {
  return Number.parseInt(sha256Hex(key).slice(0, 8), 16) % shards;
}

/**
 * Deterministic chain for an event (ADR-008). Organization events go to the organization's chain; with
 * `shards > 1` a hot organization is spread over `shards` chains by target (e.g. activation id), so one
 * device's events always share a chain.
 */
export function chainFor(input: AuditEventInput, shards = 1): string {
  if (!input.orgId) return SYSTEM_CHAIN;
  const base = orgChainPrefix(input.orgId);
  if (shards <= 1) return base;
  if (!Number.isInteger(shards) || shards > MAX_SHARDS)
    throw new Error('invalid audit shard count');
  return `${base}#${shardOf(input.target?.id ?? input.actor.id ?? '', shards)}`;
}

// ---------------------------------------------------------------------------------------------------
// Hashing and event construction
// ---------------------------------------------------------------------------------------------------

export function computeEventHash(e: Omit<AuditEvent, 'hash'>): string {
  return sha256Hex(canonicalJson(e));
}

function assertValidInput(input: AuditEventInput): void {
  if (!(ACTOR_TYPES as readonly string[]).includes(input.actor.type)) {
    throw new Error('invalid audit actor type');
  }
}

export function buildEvent(
  input: AuditEventInput,
  chain: string,
  prev: ChainHead,
  at: Date,
): AuditEvent {
  assertValidInput(input);
  const base: Omit<AuditEvent, 'hash'> = {
    chain, // part of the hashed content: an event cannot be moved to another chain unnoticed
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

export interface PlannedEvent {
  input: AuditEventInput;
  chain: string;
}

/** Assigns every input to its chain, preserving input order. */
export function planAppend(inputs: readonly AuditEventInput[], shards = 1): PlannedEvent[] {
  // Validate up front so adapters fail BEFORE taking any lock.
  for (const i of inputs) assertValidInput(i);
  return inputs.map((input) => ({ input, chain: chainFor(input, shards) }));
}

/**
 * Builds the events for a planned append given the CURRENT head of each chain involved (missing chains start
 * at genesis). Pure; throws before producing anything if any event is invalid (all-or-nothing). Returns the
 * events in input order and the new head of every touched chain.
 */
export function buildRun(
  plan: readonly PlannedEvent[],
  heads: ReadonlyMap<string, ChainHead>,
  at: Date,
): { events: AuditEvent[]; newHeads: Map<string, ChainHead> } {
  const working = new Map<string, ChainHead>();
  const events: AuditEvent[] = [];
  for (const { input, chain } of plan) {
    const prev = working.get(chain) ?? heads.get(chain) ?? { seq: 0, hash: GENESIS_HASH };
    const ev = buildEvent(input, chain, prev, at);
    working.set(chain, { seq: ev.seq, hash: ev.hash });
    events.push(ev);
  }
  return { events, newHeads: working };
}

// ---------------------------------------------------------------------------------------------------
// Verification (one definition, shared by every adapter)
// ---------------------------------------------------------------------------------------------------

export interface ChainFailure {
  chain: string;
  brokenAtSeq: number;
  reason: string;
}

/** Incremental verifier for ONE chain: feed its events in `seq` order, in batches if large. */
export class ChainVerifier {
  readonly #chain: string;
  #prev = GENESIS_HASH;
  #expectedSeq = 1;
  #failure: ChainFailure | undefined;

  constructor(chain: string) {
    this.#chain = chain;
  }

  /** Returns the failure as soon as one is found (and keeps returning it). */
  push(e: AuditEvent): ChainFailure | undefined {
    if (this.#failure) return this.#failure;
    const fail = (reason: string) =>
      (this.#failure = { chain: this.#chain, brokenAtSeq: e.seq, reason });
    if ((e.chain ?? LEGACY_CHAIN) !== this.#chain)
      return fail('event belongs to a different chain');
    if (e.seq !== this.#expectedSeq) return fail('sequence gap or reorder');
    if (e.prevHash !== this.#prev) return fail('prev_hash mismatch');
    const { hash, ...rest } = e;
    // Public, non-secret chain values: constant-time comparison is not required here.
    // eslint-disable-next-line security/detect-possible-timing-attacks
    if (computeEventHash(rest) !== hash) return fail('hash mismatch (content altered)');
    this.#prev = hash;
    this.#expectedSeq++;
    return undefined;
  }

  get failure(): ChainFailure | undefined {
    return this.#failure;
  }

  /** The verified tail so far (seq 0 / genesis for an empty chain). */
  get tail(): ChainHead {
    return { seq: this.#expectedSeq - 1, hash: this.#prev };
  }
}

/** The verified tail of a chain must be exactly the stored head (detects tail truncation / head tampering). */
export function checkHead(
  chain: string,
  tail: ChainHead,
  head: ChainHead | undefined,
): ChainFailure | undefined {
  if (!head) {
    return tail.seq === 0
      ? undefined
      : { chain, brokenAtSeq: tail.seq, reason: 'chain has events but no head record' };
  }
  if (head.seq !== tail.seq || head.hash !== tail.hash) {
    return {
      chain,
      brokenAtSeq: Math.min(head.seq, tail.seq) + 1,
      reason: 'stored head does not match the chain tail (events removed or head altered)',
    };
  }
  return undefined;
}

/** One value summarizing every chain head; publish it to an external append-only store to witness the log. */
export function computeAnchor(
  heads: ReadonlyArray<{ chain: string; seq: number; hash: string }>,
): string {
  const sorted = [...heads].sort((a, b) => (a.chain < b.chain ? -1 : a.chain > b.chain ? 1 : 0));
  return sha256Hex(canonicalJson(sorted.map((h) => [h.chain, h.seq, h.hash])));
}

export function summarize(
  chains: ReadonlyArray<{ chain: string; seq: number; hash: string }>,
): ChainVerification {
  return {
    ok: true,
    count: chains.reduce((n, c) => n + c.seq, 0),
    chains: chains.length,
    anchor: computeAnchor(chains),
  };
}

/** Pure verification of an in-memory event list plus its heads (used by the in-memory adapter and tests). */
export function verifyEvents(
  events: readonly AuditEvent[],
  heads: ReadonlyMap<string, ChainHead>,
  opts?: VerifyOptions,
): ChainVerification {
  const byChain = new Map<string, AuditEvent[]>();
  for (const e of events) {
    const c = e.chain ?? LEGACY_CHAIN;
    if (opts?.orgId !== undefined && !isOrgChain(c, opts.orgId)) continue;
    let list = byChain.get(c);
    if (!list) byChain.set(c, (list = []));
    list.push(e);
  }
  for (const c of heads.keys()) {
    if (opts?.orgId !== undefined && !isOrgChain(c, opts.orgId)) continue;
    if (!byChain.has(c)) byChain.set(c, []);
  }
  const verified: Array<{ chain: string; seq: number; hash: string }> = [];
  for (const chain of [...byChain.keys()].sort()) {
    const v = new ChainVerifier(chain);
    for (const e of byChain.get(chain)!) {
      const f = v.push(e);
      if (f) return { ok: false, ...f };
    }
    const bad = checkHead(chain, v.tail, heads.get(chain));
    if (bad) return { ok: false, ...bad };
    verified.push({ chain, ...v.tail });
  }
  return summarize(verified);
}

// ---------------------------------------------------------------------------------------------------
// In-memory adapter
// ---------------------------------------------------------------------------------------------------

/** In-memory adapter (tests, local dev). Appends are serialized, so no chain can fork. */
export class InMemoryAuditLog implements AuditLog {
  readonly #events: AuditEvent[] = [];
  readonly #heads = new Map<string, ChainHead>();
  readonly #clock: Clock;
  readonly #shards: number;
  #tail: Promise<unknown> = Promise.resolve();

  constructor(clock: Clock, opts?: { shards?: number }) {
    this.#clock = clock;
    this.#shards = opts?.shards ?? 1;
  }

  append(input: AuditEventInput): Promise<AuditEvent> {
    return this.appendMany([input]).then((r) => r[0]!);
  }

  appendMany(inputs: readonly AuditEventInput[]): Promise<AuditEvent[]> {
    const run = async (): Promise<AuditEvent[]> => {
      // Build everything first: if any event is invalid, nothing is written (all-or-nothing).
      const { events, newHeads } = buildRun(
        planAppend(inputs, this.#shards),
        this.#heads,
        this.#clock.now(),
      );
      for (const ev of events) this.#events.push(Object.freeze(ev) as AuditEvent);
      for (const [chain, head] of newHeads) this.#heads.set(chain, head);
      return events;
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

  async verifyChain(opts?: VerifyOptions): Promise<ChainVerification> {
    return verifyEvents(this.#events, this.#heads, opts);
  }

  /** Test seams: simulate an attacker with direct storage access. Not part of the port. */
  unsafeReplaceForTest(index: number, e: AuditEvent): void {
    this.#events[index] = e;
  }
  unsafeDeleteForTest(index: number): void {
    this.#events.splice(index, 1);
  }
  unsafeSetHeadForTest(chain: string, head: ChainHead | undefined): void {
    if (head) this.#heads.set(chain, head);
    else this.#heads.delete(chain);
  }
  chainsForTest(): string[] {
    return [...this.#heads.keys()].sort();
  }
}
