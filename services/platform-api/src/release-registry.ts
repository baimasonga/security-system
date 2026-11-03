import { createHash } from 'node:crypto';
import type { AuditEventInput, AuditLog } from '@trust/audit';
import { canonicalJson } from '@trust/crypto/verify';
import { SecureUpdateClient, type UpdateRoot } from '@trust/sdk-core';
import { DomainError, type Clock } from '@trust/shared-types';
import { z } from 'zod';

export const releaseLabel = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/);
const reason = z.string().trim().min(3).max(500);
export const registryParams = z
  .object({ productId: z.string().regex(/^prd_[a-f0-9]{24}$/) })
  .strict();
export const registerRootBody = z.object({ root: z.unknown(), reason }).strict();
export const targetBody = z
  .object({ platform: releaseLabel, channel: releaseLabel, reason })
  .strict();
export const reserveBody = targetBody.extend({ request_id: z.uuid() }).strict();
export interface ReleaseTarget {
  platform: string;
  channel: string;
  reservedSequence: number;
}
export interface ReleaseRegistry {
  productId: string;
  product: string;
  root: UpdateRoot;
  targets: ReleaseTarget[];
  createdAt: Date;
  updatedAt: Date;
}
export interface ReleaseReservation {
  productId: string;
  requestId: string;
  platform: string;
  channel: string;
  sequence: number;
  createdAt: Date;
}
export interface RegistryTx {
  get(): Promise<ReleaseRegistry | undefined>;
  put(row: ReleaseRegistry): Promise<void>;
  receipt(requestId: string): Promise<ReleaseReservation | undefined>;
  appendReceipt(row: ReleaseReservation): Promise<void>;
  audit(event: AuditEventInput): Promise<void>;
}
export interface RegistryStore {
  read(productId: string): Promise<ReleaseRegistry | undefined>;
  transaction<T>(productId: string, work: (tx: RegistryTx) => Promise<T>): Promise<T>;
}
const conflict = (message: string): never => {
  throw new DomainError('conflict', message);
};
const missing = (): never => {
  throw new DomainError('not_found', 'not found');
};

/** No signing, network access or software installation; see ADR-032. */
export class ReleaseRegistryService {
  readonly store: RegistryStore;
  readonly clock: Clock;
  readonly product: (id: string) => Promise<{ code: string; status: string } | undefined>;
  constructor(store: RegistryStore, clock: Clock, product: ReleaseRegistryService['product']) {
    this.store = store;
    this.clock = clock;
    this.product = product;
  }
  async read(productId: string) {
    return (await this.store.read(productId)) ?? missing();
  }
  async #active(productId: string) {
    const product = await this.product(productId);
    if (!product || product.status !== 'active') return missing();
    return product;
  }
  async register(productId: string, input: z.infer<typeof registerRootBody>, actor: string) {
    const b = registerRootBody.parse(input);
    const product = await this.#active(productId);
    const root = structuredClone(b.root) as UpdateRoot;
    try {
      new SecureUpdateClient({
        root,
        product: product.code,
        platform: 'registration',
        channel: 'registration',
        store: { get: async () => undefined, set: async () => {}, delete: async () => {} },
      });
      if (root.version !== 1 || root.expires <= Math.floor(this.clock.now().getTime() / 1000))
        throw new Error('initial root');
    } catch {
      throw new DomainError('invalid_request', 'invalid initial public update root');
    }
    return this.store.transaction(productId, async (tx) => {
      if (await tx.get()) conflict('update root already registered');
      const now = this.clock.now();
      const row: ReleaseRegistry = {
        productId,
        product: product.code,
        root,
        targets: [],
        createdAt: now,
        updatedAt: now,
      };
      await tx.put(row);
      await tx.audit({
        actor: { type: 'user', id: actor },
        action: 'updates.root_registered',
        target: { type: 'product', id: productId },
        reason: b.reason,
        metadata: { root_digest: createHash('sha256').update(canonicalJson(root)).digest('hex') },
      });
      return structuredClone(row);
    });
  }
  async addTarget(productId: string, input: z.infer<typeof targetBody>, actor: string) {
    const b = targetBody.parse(input);
    await this.#active(productId);
    return this.store.transaction(productId, async (tx) => {
      const row = (await tx.get()) ?? missing();
      this.#fresh(row);
      if (row.targets.some((t) => t.platform === b.platform && t.channel === b.channel))
        conflict('update target already registered');
      if (row.targets.length >= 32) conflict('update target capacity reached');
      row.targets.push({ platform: b.platform, channel: b.channel, reservedSequence: 0 });
      row.updatedAt = this.clock.now();
      await tx.put(row);
      await tx.audit({
        actor: { type: 'user', id: actor },
        action: 'updates.target_registered',
        target: { type: 'product', id: productId },
        reason: b.reason,
        metadata: { platform: b.platform, channel: b.channel },
      });
      return structuredClone(row);
    });
  }
  #fresh(row: ReleaseRegistry) {
    const now = this.clock.now().getTime();
    if (now < row.updatedAt.getTime() || row.root.expires * 1000 <= now)
      conflict('update root expired or registry clock moved backwards');
  }
  async reserve(productId: string, input: z.infer<typeof reserveBody>, actor: string) {
    const b = reserveBody.parse(input);
    await this.#active(productId);
    return this.store.transaction(productId, async (tx) => {
      const row = (await tx.get()) ?? missing();
      const previous = await tx.receipt(b.request_id);
      if (previous) {
        if (previous.platform !== b.platform || previous.channel !== b.channel)
          conflict('reservation request ID belongs to another target');
        return structuredClone(previous);
      }
      this.#fresh(row);
      const target = row.targets.find((t) => t.platform === b.platform && t.channel === b.channel);
      if (!target) return missing();
      if (target.reservedSequence >= Number.MAX_SAFE_INTEGER) conflict('update sequence exhausted');
      const receipt: ReleaseReservation = {
        productId,
        platform: b.platform,
        channel: b.channel,
        requestId: b.request_id,
        sequence: ++target.reservedSequence,
        createdAt: this.clock.now(),
      };
      row.updatedAt = receipt.createdAt;
      await tx.put(row);
      await tx.appendReceipt(receipt);
      await tx.audit({
        actor: { type: 'user', id: actor },
        action: 'updates.sequence_reserved',
        target: { type: 'product', id: productId },
        reason: b.reason,
        metadata: { platform: b.platform, channel: b.channel, sequence: receipt.sequence },
      });
      return structuredClone(receipt);
    });
  }
}

/** Development adapter: snapshot rollback and the same receipt contract as PostgreSQL. */
export class MemoryRegistryStore implements RegistryStore {
  #rows = new Map<string, ReleaseRegistry>();
  #receipts = new Map<string, ReleaseReservation>();
  #tail: Promise<unknown> = Promise.resolve();
  readonly audit: AuditLog;
  constructor(audit: AuditLog) {
    this.audit = audit;
  }
  async read(productId: string) {
    return structuredClone(this.#rows.get(productId));
  }
  transaction<T>(productId: string, work: (tx: RegistryTx) => Promise<T>): Promise<T> {
    const result = this.#tail.then(async () => {
      const rows = structuredClone(this.#rows),
        receipts = structuredClone(this.#receipts);
      const events: AuditEventInput[] = [];
      const out = await work({
        get: async () => structuredClone(rows.get(productId)),
        put: async (row) => {
          rows.set(productId, structuredClone(row));
        },
        receipt: async (id) => structuredClone(receipts.get(`${productId}/${id}`)),
        appendReceipt: async (row) => {
          const key = `${productId}/${row.requestId}`;
          if (receipts.has(key)) conflict('duplicate reservation');
          receipts.set(key, structuredClone(row));
        },
        audit: async (e) => {
          events.push(e);
        },
      });
      await this.audit.appendMany(events);
      this.#rows = rows;
      this.#receipts = receipts;
      return out;
    });
    this.#tail = result.catch(() => {});
    return result;
  }
}
