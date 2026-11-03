import { createHash } from 'node:crypto';
import type { AuditEventInput, AuditLog } from '@trust/audit';
import { canonicalJson } from '@trust/crypto/verify';
import {
  SecureUpdateClient,
  type UpdateRoot,
  type SignedUpdateEnvelope,
  type UpdateManifest,
} from '@trust/sdk-core';
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
export const publicationBody = reserveBody
  .extend({
    envelope: z
      .object({ signatures: z.array(z.string().min(1).max(32768)).min(1).max(16) })
      .strict(),
  })
  .strict();
export const floorBody = targetBody
  .extend({ sequence: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER) })
  .strict();
export const releaseQuery = z.object({ platform: releaseLabel, channel: releaseLabel }).strict();
export const historyQuery = releaseQuery
  .extend({
    before: z.coerce.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
    limit: z.coerce.number().int().min(1).max(50).default(20),
  })
  .strict();
export interface PublishedRelease extends ReleaseReservation {
  envelope: SignedUpdateEnvelope;
  manifest: UpdateManifest;
  publishedAt: Date;
}
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
  published(requestId: string): Promise<PublishedRelease | undefined>;
  history(
    platform: string,
    channel: string,
    before: number | undefined,
    limit: number,
  ): Promise<PublishedRelease[]>;
  appendRelease(row: PublishedRelease): Promise<void>;
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
  async raiseFloor(productId: string, input: z.infer<typeof floorBody>, actor: string) {
    const b = floorBody.parse(input);
    await this.#active(productId);
    return this.store.transaction(productId, async (tx) => {
      const row = (await tx.get()) ?? missing();
      this.#fresh(row);
      const target = row.targets.find((t) => t.platform === b.platform && t.channel === b.channel);
      if (!target) return missing();
      if (b.sequence <= target.reservedSequence) conflict('sequence floor must increase');
      if ((await tx.history(b.platform, b.channel, undefined, 1)).length)
        conflict('reconcile historical floors before first publication');
      target.reservedSequence = b.sequence;
      row.updatedAt = this.clock.now();
      await tx.put(row);
      await tx.audit({
        actor: { type: 'user', id: actor },
        action: 'updates.sequence_floor_raised',
        target: { type: 'product', id: productId },
        reason: b.reason,
        metadata: { platform: b.platform, channel: b.channel, sequence: b.sequence },
      });
      return structuredClone(row);
    });
  }
  async publish(productId: string, input: z.infer<typeof publicationBody>, actor: string) {
    const b = publicationBody.parse(input);
    await this.#active(productId);
    return this.store.transaction(productId, async (tx) => {
      const row = (await tx.get()) ?? missing();
      const reservation = (await tx.receipt(b.request_id)) ?? missing();
      if (reservation.platform !== b.platform || reservation.channel !== b.channel)
        conflict('reservation belongs to another target');
      const previous = await tx.published(b.request_id);
      if (previous) {
        if (canonicalJson(previous.envelope) !== canonicalJson(b.envelope))
          conflict('reservation already published');
        return previous;
      }
      this.#fresh(row);
      let manifest: UpdateManifest;
      try {
        manifest = await new SecureUpdateClient({
          root: row.root,
          product: row.product,
          platform: b.platform,
          channel: b.channel,
          now: () => this.clock.now(),
          store: { get: async () => undefined, set: async () => {}, delete: async () => {} },
        }).verifyManifest(b.envelope);
      } catch {
        throw new DomainError('invalid_request', 'invalid signed release');
      }
      if (manifest.sequence !== reservation.sequence)
        conflict('release must match reserved sequence');
      const target = row.targets.find((t) => t.platform === b.platform && t.channel === b.channel);
      if (!target || manifest.sequence !== target.reservedSequence)
        conflict('only the latest reservation may publish');
      const latest = (await tx.history(b.platform, b.channel, undefined, 1))[0];
      if (latest && manifest.sequence <= latest.sequence) conflict('release sequence must advance');
      const now = this.clock.now();
      const result: PublishedRelease = {
        ...reservation,
        envelope: b.envelope,
        manifest,
        publishedAt: now,
      };
      row.updatedAt = now;
      await tx.put(row);
      await tx.appendRelease(result);
      await tx.audit({
        actor: { type: 'user', id: actor },
        action: 'updates.release_published',
        target: { type: 'product', id: productId },
        reason: b.reason,
        metadata: {
          platform: b.platform,
          channel: b.channel,
          sequence: manifest.sequence,
          paused: manifest.paused,
          manifest_digest: createHash('sha256').update(canonicalJson(manifest)).digest('hex'),
        },
      });
      return structuredClone(result);
    });
  }
  async history(productId: string, input: z.infer<typeof historyQuery>) {
    const b = historyQuery.parse(input);
    return this.store.transaction(productId, async (tx) => {
      if (!(await tx.get())) return missing();
      return tx.history(b.platform, b.channel, b.before, b.limit);
    });
  }
  async current(productId: string, input: z.infer<typeof releaseQuery>) {
    const b = releaseQuery.parse(input);
    await this.#active(productId);
    return this.store.transaction(productId, async (tx) => {
      const row = (await tx.get()) ?? missing();
      const latest = (await tx.history(b.platform, b.channel, undefined, 1))[0];
      const now = this.clock.now().getTime();
      if (
        !latest ||
        now < row.updatedAt.getTime() ||
        row.root.expires * 1000 <= now ||
        latest.manifest.expires * 1000 <= now
      )
        return missing();
      return structuredClone(latest.envelope);
    });
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
  #releases = new Map<string, PublishedRelease>();
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
        receipts = structuredClone(this.#receipts),
        releases = structuredClone(this.#releases);
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
        published: async (id) => structuredClone(releases.get(`${productId}/${id}`)),
        history: async (platform, channel, before, limit) =>
          structuredClone(
            [...releases.values()]
              .filter(
                (r) =>
                  r.productId === productId &&
                  r.platform === platform &&
                  r.channel === channel &&
                  (before === undefined || r.sequence < before),
              )
              .sort((a, b) => b.sequence - a.sequence)
              .slice(0, limit),
          ),
        appendRelease: async (row) => {
          const key = `${productId}/${row.requestId}`;
          if (releases.has(key)) conflict('duplicate publication');
          releases.set(key, structuredClone(row));
        },
        audit: async (e) => {
          events.push(e);
        },
      });
      await this.audit.appendMany(events);
      this.#rows = rows;
      this.#receipts = receipts;
      this.#releases = releases;
      return out;
    });
    this.#tail = result.catch(() => {});
    return result;
  }
}
