import type { SecureStore } from './device-key.ts';
import type { EvidencePolicy } from './release-evidence.ts';
import {
  SecureUpdateClient,
  type SignedUpdateEnvelope,
  type UpdateRoot,
  type UpdateStatus,
} from './updates.ts';

export interface UpdateTarget {
  product: string;
  platform: string;
  channel: string;
}
export interface ProductUpdateRegistration {
  product: string;
  root: UpdateRoot;
  evidence: EvidencePolicy;
  targets: Array<{
    platform: string;
    channel: string;
    feedUrl: string;
    /** From trusted local build metadata, never the downloaded feed. */
    installedSequence: number;
  }>;
  maxArtifactBytes?: number;
}
export interface ProductUpdateOptions {
  products: ProductUpdateRegistration[];
  store: SecureStore;
  now?: () => Date;
  fetch?: typeof fetch;
}
export type ProductUpdateCheck =
  | { target: UpdateTarget; state: 'checked'; update: UpdateStatus }
  | { target: UpdateTarget; state: 'unavailable' };

interface RegisteredTarget {
  target: UpdateTarget;
  client: SecureUpdateClient;
  feedUrl: string;
  installedSequence: number;
  evidence: EvidencePolicy;
}

// All managers sharing THIS store object in this module participate in the same lock.
// A standalone client or another process still needs host-owned serialization.
const locks = new WeakMap<SecureStore, Map<string, Promise<unknown>>>();
function serial<T>(store: SecureStore, product: string, work: () => Promise<T>): Promise<T> {
  let products = locks.get(store);
  if (!products) {
    products = new Map();
    locks.set(store, products);
  }
  const result = (products.get(product) ?? Promise.resolve()).then(work);
  const tail = result.catch(() => {});
  products.set(product, tail);
  void tail.then(() => {
    if (products.get(product) === tail) products.delete(product);
  });
  return result;
}
function invalid(): never {
  throw new Error('update configuration rejected');
}
function targetKey(target: UpdateTarget): string {
  const parts = [target.product, target.platform, target.channel];
  if (parts.some((p) => typeof p !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(p)))
    return invalid();
  return parts.join('/');
}

/** Trusted host configuration for several independent products. Never installs software. */
export class ProductUpdateManager {
  readonly #targets = new Map<string, RegisteredTarget>();
  readonly #products = new Map<string, SecureUpdateClient>();
  readonly #store: SecureStore;

  constructor(options: ProductUpdateOptions) {
    this.#store = options.store;
    // Copy data only, retaining host functions and the shared store identity separately.
    const products = structuredClone(options.products);
    if (!Array.isArray(products) || !products.length || products.length > 128) invalid();
    for (const product of products) {
      if (
        this.#products.has(product.product) ||
        !Array.isArray(product.targets) ||
        !product.targets.length ||
        product.targets.length > 32 ||
        !Array.isArray(product.evidence?.trustedBuilders) ||
        !product.evidence.trustedBuilders.length ||
        product.evidence.trustedBuilders.some((b) => typeof b !== 'string' || !b.trim())
      )
        invalid();
      for (const entry of product.targets) {
        const target = {
          product: product.product,
          platform: entry.platform,
          channel: entry.channel,
        };
        const key = targetKey(target);
        if (
          this.#targets.has(key) ||
          !Number.isSafeInteger(entry.installedSequence) ||
          entry.installedSequence < 0
        )
          invalid();
        const client = new SecureUpdateClient({
          root: product.root,
          ...target,
          store: options.store,
          ...(options.fetch ? { fetch: options.fetch } : {}),
          ...(options.now ? { now: options.now } : {}),
          ...(product.maxArtifactBytes !== undefined
            ? { maxArtifactBytes: product.maxArtifactBytes }
            : {}),
        });
        let feed: URL;
        try {
          feed = new URL(entry.feedUrl);
        } catch {
          return invalid();
        }
        if (
          entry.feedUrl.length > 2048 ||
          feed.protocol !== 'https:' ||
          feed.username ||
          feed.password ||
          feed.hash ||
          !product.root.artifact_origins.includes(feed.origin)
        )
          invalid();
        this.#targets.set(key, {
          target,
          client,
          feedUrl: feed.href,
          installedSequence: entry.installedSequence,
          evidence: product.evidence,
        });
        this.#products.set(product.product, client);
      }
    }
  }

  listTargets(): UpdateTarget[] {
    return [...this.#targets.values()].map((r) => ({ ...r.target }));
  }
  #get(target: UpdateTarget): RegisteredTarget {
    const registered = this.#targets.get(targetKey(target));
    if (!registered) throw new Error('update target is not registered');
    return registered;
  }
  check(target: UpdateTarget): Promise<UpdateStatus> {
    const r = this.#get(target);
    return serial(this.#store, r.target.product, async () => {
      const { envelope } = await r.client.checkForUpdates(r.feedUrl);
      return r.client.getUpdateStatus(envelope, r.installedSequence);
    });
  }
  async checkAll(): Promise<ProductUpdateCheck[]> {
    const targets = this.listTargets();
    const results: ProductUpdateCheck[] = [];
    for (let offset = 0; offset < targets.length; offset += 4) {
      results.push(
        ...(await Promise.all(
          targets.slice(offset, offset + 4).map(async (target): Promise<ProductUpdateCheck> => {
            try {
              return { target, state: 'checked', update: await this.check(target) };
            } catch {
              return { target, state: 'unavailable' };
            }
          }),
        )),
      );
    }
    return results;
  }
  verifyManifest(target: UpdateTarget, envelope: SignedUpdateEnvelope) {
    const r = this.#get(target);
    const snapshot = structuredClone(envelope);
    return serial(this.#store, r.target.product, () => r.client.verifyManifest(snapshot));
  }
  rotateRoot(product: string, envelope: SignedUpdateEnvelope): Promise<void> {
    const client = this.#products.get(product);
    if (!client) throw new Error('update product is not registered');
    const snapshot = structuredClone(envelope);
    return serial(this.#store, product, () => client.rotateRoot(snapshot));
  }
  stageArtifact(target: UpdateTarget, envelope: SignedUpdateEnvelope, directory: string) {
    const r = this.#get(target);
    const snapshot = structuredClone(envelope);
    return serial(this.#store, r.target.product, async () => {
      const status = await r.client.getUpdateStatus(snapshot, r.installedSequence);
      if (status.release !== 'available') throw new Error('update is not available for staging');
      return r.client.stageArtifact(snapshot, directory, r.evidence);
    });
  }
}
