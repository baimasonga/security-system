import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { newId } from './hash.ts';
import { generateEd25519, normalizePublicJwk, type PublicJwk } from './jwk.ts';
import { SoftwareKeyCustody, type KeyCustody } from './signing.ts';

export type KeyPurpose = 'license';
export type KeyState = 'generated' | 'active' | 'deprecated' | 'revoked' | 'archived' | 'destroyed';

export interface KeyRecord {
  kid: string;
  purpose: KeyPurpose;
  state: KeyState;
  publicJwk: PublicJwk;
  createdAt: Date;
  activatedAt?: Date;
  deprecatedAt?: Date;
  revokedAt?: Date;
}

export interface TrustBundleKey {
  kid: string;
  purpose: KeyPurpose;
  state: 'active' | 'deprecated';
  jwk: PublicJwk;
}

export interface TrustBundle {
  schema: 1;
  keys: TrustBundleKey[];
}

export interface KeyLifecycleEvent {
  action: 'generate' | 'import' | 'activate' | 'deprecate' | 'revoke' | 'archive' | 'destroy';
  kid: string;
  purpose: KeyPurpose;
  from: KeyState | null;
  to: KeyState;
  reason?: string | undefined;
}

// Generate → Activate → Use → Rotate (deprecate) → Revoke → Archive → Destroy
const TRANSITIONS: Record<KeyState, KeyState[]> = {
  generated: ['active', 'destroyed'],
  active: ['deprecated', 'revoked'],
  deprecated: ['revoked', 'archived'],
  revoked: ['archived', 'destroyed'],
  archived: ['destroyed'],
  destroyed: [],
};

/**
 * Key lifecycle manager. State machine, single-active-key-per-purpose, verification allow-list,
 * and public trust bundle. Private material stays inside the injected KeyCustody.
 */
export class KeyRing {
  readonly #records = new Map<string, KeyRecord>();
  readonly #custody: SoftwareKeyCustody;
  readonly #now: () => Date;
  readonly #onEvent: (e: KeyLifecycleEvent) => void;

  constructor(opts?: {
    now?: () => Date;
    custody?: SoftwareKeyCustody;
    onEvent?: (e: KeyLifecycleEvent) => void;
  }) {
    this.#now = opts?.now ?? (() => new Date());
    this.#custody = opts?.custody ?? new SoftwareKeyCustody();
    this.#onEvent = opts?.onEvent ?? (() => {});
  }

  get custody(): KeyCustody {
    return this.#custody;
  }

  /** Generate a new key in state `generated`. It cannot sign until activated. */
  generate(purpose: KeyPurpose): KeyRecord {
    const { publicJwk, privateKey } = generateEd25519();
    return this.#register(purpose, publicJwk, privateKey, 'generate');
  }

  /** Import externally provisioned key material (secret store). PEM is PKCS#8 Ed25519. */
  importPrivateKeyPem(purpose: KeyPurpose, pem: string, kid?: string): KeyRecord {
    const privateKey = createPrivateKey(pem);
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('only Ed25519 keys supported');
    const publicJwk = normalizePublicJwk(createPublicKey(privateKey).export({ format: 'jwk' }));
    return this.#register(purpose, publicJwk, privateKey, 'import', kid);
  }

  #register(
    purpose: KeyPurpose,
    publicJwk: PublicJwk,
    privateKey: KeyObject,
    action: 'generate' | 'import',
    kid?: string,
  ): KeyRecord {
    const id = kid ?? newId('key');
    if (this.#records.has(id)) throw new Error(`kid ${id} already exists`);
    this.#custody.add(id, privateKey);
    const rec: KeyRecord = {
      kid: id,
      purpose,
      state: 'generated',
      publicJwk,
      createdAt: this.#now(),
    };
    this.#records.set(id, rec);
    this.#onEvent({ action, kid: id, purpose, from: null, to: 'generated' });
    return { ...rec };
  }

  get(kid: string): KeyRecord | undefined {
    const r = this.#records.get(kid);
    return r ? { ...r } : undefined;
  }

  list(): KeyRecord[] {
    return [...this.#records.values()].map((r) => ({ ...r }));
  }

  /** Activate a key. Any currently-active key of the same purpose is deprecated (rotation). */
  activate(kid: string, reason?: string): void {
    const rec = this.#must(kid);
    const current = this.#active(rec.purpose);
    if (current && current.kid !== kid)
      this.#transition(current.kid, 'deprecated', 'deprecate', reason);
    this.#transition(kid, 'active', 'activate', reason);
  }

  deprecate(kid: string, reason?: string): void {
    this.#transition(kid, 'deprecated', 'deprecate', reason);
  }

  /** Emergency: key stops verifying immediately (it disappears from the trust bundle). */
  revoke(kid: string, reason: string): void {
    this.#transition(kid, 'revoked', 'revoke', reason);
  }

  archive(kid: string, reason?: string): void {
    this.#transition(kid, 'archived', 'archive', reason);
  }

  /** Destroy private material. Irreversible. */
  destroy(kid: string, reason?: string): void {
    this.#transition(kid, 'destroyed', 'destroy', reason);
    this.#custody.remove(kid);
  }

  /** The key new signatures must use. Throws if none is active: signing fails closed. */
  activeKeyId(purpose: KeyPurpose): string {
    const a = this.#active(purpose);
    if (!a) throw new Error(`no active ${purpose} signing key`);
    return a.kid;
  }

  /** Only active and deprecated keys may verify; revoked/archived/destroyed never do. */
  resolveVerificationKey(purpose: KeyPurpose, kid: string): PublicJwk | undefined {
    const r = this.#records.get(kid);
    if (!r || r.purpose !== purpose) return undefined;
    return r.state === 'active' || r.state === 'deprecated' ? r.publicJwk : undefined;
  }

  /** Public verification material for clients. Contains no secrets. */
  trustBundle(purpose: KeyPurpose): TrustBundle {
    const keys: TrustBundleKey[] = [];
    for (const r of this.#records.values()) {
      if (r.purpose === purpose && (r.state === 'active' || r.state === 'deprecated')) {
        keys.push({ kid: r.kid, purpose, state: r.state, jwk: r.publicJwk });
      }
    }
    return { schema: 1, keys };
  }

  #active(purpose: KeyPurpose): KeyRecord | undefined {
    for (const r of this.#records.values())
      if (r.purpose === purpose && r.state === 'active') return r;
    return undefined;
  }

  #must(kid: string): KeyRecord {
    const r = this.#records.get(kid);
    if (!r) throw new Error(`unknown key ${kid}`);
    return r;
  }

  #transition(
    kid: string,
    to: KeyState,
    action: KeyLifecycleEvent['action'],
    reason?: string,
  ): void {
    const rec = this.#must(kid);
    if (!TRANSITIONS[rec.state].includes(to)) {
      throw new Error(`illegal key transition ${rec.state} -> ${to}`);
    }
    const from = rec.state;
    rec.state = to;
    const now = this.#now();
    if (to === 'active') rec.activatedAt = now;
    if (to === 'deprecated') rec.deprecatedAt = now;
    if (to === 'revoked') rec.revokedAt = now;
    this.#onEvent({ action, kid, purpose: rec.purpose, from, to, reason });
  }
}
