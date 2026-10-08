import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from 'node:crypto';
import {
  b64urlEncode,
  jwkThumbprint,
  normalizePublicJwk,
  type PublicJwk,
} from '@trust/crypto/verify';

/**
 * The device's own cryptographic identity. The private key is the CLIENT's key (it proves
 * possession); it is unrelated to any platform signing key, which never reaches a client.
 *
 * `SoftwareDeviceKey` stores PKCS#8 PEM in whatever `SecureStore` the host provides (OS keychain /
 * DPAPI-protected file). Hardware-backed implementations (TPM, Secure Enclave, Android Keystore)
 * implement the same `DeviceKey` interface in a later milestone.
 */
export interface DeviceKey {
  readonly publicJwk: PublicJwk;
  readonly thumbprint: string;
  sign(message: string): string;
}

export class SoftwareDeviceKey implements DeviceKey {
  readonly publicJwk: PublicJwk;
  readonly thumbprint: string;
  readonly #priv: KeyObject;

  private constructor(priv: KeyObject) {
    this.#priv = priv;
    this.publicJwk = normalizePublicJwk(createPublicKey(priv).export({ format: 'jwk' }));
    this.thumbprint = jwkThumbprint(this.publicJwk);
  }

  static generate(): SoftwareDeviceKey {
    return new SoftwareDeviceKey(generateKeyPairSync('ed25519').privateKey);
  }

  static fromPem(pem: string): SoftwareDeviceKey {
    const k = createPrivateKey(pem);
    if (k.asymmetricKeyType !== 'ed25519') throw new Error('device key must be Ed25519');
    return new SoftwareDeviceKey(k);
  }

  exportPem(): string {
    return this.#priv.export({ type: 'pkcs8', format: 'pem' }).toString();
  }

  sign(message: string): string {
    return b64urlEncode(sign(null, Buffer.from(message, 'utf8'), this.#priv));
  }
}

/** Host-provided protected storage (OS keychain, DPAPI, encrypted file...). */
export interface SecureStore {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export class MemorySecureStore implements SecureStore {
  readonly #m = new Map<string, string>();
  async get(k: string) {
    return this.#m.get(k);
  }
  async set(k: string, v: string) {
    this.#m.set(k, v);
  }
  async delete(k: string) {
    this.#m.delete(k);
  }
}
