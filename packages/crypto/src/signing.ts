import { sign as edSign, type KeyObject } from 'node:crypto';
import { b64urlEncode } from './encoding.ts';
import type { JwsHeader } from './verify.ts';

/**
 * Custody of private signing keys. The software implementation is for development/tests and for
 * deployments that inject keys from a secret store; production target is a KMS/HSM implementation
 * of this same interface where the private key is non-exportable.
 */
export interface KeyCustody {
  sign(kid: string, data: Buffer): Promise<Buffer>;
}

export async function signJws(
  payload: Record<string, unknown>,
  header: Pick<JwsHeader, 'typ' | 'kid'>,
  custody: KeyCustody,
): Promise<string> {
  const h = b64urlEncode(JSON.stringify({ alg: 'EdDSA', typ: header.typ, kid: header.kid }));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = await custody.sign(header.kid, Buffer.from(`${h}.${p}`, 'ascii'));
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

export class SoftwareKeyCustody implements KeyCustody {
  readonly #keys = new Map<string, KeyObject>();

  add(kid: string, privateKey: KeyObject): void {
    if (this.#keys.has(kid)) throw new Error(`key ${kid} already present`);
    this.#keys.set(kid, privateKey);
  }

  has(kid: string): boolean {
    return this.#keys.has(kid);
  }

  remove(kid: string): void {
    this.#keys.delete(kid);
  }

  async sign(kid: string, data: Buffer): Promise<Buffer> {
    const key = this.#keys.get(kid);
    if (!key) throw new Error(`no private key material for ${kid}`);
    return edSign(null, data, key);
  }
}
