const B64URL = /^[A-Za-z0-9_-]*$/;

export function b64urlEncode(data: Uint8Array | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return buf.toString('base64url');
}

/** Strict decode: rejects padding, whitespace and non-canonical encodings. */
export function b64urlDecode(s: string): Buffer {
  if (!B64URL.test(s)) throw new Error('invalid base64url');
  const buf = Buffer.from(s, 'base64url');
  if (buf.toString('base64url') !== s) throw new Error('non-canonical base64url');
  return buf;
}

/** Deterministic JSON: sorted keys, no whitespace. Used for hashing/signing structured data. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (value === undefined) throw new Error('undefined is not canonicalizable');
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new Error('non-finite number is not canonicalizable');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}
