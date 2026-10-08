import type { Json } from './index.ts';

const SENSITIVE_KEY =
  /pass(word)?|secret|token|authorization|cookie|private|credential|license_?key|api_?key|^d$|signature|nonce|lease$/i;
// Values that look like secrets even under an innocent key name.
const SENSITIVE_VALUE = [
  /^LK-[0-9A-Z-]{20,}$/i, // license key
  /^(sess|chal)_[A-Za-z0-9_-]{20,}$/, // session token / challenge nonce
  /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$/, // compact JWS
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

export const REDACTED = '[REDACTED]';
const MAX_DEPTH = 5;
const MAX_STRING = 512;

/**
 * Defensive redaction for anything that leaves the request path into storage or logs
 * (audit metadata, telemetry, security signals). It is a safety net, not a license to pass
 * secrets: callers should not put them there in the first place.
 */
export function redact(value: unknown, depth = 0): Json {
  if (value === null || value === undefined) return null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string') {
    if (SENSITIVE_VALUE.some((r) => r.test(value))) return REDACTED;
    return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  }
  if (depth >= MAX_DEPTH) return REDACTED;
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => redact(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, Json> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SENSITIVE_KEY.test(k) ? REDACTED : redact(v, depth + 1);
    }
    return out;
  }
  return null;
}
