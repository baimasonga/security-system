// Privacy firewall (ADR-027). Client-submitted telemetry must match an allow-listed schema exactly; values that
// look like personal data, secrets, locations of files or document content are refused. Refusals report the field
// and the rule — never the value.

export type FirewallRule =
  | 'unknown_event'
  | 'unknown_attribute'
  | 'type'
  | 'too_long'
  | 'pattern'
  | 'looks_like_email'
  | 'looks_like_phone'
  | 'looks_like_url'
  | 'looks_like_path'
  | 'looks_like_secret'
  | 'looks_like_card'
  | 'looks_like_key_material';

export interface Violation {
  field: string;
  rule: FirewallRule;
}

type ClientAttr =
  | { type: 'enum'; values: readonly string[] }
  | { type: 'number'; min: number; max: number }
  | { type: 'string'; max: number; pattern: RegExp };

/** The only events clients may send, and the only attributes each may carry. */
export const CLIENT_TELEMETRY_SCHEMA = {
  'app.started': {
    app_version: { type: 'string', max: 32, pattern: /^[0-9A-Za-z.+-]+$/ },
    platform: { type: 'enum', values: ['windows', 'macos', 'linux', 'android', 'ios', 'web'] },
  },
  'feature.used': {
    feature: { type: 'string', max: 48, pattern: /^[a-z][a-z0-9_.]*$/ },
    duration_ms: { type: 'number', min: 0, max: 86_400_000 },
  },
  'app.error': {
    code: { type: 'string', max: 48, pattern: /^[a-z][a-z0-9_.]*$/ },
    component: { type: 'string', max: 32, pattern: /^[a-z][a-z0-9_.]*$/ },
  },
} as const satisfies Record<string, Record<string, ClientAttr>>;

export type ClientTelemetryName = keyof typeof CLIENT_TELEMETRY_SCHEMA;

/**
 * Content detectors, applied to every string even when its pattern already restricts it (defense in depth: a
 * permissive pattern added later must not let personal data through).
 */
export function contentViolation(value: string): FirewallRule | undefined {
  if (
    /-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)/.test(value) ||
    /\bssh-(rsa|ed25519)\b/.test(value)
  )
    return 'looks_like_key_material';
  if (/[^\s@]+@[^\s@]+\.[^\s@]+/.test(value)) return 'looks_like_email';
  if (/\b[a-z][a-z0-9+.-]*:\/\//i.test(value) || /\bwww\./i.test(value)) return 'looks_like_url';
  if (/^[A-Za-z]:[\\/]/.test(value) || /[\\/][^\\/]+[\\/]/.test(value) || /^~[\\/]/.test(value))
    return 'looks_like_path';
  const digits = value.replace(/[^0-9]/g, '');
  if (digits.length >= 13 && digits.length <= 19 && luhn(digits)) return 'looks_like_card';
  // International form, separated digit groups, or a long digit run; dots (versions, dates) never count.
  if (
    /\+[0-9][0-9 ()-]{6,}[0-9]/.test(value) ||
    /\(?\b[0-9]{2,4}\)?[ -][0-9]{2,4}[ -][0-9]{3,4}\b/.test(value) ||
    /\b[0-9]{9,15}\b/.test(value)
  )
    return 'looks_like_phone';
  if (looksLikeSecret(value)) return 'looks_like_secret';
  return undefined;
}

function luhn(d: string): boolean {
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

/** Long runs of token-like characters mixing letter cases and digits (API keys, JWT segments, session tokens). */
function looksLikeSecret(value: string): boolean {
  if (/\beyJ[A-Za-z0-9_-]{10,}/.test(value)) return true; // JWT / JOSE header
  if (/\b(sk|pk|rk|ghp|gho|xox[abp])[-_][A-Za-z0-9_]{8,}/.test(value)) return true;
  for (const run of value.match(/[A-Za-z0-9_+/=-]{24,}/g) ?? []) {
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(run)).length;
    if (classes >= 2 && /[0-9]/.test(run)) return true;
  }
  return false;
}

export type FirewallResult =
  | { ok: true; name: ClientTelemetryName; attributes: Record<string, string | number> }
  | { ok: false; violations: Violation[] };

/** Strict check of one client event. Unknown events and attributes are refused, not silently dropped. */
export function checkClientEvent(name: string, attrs: Record<string, unknown>): FirewallResult {
  if (!Object.prototype.hasOwnProperty.call(CLIENT_TELEMETRY_SCHEMA, name))
    return { ok: false, violations: [{ field: 'name', rule: 'unknown_event' }] };
  const spec = CLIENT_TELEMETRY_SCHEMA[name as ClientTelemetryName] as Record<string, ClientAttr>;
  const violations: Violation[] = [];
  const out: Record<string, string | number> = {};
  for (const [field, v] of Object.entries(attrs)) {
    const def = Object.prototype.hasOwnProperty.call(spec, field) ? spec[field] : undefined;
    if (!def) {
      violations.push({ field, rule: 'unknown_attribute' });
      continue;
    }
    if (def.type === 'number') {
      if (typeof v !== 'number' || !Number.isFinite(v) || v < def.min || v > def.max)
        violations.push({ field, rule: 'type' });
      else out[field] = v;
      continue;
    }
    if (typeof v !== 'string') {
      violations.push({ field, rule: 'type' });
      continue;
    }
    // Bound the input before any pattern runs on it.
    const max = def.type === 'enum' ? 64 : def.max;
    if (v.length > max) {
      violations.push({ field, rule: 'too_long' });
      continue;
    }
    const content = contentViolation(v);
    if (content) violations.push({ field, rule: content });
    else if (def.type === 'enum') {
      if (!def.values.includes(v)) violations.push({ field, rule: 'pattern' });
      else out[field] = v;
    } else if (!def.pattern.test(v)) violations.push({ field, rule: 'pattern' });
    else out[field] = v;
  }
  return violations.length
    ? { ok: false, violations }
    : { ok: true, name: name as ClientTelemetryName, attributes: out };
}
