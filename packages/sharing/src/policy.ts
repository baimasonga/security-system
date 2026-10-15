// Pure sharing policy: limits, permitted file formats, names, destinations, aliases and link state.
// Nothing here performs I/O; every rule is unit-tested in isolation (packages/sharing/test/policy.test.ts).

import { DomainError } from '@trust/shared-types';

// ---------------------------------------------------------------------------------------------------
// Commercial limits (ADR-021 §Commercial controls)
// ---------------------------------------------------------------------------------------------------

export interface SharingLimits {
  /** Bytes of live and reserved objects the organization may hold at once. */
  storageBytes: number;
  maxFileBytes: number;
  /** Longest retention a temporary transfer may request. */
  maxRetentionDays: number;
  /** Persistent (non-expiring) transfers and shared documents. */
  persistent: boolean;
  /** Bytes delivered through issued download URLs per UTC month (an approximation; see docs). */
  bandwidthBytesPerMonth: number;
  /** Authenticated sharing API mutations per UTC month. */
  apiRequestsPerMonth: number;
  /** Bytes run through quarantine checks per UTC month. */
  processingBytesPerMonth: number;
  uploadRequests: boolean;
  customDomains: boolean;
  branding: boolean;
  advancedAnalytics: boolean;
}

const GiB = 1024 ** 3;
const MiB = 1024 ** 2;

/** Baseline for every organization: basic temporary sharing and generated short links (phase 1). */
export const FREE_LIMITS: Readonly<SharingLimits> = Object.freeze({
  storageBytes: 2 * GiB,
  maxFileBytes: 250 * MiB,
  maxRetentionDays: 7,
  persistent: false,
  bandwidthBytesPerMonth: 20 * GiB,
  apiRequestsPerMonth: 20_000,
  processingBytesPerMonth: 10 * GiB,
  uploadRequests: false,
  customDomains: false,
  branding: false,
  advancedAnalytics: false,
});

/** Plan entitlement keys. Deliberately not `_monthly` so the quota ledger (ADR-018) does not meter them. */
export const LIMIT_ENTITLEMENTS = {
  storageBytes: 'share_storage_bytes',
  maxFileBytes: 'share_max_file_bytes',
  maxRetentionDays: 'share_retention_days',
  persistent: 'share_persistent',
  bandwidthBytesPerMonth: 'share_bandwidth_bytes_per_month',
  apiRequestsPerMonth: 'share_api_requests_per_month',
  processingBytesPerMonth: 'share_processing_bytes_per_month',
  uploadRequests: 'share_upload_requests',
  customDomains: 'share_custom_domains',
  branding: 'share_branding',
  advancedAnalytics: 'share_advanced_analytics',
} as const satisfies Record<keyof SharingLimits, string>;

/** Hard ceilings: a mistyped plan must not create an unbounded commitment. */
const CEILING: Record<string, number> = {
  storageBytes: 100 * 1024 * GiB,
  maxFileBytes: 50 * GiB,
  maxRetentionDays: 3650,
  bandwidthBytesPerMonth: 1024 * 1024 * GiB,
  apiRequestsPerMonth: 100_000_000,
  processingBytesPerMonth: 1024 * 1024 * GiB,
};

/**
 * Combines the entitlements of the organization's currently valid licenses. Each limit is the most generous
 * value granted by any valid license, never below the free baseline and never above the hard ceiling. Only
 * server-resolved entitlements reach this function; client-supplied plan state never does.
 */
export function resolveLimits(
  entitlementSets: ReadonlyArray<Record<string, unknown>>,
): SharingLimits {
  const out: SharingLimits = { ...FREE_LIMITS };
  for (const ent of entitlementSets) {
    for (const [field, key] of Object.entries(LIMIT_ENTITLEMENTS) as Array<
      [keyof SharingLimits, string]
    >) {
      const v = ent[key];
      const cur = out[field];
      if (typeof cur === 'boolean') {
        if (v === true) (out as unknown as Record<string, unknown>)[field] = true;
      } else if (typeof v === 'number' && Number.isSafeInteger(v) && v > cur) {
        (out as unknown as Record<string, unknown>)[field] = Math.min(v, CEILING[field] ?? v);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------
// Permitted formats. The content type is derived from the extension on the server and confirmed against the
// stored bytes during quarantine; a client-declared type is never trusted.
// ---------------------------------------------------------------------------------------------------

export interface FileKind {
  ext: string;
  contentType: string;
  /** May be shown inline (view-only) from the isolated content origin. */
  inline: boolean;
  /** Leading bytes the stored object must start with (hex), or null for text checks. */
  magic: string[] | null;
  text: boolean;
}

const K = (
  ext: string,
  contentType: string,
  inline: boolean,
  magic: string[] | null,
  text = false,
): FileKind => ({ ext, contentType, inline, magic, text });

const ZIP = ['504b0304'];
export const FILE_KINDS: Readonly<Record<string, FileKind>> = Object.freeze({
  pdf: K('pdf', 'application/pdf', true, ['255044462d']),
  png: K('png', 'image/png', true, ['89504e470d0a1a0a']),
  jpg: K('jpg', 'image/jpeg', true, ['ffd8ff']),
  jpeg: K('jpeg', 'image/jpeg', true, ['ffd8ff']),
  gif: K('gif', 'image/gif', true, ['474946383761', '474946383961']),
  webp: K('webp', 'image/webp', true, ['52494646']),
  txt: K('txt', 'text/plain; charset=utf-8', true, null, true),
  csv: K('csv', 'text/csv; charset=utf-8', false, null, true),
  rtf: K('rtf', 'application/rtf', false, ['7b5c727466']),
  docx: K(
    'docx',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    false,
    ZIP,
  ),
  xlsx: K('xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', false, ZIP),
  pptx: K(
    'pptx',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    false,
    ZIP,
  ),
  odt: K('odt', 'application/vnd.oasis.opendocument.text', false, ZIP),
  ods: K('ods', 'application/vnd.oasis.opendocument.spreadsheet', false, ZIP),
  odp: K('odp', 'application/vnd.oasis.opendocument.presentation', false, ZIP),
  zip: K('zip', 'application/zip', false, ZIP),
});

/** Formats documents (editable PDFs) accept. */
export const DOCUMENT_EXTS = ['pdf'] as const;

export function fileKindFor(name: string): FileKind | undefined {
  const m = /\.([a-z0-9]{1,8})$/i.exec(name);
  return m ? FILE_KINDS[m[1]!.toLowerCase()] : undefined;
}

/** Throws unless `name` has a permitted extension (optionally limited to `allowed`). */
export function requireFileKind(name: string, allowed?: readonly string[]): FileKind {
  const kind = fileKindFor(name);
  if (!kind || (allowed && !allowed.includes(kind.ext)))
    throw new DomainError('invalid_request', 'file type not permitted', {
      permitted: [...(allowed ?? Object.keys(FILE_KINDS))],
    });
  return kind;
}

/** Checks the first bytes of a stored object against its declared kind. */
export function magicMatches(kind: FileKind, head: Uint8Array): boolean {
  if (kind.magic === null) {
    // Text formats: no NUL bytes in the sampled head (binary disguised as text).
    return !head.subarray(0, 8192).includes(0);
  }
  const hex = Buffer.from(head.subarray(0, 16)).toString('hex');
  if (kind.ext === 'webp') return hex.startsWith('52494646') && hex.slice(16, 24) === '57454250';
  return kind.magic.some((m) => hex.startsWith(m));
}

// ---------------------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------------------

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g;

/** Removes control, zero-width and bidirectional-override characters (keeps tab and newline). */
export function stripControl(s: string): string {
  return s.replace(CONTROL_TEXT, '');
}
const CONTROL_TEXT =
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g;

/** A display-safe file name: no path, control or bidi-override characters; bounded length; keeps extension. */
export function sanitizeFileName(raw: string): string {
  const base = raw.normalize('NFC').replace(CONTROL, '').split(/[\\/]/).pop()!.trim();
  const cleaned = base.replace(/^\.+/, '').replace(/["<>:|?*]/g, '_');
  if (!cleaned || cleaned.length > 200)
    throw new DomainError('invalid_request', 'invalid file name');
  return cleaned;
}

/** Relative folder path for folder uploads: sanitized segments, no traversal, bounded depth/length. */
export function sanitizeFolderPath(raw: string | undefined): string {
  if (!raw) return '';
  const segments = raw
    .normalize('NFC')
    .replace(CONTROL, '')
    .split(/[\\/]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (segments.length > 10 || segments.some((s) => s === '.' || s === '..' || s.length > 100))
    throw new DomainError('invalid_request', 'invalid folder path');
  const out = segments.map((s) => s.replace(/["<>:|?*]/g, '_')).join('/');
  if (out.length > 500) throw new DomainError('invalid_request', 'invalid folder path');
  return out;
}

/** RFC 6266 / 5987 Content-Disposition with an ASCII fallback. */
export function contentDisposition(kind: 'inline' | 'attachment', filename: string): string {
  const ascii = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\%;]/g, '_');
  return `${kind}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

// ---------------------------------------------------------------------------------------------------
// Short-link destinations and aliases. Destinations are validated syntactically and NEVER fetched by the
// platform (no previews from privileged servers; see the threat model, S-11).
// ---------------------------------------------------------------------------------------------------

export interface DestinationPolicy {
  /** Hosts the platform itself serves (no redirect loops through our own short links). */
  reservedHosts: readonly string[];
  /** Operator blocklist; matches the host and its subdomains. */
  blockedHosts: readonly string[];
}

const INTERNAL_SUFFIXES = [
  '.local',
  '.localhost',
  '.internal',
  '.lan',
  '.home.arpa',
  '.intranet',
  '.corp',
];

export function validateExternalDestination(raw: string, policy: DestinationPolicy): string {
  const bad = (why: string) =>
    new DomainError('invalid_request', `destination not permitted: ${why}`);
  if (raw.length > 2048) throw bad('too long');
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw bad('not a URL');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw bad('scheme');
  if (u.username || u.password) throw bad('embedded credentials');
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host.includes('.') || host === 'localhost') throw bad('host');
  if (/^[0-9.]+$/.test(host) || host.startsWith('[') || /^0x/i.test(host)) throw bad('IP literal');
  if (INTERNAL_SUFFIXES.some((s) => host.endsWith(s))) throw bad('internal host');
  if (u.port && !['80', '443'].includes(u.port)) throw bad('port');
  const matches = (list: readonly string[]) =>
    list.some((h) => host === h.toLowerCase() || host.endsWith(`.${h.toLowerCase()}`));
  if (matches(policy.reservedHosts)) throw bad('points at this service');
  if (matches(policy.blockedHosts)) throw bad('blocked host');
  return u.toString();
}

const RESERVED_ALIASES = new Set([
  'admin',
  'api',
  'app',
  'abuse',
  'account',
  'billing',
  'checkout',
  'd',
  'download',
  'help',
  'l',
  'login',
  'logout',
  'mail',
  'operator',
  'password',
  'r',
  'report',
  'reset',
  'rokela',
  'root',
  's',
  'security',
  'settings',
  'signin',
  'signup',
  'support',
  'verify',
  'www',
]);

/** Custom aliases for PUBLIC short links only: lowercase, readable, not impersonating platform paths. */
export function validateAlias(alias: string): string {
  const a = alias.trim().toLowerCase();
  if (
    !/^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$/.test(a) ||
    a.includes('--') ||
    RESERVED_ALIASES.has(a)
  )
    throw new DomainError('invalid_request', 'alias not available');
  return a;
}

export function validateHostname(raw: string): string {
  const h = raw.trim().toLowerCase().replace(/\.$/, '');
  const labels = h.split('.');
  if (
    h.length > 253 ||
    labels.length < 2 ||
    labels.some((l) => !/^[a-z0-9-]{1,63}$/.test(l) || l.startsWith('-') || l.endsWith('-')) ||
    !/^[a-z]{2,63}$/.test(labels[labels.length - 1]!) ||
    INTERNAL_SUFFIXES.some((s) => h.endsWith(s))
  )
    throw new DomainError('invalid_request', 'invalid hostname');
  return h;
}

export function validateAccentColor(raw: string): string {
  if (!/^#[0-9a-f]{6}$/i.test(raw)) throw new DomainError('invalid_request', 'invalid color');
  return raw.toLowerCase();
}

// ---------------------------------------------------------------------------------------------------
// Analytics hygiene
// ---------------------------------------------------------------------------------------------------

const BOT_UA =
  /bot|crawl|spider|slurp|preview|scanner|facebookexternalhit|embedly|whatsapp|telegram|skype|slack|discord|curl|wget|python-requests|httpclient|go-http-client|okhttp|java\/|headless|lighthouse|microsoft office|outlook|ms-office|safelinks|proofpoint|mimecast|barracuda|symantec|trendmicro|forcepoint|urldefense/i;

/** Obvious automated clients. Email scanners and link previews that mimic browsers are NOT caught. */
export function looksAutomated(userAgent: string | undefined): boolean {
  return !userAgent || userAgent.length < 10 || BOT_UA.test(userAgent);
}

/** Only the referring host is kept (approximate referral; no paths, queries or fragments). */
export function referrerHost(referer: string | undefined): string {
  if (!referer) return '';
  try {
    const u = new URL(referer);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
    return u.hostname.toLowerCase().slice(0, 253);
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------------------------------
// Link state
// ---------------------------------------------------------------------------------------------------

export type LinkStatus = 'active' | 'suspended' | 'revoked';
export type EffectiveLinkState = 'active' | 'suspended' | 'revoked' | 'expired' | 'unavailable';

/** One evaluation used by every public path; owners see the same answer in their workspace. */
export function effectiveLinkState(
  link: { status: LinkStatus; expiresAt: Date | null },
  now: Date,
  targetUsable: boolean,
): EffectiveLinkState {
  if (link.status !== 'active') return link.status;
  if (link.expiresAt && link.expiresAt.getTime() <= now.getTime()) return 'expired';
  if (!targetUsable) return 'unavailable';
  return 'active';
}

export const PERMISSIONS = ['view', 'download', 'review'] as const;
export type SharePermission = (typeof PERMISSIONS)[number];

/** What a share permission lets a recipient do. View-only cannot prevent screenshots or copying. */
export function permits(
  permission: SharePermission,
  action: 'view' | 'download' | 'comment',
): boolean {
  if (action === 'view') return true;
  if (action === 'download') return permission === 'download';
  return permission === 'review';
}

export function monthKey(d: Date): string {
  return d.toISOString().slice(0, 7);
}
export function dayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** S3 multipart rules: parts of at least 5 MiB (except the last), at most 10 000 parts. */
export function planParts(
  size: number,
  preferred = 8 * MiB,
  minimum = 5 * MiB,
): { partSize: number; partCount: number } {
  if (!Number.isSafeInteger(size) || size < 1)
    throw new DomainError('invalid_request', 'invalid size');
  const partSize = Math.max(preferred, minimum, Math.ceil(size / 10_000));
  return { partSize, partCount: Math.max(1, Math.ceil(size / partSize)) };
}

export function normalizeEmail(raw: string): string {
  const e = raw.trim().toLowerCase();
  if (e.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e))
    throw new DomainError('invalid_request', 'invalid email');
  return e;
}
