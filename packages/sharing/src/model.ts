import { AuditBuffer, type AuditEventInput, type AuditLog, type AuditWriter } from '@trust/audit';
import type { LinkStatus, SharePermission } from './policy.ts';

// ---------------------------------------------------------------------------------------------------
// Records (docs/architecture/10-file-sharing-and-short-links.md §Data model). Every row is tenant-scoped by
// `orgId`; ids are opaque, unguessable and never authority on their own.
// ---------------------------------------------------------------------------------------------------

export type BlobStatus =
  'uploading' | 'quarantined' | 'clean' | 'rejected' | 'deleting' | 'deleted';
export type UploadTarget = 'transfer_file' | 'transfer_replace' | 'draft' | 'submission_file';

/** Lock anchor for an organization's storage and usage accounting. */
export interface AccountRow {
  id: string; // = orgId
  orgId: string;
  createdAt: Date;
}

/** One immutable stored object. Blobs are never rewritten; replacement creates a new blob. */
export interface BlobRow {
  id: string;
  orgId: string;
  objectKey: string;
  ext: string;
  contentType: string;
  declaredSize: number;
  size: number | null;
  sha256: string | null;
  status: BlobStatus;
  rejectReason: string | null;
  multipartId: string | null;
  partSize: number;
  partCount: number;
  uploadExpiresAt: Date | null;
  targetType: UploadTarget;
  targetId: string;
  /** Replacement explanation shown to recipients (transfer_replace only). */
  note: string | null;
  createdBy: string | null;
  createdAt: Date;
  completedAt: Date | null;
  scannedAt: Date | null;
  deletedAt: Date | null;
}

export interface DocumentRow {
  id: string;
  orgId: string;
  title: string;
  createdBy: string;
  /** Private working copy saved by the editor. Never reachable through any share link. */
  draftBlobId: string | null;
  draftUpdatedAt: Date | null;
  publishedVersionId: string | null;
  publishedAt: Date | null;
  requireApproval: boolean;
  status: 'active' | 'deleted';
  createdAt: Date;
  updatedAt: Date;
}

/** Immutable export of a document. */
export interface VersionRow {
  id: string;
  orgId: string;
  documentId: string;
  number: number;
  blobId: string;
  fileName: string;
  note: string | null;
  createdBy: string;
  createdAt: Date;
  publishedAt: Date | null;
  replacementNote: string | null;
}

export interface TransferRow {
  id: string;
  orgId: string;
  createdBy: string;
  title: string;
  message: string | null;
  kind: 'temporary' | 'persistent';
  status: 'active' | 'revoked' | 'expired' | 'deleted' | 'purged';
  expiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface TransferFileRow {
  id: string;
  orgId: string;
  transferId: string;
  blobId: string;
  name: string;
  folderPath: string;
  ext: string;
  size: number;
  status: 'current' | 'removed';
  revision: number;
  replacedAt: Date | null;
  replacementNote: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface LinkRow {
  id: string;
  orgId: string;
  salt: string;
  tokenHash: string;
  createdBy: string;
  label: string | null;
  targetType: 'transfer' | 'document';
  targetId: string;
  versionMode: 'latest' | 'fixed' | null;
  versionId: string | null;
  permission: SharePermission;
  passwordHash: string | null;
  expiresAt: Date | null;
  maxDownloads: number | null;
  downloadCount: number;
  restriction: 'none' | 'members' | 'recipients';
  recipients: string[];
  notifyOnAccess: boolean;
  status: LinkStatus;
  statusReason: string | null;
  /** Set by an operator (abuse review); the owner cannot lift it. */
  operatorHold: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface CommentRow {
  id: string;
  orgId: string;
  documentId: string;
  versionId: string;
  linkId: string | null;
  authorUserId: string;
  body: string;
  page: number | null;
  createdAt: Date;
}

export interface ReviewRow {
  id: string;
  orgId: string;
  documentId: string;
  versionId: string;
  linkId: string | null;
  reviewerUserId: string;
  decision: 'approved' | 'changes_requested';
  note: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type DestinationType = 'external' | 'share' | 'request';

export interface ShortLinkRow {
  id: string;
  orgId: string;
  kind: 'public' | 'confidential';
  domainId: string | null;
  /** Public code (alias or generated). Null for confidential links, whose code is derived and only hashed. */
  code: string | null;
  salt: string | null;
  /** Unique lookup: `p|<domainKey>|<code>` or `c|<hash>`. */
  lookupKey: string;
  destinationType: DestinationType;
  destinationUrl: string | null;
  /** Share link or upload request id for confidential destinations. */
  targetId: string | null;
  status: LinkStatus;
  statusReason: string | null;
  operatorHold: boolean;
  expiresAt: Date | null;
  passwordHash: string | null;
  requireAuth: boolean;
  label: string | null;
  folder: string;
  tags: string[];
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface DestinationRow {
  id: string;
  orgId: string;
  shortLinkId: string;
  destinationType: DestinationType;
  destinationUrl: string | null;
  targetId: string | null;
  changedBy: string;
  reason: string | null;
  createdAt: Date;
}

export interface Requirement {
  key: string;
  label: string;
  accept: string[];
  required: boolean;
  maxFiles: number;
}

export interface UploadRequestRow {
  id: string;
  orgId: string;
  salt: string;
  tokenHash: string;
  createdBy: string;
  title: string;
  instructions: string | null;
  requirements: Requirement[];
  deadline: Date;
  maxFileBytes: number;
  maxTotalBytes: number;
  passwordHash: string | null;
  status: 'open' | 'closed' | 'purged';
  operatorHold: boolean;
  notify: boolean;
  deleteAfter: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface SubmissionRow {
  id: string;
  orgId: string;
  requestId: string;
  secretHash: string;
  submitterName: string;
  submitterEmail: string | null;
  status: 'open' | 'submitted';
  createdAt: Date;
  submittedAt: Date | null;
}

export interface SubmissionFileRow {
  id: string;
  orgId: string;
  requestId: string;
  submissionId: string;
  blobId: string;
  requirementKey: string;
  name: string;
  ext: string;
  size: number;
  status: 'current' | 'removed';
  createdAt: Date;
}

export const EVENT_KINDS = [
  'visit',
  'access',
  'view',
  'download',
  'acknowledge',
  'password_failed',
  'denied',
  'comment',
  'review',
  'upload',
  'submitted',
] as const;
export type EventKind = (typeof EVENT_KINDS)[number];

/** Delivery receipt / link event. Ids and coarse attributes only: no filenames, titles, IPs or paths. */
export interface EventRow {
  id: string;
  orgId: string;
  subjectType: 'share' | 'request';
  subjectId: string;
  kind: EventKind;
  userId: string | null;
  email: string | null;
  fileId: string | null;
  bot: boolean;
  referrerHost: string;
  declaredName: string | null;
  createdAt: Date;
}

export interface NotificationRow {
  id: string;
  orgId: string;
  userId: string;
  kind: string;
  subjectType: string;
  subjectId: string;
  message: string;
  createdAt: Date;
  readAt: Date | null;
}

export interface JobRow {
  id: string;
  orgId: string;
  kind: 'scan' | 'delete_blob' | 'notify_email';
  subjectId: string;
  payload: Record<string, string>;
  runAfter: Date;
  attempts: number;
  claim: string | null;
  lockedUntil: Date | null;
  lastError: string | null;
  createdAt: Date;
}

export interface DomainRow {
  id: string;
  orgId: string;
  hostname: string;
  verificationToken: string;
  status: 'pending' | 'verified';
  createdAt: Date;
  verifiedAt: Date | null;
  checkedAt: Date | null;
}

export interface BrandRow {
  id: string; // = orgId
  orgId: string;
  displayName: string;
  accentColor: string;
  updatedAt: Date;
}

export interface AbuseRow {
  id: string;
  /** Owning organization of the reported item, or '' when the reference did not resolve. */
  orgId: string;
  subjectType: 'short' | 'share' | 'request' | 'unknown';
  subjectId: string | null;
  reference: string;
  category: 'phishing' | 'malware' | 'spam' | 'other';
  details: string | null;
  reporterEmail: string | null;
  status: 'open' | 'actioned' | 'dismissed';
  createdAt: Date;
  resolvedAt: Date | null;
  resolvedBy: string | null;
  resolution: string | null;
}

export interface Rows {
  account: AccountRow;
  blob: BlobRow;
  document: DocumentRow;
  version: VersionRow;
  transfer: TransferRow;
  transferFile: TransferFileRow;
  link: LinkRow;
  comment: CommentRow;
  review: ReviewRow;
  shortLink: ShortLinkRow;
  destination: DestinationRow;
  uploadRequest: UploadRequestRow;
  submission: SubmissionRow;
  submissionFile: SubmissionFileRow;
  event: EventRow;
  notification: NotificationRow;
  job: JobRow;
  domain: DomainRow;
  brand: BrandRow;
  abuse: AbuseRow;
}
export type Kind = keyof Rows;
export const KINDS = [
  'account',
  'blob',
  'document',
  'version',
  'transfer',
  'transferFile',
  'link',
  'comment',
  'review',
  'shortLink',
  'destination',
  'uploadRequest',
  'submission',
  'submissionFile',
  'event',
  'notification',
  'job',
  'domain',
  'brand',
  'abuse',
] as const satisfies readonly Kind[];

/** Global unique lookups (public paths resolve a secret's hash to its row; the row then names its tenant). */
export const UNIQUE_LOOKUPS = {
  link: ['tokenHash'],
  uploadRequest: ['tokenHash'],
  submission: ['secretHash'],
  shortLink: ['lookupKey'],
  domain: ['hostname'],
  abuse: [],
} as const satisfies Partial<Record<Kind, readonly string[]>>;
export type UniqueKind = keyof typeof UNIQUE_LOOKUPS;
export type UniqueField<K extends UniqueKind> = (typeof UNIQUE_LOOKUPS)[K][number];

/** Composite uniqueness enforced by every adapter (`duplicate:<kind>` on violation). */
export const UNIQUE_TOGETHER: Partial<Record<Kind, readonly string[][]>> = {
  link: [['tokenHash']],
  uploadRequest: [['tokenHash']],
  submission: [['secretHash']],
  shortLink: [['lookupKey']],
  domain: [['hostname']],
  version: [['documentId', 'number']],
  review: [['versionId', 'reviewerUserId']],
};

export interface ListOptions {
  limit?: number;
  /** Newest first by `createdAt` (default) or oldest first. */
  order?: 'newest' | 'oldest';
}

export type UsageMetric = 'bandwidth_bytes' | 'api_requests' | 'processing_bytes' | 'upload_bytes';
export const USAGE_METRICS: readonly UsageMetric[] = [
  'bandwidth_bytes',
  'api_requests',
  'processing_bytes',
  'upload_bytes',
];

export interface StatRow {
  orgId: string;
  subjectType: 'share' | 'short' | 'request';
  subjectId: string;
  day: string;
  kind: string;
  bot: boolean;
  referrerHost: string;
  count: number;
}

export interface AttemptState {
  count: number;
  lockedUntil: Date | null;
}

export interface ShortLinkQuery {
  q?: string;
  folder?: string;
  tag?: string;
  status?: LinkStatus;
  limit?: number;
}

/** Data access for sharing. Methods taking `orgId` never return another tenant's rows. */
export interface SharingRepo {
  insert<K extends Kind>(kind: K, row: Rows[K]): Promise<void>;
  get<K extends Kind>(kind: K, orgId: string, id: string): Promise<Rows[K] | undefined>;
  /** As `get`, plus an exclusive row lock until the transaction ends (PostgreSQL). */
  getForUpdate<K extends Kind>(kind: K, orgId: string, id: string): Promise<Rows[K] | undefined>;
  findUnique<K extends UniqueKind>(
    kind: K,
    field: UniqueField<K>,
    value: string,
  ): Promise<Rows[K] | undefined>;
  update<K extends Kind>(
    kind: K,
    orgId: string,
    id: string,
    patch: Partial<Rows[K]>,
  ): Promise<void>;
  /** Deletes one row (only kinds whose policy allows deletion: jobs, domains). */
  remove(kind: 'job' | 'domain', orgId: string, id: string): Promise<void>;
  /** Equality filter over allow-listed columns. */
  list<K extends Kind>(
    kind: K,
    orgId: string,
    where?: Partial<Rows[K]>,
    opts?: ListOptions,
  ): Promise<Rows[K][]>;

  /** Creates the organization's accounting row if needed and locks it (lock order: account first). */
  lockAccount(orgId: string, now: Date): Promise<void>;
  /** Bytes held or reserved by blobs that are not yet deleted. */
  storageBytes(orgId: string): Promise<number>;
  /** Atomically adds to a monthly usage counter and returns the new total. */
  addUsage(orgId: string, period: string, metric: UsageMetric, amount: number): Promise<number>;
  usage(orgId: string, period: string): Promise<Record<UsageMetric, number>>;
  /** True while any current document draft/version, transfer file or submission file references the blob. */
  blobReferenced(orgId: string, blobId: string): Promise<boolean>;
  nextVersionNumber(orgId: string, documentId: string): Promise<number>;
  searchShortLinks(orgId: string, q: ShortLinkQuery): Promise<ShortLinkRow[]>;

  /** Fenced job claim: due, unleased jobs get `claim` and a lease until `lockedUntil`. */
  claimJobs(now: Date, limit: number, claim: string, lockedUntil: Date): Promise<JobRow[]>;
  /** Cross-tenant maintenance scans, bounded by `limit`. */
  dueTransfers(now: Date, limit: number): Promise<TransferRow[]>;
  dueUploadRequests(now: Date, limit: number): Promise<UploadRequestRow[]>;
  staleUploads(now: Date, limit: number): Promise<BlobRow[]>;
  listAbuse(status: AbuseRow['status'] | undefined, limit: number): Promise<AbuseRow[]>;
  getAbuseForUpdate(id: string): Promise<AbuseRow | undefined>;

  bumpStat(row: Omit<StatRow, 'count'>, n: number): Promise<void>;
  listStats(
    orgId: string,
    subjectType: StatRow['subjectType'],
    subjectId: string,
    sinceDay: string,
  ): Promise<StatRow[]>;

  findAttempt(key: string): Promise<AttemptState | undefined>;
  recordAttemptFailure(key: string, now: Date, max: number, lockMs: number): Promise<AttemptState>;
  clearAttempt(key: string): Promise<void>;

  purgeEvents(before: Date, limit: number): Promise<number>;
  purgeStats(beforeDay: string, limit: number): Promise<number>;
  purgeAttempts(before: Date, limit: number): Promise<number>;
  purgeNotifications(before: Date, limit: number): Promise<number>;
}

export interface SharingTx extends SharingRepo {
  audit: AuditWriter;
}

/** Persistence port for sharing. Adapters: in-memory (tests/dev), PostgreSQL. */
export interface SharingStore extends SharingRepo {
  /** Unit of work with atomic audit. `fn` must be safe to re-run (PostgreSQL retries deadlocks). */
  transaction<T>(fn: (tx: SharingTx) => Promise<T>): Promise<T>;
}

// ---------------------------------------------------------------------------------------------------
// In-memory adapter
// ---------------------------------------------------------------------------------------------------

type Table = Map<string, Record<string, unknown>>;
interface State {
  tables: Record<Kind, Table>;
  usage: Map<string, number>;
  stats: Map<string, StatRow>;
  attempts: Map<string, AttemptState & { updatedAt: Date }>;
}

const clone = <T>(v: T): T => structuredClone(v);
const matches = (row: Record<string, unknown>, where: Record<string, unknown>) =>
  Object.entries(where).every(([k, v]) => {
    const r = row[k];
    if (r instanceof Date && v instanceof Date) return r.getTime() === v.getTime();
    return r === v;
  });

class MemoryRepo implements SharingRepo {
  readonly s: State = {
    tables: Object.fromEntries(KINDS.map((k) => [k, new Map()])) as Record<Kind, Table>,
    usage: new Map(),
    stats: new Map(),
    attempts: new Map(),
  };

  _tbl(kind: Kind): Table {
    return this.s.tables[kind];
  }

  async insert<K extends Kind>(kind: K, row: Rows[K]): Promise<void> {
    const t = this._tbl(kind);
    const r = row as unknown as Record<string, unknown>;
    if (t.has(r['id'] as string)) throw new Error(`duplicate:${kind}`);
    for (const cols of UNIQUE_TOGETHER[kind] ?? []) {
      for (const existing of t.values())
        if (cols.every((c) => existing[c] === r[c])) throw new Error(`duplicate:${kind}`);
    }
    t.set(r['id'] as string, clone(r));
  }
  async get<K extends Kind>(kind: K, orgId: string, id: string): Promise<Rows[K] | undefined> {
    const r = this._tbl(kind).get(id);
    return r && r['orgId'] === orgId ? (clone(r) as unknown as Rows[K]) : undefined;
  }
  getForUpdate<K extends Kind>(kind: K, orgId: string, id: string) {
    return this.get(kind, orgId, id);
  }
  async findUnique<K extends UniqueKind>(kind: K, field: UniqueField<K>, value: string) {
    for (const r of this._tbl(kind).values())
      if (r[field as string] === value) return clone(r) as unknown as Rows[K];
    return undefined;
  }
  async update<K extends Kind>(kind: K, orgId: string, id: string, patch: Partial<Rows[K]>) {
    const r = this._tbl(kind).get(id);
    if (!r || r['orgId'] !== orgId) return;
    const next: Record<string, unknown> = {
      ...r,
      ...clone(patch as Record<string, unknown>),
      id,
      orgId,
    };
    for (const cols of UNIQUE_TOGETHER[kind] ?? []) {
      for (const [otherId, existing] of this._tbl(kind))
        if (otherId !== id && cols.every((c) => existing[c] === next[c]))
          throw new Error(`duplicate:${kind}`);
    }
    this._tbl(kind).set(id, next);
  }
  async remove(kind: 'job' | 'domain', orgId: string, id: string) {
    const r = this._tbl(kind).get(id);
    if (r && r['orgId'] === orgId) this._tbl(kind).delete(id);
  }
  async list<K extends Kind>(
    kind: K,
    orgId: string,
    where: Partial<Rows[K]> = {},
    opts: ListOptions = {},
  ): Promise<Rows[K][]> {
    const rows = [...this._tbl(kind).values()].filter(
      (r) => r['orgId'] === orgId && matches(r, where as Record<string, unknown>),
    );
    rows.sort((a, b) => {
      const d = (a['createdAt'] as Date).getTime() - (b['createdAt'] as Date).getTime();
      const tie = String(a['id']).localeCompare(String(b['id']));
      return opts.order === 'oldest' ? d || tie : -d || -tie;
    });
    return rows.slice(0, opts.limit ?? 500).map((r) => clone(r) as unknown as Rows[K]);
  }

  async lockAccount(orgId: string, now: Date) {
    if (!this._tbl('account').has(orgId))
      this._tbl('account').set(orgId, { id: orgId, orgId, createdAt: now });
  }
  async storageBytes(orgId: string) {
    let n = 0;
    for (const b of this._tbl('blob').values())
      if (b['orgId'] === orgId && b['status'] !== 'deleted')
        n += (b['size'] as number | null) ?? (b['declaredSize'] as number);
    return n;
  }
  async addUsage(orgId: string, period: string, metric: UsageMetric, amount: number) {
    const k = `${orgId}|${period}|${metric}`;
    const v = (this.s.usage.get(k) ?? 0) + amount;
    this.s.usage.set(k, v);
    return v;
  }
  async usage(orgId: string, period: string) {
    return Object.fromEntries(
      USAGE_METRICS.map((m) => [m, this.s.usage.get(`${orgId}|${period}|${m}`) ?? 0]),
    ) as Record<UsageMetric, number>;
  }
  async blobReferenced(orgId: string, blobId: string) {
    const live = (kind: Kind, pred: (r: Record<string, unknown>) => boolean) =>
      [...this._tbl(kind).values()].some((r) => r['orgId'] === orgId && pred(r));
    return (
      live('document', (d) => d['status'] === 'active' && d['draftBlobId'] === blobId) ||
      live(
        'version',
        (v) =>
          v['blobId'] === blobId &&
          this._tbl('document').get(v['documentId'] as string)?.['status'] === 'active',
      ) ||
      live('transferFile', (f) => f['status'] === 'current' && f['blobId'] === blobId) ||
      live('submissionFile', (f) => f['status'] === 'current' && f['blobId'] === blobId)
    );
  }
  async nextVersionNumber(orgId: string, documentId: string) {
    let max = 0;
    for (const v of this._tbl('version').values())
      if (v['orgId'] === orgId && v['documentId'] === documentId)
        max = Math.max(max, v['number'] as number);
    return max + 1;
  }
  async searchShortLinks(orgId: string, q: ShortLinkQuery) {
    const needle = q.q?.toLowerCase();
    const rows = (await this.list('shortLink', orgId, {}, { limit: 100_000 })).filter(
      (r) =>
        (!q.folder || r.folder === q.folder) &&
        (!q.tag || r.tags.includes(q.tag)) &&
        (!q.status || r.status === q.status) &&
        (!needle ||
          [r.code, r.label, r.destinationUrl].some((v) => v?.toLowerCase().includes(needle))),
    );
    return rows.slice(0, q.limit ?? 200);
  }

  async claimJobs(now: Date, limit: number, claim: string, lockedUntil: Date) {
    const due = [...this._tbl('job').values()]
      .filter(
        (j) =>
          (j['runAfter'] as Date) <= now &&
          (!j['lockedUntil'] || (j['lockedUntil'] as Date) <= now),
      )
      .sort((a, b) => +(a['runAfter'] as Date) - +(b['runAfter'] as Date))
      .slice(0, limit);
    for (const j of due) Object.assign(j, { claim, lockedUntil });
    return due.map((j) => clone(j) as unknown as JobRow);
  }
  async dueTransfers(now: Date, limit: number) {
    return [...this._tbl('transfer').values()]
      .filter(
        (t) =>
          (t['status'] === 'active' && t['expiresAt'] && (t['expiresAt'] as Date) <= now) ||
          t['status'] === 'deleted' ||
          (t['status'] === 'expired' && t['kind'] === 'temporary') ||
          (t['status'] === 'revoked' &&
            t['kind'] === 'temporary' &&
            t['expiresAt'] &&
            (t['expiresAt'] as Date) <= now),
      )
      .slice(0, limit)
      .map((t) => clone(t) as unknown as TransferRow);
  }
  async dueUploadRequests(now: Date, limit: number) {
    return [...this._tbl('uploadRequest').values()]
      .filter(
        (r) => r['status'] !== 'purged' && r['deleteAfter'] && (r['deleteAfter'] as Date) <= now,
      )
      .slice(0, limit)
      .map((r) => clone(r) as unknown as UploadRequestRow);
  }
  async staleUploads(now: Date, limit: number) {
    return [...this._tbl('blob').values()]
      .filter(
        (b) =>
          b['status'] === 'uploading' &&
          b['uploadExpiresAt'] &&
          (b['uploadExpiresAt'] as Date) <= now,
      )
      .slice(0, limit)
      .map((b) => clone(b) as unknown as BlobRow);
  }
  async listAbuse(status: AbuseRow['status'] | undefined, limit: number) {
    return [...this._tbl('abuse').values()]
      .filter((r) => !status || r['status'] === status)
      .sort((a, b) => +(b['createdAt'] as Date) - +(a['createdAt'] as Date))
      .slice(0, limit)
      .map((r) => clone(r) as unknown as AbuseRow);
  }
  async getAbuseForUpdate(id: string) {
    const r = this._tbl('abuse').get(id);
    return r ? (clone(r) as unknown as AbuseRow) : undefined;
  }

  async bumpStat(row: Omit<StatRow, 'count'>, n: number) {
    const k = [
      row.orgId,
      row.subjectType,
      row.subjectId,
      row.day,
      row.kind,
      row.bot,
      row.referrerHost,
    ].join('|');
    const cur = this.s.stats.get(k);
    this.s.stats.set(k, { ...row, count: (cur?.count ?? 0) + n });
  }
  async listStats(
    orgId: string,
    subjectType: StatRow['subjectType'],
    subjectId: string,
    sinceDay: string,
  ) {
    return [...this.s.stats.values()]
      .filter(
        (s) =>
          s.orgId === orgId &&
          s.subjectType === subjectType &&
          s.subjectId === subjectId &&
          s.day >= sinceDay,
      )
      .sort((a, b) => a.day.localeCompare(b.day) || a.kind.localeCompare(b.kind))
      .map((s) => ({ ...s }));
  }

  async findAttempt(key: string) {
    const a = this.s.attempts.get(key);
    return a ? { count: a.count, lockedUntil: a.lockedUntil } : undefined;
  }
  async recordAttemptFailure(key: string, now: Date, max: number, lockMs: number) {
    const count = (this.s.attempts.get(key)?.count ?? 0) + 1;
    const lockedUntil = count >= max ? new Date(now.getTime() + lockMs) : null;
    this.s.attempts.set(key, { count, lockedUntil, updatedAt: now });
    return { count, lockedUntil };
  }
  async clearAttempt(key: string) {
    this.s.attempts.delete(key);
  }

  _purge(kind: Kind, before: Date, limit: number) {
    let n = 0;
    for (const [id, r] of this._tbl(kind)) {
      if (n >= limit) break;
      if ((r['createdAt'] as Date) < before) {
        this._tbl(kind).delete(id);
        n++;
      }
    }
    return n;
  }
  async purgeEvents(before: Date, limit: number) {
    return this._purge('event', before, limit);
  }
  async purgeNotifications(before: Date, limit: number) {
    return this._purge('notification', before, limit);
  }
  async purgeStats(beforeDay: string, limit: number) {
    let n = 0;
    for (const [k, s] of this.s.stats) {
      if (n >= limit) break;
      if (s.day < beforeDay) {
        this.s.stats.delete(k);
        n++;
      }
    }
    return n;
  }
  async purgeAttempts(before: Date, limit: number) {
    let n = 0;
    for (const [k, a] of this.s.attempts) {
      if (n >= limit) break;
      if (a.updatedAt < before) {
        this.s.attempts.delete(k);
        n++;
      }
    }
    return n;
  }
}

/** In-memory adapter: serialized transactions with snapshot rollback; audit flushed only on commit. */
export class InMemorySharingStore extends MemoryRepo implements SharingStore {
  #lock: Promise<unknown> = Promise.resolve();
  readonly #audit: AuditLog | undefined;
  readonly committedAudit: AuditEventInput[] = [];

  constructor(opts?: { audit?: AuditLog }) {
    super();
    this.#audit = opts?.audit;
  }

  transaction<T>(fn: (tx: SharingTx) => Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      const snapshot = structuredClone(this.s);
      const buffer = new AuditBuffer();
      const tx = Object.assign(Object.create(this) as MemoryRepo, {
        audit: buffer,
      }) as unknown as SharingTx;
      try {
        const out = await fn(tx);
        const events = buffer.drain();
        if (this.#audit) await this.#audit.appendMany(events);
        else this.committedAudit.push(...events);
        return out;
      } catch (e) {
        Object.assign(this.s, snapshot);
        throw e;
      }
    };
    const p = this.#lock.then(run, run);
    this.#lock = p.catch(() => undefined);
    return p;
  }
}
