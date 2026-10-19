import { randomBytes } from 'node:crypto';
import { newId } from '@trust/crypto';
import { DomainError, type Clock, type UserPrincipal } from '@trust/shared-types';
import type {
  AbuseRow,
  BlobRow,
  DestinationType,
  DocumentRow,
  EventKind,
  EventRow,
  JobRow,
  LinkRow,
  Requirement,
  ShortLinkRow,
  SharingRepo,
  SharingStore,
  SharingTx,
  SubmissionRow,
  TransferRow,
  UploadRequestRow,
  UploadTarget,
  VersionRow,
} from './model.ts';
import {
  DOCUMENT_EXTS,
  FILE_KINDS,
  PERMISSIONS,
  contentDisposition,
  stripControl,
  dayKey,
  effectiveLinkState,
  looksAutomated,
  monthKey,
  normalizeEmail,
  permits,
  planParts,
  referrerHost,
  requireFileKind,
  resolveLimits,
  sanitizeFileName,
  sanitizeFolderPath,
  validateAccentColor,
  validateAlias,
  validateExternalDestination,
  validateHostname,
  type DestinationPolicy,
  type EffectiveLinkState,
  type SharePermission,
  type SharingLimits,
} from './policy.ts';
import { qrSvg } from './qr.ts';
import { objectKey, type FileScanner, type ObjectStore } from './storage.ts';
import {
  newPublicCode,
  newSalt,
  newSubmissionSecret,
  tokenHash,
  type GrantClaims,
  type SharingKeys,
} from './tokens.ts';

export type SharePerm = 'share:read' | 'share:create' | 'share:manage';

export interface SharingConfig {
  /** Origin of the portal and public share pages (`/s/`, `/r/`, `/d/`). */
  publicOrigin: string;
  /** Default origin for public short links (`/l/`). May equal `publicOrigin`. */
  shortOrigin: string;
  grantTtlSeconds: number;
  downloadUrlTtlSeconds: number;
  uploadUrlTtlSeconds: number;
  uploadSessionHours: number;
  passwordMaxFailures: number;
  passwordLockMinutes: number;
  eventRetentionDays: number;
  statRetentionDays: number;
  notificationRetentionDays: number;
  scanMaxAttempts: number;
  jobLeaseSeconds: number;
  partBytes: number;
}

export const DEFAULT_SHARING_CONFIG: Omit<SharingConfig, 'publicOrigin' | 'shortOrigin'> = {
  grantTtlSeconds: 900,
  downloadUrlTtlSeconds: 60,
  uploadUrlTtlSeconds: 900,
  uploadSessionHours: 24,
  passwordMaxFailures: 10,
  passwordLockMinutes: 15,
  eventRetentionDays: 180,
  statRetentionDays: 400,
  notificationRetentionDays: 90,
  scanMaxAttempts: 6,
  jobLeaseSeconds: 300,
  partBytes: 8 * 1024 * 1024,
};

export interface SharingDeps {
  store: SharingStore;
  objects: ObjectStore;
  scanner: FileScanner;
  keys: SharingKeys;
  clock: Clock;
  config: SharingConfig;
  destinations: DestinationPolicy;
  /** Org-scoped authorization: non-members get 404, members lacking the permission get 403. */
  authorize(p: UserPrincipal, orgId: string, permission: SharePerm): Promise<void>;
  identity(userId: string): Promise<{ email: string; emailVerified: boolean } | undefined>;
  isMember(orgId: string, userId: string): Promise<boolean>;
  /** Server-resolved entitlements of the organization's currently valid licenses. */
  entitlements(orgId: string): Promise<Array<Record<string, unknown>>>;
  passwords: {
    hash(pw: string): Promise<string>;
    verify(pw: string, hash: string): Promise<boolean>;
  };
  /** Optional email delivery for opt-in notifications (sent by the job worker, never inline). */
  mailer?: { send(m: { id: string; to: string; subject: string; text: string }): Promise<unknown> };
  /** DNS TXT lookup for custom-domain verification. DNS only: the platform never fetches tenant URLs. */
  resolveTxt?: (name: string) => Promise<string[][]>;
}

/** Request facts for public endpoints. Only coarse, non-identifying attributes are ever stored. */
export interface PublicContext {
  principal?: UserPrincipal | undefined;
  userAgent?: string | undefined;
  referer?: string | undefined;
}

const notFound = () => new DomainError('not_found', 'not found');
const invalid = (m: string) => new DomainError('invalid_request', m);
const quota = (what: string) =>
  new DomainError('quota_exceeded', `${what} limit reached for this plan`);
const unavailable = (state: string) =>
  new DomainError('link_unavailable', 'this link is no longer available', { state });

const NOTICES = [
  'View-only access cannot prevent screenshots, photos of the screen or other copying.',
  'Revoking a link stops future access through it; it cannot remove copies already downloaded.',
];

const text = (raw: string | undefined | null, max: number, field: string): string | null => {
  if (raw === undefined || raw === null) return null;
  const v = stripControl(raw.normalize('NFC')).trim();
  if (v.length > max) throw invalid(`${field} is too long`);
  return v.length ? v : null;
};
const title = (raw: string, field = 'title') => {
  const v = text(raw, 200, field);
  if (!v) throw invalid(`${field} is required`);
  return v;
};

/**
 * File sharing, document publication, short links and upload requests (ADR-021).
 *
 * Invariants (each has a negative-path test in services/platform-api/test/sharing*.test.ts):
 *  - Every workspace method authorizes org membership first; another tenant's ids are indistinguishable from
 *    unknown ids (404).
 *  - Drafts are never reachable through a link; `latest` links serve only the explicitly published version.
 *  - Public access re-evaluates the link on EVERY request (revocation, expiry, recipients), not only at grant.
 *  - Bytes are served only after quarantine checks pass, from the isolated content origin.
 *  - Quotas are checked under the organization's account lock before uploads are accepted and before exports.
 *  - State changes and their audit events commit together; transaction callbacks have no external effects.
 */
export class SharingService {
  readonly #d: SharingDeps;
  readonly #c: SharingConfig;

  constructor(deps: SharingDeps) {
    this.#d = deps;
    this.#c = deps.config;
  }

  get config(): SharingConfig {
    return this.#c;
  }

  #now(): Date {
    return this.#d.clock.now();
  }
  #at(ms: number): Date {
    return new Date(this.#now().getTime() + ms);
  }

  async limits(orgId: string): Promise<SharingLimits> {
    return resolveLimits(await this.#d.entitlements(orgId));
  }

  /** Authorize, then run `fn` in a transaction holding the account lock, after metering one API mutation. */
  async #mutate<T>(
    p: UserPrincipal,
    orgId: string,
    perm: SharePerm,
    fn: (tx: SharingTx, ctx: { now: Date; limits: SharingLimits }) => Promise<T>,
  ): Promise<T> {
    await this.#d.authorize(p, orgId, perm);
    const limits = await this.limits(orgId);
    return this.#d.store.transaction(async (tx) => {
      const now = this.#now();
      await tx.lockAccount(orgId, now);
      const n = await tx.addUsage(orgId, monthKey(now), 'api_requests', 1);
      if (n > limits.apiRequestsPerMonth) throw quota('API request');
      return fn(tx, { now, limits });
    });
  }

  /** Creators manage their own items; anything else needs `share:manage` (admins/owners). */
  async #requireManager(p: UserPrincipal, orgId: string, createdBy: string | null): Promise<void> {
    if (createdBy !== p.userId) await this.#d.authorize(p, orgId, 'share:manage');
  }

  #audit(
    tx: SharingTx,
    actor: { type: 'user' | 'system' | 'anonymous' | 'operator'; id?: string },
    orgId: string,
    action: string,
    target: { type: string; id: string },
    metadata?: Record<string, unknown>,
    reason?: string | null,
  ) {
    return tx.audit.append({
      actor,
      action,
      target,
      orgId,
      ...(reason ? { reason } : {}),
      ...(metadata ? { metadata } : {}),
    });
  }

  // =============================================================================================
  // Overview and usage
  // =============================================================================================

  async overview(p: UserPrincipal, orgId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const limits = await this.limits(orgId);
    const period = monthKey(this.#now());
    const [storageBytes, usage] = await Promise.all([
      this.#d.store.storageBytes(orgId),
      this.#d.store.usage(orgId, period),
    ]);
    return {
      period,
      limits,
      usage: {
        storageBytes,
        bandwidthBytes: usage.bandwidth_bytes,
        apiRequests: usage.api_requests,
        processingBytes: usage.processing_bytes,
        uploadBytes: usage.upload_bytes,
      },
    };
  }

  // =============================================================================================
  // Documents: private drafts → immutable exported versions → explicit publication
  // =============================================================================================

  async createDocument(
    p: UserPrincipal,
    orgId: string,
    input: { title: string; requireApproval?: boolean },
  ) {
    const t = title(input.title);
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const doc: DocumentRow = {
        id: newId('doc'),
        orgId,
        title: t,
        createdBy: p.userId,
        draftBlobId: null,
        draftUpdatedAt: null,
        publishedVersionId: null,
        publishedAt: null,
        requireApproval: input.requireApproval ?? false,
        status: 'active',
        createdAt: now,
        updatedAt: now,
      };
      await tx.insert('document', doc);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.document.created',
        {
          type: 'share_document',
          id: doc.id,
        },
        { require_approval: doc.requireApproval },
      );
      return documentView(doc);
    });
  }

  async listDocuments(p: UserPrincipal, orgId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    return (await this.#d.store.list('document', orgId, { status: 'active' })).map(documentView);
  }

  async getDocument(p: UserPrincipal, orgId: string, documentId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const s = this.#d.store;
    const doc = await s.get('document', orgId, documentId);
    if (!doc || doc.status !== 'active') throw notFound();
    const versions = await s.list('version', orgId, { documentId }, { limit: 1000 });
    const reviews = await s.list('review', orgId, { documentId }, { limit: 5000 });
    const draft = doc.draftBlobId ? await s.get('blob', orgId, doc.draftBlobId) : undefined;
    const pendingDraft = (
      await s.list('blob', orgId, { targetType: 'draft', targetId: documentId }, { limit: 5 })
    )
      .filter(
        (b) => b.status === 'uploading' || b.status === 'quarantined' || b.status === 'rejected',
      )
      .map((b) => ({
        uploadId: b.id,
        status: fileStatus(b.status),
        rejectReason: b.rejectReason,
        createdAt: b.createdAt,
      }));
    return {
      ...documentView(doc),
      draft: draft
        ? { size: draft.size, updatedAt: doc.draftUpdatedAt, sha256: draft.sha256 }
        : null,
      draftUploads: pendingDraft,
      versions: versions
        .sort((a, b) => b.number - a.number)
        .map((v) => ({
          ...versionView(v),
          published: v.id === doc.publishedVersionId,
          approvals: reviews.filter((r) => r.versionId === v.id && r.decision === 'approved')
            .length,
          changesRequested: reviews.filter(
            (r) => r.versionId === v.id && r.decision === 'changes_requested',
          ).length,
        })),
    };
  }

  /** Workflow 1: create an immutable export from the current private draft. Drafts are never shared. */
  async exportVersion(
    p: UserPrincipal,
    orgId: string,
    documentId: string,
    input: { note?: string | undefined; fileName?: string | undefined },
  ) {
    const note = text(input.note, 1000, 'note');
    return this.#mutate(p, orgId, 'share:create', async (tx, { now, limits }) => {
      const doc = await tx.getForUpdate('document', orgId, documentId);
      if (!doc || doc.status !== 'active') throw notFound();
      await this.#requireManager(p, orgId, doc.createdBy);
      if (!doc.draftBlobId) throw new DomainError('conflict', 'save a draft before exporting');
      const blob = await tx.getForUpdate('blob', orgId, doc.draftBlobId);
      if (!blob || blob.status !== 'clean')
        throw new DomainError('conflict', 'the draft is not ready');
      // Exports reference the immutable draft object (no copy), but an organization already over its storage
      // allowance (for example after a downgrade) cannot create more exports until it frees space.
      if ((await tx.storageBytes(orgId)) > limits.storageBytes) throw quota('storage');
      const versions = await tx.list('version', orgId, { documentId }, { limit: 1 });
      if (versions[0]?.blobId === blob.id)
        throw new DomainError('conflict', `no changes since version ${versions[0].number}`);
      const number = await tx.nextVersionNumber(orgId, documentId);
      const fileName = sanitizeFileName(
        input.fileName ?? `${doc.title.replace(/[\\/]/g, '-').slice(0, 150)} v${number}.pdf`,
      );
      requireFileKind(fileName, DOCUMENT_EXTS);
      const v: VersionRow = {
        id: newId('ver'),
        orgId,
        documentId,
        number,
        blobId: blob.id,
        fileName,
        note,
        createdBy: p.userId,
        createdAt: now,
        publishedAt: null,
        replacementNote: null,
      };
      await tx.insert('version', v);
      await tx.update('document', orgId, documentId, { updatedAt: now });
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.document.exported',
        {
          type: 'share_document',
          id: documentId,
        },
        { version_id: v.id, number, sha256: blob.sha256 },
      );
      return versionView(v);
    });
  }

  /**
   * Workflows 2/5: make a version the one `latest` links serve. Explicit only; nothing else changes it. With
   * `requireApproval`, the version needs an approval from someone other than its author and no open
   * change request.
   */
  async publishVersion(
    p: UserPrincipal,
    orgId: string,
    documentId: string,
    input: { versionId: string; replacementNote?: string | undefined },
  ) {
    const note = text(input.replacementNote, 1000, 'replacement note');
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const doc = await tx.getForUpdate('document', orgId, documentId);
      if (!doc || doc.status !== 'active') throw notFound();
      await this.#requireManager(p, orgId, doc.createdBy);
      const v = await tx.getForUpdate('version', orgId, input.versionId);
      if (!v || v.documentId !== documentId) throw notFound();
      if (doc.requireApproval && !(await this.#approved(tx, orgId, v)))
        throw new DomainError(
          'conflict',
          'this version needs an approval before it can be published',
        );
      if (doc.publishedVersionId === v.id) return versionView(v);
      await tx.update('version', orgId, v.id, {
        publishedAt: v.publishedAt ?? now,
        replacementNote: doc.publishedVersionId ? note : null,
      });
      await tx.update('document', orgId, documentId, {
        publishedVersionId: v.id,
        publishedAt: now,
        updatedAt: now,
      });
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.document.published',
        {
          type: 'share_document',
          id: documentId,
        },
        { version_id: v.id, number: v.number, previous_version_id: doc.publishedVersionId },
      );
      return versionView({
        ...v,
        publishedAt: v.publishedAt ?? now,
        replacementNote: doc.publishedVersionId ? note : null,
      });
    });
  }

  async #approved(r: SharingRepo, orgId: string, v: VersionRow): Promise<boolean> {
    const reviews = await r.list('review', orgId, { versionId: v.id }, { limit: 1000 });
    return (
      reviews.some((x) => x.decision === 'approved' && x.reviewerUserId !== v.createdBy) &&
      !reviews.some((x) => x.decision === 'changes_requested')
    );
  }

  async reviewThread(p: UserPrincipal, orgId: string, documentId: string, versionId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const v = await this.#d.store.get('version', orgId, versionId);
    if (!v || v.documentId !== documentId) throw notFound();
    return this.#thread(orgId, v);
  }

  async #thread(orgId: string, v: VersionRow) {
    const s = this.#d.store;
    const [comments, reviews] = await Promise.all([
      s.list('comment', orgId, { versionId: v.id }, { limit: 1000, order: 'oldest' }),
      s.list('review', orgId, { versionId: v.id }, { limit: 1000, order: 'oldest' }),
    ]);
    const emails = new Map<string, string>();
    for (const id of new Set([
      ...comments.map((c) => c.authorUserId),
      ...reviews.map((r) => r.reviewerUserId),
    ]))
      emails.set(id, (await this.#d.identity(id))?.email ?? 'unknown');
    return {
      versionId: v.id,
      number: v.number,
      comments: comments.map((c) => ({
        id: c.id,
        author: emails.get(c.authorUserId),
        page: c.page,
        body: c.body,
        createdAt: c.createdAt,
      })),
      reviews: reviews.map((r) => ({
        reviewer: emails.get(r.reviewerUserId),
        decision: r.decision,
        note: r.note,
        updatedAt: r.updatedAt,
      })),
    };
  }

  async deleteDocument(p: UserPrincipal, orgId: string, documentId: string) {
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const doc = await tx.getForUpdate('document', orgId, documentId);
      if (!doc || doc.status !== 'active') throw notFound();
      await this.#requireManager(p, orgId, doc.createdBy);
      await tx.update('document', orgId, documentId, { status: 'deleted', updatedAt: now });
      const blobs = new Set(
        (await tx.list('version', orgId, { documentId }, { limit: 10_000 })).map((v) => v.blobId),
      );
      if (doc.draftBlobId) blobs.add(doc.draftBlobId);
      for (const b of blobs) await this.#enqueue(tx, orgId, 'delete_blob', b, now);
      await this.#audit(tx, { type: 'user', id: p.userId }, orgId, 'share.document.deleted', {
        type: 'share_document',
        id: documentId,
      });
      return { deleted: true };
    });
  }

  // =============================================================================================
  // Transfers
  // =============================================================================================

  #transferExpiry(
    kind: 'temporary' | 'persistent',
    expiresAt: Date | null | undefined,
    limits: SharingLimits,
    now: Date,
  ): Date | null {
    if (kind === 'persistent') {
      if (!limits.persistent)
        throw new DomainError('forbidden', 'persistent sharing is not included in this plan');
      if (expiresAt && expiresAt <= now) throw invalid('expiry must be in the future');
      return expiresAt ?? null;
    }
    const max = now.getTime() + limits.maxRetentionDays * 86_400_000;
    const exp = expiresAt ?? new Date(Math.min(max, now.getTime() + 7 * 86_400_000));
    if (exp <= now) throw invalid('expiry must be in the future');
    if (exp.getTime() > max)
      throw new DomainError(
        'quota_exceeded',
        `temporary transfers may last at most ${limits.maxRetentionDays} days on this plan`,
      );
    return exp;
  }

  async createTransfer(
    p: UserPrincipal,
    orgId: string,
    input: {
      title: string;
      message?: string | undefined;
      kind: 'temporary' | 'persistent';
      expiresAt?: Date | null | undefined;
    },
  ) {
    const t = title(input.title);
    const message = text(input.message, 2000, 'message');
    return this.#mutate(p, orgId, 'share:create', async (tx, { now, limits }) => {
      const tr: TransferRow = {
        id: newId('trf'),
        orgId,
        createdBy: p.userId,
        title: t,
        message,
        kind: input.kind,
        status: 'active',
        expiresAt: this.#transferExpiry(input.kind, input.expiresAt, limits, now),
        createdAt: now,
        updatedAt: now,
      };
      await tx.insert('transfer', tr);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.transfer.created',
        {
          type: 'share_transfer',
          id: tr.id,
        },
        { kind: tr.kind, expires_at: tr.expiresAt?.toISOString() ?? null },
      );
      return transferView(tr);
    });
  }

  async listTransfers(p: UserPrincipal, orgId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const rows = await this.#d.store.list('transfer', orgId, {}, { limit: 500 });
    return rows
      .filter((t) => t.status !== 'purged' && t.status !== 'deleted')
      .map((t) => transferView(t, this.#now()));
  }

  async getTransfer(p: UserPrincipal, orgId: string, transferId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const tr = await this.#d.store.get('transfer', orgId, transferId);
    if (!tr || tr.status === 'deleted' || tr.status === 'purged') throw notFound();
    const files = await this.#transferFiles(orgId, tr.id);
    const pending = (
      await this.#d.store.list('blob', orgId, { targetType: 'transfer_replace' }, { limit: 500 })
    )
      .filter(
        (b) =>
          files.some((f) => f.id === b.targetId) && ['uploading', 'quarantined'].includes(b.status),
      )
      .map((b) => ({ uploadId: b.id, fileId: b.targetId, status: fileStatus(b.status) }));
    return { ...transferView(tr, this.#now()), files, pendingReplacements: pending };
  }

  async #transferFiles(orgId: string, transferId: string, r: SharingRepo = this.#d.store) {
    const files = await r.list(
      'transferFile',
      orgId,
      { transferId, status: 'current' },
      { limit: 5000, order: 'oldest' },
    );
    const out = [];
    for (const f of files) {
      const b = await r.get('blob', orgId, f.blobId);
      out.push({
        id: f.id,
        name: f.name,
        folderPath: f.folderPath,
        size: f.size,
        contentType: FILE_KINDS[f.ext]?.contentType ?? 'application/octet-stream',
        inline: !!FILE_KINDS[f.ext]?.inline,
        status: fileStatus(b?.status ?? 'deleted'),
        rejectReason: b?.rejectReason ?? null,
        revision: f.revision,
        replacedAt: f.replacedAt,
        replacementNote: f.replacementNote,
        uploadId: b && b.status === 'uploading' ? b.id : null,
      });
    }
    return out;
  }

  async updateTransfer(
    p: UserPrincipal,
    orgId: string,
    transferId: string,
    input: {
      title?: string | undefined;
      message?: string | null | undefined;
      expiresAt?: Date | null | undefined;
    },
  ) {
    return this.#mutate(p, orgId, 'share:create', async (tx, { now, limits }) => {
      const tr = await tx.getForUpdate('transfer', orgId, transferId);
      if (!tr || tr.status !== 'active') throw notFound();
      await this.#requireManager(p, orgId, tr.createdBy);
      const patch: Partial<TransferRow> = { updatedAt: now };
      if (input.title !== undefined) patch.title = title(input.title);
      if (input.message !== undefined) patch.message = text(input.message, 2000, 'message');
      if (input.expiresAt !== undefined)
        patch.expiresAt = this.#transferExpiry(tr.kind, input.expiresAt, limits, now);
      await tx.update('transfer', orgId, transferId, patch);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.transfer.updated',
        {
          type: 'share_transfer',
          id: transferId,
        },
        { expires_at: (patch.expiresAt ?? tr.expiresAt)?.toISOString() ?? null },
      );
      return transferView({ ...tr, ...patch }, now);
    });
  }

  /** Revocation stops future access through every link to the transfer. Temporary files are still removed at expiry. */
  async revokeTransfer(p: UserPrincipal, orgId: string, transferId: string, reason?: string) {
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const tr = await tx.getForUpdate('transfer', orgId, transferId);
      if (!tr || tr.status === 'deleted' || tr.status === 'purged') throw notFound();
      await this.#requireManager(p, orgId, tr.createdBy);
      if (tr.status === 'active') {
        await tx.update('transfer', orgId, transferId, { status: 'revoked', updatedAt: now });
        await this.#audit(
          tx,
          { type: 'user', id: p.userId },
          orgId,
          'share.transfer.revoked',
          {
            type: 'share_transfer',
            id: transferId,
          },
          undefined,
          text(reason, 500, 'reason'),
        );
      }
      return transferView({ ...tr, status: tr.status === 'active' ? 'revoked' : tr.status }, now);
    });
  }

  /** Deletes the transfer; its files are removed by the next retention pass. */
  async deleteTransfer(p: UserPrincipal, orgId: string, transferId: string) {
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const tr = await tx.getForUpdate('transfer', orgId, transferId);
      if (!tr || tr.status === 'deleted' || tr.status === 'purged') throw notFound();
      await this.#requireManager(p, orgId, tr.createdBy);
      await tx.update('transfer', orgId, transferId, { status: 'deleted', updatedAt: now });
      await this.#audit(tx, { type: 'user', id: p.userId }, orgId, 'share.transfer.deleted', {
        type: 'share_transfer',
        id: transferId,
      });
      return { deleted: true };
    });
  }

  async removeTransferFile(p: UserPrincipal, orgId: string, transferId: string, fileId: string) {
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const tr = await tx.getForUpdate('transfer', orgId, transferId);
      if (!tr || tr.status !== 'active') throw notFound();
      await this.#requireManager(p, orgId, tr.createdBy);
      const f = await tx.getForUpdate('transferFile', orgId, fileId);
      if (!f || f.transferId !== transferId || f.status !== 'current') throw notFound();
      await tx.update('transferFile', orgId, fileId, { status: 'removed', updatedAt: now });
      await this.#enqueue(tx, orgId, 'delete_blob', f.blobId, now);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.transfer.file_removed',
        {
          type: 'share_transfer',
          id: transferId,
        },
        { file_id: fileId },
      );
      return { removed: true };
    });
  }

  // =============================================================================================
  // Resumable uploads (owner side)
  // =============================================================================================

  /**
   * Starts a resumable multipart upload directly to private object storage. Quotas (file size, storage,
   * processing) are applied here, before any byte is accepted; the declared size is reserved until completion.
   */
  async beginUpload(
    p: UserPrincipal,
    orgId: string,
    input: {
      target: 'transfer' | 'replace' | 'draft';
      transferId?: string | undefined;
      fileId?: string | undefined;
      documentId?: string | undefined;
      name: string;
      folderPath?: string | undefined;
      size: number;
      note?: string | undefined;
    },
  ) {
    await this.#d.authorize(p, orgId, 'share:create');
    const name = sanitizeFileName(input.name);
    const kind = requireFileKind(name, input.target === 'draft' ? DOCUMENT_EXTS : undefined);
    const folderPath = sanitizeFolderPath(input.folderPath);
    const note = text(input.note, 1000, 'replacement note');
    const targetType: UploadTarget =
      input.target === 'transfer'
        ? 'transfer_file'
        : input.target === 'replace'
          ? 'transfer_replace'
          : 'draft';
    const targetRef =
      input.target === 'draft'
        ? input.documentId
        : input.target === 'replace'
          ? input.fileId
          : input.transferId;
    if (!targetRef) throw invalid('upload target is required');

    return this.#startMultipart(
      orgId,
      kind.ext,
      kind.contentType,
      input.size,
      async (tx, blob, limits) => {
        const n = await tx.addUsage(orgId, monthKey(blob.createdAt), 'api_requests', 1);
        if (n > limits.apiRequestsPerMonth) throw quota('API request');
        blob.createdBy = p.userId;
        blob.targetType = targetType;
        blob.note = note;
        if (input.target === 'draft') {
          const doc = await tx.getForUpdate('document', orgId, targetRef);
          if (!doc || doc.status !== 'active') throw notFound();
          await this.#requireManager(p, orgId, doc.createdBy);
          blob.targetId = doc.id;
          await tx.insert('blob', blob);
          return { fileId: null };
        }
        const transferId = input.target === 'transfer' ? targetRef : input.transferId;
        const tr = transferId ? await tx.getForUpdate('transfer', orgId, transferId) : undefined;
        if (!tr || tr.status !== 'active') throw notFound();
        await this.#requireManager(p, orgId, tr.createdBy);
        if (input.target === 'replace') {
          const f = await tx.get('transferFile', orgId, targetRef);
          if (!f || f.transferId !== tr.id || f.status !== 'current') throw notFound();
          if (f.ext !== kind.ext)
            throw invalid('a replacement must have the same file type as the original');
          blob.targetId = f.id;
          await tx.insert('blob', blob);
          return { fileId: f.id };
        }
        const fileId = newId('tfl');
        blob.targetId = fileId;
        await tx.insert('blob', blob);
        await tx.insert('transferFile', {
          id: fileId,
          orgId,
          transferId: tr.id,
          blobId: blob.id,
          name,
          folderPath,
          ext: kind.ext,
          size: input.size,
          status: 'current',
          revision: 1,
          replacedAt: null,
          replacementNote: null,
          createdAt: blob.createdAt,
          updatedAt: blob.createdAt,
        });
        return { fileId };
      },
      name,
    );
  }

  async #startMultipart(
    orgId: string,
    ext: string,
    contentType: string,
    size: number,
    attach: (
      tx: SharingTx,
      blob: BlobRow,
      limits: SharingLimits,
    ) => Promise<{ fileId: string | null }>,
    fileName: string,
  ) {
    const limits = await this.limits(orgId);
    if (!Number.isSafeInteger(size) || size < 1) throw invalid('invalid size');
    if (size > limits.maxFileBytes) throw quota('file size');
    const { partSize, partCount } = planParts(
      size,
      this.#c.partBytes,
      this.#d.objects.minPartBytes,
    );
    const blobId = newId('blb');
    const key = objectKey(orgId, blobId);
    const { uploadId } = await this.#d.objects.createMultipart(key, contentType);
    try {
      return await this.#d.store.transaction(async (tx) => {
        const now = this.#now();
        await tx.lockAccount(orgId, now);
        if ((await tx.storageBytes(orgId)) + size > limits.storageBytes) throw quota('storage');
        const usage = await tx.usage(orgId, monthKey(now));
        if (usage.processing_bytes + size > limits.processingBytesPerMonth)
          throw quota('processing');
        const blob: BlobRow = {
          id: blobId,
          orgId,
          objectKey: key,
          ext,
          contentType,
          declaredSize: size,
          size: null,
          sha256: null,
          status: 'uploading',
          rejectReason: null,
          multipartId: uploadId,
          partSize,
          partCount,
          uploadExpiresAt: new Date(now.getTime() + this.#c.uploadSessionHours * 3_600_000),
          targetType: 'transfer_file',
          targetId: '',
          note: null,
          createdBy: null,
          createdAt: now,
          completedAt: null,
          scannedAt: null,
          deletedAt: null,
        };
        const { fileId } = await attach(tx, blob, limits);
        await tx.addUsage(orgId, monthKey(now), 'upload_bytes', size);
        return uploadView(blob, fileId, fileName);
      });
    } catch (e) {
      await this.#d.objects.abortMultipart(key, uploadId).catch(() => undefined);
      throw e;
    }
  }

  async #ownerUpload(p: UserPrincipal, orgId: string, uploadId: string): Promise<BlobRow> {
    await this.#d.authorize(p, orgId, 'share:create');
    const b = await this.#d.store.get('blob', orgId, uploadId);
    if (!b || b.targetType === 'submission_file') throw notFound();
    await this.#requireManager(p, orgId, b.createdBy);
    return b;
  }

  async signUploadParts(p: UserPrincipal, orgId: string, uploadId: string, partNumbers: number[]) {
    return this.#signParts(await this.#ownerUpload(p, orgId, uploadId), partNumbers);
  }
  async uploadStatus(p: UserPrincipal, orgId: string, uploadId: string) {
    return this.#uploadStatus(await this.#ownerUpload(p, orgId, uploadId));
  }
  async completeUpload(p: UserPrincipal, orgId: string, uploadId: string) {
    return this.#complete(await this.#ownerUpload(p, orgId, uploadId));
  }
  async abortUpload(p: UserPrincipal, orgId: string, uploadId: string) {
    return this.#abort(await this.#ownerUpload(p, orgId, uploadId));
  }

  #partBytes(b: BlobRow, n: number): number {
    return n < b.partCount ? b.partSize : b.declaredSize - b.partSize * (b.partCount - 1);
  }

  async #signParts(b: BlobRow, partNumbers: number[]) {
    const now = this.#now();
    if (
      b.status !== 'uploading' ||
      !b.multipartId ||
      !b.uploadExpiresAt ||
      b.uploadExpiresAt <= now
    )
      throw new DomainError('conflict', 'this upload is no longer accepting data');
    const nums = [...new Set(partNumbers)];
    if (
      !nums.length ||
      nums.length > 100 ||
      nums.some((n) => !Number.isInteger(n) || n < 1 || n > b.partCount)
    )
      throw invalid('invalid part numbers');
    const exp = new Date(
      Math.min(b.uploadExpiresAt.getTime(), now.getTime() + this.#c.uploadUrlTtlSeconds * 1000),
    );
    const parts = [];
    for (const n of nums.sort((x, y) => x - y))
      parts.push({
        partNumber: n,
        size: this.#partBytes(b, n),
        url: await this.#d.objects.signPart(
          b.objectKey,
          b.multipartId,
          n,
          this.#partBytes(b, n),
          exp,
        ),
      });
    return { uploadId: b.id, expiresAt: exp, parts };
  }

  /** Resume point after an interruption: which parts storage already holds. */
  async #uploadStatus(b: BlobRow) {
    if (b.status !== 'uploading' || !b.multipartId)
      return {
        uploadId: b.id,
        status: fileStatus(b.status),
        partSize: b.partSize,
        partCount: b.partCount,
        uploadedParts: [],
        bytesUploaded: b.size ?? 0,
        rejectReason: b.rejectReason,
      };
    const held = (await this.#d.objects.listParts(b.objectKey, b.multipartId)).filter(
      (x) => x.partNumber <= b.partCount && x.size === this.#partBytes(b, x.partNumber),
    );
    return {
      uploadId: b.id,
      status: 'uploading' as const,
      partSize: b.partSize,
      partCount: b.partCount,
      uploadedParts: held.map((x) => x.partNumber).sort((x, y) => x - y),
      bytesUploaded: held.reduce((n, x) => n + x.size, 0),
      expiresAt: b.uploadExpiresAt,
      rejectReason: null,
    };
  }

  async #complete(b: BlobRow) {
    if (b.status !== 'uploading') return this.#uploadStatus(b);
    if (!b.multipartId || !b.uploadExpiresAt || b.uploadExpiresAt <= this.#now())
      throw new DomainError('conflict', 'this upload is no longer accepting data');
    const held = await this.#d.objects.listParts(b.objectKey, b.multipartId);
    const byNum = new Map(held.map((x) => [x.partNumber, x]));
    const missing: number[] = [];
    for (let n = 1; n <= b.partCount; n++) {
      const part = byNum.get(n);
      if (!part || part.size !== this.#partBytes(b, n)) missing.push(n);
    }
    if (missing.length)
      throw new DomainError('conflict', 'upload is incomplete', {
        missing_parts: missing.slice(0, 100),
      });
    let size: number;
    try {
      size = (
        await this.#d.objects.completeMultipart(
          b.objectKey,
          b.multipartId,
          [...byNum.values()]
            .filter((x) => x.partNumber <= b.partCount)
            .sort((x, y) => x.partNumber - y.partNumber),
        )
      ).size;
    } catch (e) {
      // A concurrent completion may have won; report its outcome.
      const now = await this.#d.store.get('blob', b.orgId, b.id);
      if (now && now.status !== 'uploading') return this.#uploadStatus(now);
      throw e;
    }
    return this.#d.store.transaction(async (tx) => {
      const now = this.#now();
      const cur = await tx.getForUpdate('blob', b.orgId, b.id);
      if (!cur) throw notFound();
      if (cur.status !== 'uploading') return this.#uploadStatus(cur);
      const ok = size === cur.declaredSize;
      await tx.update('blob', b.orgId, b.id, {
        status: ok ? 'quarantined' : 'rejected',
        rejectReason: ok ? null : 'size_mismatch',
        size,
        completedAt: now,
        uploadExpiresAt: null,
      });
      await this.#enqueue(tx, b.orgId, ok ? 'scan' : 'delete_blob', b.id, now);
      return {
        uploadId: b.id,
        status: ok ? ('processing' as const) : ('rejected' as const),
        partSize: cur.partSize,
        partCount: cur.partCount,
        uploadedParts: [],
        bytesUploaded: size,
        rejectReason: ok ? null : 'size_mismatch',
      };
    });
  }

  async #abort(b: BlobRow) {
    return this.#d.store.transaction(async (tx) => {
      const now = this.#now();
      const cur = await tx.getForUpdate('blob', b.orgId, b.id);
      if (!cur) throw notFound();
      if (cur.status !== 'uploading')
        throw new DomainError('conflict', 'only an unfinished upload can be cancelled');
      await this.#detachUpload(tx, cur, now);
      return { aborted: true };
    });
  }

  /** Marks an unfinished upload for deletion and removes the file entry it created. */
  async #detachUpload(tx: SharingTx, b: BlobRow, now: Date) {
    await tx.update('blob', b.orgId, b.id, { status: 'deleting' });
    if (b.targetType === 'transfer_file')
      await tx.update('transferFile', b.orgId, b.targetId, { status: 'removed', updatedAt: now });
    if (b.targetType === 'submission_file')
      await tx.update('submissionFile', b.orgId, b.targetId, { status: 'removed' });
    await this.#enqueue(tx, b.orgId, 'delete_blob', b.id, now);
  }

  /** Owner download of any clean object in the organization's workspace (draft, version, transfer or submission). */
  async ownerFileUrl(
    p: UserPrincipal,
    orgId: string,
    ref: {
      type: 'draft' | 'version' | 'transfer_file' | 'submission_file';
      id: string;
      documentId?: string;
    },
  ) {
    await this.#d.authorize(p, orgId, 'share:read');
    const s = this.#d.store;
    let blobId: string | undefined;
    let name = 'download';
    if (ref.type === 'draft') {
      const d = await s.get('document', orgId, ref.id);
      if (d?.status === 'active' && d.draftBlobId)
        [blobId, name] = [d.draftBlobId, `${d.title} (draft).pdf`];
    } else if (ref.type === 'version') {
      const v = await s.get('version', orgId, ref.id);
      const d = v && (await s.get('document', orgId, v.documentId));
      if (v && d?.status === 'active') [blobId, name] = [v.blobId, v.fileName];
    } else if (ref.type === 'transfer_file') {
      const f = await s.get('transferFile', orgId, ref.id);
      if (f?.status === 'current') [blobId, name] = [f.blobId, f.name];
    } else {
      const f = await s.get('submissionFile', orgId, ref.id);
      if (f?.status === 'current') [blobId, name] = [f.blobId, f.name];
    }
    const b = blobId ? await s.get('blob', orgId, blobId) : undefined;
    if (!b) throw notFound();
    if (b.status !== 'clean')
      throw new DomainError('conflict', 'the file is not available', {
        status: fileStatus(b.status),
      });
    const limits = await this.limits(orgId);
    await s.transaction(async (tx) => {
      const now = this.#now();
      await tx.lockAccount(orgId, now);
      if (
        (await tx.addUsage(orgId, monthKey(now), 'bandwidth_bytes', b.size ?? 0)) >
        limits.bandwidthBytesPerMonth
      )
        throw quota('bandwidth');
    });
    return this.#signedDownload(b, name, 'attachment');
  }

  async #signedDownload(b: BlobRow, filename: string, disposition: 'inline' | 'attachment') {
    const expiresAt = this.#at(this.#c.downloadUrlTtlSeconds * 1000);
    const url = await this.#d.objects.signDownload(b.objectKey, {
      filename,
      contentType: FILE_KINDS[b.ext]?.contentType ?? 'application/octet-stream',
      disposition,
      expiresAt,
    });
    return { url, expiresAt, disposition: contentDisposition(disposition, filename) };
  }

  // =============================================================================================
  // Share links (access policies)
  // =============================================================================================

  #shareUrl(l: Pick<LinkRow, 'id' | 'salt'>) {
    return `${this.#c.publicOrigin}/s/${this.#d.keys.token('share', l.id, l.salt)}`;
  }

  async createLink(
    p: UserPrincipal,
    orgId: string,
    input: {
      targetType: 'transfer' | 'document';
      targetId: string;
      versionMode?: 'latest' | 'fixed' | undefined;
      versionId?: string | undefined;
      permission: SharePermission;
      password?: string | undefined;
      expiresAt?: Date | undefined;
      maxDownloads?: number | undefined;
      restriction?: 'none' | 'members' | 'recipients' | undefined;
      recipients?: string[] | undefined;
      notifyOnAccess?: boolean | undefined;
      label?: string | undefined;
    },
  ) {
    if (!PERMISSIONS.includes(input.permission)) throw invalid('invalid permission');
    const restriction = input.restriction ?? 'none';
    const recipients = [...new Set((input.recipients ?? []).map(normalizeEmail))];
    if (recipients.length > 50) throw invalid('at most 50 recipients');
    if (restriction === 'recipients' && !recipients.length)
      throw invalid('name at least one recipient');
    if (restriction !== 'recipients' && recipients.length)
      throw invalid('recipients require restriction "recipients"');
    if (input.permission === 'review' && restriction === 'none')
      throw invalid('review links must be restricted to authenticated recipients');
    const passwordHash = await this.#passwordHash(input.password);
    const label = text(input.label, 200, 'label');
    if (
      input.maxDownloads !== undefined &&
      (!Number.isInteger(input.maxDownloads) ||
        input.maxDownloads < 1 ||
        input.maxDownloads > 100_000)
    )
      throw invalid('invalid download limit');
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      if (input.expiresAt && input.expiresAt <= now) throw invalid('expiry must be in the future');
      const target = await this.#checkTarget(tx, p, orgId, input);
      const salt = newSalt();
      const id = newId('lnk');
      const token = this.#d.keys.token('share', id, salt);
      const link: LinkRow = {
        id,
        orgId,
        salt,
        tokenHash: tokenHash(token),
        createdBy: p.userId,
        label,
        targetType: input.targetType,
        targetId: input.targetId,
        versionMode: target.versionMode,
        versionId: target.versionId,
        permission: input.permission,
        passwordHash,
        expiresAt: input.expiresAt ?? null,
        maxDownloads: input.maxDownloads ?? null,
        downloadCount: 0,
        restriction,
        recipients,
        notifyOnAccess: input.notifyOnAccess ?? false,
        status: 'active',
        statusReason: null,
        operatorHold: false,
        createdAt: now,
        updatedAt: now,
      };
      await tx.insert('link', link);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.link.created',
        { type: 'share_link', id },
        {
          target_type: link.targetType,
          target_id: link.targetId,
          version_mode: link.versionMode,
          version_id: link.versionId,
          permission: link.permission,
          restriction,
          recipients: recipients.length,
          password: !!passwordHash,
          expires_at: link.expiresAt?.toISOString() ?? null,
          max_downloads: link.maxDownloads,
        },
      );
      return this.#linkView(link, now, true);
    });
  }

  async #checkTarget(
    r: SharingRepo,
    p: UserPrincipal,
    orgId: string,
    input: {
      targetType: 'transfer' | 'document';
      targetId: string;
      versionMode?: 'latest' | 'fixed' | undefined;
      versionId?: string | undefined;
      permission: SharePermission;
    },
  ): Promise<{ versionMode: 'latest' | 'fixed' | null; versionId: string | null }> {
    if (input.targetType === 'transfer') {
      if (input.versionMode || input.versionId) throw invalid('transfers have no versions');
      if (input.permission === 'review') throw invalid('review links are available for documents');
      const tr = await r.get('transfer', orgId, input.targetId);
      if (!tr || tr.status !== 'active') throw notFound();
      await this.#requireManager(p, orgId, tr.createdBy);
      return { versionMode: null, versionId: null };
    }
    const doc = await r.get('document', orgId, input.targetId);
    if (!doc || doc.status !== 'active') throw notFound();
    await this.#requireManager(p, orgId, doc.createdBy);
    if (input.versionMode === 'latest') {
      if (input.versionId)
        throw invalid('latest links follow the published version; omit version_id');
      return { versionMode: 'latest', versionId: null };
    }
    if (input.versionMode !== 'fixed' || !input.versionId)
      throw invalid('choose "latest" or a fixed version_id');
    const v = await r.get('version', orgId, input.versionId);
    if (!v || v.documentId !== doc.id) throw notFound();
    if (
      doc.requireApproval &&
      input.permission !== 'review' &&
      !v.publishedAt &&
      !(await this.#approved(r, orgId, v))
    )
      throw new DomainError(
        'conflict',
        'only approved or published versions can be shared for viewing or download',
      );
    return { versionMode: 'fixed', versionId: v.id };
  }

  async #passwordHash(pw: string | undefined | null): Promise<string | null> {
    if (pw === undefined || pw === null) return null;
    if (pw.length < 8 || pw.length > 128) throw invalid('passwords must be 8–128 characters');
    return this.#d.passwords.hash(pw);
  }

  async listLinks(p: UserPrincipal, orgId: string, filter?: { targetId?: string | undefined }) {
    await this.#d.authorize(p, orgId, 'share:read');
    const rows = await this.#d.store.list(
      'link',
      orgId,
      filter?.targetId ? { targetId: filter.targetId } : {},
      { limit: 1000 },
    );
    const now = this.#now();
    return Promise.all(rows.map((l) => this.#linkView(l, now, false)));
  }

  async getLink(p: UserPrincipal, orgId: string, linkId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const l = await this.#d.store.get('link', orgId, linkId);
    if (!l) throw notFound();
    return this.#linkView(l, this.#now(), true);
  }

  async #linkView(l: LinkRow, now: Date, withUrl: boolean) {
    const target = await this.#resolveTarget(this.#d.store, l, now);
    return {
      id: l.id,
      label: l.label,
      url: withUrl ? this.#shareUrl(l) : undefined,
      targetType: l.targetType,
      targetId: l.targetId,
      versionMode: l.versionMode,
      versionId: l.versionId,
      servesVersion: target.version ? target.version.number : null,
      permission: l.permission,
      restriction: l.restriction,
      recipients: l.recipients,
      hasPassword: !!l.passwordHash,
      expiresAt: l.expiresAt,
      maxDownloads: l.maxDownloads,
      downloadCount: l.downloadCount,
      notifyOnAccess: l.notifyOnAccess,
      status: l.status,
      operatorHold: l.operatorHold,
      state: effectiveLinkState(l, now, target.usable),
      createdAt: l.createdAt,
      updatedAt: l.updatedAt,
    };
  }

  async updateLink(
    p: UserPrincipal,
    orgId: string,
    linkId: string,
    input: {
      label?: string | null | undefined;
      expiresAt?: Date | null | undefined;
      maxDownloads?: number | null | undefined;
      password?: string | null | undefined;
      restriction?: 'none' | 'members' | 'recipients' | undefined;
      recipients?: string[] | undefined;
      notifyOnAccess?: boolean | undefined;
      permission?: SharePermission | undefined;
      versionId?: string | undefined;
    },
  ) {
    const newHash =
      input.password === undefined ? undefined : await this.#passwordHash(input.password);
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const l = await tx.getForUpdate('link', orgId, linkId);
      if (!l || l.status === 'revoked') throw notFound();
      await this.#requireManager(p, orgId, l.createdBy);
      const next: LinkRow = { ...l, updatedAt: now };
      if (input.label !== undefined) next.label = text(input.label, 200, 'label');
      if (input.expiresAt !== undefined) {
        if (input.expiresAt && input.expiresAt <= now)
          throw invalid('expiry must be in the future');
        next.expiresAt = input.expiresAt;
      }
      if (input.maxDownloads !== undefined) {
        if (
          input.maxDownloads !== null &&
          (!Number.isInteger(input.maxDownloads) ||
            input.maxDownloads < 1 ||
            input.maxDownloads > 100_000)
        )
          throw invalid('invalid download limit');
        if (input.maxDownloads !== null && input.maxDownloads < l.downloadCount)
          throw invalid(
            `the limit cannot be lower than the ${l.downloadCount} downloads already made`,
          );
        next.maxDownloads = input.maxDownloads;
      }
      if (newHash !== undefined) next.passwordHash = newHash;
      if (input.restriction !== undefined) next.restriction = input.restriction;
      if (input.recipients !== undefined)
        next.recipients = [...new Set(input.recipients.map(normalizeEmail))];
      if (input.notifyOnAccess !== undefined) next.notifyOnAccess = input.notifyOnAccess;
      if (input.permission !== undefined) {
        if (!PERMISSIONS.includes(input.permission)) throw invalid('invalid permission');
        next.permission = input.permission;
      }
      if (input.versionId !== undefined) {
        if (l.versionMode !== 'fixed') throw invalid('only fixed-version links can be re-pinned');
        next.versionId = input.versionId;
      }
      if (next.recipients.length > 50) throw invalid('at most 50 recipients');
      if (next.restriction === 'recipients' && !next.recipients.length)
        throw invalid('name at least one recipient');
      if (next.restriction !== 'recipients') next.recipients = [];
      if (next.permission === 'review' && next.restriction === 'none')
        throw invalid('review links must be restricted to authenticated recipients');
      await this.#checkTarget(tx, p, orgId, {
        targetType: next.targetType,
        targetId: next.targetId,
        versionMode: next.versionMode ?? undefined,
        versionId: next.versionId ?? undefined,
        permission: next.permission,
      });
      await tx.update('link', orgId, linkId, next);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.link.updated',
        { type: 'share_link', id: linkId },
        {
          changed: Object.keys(input)
            .filter((k) => (input as Record<string, unknown>)[k] !== undefined)
            .sort(),
          version_id: next.versionId,
          permission: next.permission,
          restriction: next.restriction,
          expires_at: next.expiresAt?.toISOString() ?? null,
        },
      );
      return this.#linkView(next, now, true);
    });
  }

  /** Revocation (terminal), suspension and resumption by the owner. Operator holds cannot be lifted here. */
  async setLinkStatus(
    p: UserPrincipal,
    orgId: string,
    linkId: string,
    action: 'revoke' | 'suspend' | 'resume',
    reason?: string,
  ) {
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const l = await tx.getForUpdate('link', orgId, linkId);
      if (!l) throw notFound();
      await this.#requireManager(p, orgId, l.createdBy);
      const status = nextStatus(l, action);
      await tx.update('link', orgId, linkId, {
        status,
        statusReason: text(reason, 500, 'reason'),
        updatedAt: now,
      });
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        `share.link.${action === 'revoke' ? 'revoked' : action === 'suspend' ? 'suspended' : 'resumed'}`,
        {
          type: 'share_link',
          id: linkId,
        },
        undefined,
        text(reason, 500, 'reason'),
      );
      return this.#linkView({ ...l, status, updatedAt: now }, now, true);
    });
  }

  /** Delivery receipts: distinct visit, authenticated access, view, download and acknowledgement events. */
  async linkActivity(p: UserPrincipal, orgId: string, linkId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const l = await this.#d.store.get('link', orgId, linkId);
    if (!l) throw notFound();
    const since = dayKey(new Date(this.#now().getTime() - 400 * 86_400_000));
    const [events, stats] = await Promise.all([
      this.#d.store.list(
        'event',
        orgId,
        { subjectType: 'share', subjectId: linkId },
        { limit: 500 },
      ),
      this.#d.store.listStats(orgId, 'share', linkId, since),
    ]);
    return {
      linkId,
      totals: totals(stats),
      events: events.map(eventView),
      notes: [
        'A visit or access event shows the link was opened. It is not proof that anyone read the document.',
        'Email security scanners and link previews can open links automatically; obvious bots are counted separately.',
        'Acknowledgements are explicit confirmations. Unauthenticated acknowledgements carry a self-declared name.',
      ],
    };
  }

  // =============================================================================================
  // Public share access
  // =============================================================================================

  async #resolveTarget(r: SharingRepo, l: LinkRow, now: Date): Promise<ResolvedTarget> {
    if (l.targetType === 'transfer') {
      const tr = await r.get('transfer', l.orgId, l.targetId);
      const usable = !!tr && tr.status === 'active' && (!tr.expiresAt || tr.expiresAt > now);
      return { usable, transfer: tr, document: undefined, version: undefined };
    }
    const doc = await r.get('document', l.orgId, l.targetId);
    if (!doc || doc.status !== 'active')
      return { usable: false, transfer: undefined, document: doc, version: undefined };
    const versionId = l.versionMode === 'fixed' ? l.versionId : doc.publishedVersionId;
    const v = versionId ? await r.get('version', l.orgId, versionId) : undefined;
    const ok = !!v && v.documentId === doc.id;
    return { usable: ok, transfer: undefined, document: doc, version: ok ? v : undefined };
  }

  async #linkByToken(token: string): Promise<LinkRow> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw notFound();
    const l = await this.#d.store.findUnique('link', 'tokenHash', tokenHash(token));
    if (!l) throw notFound();
    return l;
  }

  /** Server-side recipient restriction. Same message for every refusal so membership is not revealed. */
  async #recipient(
    l: { orgId: string; restriction: LinkRow['restriction']; recipients: string[] },
    principal: UserPrincipal | undefined,
  ) {
    if (!principal) {
      if (l.restriction === 'none') return null;
      throw new DomainError('unauthenticated', 'sign in to open this link');
    }
    const who = await this.#d.identity(principal.userId);
    const deny = () =>
      new DomainError('forbidden', 'this link is restricted to specific recipients');
    if (l.restriction === 'members' && !(await this.#d.isMember(l.orgId, principal.userId)))
      throw deny();
    if (
      l.restriction === 'recipients' &&
      (!who || !who.emailVerified || !l.recipients.includes(who.email))
    )
      throw deny();
    return { userId: principal.userId, email: who?.email ?? null };
  }

  async #checkPassword(
    key: string,
    hash: string | null,
    supplied: string | undefined,
    onFail: () => Promise<void>,
  ) {
    if (!hash) return;
    const now = this.#now();
    const a = await this.#d.store.findAttempt(key);
    if (a?.lockedUntil && a.lockedUntil > now)
      throw new DomainError('rate_limited', 'too many incorrect passwords; try again later');
    if (!supplied) throw new DomainError('password_required', 'a password is required');
    if (supplied.length > 128 || !(await this.#d.passwords.verify(supplied, hash))) {
      await this.#d.store.recordAttemptFailure(
        key,
        now,
        this.#c.passwordMaxFailures,
        this.#c.passwordLockMinutes * 60_000,
      );
      await onFail();
      throw new DomainError('password_required', 'incorrect password');
    }
    if (a) await this.#d.store.clearAttempt(key);
  }

  async #recordEvent(
    tx: SharingRepo,
    subject: { orgId: string; subjectType: 'share' | 'request'; subjectId: string },
    kind: EventKind,
    ctx: PublicContext,
    extra: Partial<Pick<EventRow, 'userId' | 'email' | 'fileId' | 'declaredName'>> = {},
  ) {
    const now = this.#now();
    const bot = looksAutomated(ctx.userAgent);
    const ref = kind === 'visit' || kind === 'access' ? referrerHost(ctx.referer) : '';
    await tx.insert('event', {
      id: newId('evt'),
      orgId: subject.orgId,
      subjectType: subject.subjectType,
      subjectId: subject.subjectId,
      kind,
      userId: extra.userId ?? null,
      email: extra.email ?? null,
      fileId: extra.fileId ?? null,
      bot,
      referrerHost: ref,
      declaredName: extra.declaredName ?? null,
      createdAt: now,
    });
    await tx.bumpStat({ ...subject, day: dayKey(now), kind, bot, referrerHost: ref }, 1);
  }

  async #notify(
    tx: SharingTx,
    orgId: string,
    userId: string,
    kind: string,
    subject: { type: string; id: string },
    message: string,
    email: boolean,
  ) {
    const now = this.#now();
    await tx.insert('notification', {
      id: newId('ntf'),
      orgId,
      userId,
      kind,
      subjectType: subject.type,
      subjectId: subject.id,
      message,
      createdAt: now,
      readAt: null,
    });
    if (email && this.#d.mailer)
      await this.#enqueue(tx, orgId, 'notify_email', subject.id, now, {
        userId,
        subject: 'Rokela Bai Bureh Warrior sharing notification',
        text: `${message}\n\nOpen your Rokela Bai Bureh Warrior workspace to see details. You receive this because notifications are on for this item.`,
      });
  }

  /** Opens a share link: state, restriction and password checks, then a short-lived grant and the manifest. */
  async openShare(token: string, input: { password?: string | undefined }, ctx: PublicContext) {
    const l = await this.#linkByToken(token);
    const now = this.#now();
    const target = await this.#resolveTarget(this.#d.store, l, now);
    const state = effectiveLinkState(l, now, target.usable);
    if (state !== 'active')
      throw unavailable(
        state === 'unavailable' && l.versionMode === 'latest' && target.document
          ? 'not_published'
          : state,
      );
    const who = await this.#recipient(l, ctx.principal);
    await this.#checkPassword(`share:${l.id}`, l.passwordHash, input.password, () =>
      this.#d.store.transaction((tx) =>
        this.#recordEvent(
          tx,
          { orgId: l.orgId, subjectType: 'share', subjectId: l.id },
          'password_failed',
          ctx,
        ),
      ),
    );
    await this.#d.store.transaction(async (tx) => {
      await this.#recordEvent(
        tx,
        { orgId: l.orgId, subjectType: 'share', subjectId: l.id },
        who ? 'access' : 'visit',
        ctx,
        {
          userId: who?.userId ?? null,
          email: who?.email ?? null,
        },
      );
      if (who && l.notifyOnAccess && !looksAutomated(ctx.userAgent))
        await this.#notify(
          tx,
          l.orgId,
          l.createdBy,
          'share.accessed',
          { type: 'share_link', id: l.id },
          `${who.email ?? 'A signed-in recipient'} opened your shared link${l.label ? ` "${l.label}"` : ''}.`,
          true,
        );
    });
    const exp = Math.floor(now.getTime() / 1000) + this.#c.grantTtlSeconds;
    const grant = this.#d.keys.grant({ k: 'share', s: l.id, u: who?.userId ?? null, exp });
    return {
      ...(await this.#manifest(l, target, now)),
      grant,
      grantExpiresAt: new Date(exp * 1000),
    };
  }

  async #manifest(l: LinkRow, target: ResolvedTarget, _now: Date) {
    const brand = await this.#brand(l.orgId);
    const base = {
      permission: l.permission,
      restriction: l.restriction,
      expiresAt: l.expiresAt,
      downloadsRemaining:
        l.maxDownloads === null ? null : Math.max(0, l.maxDownloads - l.downloadCount),
      branding: brand,
      notices: NOTICES,
    };
    if (target.transfer) {
      const files = (await this.#transferFiles(l.orgId, target.transfer.id)).map((f) => {
        return {
          id: f.id,
          name: f.name,
          folderPath: f.folderPath,
          size: f.size,
          contentType: f.contentType,
          status: f.status,
          viewable: f.status === 'available' && f.inline,
          downloadable: f.status === 'available' && permits(l.permission, 'download'),
          revision: f.revision,
          replacedAt: f.replacedAt,
          replacementNote: f.replacementNote,
        };
      });
      return {
        ...base,
        kind: 'transfer' as const,
        title: target.transfer.title,
        message: target.transfer.message,
        transferExpiresAt: target.transfer.expiresAt,
        files,
      };
    }
    const doc = target.document!;
    const v = target.version!;
    const blob = await this.#d.store.get('blob', l.orgId, v.blobId);
    const history =
      l.versionMode === 'latest'
        ? (await this.#d.store.list('version', l.orgId, { documentId: doc.id }, { limit: 1000 }))
            .filter((x) => x.publishedAt)
            .sort((a, b) => b.number - a.number)
            .map((x) => ({
              number: x.number,
              publishedAt: x.publishedAt,
              replacementNote: x.replacementNote,
            }))
        : [];
    return {
      ...base,
      kind: 'document' as const,
      title: doc.title,
      version: {
        mode: l.versionMode,
        number: v.number,
        publishedAt: v.publishedAt,
        replacementNote: l.versionMode === 'latest' ? v.replacementNote : null,
        label:
          l.versionMode === 'fixed'
            ? `Fixed version ${v.number}. This link always serves this exact version.`
            : `Latest published version (version ${v.number}). This link follows the version the sender publishes.`,
      },
      history,
      files: [
        {
          id: v.id,
          name: v.fileName,
          folderPath: '',
          size: blob?.size ?? 0,
          contentType: 'application/pdf',
          status: fileStatus(blob?.status ?? 'deleted'),
          viewable: blob?.status === 'clean',
          downloadable: blob?.status === 'clean' && permits(l.permission, 'download'),
          revision: v.number,
          replacedAt: null,
          replacementNote: null,
        },
      ],
    };
  }

  /** Every grant use re-checks the link, target and restriction: revocation applies to the very next request. */
  async #useGrant(token: string, grant: string | undefined, ctx: PublicContext) {
    const l = await this.#linkByToken(token);
    const now = this.#now();
    const claims: GrantClaims | undefined = this.#d.keys.verifyGrant(grant, now.getTime());
    if (!claims || claims.k !== 'share' || claims.s !== l.id)
      throw new DomainError('unauthenticated', 'your access has expired; open the link again');
    if (claims.u && ctx.principal?.userId !== claims.u)
      throw new DomainError('unauthenticated', 'sign in again to continue');
    const target = await this.#resolveTarget(this.#d.store, l, now);
    const state = effectiveLinkState(l, now, target.usable);
    if (state !== 'active') throw unavailable(state);
    const who = await this.#recipient(l, claims.u ? ctx.principal : undefined);
    return { l, target, who, now };
  }

  async shareFileUrl(
    token: string,
    input: { grant: string; fileId: string; disposition: 'inline' | 'attachment' },
    ctx: PublicContext,
  ) {
    const { l, target, who } = await this.#useGrant(token, input.grant, ctx);
    let blobId: string;
    let name: string;
    if (target.transfer) {
      const f = await this.#d.store.get('transferFile', l.orgId, input.fileId);
      if (!f || f.transferId !== target.transfer.id || f.status !== 'current') throw notFound();
      [blobId, name] = [f.blobId, f.name];
    } else {
      if (target.version!.id !== input.fileId)
        throw new DomainError('conflict', 'a newer version was published; reload the page');
      [blobId, name] = [target.version!.blobId, target.version!.fileName];
    }
    const blob = await this.#d.store.get('blob', l.orgId, blobId);
    if (!blob || blob.status !== 'clean')
      throw new DomainError('conflict', 'this file is not available yet', {
        status: fileStatus(blob?.status ?? 'deleted'),
      });
    const kind = FILE_KINDS[blob.ext];
    if (input.disposition === 'inline' && !kind?.inline)
      throw new DomainError('forbidden', 'this file type cannot be viewed in the browser');
    if (input.disposition === 'attachment' && !permits(l.permission, 'download'))
      throw new DomainError('forbidden', 'this link is view-only');
    const limits = await this.limits(l.orgId);
    await this.#d.store.transaction(async (tx) => {
      const now = this.#now();
      await tx.lockAccount(l.orgId, now);
      const cur = await tx.getForUpdate('link', l.orgId, l.id);
      if (!cur || cur.status !== 'active') throw unavailable(cur?.status ?? 'revoked');
      if (input.disposition === 'attachment') {
        if (cur.maxDownloads !== null && cur.downloadCount >= cur.maxDownloads)
          throw unavailable('download_limit_reached');
        await tx.update('link', l.orgId, l.id, { downloadCount: cur.downloadCount + 1 });
      }
      if (
        (await tx.addUsage(l.orgId, monthKey(now), 'bandwidth_bytes', blob.size ?? 0)) >
        limits.bandwidthBytesPerMonth
      )
        throw new DomainError('quota_exceeded', 'this share is temporarily unavailable');
      const kindName = input.disposition === 'attachment' ? 'download' : 'view';
      await this.#recordEvent(
        tx,
        { orgId: l.orgId, subjectType: 'share', subjectId: l.id },
        kindName,
        ctx,
        {
          userId: who?.userId ?? null,
          email: who?.email ?? null,
          fileId: input.fileId,
        },
      );
      if (kindName === 'download' && l.notifyOnAccess && !looksAutomated(ctx.userAgent))
        await this.#notify(
          tx,
          l.orgId,
          l.createdBy,
          'share.downloaded',
          { type: 'share_link', id: l.id },
          `${who?.email ?? 'A recipient'} downloaded a file from your shared link${l.label ? ` "${l.label}"` : ''}.`,
          true,
        );
    });
    return this.#signedDownload(blob, name, input.disposition);
  }

  /** Explicit acknowledgement, recorded as its own event (never inferred from a visit or download). */
  async acknowledgeShare(
    token: string,
    input: { grant: string; declaredName?: string | undefined },
    ctx: PublicContext,
  ) {
    const { l, who } = await this.#useGrant(token, input.grant, ctx);
    const declared = text(input.declaredName, 100, 'name');
    if (!who && !declared) throw invalid('enter your name to acknowledge');
    const at = this.#now();
    await this.#d.store.transaction(async (tx) => {
      await this.#recordEvent(
        tx,
        { orgId: l.orgId, subjectType: 'share', subjectId: l.id },
        'acknowledge',
        ctx,
        {
          userId: who?.userId ?? null,
          email: who?.email ?? null,
          declaredName: declared,
        },
      );
      if (l.notifyOnAccess)
        await this.#notify(
          tx,
          l.orgId,
          l.createdBy,
          'share.acknowledged',
          { type: 'share_link', id: l.id },
          `${who?.email ?? `${declared} (unverified name)`} acknowledged receipt of your shared link${l.label ? ` "${l.label}"` : ''}.`,
          true,
        );
    });
    return { acknowledgedAt: at, verifiedIdentity: !!who };
  }

  async #reviewContext(token: string, grant: string | undefined, ctx: PublicContext) {
    const g = await this.#useGrant(token, grant, ctx);
    if (!permits(g.l.permission, 'comment') || !g.target.version || !g.who)
      throw new DomainError('forbidden', 'this link does not allow review');
    return { ...g, version: g.target.version, who: g.who };
  }

  async reviewComments(token: string, grant: string | undefined, ctx: PublicContext) {
    const { l, version } = await this.#reviewContext(token, grant, ctx);
    return this.#thread(l.orgId, version);
  }

  async addComment(
    token: string,
    input: { grant: string; body: string; page?: number | undefined },
    ctx: PublicContext,
  ) {
    const { l, version, who } = await this.#reviewContext(token, input.grant, ctx);
    const body = text(input.body, 2000, 'comment');
    if (!body) throw invalid('comment is required');
    if (
      input.page !== undefined &&
      (!Number.isInteger(input.page) || input.page < 1 || input.page > 100_000)
    )
      throw invalid('invalid page');
    return this.#d.store.transaction(async (tx) => {
      const now = this.#now();
      const c = {
        id: newId('cmt'),
        orgId: l.orgId,
        documentId: version.documentId,
        versionId: version.id,
        linkId: l.id,
        authorUserId: who.userId,
        body,
        page: input.page ?? null,
        createdAt: now,
      };
      await tx.insert('comment', c);
      await this.#recordEvent(
        tx,
        { orgId: l.orgId, subjectType: 'share', subjectId: l.id },
        'comment',
        ctx,
        { userId: who.userId, email: who.email },
      );
      await this.#audit(
        tx,
        { type: 'user', id: who.userId },
        l.orgId,
        'share.review.commented',
        { type: 'share_document', id: version.documentId },
        { version_id: version.id, comment_id: c.id },
      );
      await this.#notify(
        tx,
        l.orgId,
        l.createdBy,
        'share.review.comment',
        { type: 'share_document', id: version.documentId },
        `${who.email ?? 'A reviewer'} commented on version ${version.number}.`,
        l.notifyOnAccess,
      );
      return { id: c.id, createdAt: now };
    });
  }

  async decideReview(
    token: string,
    input: { grant: string; decision: 'approved' | 'changes_requested'; note?: string | undefined },
    ctx: PublicContext,
  ) {
    const { l, version, who } = await this.#reviewContext(token, input.grant, ctx);
    const note = text(input.note, 1000, 'note');
    return this.#d.store.transaction(async (tx) => {
      const now = this.#now();
      const existing = (
        await tx.list(
          'review',
          l.orgId,
          { versionId: version.id, reviewerUserId: who.userId },
          { limit: 1 },
        )
      )[0];
      if (existing)
        await tx.update('review', l.orgId, existing.id, {
          decision: input.decision,
          note,
          linkId: l.id,
          updatedAt: now,
        });
      else
        await tx.insert('review', {
          id: newId('rvw'),
          orgId: l.orgId,
          documentId: version.documentId,
          versionId: version.id,
          linkId: l.id,
          reviewerUserId: who.userId,
          decision: input.decision,
          note,
          createdAt: now,
          updatedAt: now,
        });
      await this.#recordEvent(
        tx,
        { orgId: l.orgId, subjectType: 'share', subjectId: l.id },
        'review',
        ctx,
        { userId: who.userId, email: who.email },
      );
      await this.#audit(
        tx,
        { type: 'user', id: who.userId },
        l.orgId,
        'share.review.decided',
        { type: 'share_document', id: version.documentId },
        { version_id: version.id, decision: input.decision },
      );
      await this.#notify(
        tx,
        l.orgId,
        l.createdBy,
        'share.review.decision',
        { type: 'share_document', id: version.documentId },
        `${who.email ?? 'A reviewer'} ${input.decision === 'approved' ? 'approved' : 'requested changes to'} version ${version.number}.`,
        l.notifyOnAccess,
      );
      return { decision: input.decision, updatedAt: now };
    });
  }

  // =============================================================================================
  // Short links
  // =============================================================================================

  #shortUrl(s: ShortLinkRow, domains: Map<string, string>): string {
    if (s.kind === 'confidential')
      return `${this.#c.publicOrigin}/d/${this.#d.keys.token('short', s.id, s.salt!, 16)}`;
    const host = s.domainId ? domains.get(s.domainId) : undefined;
    return `${host ? `https://${host}` : this.#c.shortOrigin}/l/${s.code}`;
  }

  async #domainHosts(orgId: string): Promise<Map<string, string>> {
    return new Map(
      (await this.#d.store.list('domain', orgId, {}, { limit: 100 })).map((d) => [
        d.id,
        d.hostname,
      ]),
    );
  }

  async #checkDestination(
    r: SharingRepo,
    orgId: string,
    kind: 'public' | 'confidential',
    type: DestinationType,
    url: string | undefined,
    targetId: string | undefined,
  ) {
    if (kind === 'public') {
      if (type !== 'external' || !url)
        throw invalid('public short links point to external web addresses');
      return {
        destinationUrl: validateExternalDestination(url, this.#d.destinations),
        targetId: null,
      };
    }
    if (type === 'external' || !targetId)
      throw invalid('confidential short links point to a share link or upload request');
    const row =
      type === 'share'
        ? await r.get('link', orgId, targetId)
        : await r.get('uploadRequest', orgId, targetId);
    if (!row) throw notFound();
    return { destinationUrl: null, targetId };
  }

  async createShortLink(
    p: UserPrincipal,
    orgId: string,
    input: {
      kind: 'public' | 'confidential';
      destinationType: DestinationType;
      destinationUrl?: string | undefined;
      targetId?: string | undefined;
      alias?: string | undefined;
      domainId?: string | undefined;
      expiresAt?: Date | undefined;
      password?: string | undefined;
      requireAuth?: boolean | undefined;
      label?: string | undefined;
      folder?: string | undefined;
      tags?: string[] | undefined;
    },
  ) {
    if (
      input.kind === 'confidential' &&
      (input.alias || input.domainId || input.password || input.requireAuth)
    )
      throw invalid(
        'confidential short links use an unpredictable code; access control belongs to the share link',
      );
    const alias = input.alias ? validateAlias(input.alias) : undefined;
    const passwordHash = await this.#passwordHash(input.password);
    const folder = folderName(input.folder);
    const tags = tagList(input.tags);
    const label = text(input.label, 200, 'label');
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.#mutate(p, orgId, 'share:create', async (tx, { now, limits }) => {
          if (input.expiresAt && input.expiresAt <= now)
            throw invalid('expiry must be in the future');
          const dest = await this.#checkDestination(
            tx,
            orgId,
            input.kind,
            input.destinationType,
            input.destinationUrl,
            input.targetId,
          );
          if (input.domainId) {
            if (!limits.customDomains)
              throw new DomainError('forbidden', 'custom domains are not included in this plan');
            const d = await tx.get('domain', orgId, input.domainId);
            if (!d || d.status !== 'verified')
              throw new DomainError('conflict', 'the domain is not verified');
          }
          const id = newId('sln');
          const salt = input.kind === 'confidential' ? newSalt() : null;
          const code = input.kind === 'public' ? (alias ?? newPublicCode()) : null;
          const lookupKey =
            input.kind === 'public'
              ? `p|${input.domainId ?? ''}|${code}`
              : `c|${tokenHash(this.#d.keys.token('short', id, salt!, 16))}`;
          const row: ShortLinkRow = {
            id,
            orgId,
            kind: input.kind,
            domainId: input.domainId ?? null,
            code,
            salt,
            lookupKey,
            destinationType: input.destinationType,
            destinationUrl: dest.destinationUrl,
            targetId: dest.targetId,
            status: 'active',
            statusReason: null,
            operatorHold: false,
            expiresAt: input.expiresAt ?? null,
            passwordHash,
            requireAuth: input.requireAuth ?? false,
            label,
            folder,
            tags,
            createdBy: p.userId,
            createdAt: now,
            updatedAt: now,
          };
          await tx.insert('shortLink', row);
          await tx.insert('destination', {
            id: newId('dst'),
            orgId,
            shortLinkId: id,
            destinationType: row.destinationType,
            destinationUrl: row.destinationUrl,
            targetId: row.targetId,
            changedBy: p.userId,
            reason: 'created',
            createdAt: now,
          });
          await this.#audit(
            tx,
            { type: 'user', id: p.userId },
            orgId,
            'short_link.created',
            { type: 'short_link', id },
            {
              kind: row.kind,
              destination_type: row.destinationType,
              destination_host: row.destinationUrl ? new URL(row.destinationUrl).hostname : null,
              target_id: row.targetId,
              custom_alias: !!alias,
            },
          );
          return this.#shortView(row, await this.#domainHosts(orgId), now);
        });
      } catch (e) {
        if (e instanceof Error && e.message === 'duplicate:shortLink') {
          if (alias) throw new DomainError('conflict', 'alias not available');
          if (attempt < 4) continue;
        }
        throw e;
      }
    }
  }

  #shortView(s: ShortLinkRow, domains: Map<string, string>, now: Date) {
    return {
      id: s.id,
      kind: s.kind,
      url: this.#shortUrl(s, domains),
      code: s.code,
      domainId: s.domainId,
      destinationType: s.destinationType,
      destinationUrl: s.destinationUrl,
      targetId: s.targetId,
      status: s.status,
      operatorHold: s.operatorHold,
      state: effectiveLinkState(s, now, true),
      expiresAt: s.expiresAt,
      hasPassword: !!s.passwordHash,
      requireAuth: s.requireAuth,
      label: s.label,
      folder: s.folder,
      tags: s.tags,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
    };
  }

  async listShortLinks(
    p: UserPrincipal,
    orgId: string,
    q: { q?: string; folder?: string; tag?: string; status?: 'active' | 'suspended' | 'revoked' },
  ) {
    await this.#d.authorize(p, orgId, 'share:read');
    const [rows, domains] = await Promise.all([
      this.#d.store.searchShortLinks(orgId, { ...q, q: q.q?.slice(0, 200), limit: 500 }),
      this.#domainHosts(orgId),
    ]);
    const now = this.#now();
    return rows.map((r) => this.#shortView(r, domains, now));
  }

  async getShortLink(p: UserPrincipal, orgId: string, id: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const s = await this.#d.store.get('shortLink', orgId, id);
    if (!s) throw notFound();
    return this.#shortView(s, await this.#domainHosts(orgId), this.#now());
  }

  /** Editable destination with history and audit. Codes and kinds never change. */
  async updateShortLink(
    p: UserPrincipal,
    orgId: string,
    id: string,
    input: {
      destinationUrl?: string | undefined;
      targetId?: string | undefined;
      reason?: string | undefined;
      expiresAt?: Date | null | undefined;
      password?: string | null | undefined;
      requireAuth?: boolean | undefined;
      label?: string | null | undefined;
      folder?: string | undefined;
      tags?: string[] | undefined;
    },
  ) {
    const newHash =
      input.password === undefined ? undefined : await this.#passwordHash(input.password);
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const s = await tx.getForUpdate('shortLink', orgId, id);
      if (!s || s.status === 'revoked') throw notFound();
      await this.#requireManager(p, orgId, s.createdBy);
      const next: ShortLinkRow = { ...s, updatedAt: now };
      const changesDestination = input.destinationUrl !== undefined || input.targetId !== undefined;
      if (changesDestination) {
        const d = await this.#checkDestination(
          tx,
          orgId,
          s.kind,
          s.destinationType,
          input.destinationUrl,
          input.targetId,
        );
        next.destinationUrl = d.destinationUrl;
        next.targetId = d.targetId;
      }
      if (input.expiresAt !== undefined) {
        if (input.expiresAt && input.expiresAt <= now)
          throw invalid('expiry must be in the future');
        next.expiresAt = input.expiresAt;
      }
      if (s.kind === 'confidential' && (newHash || input.requireAuth))
        throw invalid('access control for confidential links belongs to the share link');
      if (newHash !== undefined) next.passwordHash = newHash;
      if (input.requireAuth !== undefined) next.requireAuth = input.requireAuth;
      if (input.label !== undefined) next.label = text(input.label, 200, 'label');
      if (input.folder !== undefined) next.folder = folderName(input.folder);
      if (input.tags !== undefined) next.tags = tagList(input.tags);
      await tx.update('shortLink', orgId, id, next);
      const reason = text(input.reason, 500, 'reason');
      if (
        changesDestination &&
        (next.destinationUrl !== s.destinationUrl || next.targetId !== s.targetId)
      ) {
        await tx.insert('destination', {
          id: newId('dst'),
          orgId,
          shortLinkId: id,
          destinationType: next.destinationType,
          destinationUrl: next.destinationUrl,
          targetId: next.targetId,
          changedBy: p.userId,
          reason,
          createdAt: now,
        });
        await this.#audit(
          tx,
          { type: 'user', id: p.userId },
          orgId,
          'short_link.destination_changed',
          { type: 'short_link', id },
          {
            from_host: s.destinationUrl ? new URL(s.destinationUrl).hostname : null,
            to_host: next.destinationUrl ? new URL(next.destinationUrl).hostname : null,
            from_target: s.targetId,
            to_target: next.targetId,
          },
          reason,
        );
      } else {
        await this.#audit(
          tx,
          { type: 'user', id: p.userId },
          orgId,
          'short_link.updated',
          { type: 'short_link', id },
          {
            changed: Object.keys(input)
              .filter((k) => (input as Record<string, unknown>)[k] !== undefined)
              .sort(),
          },
        );
      }
      return this.#shortView(next, await this.#domainHosts(orgId), now);
    });
  }

  async setShortLinkStatus(
    p: UserPrincipal,
    orgId: string,
    id: string,
    action: 'revoke' | 'suspend' | 'resume',
    reason?: string,
  ) {
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const s = await tx.getForUpdate('shortLink', orgId, id);
      if (!s) throw notFound();
      await this.#requireManager(p, orgId, s.createdBy);
      const status = nextStatus(s, action);
      await tx.update('shortLink', orgId, id, {
        status,
        statusReason: text(reason, 500, 'reason'),
        updatedAt: now,
      });
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        `short_link.${action === 'revoke' ? 'revoked' : action === 'suspend' ? 'suspended' : 'resumed'}`,
        { type: 'short_link', id },
        undefined,
        text(reason, 500, 'reason'),
      );
      return this.#shortView({ ...s, status }, await this.#domainHosts(orgId), now);
    });
  }

  /** Bulk management. All ids must belong to the organization; the whole batch applies or none of it does. */
  async bulkShortLinks(
    p: UserPrincipal,
    orgId: string,
    input: {
      ids: string[];
      action: 'revoke' | 'suspend' | 'resume' | 'move' | 'tag' | 'untag';
      folder?: string | undefined;
      tag?: string | undefined;
      reason?: string | undefined;
    },
  ) {
    const ids = [...new Set(input.ids)];
    if (!ids.length || ids.length > 100) throw invalid('choose 1–100 links');
    const folder = input.action === 'move' ? folderName(input.folder) : undefined;
    const tag =
      input.action === 'tag' || input.action === 'untag'
        ? tagList([input.tag ?? ''])[0]
        : undefined;
    if ((input.action === 'tag' || input.action === 'untag') && !tag)
      throw invalid('tag is required');
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      for (const id of ids) {
        const s = await tx.getForUpdate('shortLink', orgId, id);
        if (!s) throw notFound();
        await this.#requireManager(p, orgId, s.createdBy);
        const patch: Partial<ShortLinkRow> = { updatedAt: now };
        if (input.action === 'move') patch.folder = folder!;
        else if (input.action === 'tag') patch.tags = tagList([...s.tags, tag!]);
        else if (input.action === 'untag') patch.tags = s.tags.filter((t) => t !== tag);
        else patch.status = nextStatus(s, input.action);
        await tx.update('shortLink', orgId, id, patch);
      }
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'short_link.bulk_updated',
        { type: 'org', id: orgId },
        { action: input.action, count: ids.length, ids: ids.slice(0, 100) },
        text(input.reason, 500, 'reason'),
      );
      return { updated: ids.length };
    });
  }

  async shortLinkHistory(p: UserPrincipal, orgId: string, id: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    if (!(await this.#d.store.get('shortLink', orgId, id))) throw notFound();
    const rows = await this.#d.store.list(
      'destination',
      orgId,
      { shortLinkId: id },
      { limit: 1000, order: 'oldest' },
    );
    const emails = new Map<string, string>();
    for (const u of new Set(rows.map((r) => r.changedBy)))
      emails.set(u, (await this.#d.identity(u))?.email ?? 'unknown');
    return rows.map((r) => ({
      destinationType: r.destinationType,
      destinationUrl: r.destinationUrl,
      targetId: r.targetId,
      changedBy: emails.get(r.changedBy),
      reason: r.reason,
      createdAt: r.createdAt,
    }));
  }

  async shortLinkQr(
    p: UserPrincipal,
    orgId: string,
    id: string,
  ): Promise<{ svg: string; fileName: string }> {
    const s = await this.getShortLink(p, orgId, id);
    return { svg: qrSvg(s.url), fileName: `qr-${s.code ?? s.id}.svg` };
  }

  /** Aggregate visits (bots separated). Referral hosts are an advanced-analytics feature and approximate. */
  async shortLinkStats(p: UserPrincipal, orgId: string, id: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    if (!(await this.#d.store.get('shortLink', orgId, id))) throw notFound();
    const limits = await this.limits(orgId);
    const since = dayKey(new Date(this.#now().getTime() - 90 * 86_400_000));
    const stats = await this.#d.store.listStats(orgId, 'short', id, since);
    const daily = new Map<string, { visits: number; bots: number }>();
    const refs = new Map<string, number>();
    for (const s of stats) {
      const d = daily.get(s.day) ?? { visits: 0, bots: 0 };
      if (s.bot) d.bots += s.count;
      else d.visits += s.count;
      daily.set(s.day, d);
      if (!s.bot && s.referrerHost)
        refs.set(s.referrerHost, (refs.get(s.referrerHost) ?? 0) + s.count);
    }
    return {
      totals: totals(stats),
      daily: [...daily.entries()].map(([day, v]) => ({ day, ...v })),
      referrers: limits.advancedAnalytics
        ? [...refs.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20)
            .map(([host, count]) => ({ host, count }))
        : null,
      notes: [
        'Counts are aggregates; no IP addresses or individual visitor records are kept for short links.',
        'Email scanners and link previews can inflate counts. Obvious bots are reported separately.',
        'Referral hosts are approximate: many browsers and apps send no referrer.',
      ],
    };
  }

  #shortState(s: ShortLinkRow, now: Date) {
    const state = effectiveLinkState(s, now, true);
    if (state !== 'active') throw unavailable(state);
  }

  async #shortRow(host: string | undefined, code: string): Promise<ShortLinkRow> {
    const c = code.toLowerCase();
    if (!/^[a-z0-9-]{3,64}$/.test(c)) throw notFound();
    let domainKey = '';
    const h = (host ?? '').toLowerCase().replace(/:\d+$/, '');
    const defaultHost = new URL(this.#c.shortOrigin).hostname;
    const publicHost = new URL(this.#c.publicOrigin).hostname;
    if (h && h !== defaultHost && h !== publicHost) {
      // A verified custom domain has its own namespace; any other host serves the default namespace.
      const d = await this.#d.store.findUnique('domain', 'hostname', h);
      if (d?.status === 'verified') domainKey = d.id;
    }
    const s = await this.#d.store.findUnique('shortLink', 'lookupKey', `p|${domainKey}|${c}`);
    if (!s || s.kind !== 'public') throw notFound();
    return s;
  }

  async #countShort(s: ShortLinkRow, ctx: PublicContext) {
    const now = this.#now();
    const bot = looksAutomated(ctx.userAgent);
    await this.#d.store.bumpStat(
      {
        orgId: s.orgId,
        subjectType: 'short',
        subjectId: s.id,
        day: dayKey(now),
        kind: 'visit',
        bot,
        referrerHost: referrerHost(ctx.referer),
      },
      1,
    );
  }

  /** Public short link: redirect target, or an interstitial when a password or sign-in is required. */
  async resolveShortLink(
    host: string | undefined,
    code: string,
    ctx: PublicContext,
  ): Promise<{ location: string } | { interstitial: { password: boolean; signIn: boolean } }> {
    const s = await this.#shortRow(host, code);
    this.#shortState(s, this.#now());
    await this.#countShort(s, ctx);
    if (s.passwordHash || s.requireAuth)
      return { interstitial: { password: !!s.passwordHash, signIn: s.requireAuth } };
    return { location: s.destinationUrl! };
  }

  async unlockShortLink(
    host: string | undefined,
    code: string,
    input: { password?: string | undefined },
    ctx: PublicContext,
  ) {
    const s = await this.#shortRow(host, code);
    this.#shortState(s, this.#now());
    if (s.requireAuth && !ctx.principal)
      throw new DomainError('unauthenticated', 'sign in to open this link');
    await this.#checkPassword(
      `short:${s.id}`,
      s.passwordHash,
      input.password,
      async () => undefined,
    );
    return { location: s.destinationUrl! };
  }

  async resolveConfidential(code: string, ctx: PublicContext): Promise<{ location: string }> {
    if (!/^[A-Za-z0-9_-]{16}$/.test(code)) throw notFound();
    const s = await this.#d.store.findUnique('shortLink', 'lookupKey', `c|${tokenHash(code)}`);
    if (!s || s.kind !== 'confidential') throw notFound();
    this.#shortState(s, this.#now());
    await this.#countShort(s, ctx);
    if (s.destinationType === 'share') {
      const l = await this.#d.store.get('link', s.orgId, s.targetId!);
      if (!l) throw notFound();
      return { location: this.#shareUrl(l) };
    }
    const r = await this.#d.store.get('uploadRequest', s.orgId, s.targetId!);
    if (!r) throw notFound();
    return { location: this.#requestUrl(r) };
  }

  // =============================================================================================
  // Upload requests (collect files without exposing other uploads)
  // =============================================================================================

  #requestUrl(r: Pick<UploadRequestRow, 'id' | 'salt'>) {
    return `${this.#c.publicOrigin}/r/${this.#d.keys.token('request', r.id, r.salt)}`;
  }

  async createUploadRequest(
    p: UserPrincipal,
    orgId: string,
    input: {
      title: string;
      instructions?: string | undefined;
      requirements: Array<{
        key: string;
        label: string;
        accept?: string[] | undefined;
        required?: boolean | undefined;
        maxFiles?: number | undefined;
      }>;
      deadline: Date;
      maxFileBytes: number;
      maxTotalBytes: number;
      password?: string | undefined;
      notify?: boolean | undefined;
      retentionDays?: number | null | undefined;
    },
  ) {
    const t = title(input.title);
    const instructions = text(input.instructions, 4000, 'instructions');
    if (!input.requirements.length || input.requirements.length > 20)
      throw invalid('add 1–20 file requirements');
    const reqs: Requirement[] = input.requirements.map((r) => {
      if (!/^[a-z0-9_-]{1,40}$/.test(r.key)) throw invalid('invalid requirement key');
      const accept = [
        ...new Set(
          (r.accept?.length ? r.accept : Object.keys(FILE_KINDS)).map((a) => a.toLowerCase()),
        ),
      ];
      if (accept.some((a) => !FILE_KINDS[a]))
        throw invalid('requirement accepts a type that is not permitted');
      const maxFiles = r.maxFiles ?? 1;
      if (!Number.isInteger(maxFiles) || maxFiles < 1 || maxFiles > 50)
        throw invalid('invalid file count');
      return {
        key: r.key,
        label: title(r.label, 'requirement label'),
        accept,
        required: r.required ?? true,
        maxFiles,
      };
    });
    if (new Set(reqs.map((r) => r.key)).size !== reqs.length)
      throw invalid('requirement keys must be unique');
    const passwordHash = await this.#passwordHash(input.password);
    return this.#mutate(p, orgId, 'share:create', async (tx, { now, limits }) => {
      if (!limits.uploadRequests)
        throw new DomainError('forbidden', 'upload requests are not included in this plan');
      if (input.deadline <= now || input.deadline.getTime() > now.getTime() + 366 * 86_400_000)
        throw invalid('the deadline must be within the next year');
      if (
        !Number.isSafeInteger(input.maxFileBytes) ||
        input.maxFileBytes < 1 ||
        input.maxFileBytes > limits.maxFileBytes
      )
        throw quota('file size');
      if (
        !Number.isSafeInteger(input.maxTotalBytes) ||
        input.maxTotalBytes < input.maxFileBytes ||
        input.maxTotalBytes > limits.storageBytes
      )
        throw quota('storage');
      let deleteAfter: Date | null;
      if (input.retentionDays === null) {
        if (!limits.persistent)
          throw new DomainError('forbidden', 'persistent retention is not included in this plan');
        deleteAfter = null;
      } else {
        const days = input.retentionDays ?? limits.maxRetentionDays;
        if (
          !Number.isInteger(days) ||
          days < 1 ||
          (days > limits.maxRetentionDays && !limits.persistent)
        )
          throw quota('retention');
        deleteAfter = new Date(input.deadline.getTime() + days * 86_400_000);
      }
      const id = newId('urq');
      const salt = newSalt();
      const row: UploadRequestRow = {
        id,
        orgId,
        salt,
        tokenHash: tokenHash(this.#d.keys.token('request', id, salt)),
        createdBy: p.userId,
        title: t,
        instructions,
        requirements: reqs,
        deadline: input.deadline,
        maxFileBytes: input.maxFileBytes,
        maxTotalBytes: input.maxTotalBytes,
        passwordHash,
        status: 'open',
        operatorHold: false,
        notify: input.notify ?? false,
        deleteAfter,
        createdAt: now,
        updatedAt: now,
      };
      await tx.insert('uploadRequest', row);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.request.created',
        { type: 'upload_request', id },
        {
          requirements: reqs.length,
          deadline: row.deadline.toISOString(),
          delete_after: deleteAfter?.toISOString() ?? null,
          password: !!passwordHash,
        },
      );
      return this.#requestView(row, now);
    });
  }

  #requestView(r: UploadRequestRow, now: Date) {
    return {
      id: r.id,
      url: this.#requestUrl(r),
      title: r.title,
      instructions: r.instructions,
      requirements: r.requirements,
      deadline: r.deadline,
      maxFileBytes: r.maxFileBytes,
      maxTotalBytes: r.maxTotalBytes,
      hasPassword: !!r.passwordHash,
      notify: r.notify,
      status: r.status,
      operatorHold: r.operatorHold,
      accepting: r.status === 'open' && r.deadline > now,
      deleteAfter: r.deleteAfter,
      createdAt: r.createdAt,
    };
  }

  async listUploadRequests(p: UserPrincipal, orgId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const now = this.#now();
    return (await this.#d.store.list('uploadRequest', orgId, {}, { limit: 500 }))
      .filter((r) => r.status !== 'purged')
      .map((r) => this.#requestView(r, now));
  }

  async getUploadRequest(p: UserPrincipal, orgId: string, id: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const s = this.#d.store;
    const r = await s.get('uploadRequest', orgId, id);
    if (!r || r.status === 'purged') throw notFound();
    const subs = await s.list('submission', orgId, { requestId: id }, { limit: 1000 });
    const files = await s.list(
      'submissionFile',
      orgId,
      { requestId: id, status: 'current' },
      { limit: 10_000, order: 'oldest' },
    );
    const blobs = new Map<string, BlobRow>();
    for (const f of files) {
      const b = await s.get('blob', orgId, f.blobId);
      if (b) blobs.set(b.id, b);
    }
    return {
      ...this.#requestView(r, this.#now()),
      submissions: subs.map((x) => ({
        id: x.id,
        submitterName: x.submitterName,
        submitterEmail: x.submitterEmail,
        identityVerified: false,
        status: x.status,
        createdAt: x.createdAt,
        submittedAt: x.submittedAt,
        files: files
          .filter((f) => f.submissionId === x.id)
          .map((f) => ({
            id: f.id,
            requirementKey: f.requirementKey,
            name: f.name,
            size: f.size,
            status: fileStatus(blobs.get(f.blobId)?.status ?? 'deleted'),
            rejectReason: blobs.get(f.blobId)?.rejectReason ?? null,
          })),
      })),
    };
  }

  async closeUploadRequest(
    p: UserPrincipal,
    orgId: string,
    id: string,
    action: 'close' | 'delete',
  ) {
    return this.#mutate(p, orgId, 'share:create', async (tx, { now }) => {
      const r = await tx.getForUpdate('uploadRequest', orgId, id);
      if (!r || r.status === 'purged') throw notFound();
      await this.#requireManager(p, orgId, r.createdBy);
      const patch: Partial<UploadRequestRow> = { status: 'closed', updatedAt: now };
      if (action === 'delete') patch.deleteAfter = now;
      await tx.update('uploadRequest', orgId, id, patch);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        action === 'close' ? 'share.request.closed' : 'share.request.deleted',
        { type: 'upload_request', id },
      );
      return this.#requestView({ ...r, ...patch }, now);
    });
  }

  async #requestByToken(token: string): Promise<UploadRequestRow> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw notFound();
    const r = await this.#d.store.findUnique('uploadRequest', 'tokenHash', tokenHash(token));
    if (!r || r.status === 'purged') throw notFound();
    return r;
  }

  #requestAccepting(r: UploadRequestRow, now: Date) {
    if (r.operatorHold) throw unavailable('suspended');
    if (r.status !== 'open') throw unavailable('closed');
    if (r.deadline <= now) throw unavailable('deadline_passed');
  }

  async openUploadRequest(
    token: string,
    input: { password?: string | undefined },
    ctx: PublicContext,
  ) {
    const r = await this.#requestByToken(token);
    const now = this.#now();
    this.#requestAccepting(r, now);
    await this.#checkPassword(`request:${r.id}`, r.passwordHash, input.password, () =>
      this.#d.store.transaction((tx) =>
        this.#recordEvent(
          tx,
          { orgId: r.orgId, subjectType: 'request', subjectId: r.id },
          'password_failed',
          ctx,
        ),
      ),
    );
    await this.#d.store.transaction((tx) =>
      this.#recordEvent(
        tx,
        { orgId: r.orgId, subjectType: 'request', subjectId: r.id },
        'visit',
        ctx,
      ),
    );
    const exp = Math.floor(now.getTime() / 1000) + this.#c.grantTtlSeconds;
    return {
      title: r.title,
      instructions: r.instructions,
      requirements: r.requirements,
      deadline: r.deadline,
      maxFileBytes: r.maxFileBytes,
      maxTotalBytes: r.maxTotalBytes,
      branding: await this.#brand(r.orgId),
      grant: this.#d.keys.grant({ k: 'request', s: r.id, u: null, exp }),
      notices: [
        'Your files are visible only to the requester. Other people using this page cannot see them, and you cannot see theirs.',
        'Files are checked before the requester can open them.',
      ],
    };
  }

  async startSubmission(
    token: string,
    input: { grant: string; name: string; email?: string | undefined },
    ctx: PublicContext,
  ) {
    const r = await this.#requestByToken(token);
    const now = this.#now();
    const claims = this.#d.keys.verifyGrant(input.grant, now.getTime());
    if (!claims || claims.k !== 'request' || claims.s !== r.id)
      throw new DomainError('unauthenticated', 'open the request page again');
    this.#requestAccepting(r, now);
    const name = title(input.name, 'name');
    const email = input.email ? normalizeEmail(input.email) : null;
    const secret = newSubmissionSecret();
    const sub: SubmissionRow = {
      id: newId('sbm'),
      orgId: r.orgId,
      requestId: r.id,
      secretHash: tokenHash(secret),
      submitterName: name,
      submitterEmail: email,
      status: 'open',
      createdAt: now,
      submittedAt: null,
    };
    await this.#d.store.transaction(async (tx) => {
      await tx.insert('submission', sub);
      await this.#recordEvent(
        tx,
        { orgId: r.orgId, subjectType: 'request', subjectId: r.id },
        'upload',
        ctx,
        { declaredName: name },
      );
    });
    return { submissionId: sub.id, submissionSecret: secret };
  }

  async #submission(token: string, secret: string | undefined) {
    const r = await this.#requestByToken(token);
    if (!secret || !/^sub_[A-Za-z0-9_-]{43}$/.test(secret))
      throw new DomainError('unauthenticated', 'submission not found');
    const sub = await this.#d.store.findUnique('submission', 'secretHash', tokenHash(secret));
    if (!sub || sub.requestId !== r.id)
      throw new DomainError('unauthenticated', 'submission not found');
    return { r, sub };
  }

  async beginSubmissionUpload(
    token: string,
    secret: string,
    input: { requirementKey: string; name: string; size: number },
  ) {
    const { r, sub } = await this.#submission(token, secret);
    this.#requestAccepting(r, this.#now());
    if (sub.status !== 'open')
      throw new DomainError('conflict', 'this submission was already sent');
    const reqm = r.requirements.find((x) => x.key === input.requirementKey);
    if (!reqm) throw invalid('unknown requirement');
    const name = sanitizeFileName(input.name);
    const kind = requireFileKind(name, reqm.accept);
    if (!Number.isSafeInteger(input.size) || input.size < 1) throw invalid('invalid size');
    if (input.size > r.maxFileBytes) throw quota('file size');
    return this.#startMultipart(
      r.orgId,
      kind.ext,
      kind.contentType,
      input.size,
      async (tx, blob) => {
        const cur = await tx.getForUpdate('submission', r.orgId, sub.id);
        if (!cur || cur.status !== 'open')
          throw new DomainError('conflict', 'this submission was already sent');
        const existing = await tx.list(
          'submissionFile',
          r.orgId,
          { submissionId: sub.id, status: 'current' },
          { limit: 10_000 },
        );
        if (existing.filter((f) => f.requirementKey === reqm.key).length >= reqm.maxFiles)
          throw new DomainError('conflict', 'enough files were uploaded for this requirement');
        if (existing.reduce((n, f) => n + f.size, 0) + input.size > r.maxTotalBytes)
          throw quota('submission size');
        const fileId = newId('sfl');
        blob.targetType = 'submission_file';
        blob.targetId = fileId;
        await tx.insert('blob', blob);
        await tx.insert('submissionFile', {
          id: fileId,
          orgId: r.orgId,
          requestId: r.id,
          submissionId: sub.id,
          blobId: blob.id,
          requirementKey: reqm.key,
          name,
          ext: kind.ext,
          size: input.size,
          status: 'current',
          createdAt: blob.createdAt,
        });
        return { fileId };
      },
      name,
    );
  }

  async #submissionUpload(token: string, secret: string, uploadId: string) {
    const { r, sub } = await this.#submission(token, secret);
    const b = await this.#d.store.get('blob', r.orgId, uploadId);
    const f =
      b?.targetType === 'submission_file'
        ? await this.#d.store.get('submissionFile', r.orgId, b.targetId)
        : undefined;
    if (!b || !f || f.submissionId !== sub.id) throw notFound();
    return { r, sub, b };
  }

  async signSubmissionParts(token: string, secret: string, uploadId: string, parts: number[]) {
    const { r, b } = await this.#submissionUpload(token, secret, uploadId);
    this.#requestAccepting(r, this.#now());
    return this.#signParts(b, parts);
  }
  async submissionUploadStatus(token: string, secret: string, uploadId: string) {
    return this.#uploadStatus((await this.#submissionUpload(token, secret, uploadId)).b);
  }
  async completeSubmissionUpload(token: string, secret: string, uploadId: string) {
    return this.#complete((await this.#submissionUpload(token, secret, uploadId)).b);
  }
  async abortSubmissionUpload(token: string, secret: string, uploadId: string) {
    return this.#abort((await this.#submissionUpload(token, secret, uploadId)).b);
  }

  /** The submitter's own files only. */
  async submissionStatus(token: string, secret: string) {
    const { r, sub } = await this.#submission(token, secret);
    const files = await this.#d.store.list(
      'submissionFile',
      r.orgId,
      { submissionId: sub.id, status: 'current' },
      { limit: 10_000, order: 'oldest' },
    );
    const out = [];
    for (const f of files) {
      const b = await this.#d.store.get('blob', r.orgId, f.blobId);
      out.push({
        id: f.id,
        requirementKey: f.requirementKey,
        name: f.name,
        size: f.size,
        status: fileStatus(b?.status ?? 'deleted'),
        uploadId: b?.status === 'uploading' ? b.id : null,
      });
    }
    return { submissionId: sub.id, status: sub.status, files: out };
  }

  async submit(token: string, secret: string, ctx: PublicContext) {
    const { r, sub } = await this.#submission(token, secret);
    const now = this.#now();
    this.#requestAccepting(r, now);
    return this.#d.store.transaction(async (tx) => {
      const cur = await tx.getForUpdate('submission', r.orgId, sub.id);
      if (!cur || cur.status !== 'open')
        throw new DomainError('conflict', 'this submission was already sent');
      const files = await tx.list(
        'submissionFile',
        r.orgId,
        { submissionId: sub.id, status: 'current' },
        { limit: 10_000 },
      );
      const states = new Map<string, BlobRow['status']>();
      for (const f of files)
        states.set(f.id, (await tx.get('blob', r.orgId, f.blobId))?.status ?? 'deleted');
      if ([...states.values()].some((s) => s === 'uploading'))
        throw new DomainError('conflict', 'finish or cancel the uploads in progress first');
      const missing = r.requirements
        .filter(
          (q) =>
            q.required &&
            !files.some(
              (f) =>
                f.requirementKey === q.key && ['quarantined', 'clean'].includes(states.get(f.id)!),
            ),
        )
        .map((q) => q.key);
      if (missing.length)
        throw new DomainError('conflict', 'required files are missing', { missing });
      await tx.update('submission', r.orgId, sub.id, { status: 'submitted', submittedAt: now });
      await this.#recordEvent(
        tx,
        { orgId: r.orgId, subjectType: 'request', subjectId: r.id },
        'submitted',
        ctx,
        { declaredName: sub.submitterName },
      );
      await this.#audit(
        tx,
        { type: 'anonymous' },
        r.orgId,
        'share.request.submission_received',
        { type: 'upload_request', id: r.id },
        { submission_id: sub.id, files: files.length },
      );
      await this.#notify(
        tx,
        r.orgId,
        r.createdBy,
        'request.submitted',
        { type: 'upload_request', id: r.id },
        `${sub.submitterName} (unverified name) sent ${files.length} file(s) to your upload request "${r.title}".`,
        r.notify,
      );
      return { submissionId: sub.id, status: 'submitted' as const, submittedAt: now };
    });
  }

  // =============================================================================================
  // Notifications, branding, custom domains
  // =============================================================================================

  async listNotifications(p: UserPrincipal, orgId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    return (
      await this.#d.store.list('notification', orgId, { userId: p.userId }, { limit: 100 })
    ).map((n) => ({
      id: n.id,
      kind: n.kind,
      subjectType: n.subjectType,
      subjectId: n.subjectId,
      message: n.message,
      createdAt: n.createdAt,
      read: !!n.readAt,
    }));
  }

  async markNotificationsRead(p: UserPrincipal, orgId: string, ids: string[]) {
    await this.#d.authorize(p, orgId, 'share:read');
    if (ids.length > 100) throw invalid('at most 100 ids');
    await this.#d.store.transaction(async (tx) => {
      const now = this.#now();
      for (const id of new Set(ids)) {
        const n = await tx.get('notification', orgId, id);
        if (n && n.userId === p.userId && !n.readAt)
          await tx.update('notification', orgId, id, { readAt: now });
      }
    });
    return { read: ids.length };
  }

  async #brand(orgId: string) {
    const limits = await this.limits(orgId);
    if (!limits.branding) return null;
    const b = await this.#d.store.get('brand', orgId, orgId);
    return b ? { displayName: b.displayName, accentColor: b.accentColor } : null;
  }

  async getBranding(p: UserPrincipal, orgId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    const b = await this.#d.store.get('brand', orgId, orgId);
    return {
      available: (await this.limits(orgId)).branding,
      displayName: b?.displayName ?? null,
      accentColor: b?.accentColor ?? null,
    };
  }

  async setBranding(
    p: UserPrincipal,
    orgId: string,
    input: { displayName: string; accentColor: string },
  ) {
    const displayName = title(input.displayName, 'display name');
    const accentColor = validateAccentColor(input.accentColor);
    return this.#mutate(p, orgId, 'share:manage', async (tx, { now, limits }) => {
      if (!limits.branding)
        throw new DomainError('forbidden', 'branded pages are not included in this plan');
      const row = { id: orgId, orgId, displayName, accentColor, updatedAt: now };
      if (await tx.get('brand', orgId, orgId)) await tx.update('brand', orgId, orgId, row);
      else await tx.insert('brand', row);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.branding.updated',
        { type: 'org', id: orgId },
        { accent_color: accentColor },
      );
      return { available: true, displayName, accentColor };
    });
  }

  #domainView(d: {
    id: string;
    hostname: string;
    status: string;
    verificationToken: string;
    verifiedAt: Date | null;
    checkedAt: Date | null;
    createdAt: Date;
  }) {
    return {
      id: d.id,
      hostname: d.hostname,
      status: d.status,
      verification: {
        recordType: 'TXT',
        name: `_rokela-challenge.${d.hostname}`,
        value: `rokela-verify=${d.verificationToken}`,
      },
      verifiedAt: d.verifiedAt,
      checkedAt: d.checkedAt,
      createdAt: d.createdAt,
      routing:
        'After verification, point a CNAME for the hostname at the platform short-link host; the operator provisions TLS for it at the edge.',
    };
  }

  async addDomain(p: UserPrincipal, orgId: string, input: { hostname: string }) {
    const hostname = validateHostname(input.hostname);
    const reserved = [
      new URL(this.#c.publicOrigin).hostname,
      new URL(this.#c.shortOrigin).hostname,
      ...this.#d.destinations.reservedHosts,
    ];
    if (reserved.some((h) => hostname === h || hostname.endsWith(`.${h}`)))
      throw invalid('this hostname belongs to the platform');
    try {
      return await this.#mutate(p, orgId, 'share:manage', async (tx, { now, limits }) => {
        if (!limits.customDomains)
          throw new DomainError('forbidden', 'custom domains are not included in this plan');
        const row = {
          id: newId('dom'),
          orgId,
          hostname,
          verificationToken: randomBytes(16).toString('hex'),
          status: 'pending' as const,
          createdAt: now,
          verifiedAt: null,
          checkedAt: null,
        };
        await tx.insert('domain', row);
        await this.#audit(
          tx,
          { type: 'user', id: p.userId },
          orgId,
          'share.domain.added',
          { type: 'custom_domain', id: row.id },
          { hostname },
        );
        return this.#domainView(row);
      });
    } catch (e) {
      if (e instanceof Error && e.message === 'duplicate:domain')
        throw new DomainError('conflict', 'this hostname is already registered');
      throw e;
    }
  }

  async listDomains(p: UserPrincipal, orgId: string) {
    await this.#d.authorize(p, orgId, 'share:read');
    return (await this.#d.store.list('domain', orgId, {}, { limit: 100 })).map((d) =>
      this.#domainView(d),
    );
  }

  /** Ownership check by DNS TXT record. The platform resolves DNS only; it never requests the tenant's site. */
  async verifyDomain(p: UserPrincipal, orgId: string, id: string) {
    await this.#d.authorize(p, orgId, 'share:manage');
    const d = await this.#d.store.get('domain', orgId, id);
    if (!d) throw notFound();
    let found = false;
    if (this.#d.resolveTxt) {
      try {
        const records = await this.#d.resolveTxt(`_rokela-challenge.${d.hostname}`);
        found = records.some((parts) => parts.join('') === `rokela-verify=${d.verificationToken}`);
      } catch {
        found = false;
      }
    }
    return this.#mutate(p, orgId, 'share:manage', async (tx, { now }) => {
      const cur = await tx.getForUpdate('domain', orgId, id);
      if (!cur) throw notFound();
      if (!found) {
        await tx.update('domain', orgId, id, { checkedAt: now });
        return { ...this.#domainView({ ...cur, checkedAt: now }), verified: false };
      }
      await tx.update('domain', orgId, id, {
        status: 'verified',
        verifiedAt: cur.verifiedAt ?? now,
        checkedAt: now,
      });
      if (cur.status !== 'verified')
        await this.#audit(
          tx,
          { type: 'user', id: p.userId },
          orgId,
          'share.domain.verified',
          { type: 'custom_domain', id },
          { hostname: cur.hostname },
        );
      return {
        ...this.#domainView({
          ...cur,
          status: 'verified',
          verifiedAt: cur.verifiedAt ?? now,
          checkedAt: now,
        }),
        verified: true,
      };
    });
  }

  async removeDomain(p: UserPrincipal, orgId: string, id: string) {
    return this.#mutate(p, orgId, 'share:manage', async (tx) => {
      const d = await tx.getForUpdate('domain', orgId, id);
      if (!d) throw notFound();
      const inUse = (await tx.list('shortLink', orgId, { domainId: id }, { limit: 1000 })).some(
        (s) => s.status !== 'revoked',
      );
      if (inUse) throw new DomainError('conflict', 'revoke the short links on this domain first');
      await tx.remove('domain', orgId, id);
      await this.#audit(
        tx,
        { type: 'user', id: p.userId },
        orgId,
        'share.domain.removed',
        { type: 'custom_domain', id },
        { hostname: d.hostname },
      );
      return { removed: true };
    });
  }

  // =============================================================================================
  // Abuse reporting and operator review
  // =============================================================================================

  async reportAbuse(input: {
    reference: string;
    category: AbuseRow['category'];
    details?: string | undefined;
    email?: string | undefined;
  }) {
    const reference = text(input.reference, 2048, 'reference');
    if (!reference) throw invalid('reference is required');
    const details = text(input.details, 4000, 'details');
    const email = input.email ? normalizeEmail(input.email) : null;
    const subject = await this.#resolveReference(reference);
    const row: AbuseRow = {
      id: newId('abr'),
      orgId: subject?.orgId ?? '',
      subjectType: subject?.type ?? 'unknown',
      subjectId: subject?.id ?? null,
      reference,
      category: input.category,
      details,
      reporterEmail: email,
      status: 'open',
      createdAt: this.#now(),
      resolvedAt: null,
      resolvedBy: null,
      resolution: null,
    };
    await this.#d.store.transaction((tx) => tx.insert('abuse', row));
    // Same response whether or not the reference resolved: reports are not an existence oracle.
    return { id: row.id, received: true };
  }

  async #resolveReference(
    ref: string,
  ): Promise<{ orgId: string; type: 'short' | 'share' | 'request'; id: string } | undefined> {
    let host: string | undefined;
    let path = ref;
    try {
      const u = new URL(ref);
      host = u.host;
      path = u.pathname;
    } catch {
      /* a bare code or path */
    }
    const m = /^\/?([lsrd])\/([A-Za-z0-9_-]{3,64})\/?$/.exec(path);
    if (!m) return undefined;
    const [, kind, code] = m as unknown as [string, string, string];
    try {
      if (kind === 'l') {
        const s = await this.#shortRow(host, code);
        return { orgId: s.orgId, type: 'short', id: s.id };
      }
      if (kind === 'd') {
        const s = await this.#d.store.findUnique('shortLink', 'lookupKey', `c|${tokenHash(code)}`);
        return s ? { orgId: s.orgId, type: 'short', id: s.id } : undefined;
      }
      if (kind === 's') {
        const l = await this.#linkByToken(code);
        return { orgId: l.orgId, type: 'share', id: l.id };
      }
      const r = await this.#requestByToken(code);
      return { orgId: r.orgId, type: 'request', id: r.id };
    } catch {
      return undefined;
    }
  }

  async listAbuseReports(status?: AbuseRow['status']) {
    return (await this.#d.store.listAbuse(status, 200)).map((r) => ({ ...r }));
  }

  /** Operator decision on a report. Suspension places an operator hold the owner cannot lift. */
  async resolveAbuseReport(
    operatorId: string,
    id: string,
    input: { action: 'suspend' | 'dismiss'; reason: string },
  ) {
    const reason = text(input.reason, 500, 'reason');
    if (!reason || reason.length < 3) throw invalid('a reason is required');
    return this.#d.store.transaction(async (tx) => {
      const now = this.#now();
      const r = await tx.getAbuseForUpdate(id);
      if (!r) throw notFound();
      if (r.status !== 'open') throw new DomainError('conflict', 'report already resolved');
      if (input.action === 'suspend') {
        if (!r.subjectId || r.subjectType === 'unknown')
          throw new DomainError('conflict', 'the report does not name a resolvable link');
        await this.#hold(tx, r.orgId, r.subjectType, r.subjectId, true, reason, operatorId);
      }
      await tx.update('abuse', r.orgId, id, {
        status: input.action === 'suspend' ? 'actioned' : 'dismissed',
        resolvedAt: now,
        resolvedBy: operatorId,
        resolution: reason,
      });
      await tx.audit.append({
        actor: { type: 'operator', id: operatorId },
        action: `abuse.report_${input.action === 'suspend' ? 'actioned' : 'dismissed'}`,
        target: { type: 'abuse_report', id },
        ...(r.orgId ? { orgId: r.orgId } : {}),
        reason,
        metadata: { subject_type: r.subjectType, subject_id: r.subjectId, category: r.category },
      });
      return { id, status: input.action === 'suspend' ? 'actioned' : 'dismissed' };
    });
  }

  async setOperatorHold(
    operatorId: string,
    orgId: string,
    type: 'short' | 'share' | 'request',
    id: string,
    hold: boolean,
    reason: string,
  ) {
    const r = text(reason, 500, 'reason');
    if (!r || r.length < 3) throw invalid('a reason is required');
    return this.#d.store.transaction((tx) => this.#hold(tx, orgId, type, id, hold, r, operatorId));
  }

  async #hold(
    tx: SharingTx,
    orgId: string,
    type: 'short' | 'share' | 'request',
    id: string,
    hold: boolean,
    reason: string,
    operatorId: string,
  ) {
    const now = this.#now();
    const kind = type === 'short' ? 'shortLink' : type === 'share' ? 'link' : 'uploadRequest';
    const row = await tx.getForUpdate(kind, orgId, id);
    if (!row) throw notFound();
    if (kind === 'uploadRequest')
      await tx.update('uploadRequest', orgId, id, { operatorHold: hold, updatedAt: now });
    else
      await tx.update(kind as 'link', orgId, id, {
        operatorHold: hold,
        status: hold
          ? (row as LinkRow).status === 'revoked'
            ? 'revoked'
            : 'suspended'
          : (row as LinkRow).status === 'revoked'
            ? 'revoked'
            : 'active',
        statusReason: hold ? `operator: ${reason}` : null,
        updatedAt: now,
      });
    await tx.audit.append({
      actor: { type: 'operator', id: operatorId },
      action: hold ? 'share.operator_hold.placed' : 'share.operator_hold.lifted',
      target: { type, id },
      orgId,
      reason,
    });
    return { id, type, operatorHold: hold };
  }

  // =============================================================================================
  // Background jobs: quarantine checks, deletion, notification mail; retention
  // =============================================================================================

  async #enqueue(
    tx: SharingTx,
    orgId: string,
    kind: JobRow['kind'],
    subjectId: string,
    now: Date,
    payload: Record<string, string> = {},
  ) {
    await tx.insert('job', {
      id: newId('job'),
      orgId,
      kind,
      subjectId,
      payload,
      runAfter: now,
      attempts: 0,
      claim: null,
      lockedUntil: null,
      lastError: null,
      createdAt: now,
    });
  }

  /** Claims and runs due jobs. Safe with several workers (fenced claims) and after crashes (leases expire). */
  async processJobs(opts: { limit?: number } = {}): Promise<{ done: number; failed: number }> {
    const claim = newId('clm');
    const now = this.#now();
    const jobs = await this.#d.store.transaction((tx) =>
      tx.claimJobs(
        now,
        opts.limit ?? 20,
        claim,
        new Date(now.getTime() + this.#c.jobLeaseSeconds * 1000),
      ),
    );
    let done = 0;
    let failed = 0;
    for (const job of jobs) {
      try {
        await this.#runJob(job, claim);
        done++;
      } catch (e) {
        failed++;
        await this.#failJob(job, claim, e).catch(() => undefined);
      }
    }
    return { done, failed };
  }

  async #finish(tx: SharingTx, job: JobRow, claim: string): Promise<boolean> {
    const j = await tx.getForUpdate('job', job.orgId, job.id);
    if (!j || j.claim !== claim) return false; // lease lost to another worker
    await tx.remove('job', job.orgId, job.id);
    return true;
  }

  async #runJob(job: JobRow, claim: string) {
    const s = this.#d.store;
    if (job.kind === 'scan') {
      const blob = await s.get('blob', job.orgId, job.subjectId);
      if (!blob || blob.status !== 'quarantined') {
        await s.transaction((tx) => this.#finish(tx, job, claim));
        return;
      }
      const verdict = await this.#d.scanner.scan({
        ext: blob.ext,
        open: () => this.#d.objects.read(blob.objectKey),
      });
      await s.transaction(async (tx) => {
        if (!(await this.#finish(tx, job, claim))) return;
        const now = this.#now();
        const b = await tx.getForUpdate('blob', job.orgId, blob.id);
        if (!b || b.status !== 'quarantined') return;
        const clean = verdict.verdict === 'clean' && verdict.size === b.size;
        await tx.update('blob', b.orgId, b.id, {
          status: clean ? 'clean' : 'rejected',
          rejectReason: clean ? null : (verdict.reason ?? 'size_mismatch'),
          sha256: verdict.sha256,
          scannedAt: now,
        });
        await tx.addUsage(b.orgId, monthKey(now), 'processing_bytes', b.size ?? 0);
        if (clean) await this.#attach(tx, { ...b, status: 'clean' }, now);
        else {
          await this.#enqueue(tx, b.orgId, 'delete_blob', b.id, now);
          await tx.audit.append({
            actor: { type: 'system' },
            action: 'share.file.rejected',
            target: { type: 'share_blob', id: b.id },
            orgId: b.orgId,
            metadata: { reason: verdict.reason, scanner: this.#d.scanner.name },
          });
          const owner = await this.#ownerOf(tx, b);
          if (owner)
            await this.#notify(
              tx,
              b.orgId,
              owner,
              'file.rejected',
              { type: b.targetType, id: b.targetId },
              `An uploaded file did not pass checks (${verdict.reason ?? 'size_mismatch'}) and was removed.`,
              false,
            );
        }
      });
      return;
    }
    if (job.kind === 'delete_blob') {
      const plan = await s.transaction(async (tx) => {
        const j = await tx.getForUpdate('job', job.orgId, job.id);
        if (!j || j.claim !== claim) return undefined;
        const b = await tx.getForUpdate('blob', job.orgId, job.subjectId);
        if (!b || b.status === 'deleted') {
          await tx.remove('job', job.orgId, job.id);
          return undefined;
        }
        // Never delete an object still referenced by another active document, version or transfer
        // (rejected content is always removed).
        if (
          b.status !== 'rejected' &&
          b.status !== 'deleting' &&
          (await tx.blobReferenced(b.orgId, b.id))
        ) {
          await tx.remove('job', job.orgId, job.id);
          return undefined;
        }
        if (b.status !== 'rejected') await tx.update('blob', b.orgId, b.id, { status: 'deleting' });
        return b;
      });
      if (!plan) return;
      if (plan.multipartId && !plan.completedAt)
        await this.#d.objects.abortMultipart(plan.objectKey, plan.multipartId);
      await this.#d.objects.delete(plan.objectKey);
      await s.transaction(async (tx) => {
        if (!(await this.#finish(tx, job, claim))) return;
        await tx.update('blob', plan.orgId, plan.id, { status: 'deleted', deletedAt: this.#now() });
      });
      return;
    }
    // notify_email
    const who = job.payload['userId'] ? await this.#d.identity(job.payload['userId']) : undefined;
    if (this.#d.mailer && who)
      await this.#d.mailer.send({
        id: job.id,
        to: who.email,
        subject: job.payload['subject'] ?? 'Notification',
        text: job.payload['text'] ?? '',
      });
    await s.transaction((tx) => this.#finish(tx, job, claim));
  }

  async #ownerOf(r: SharingRepo, b: BlobRow): Promise<string | null> {
    if (b.createdBy) return b.createdBy;
    if (b.targetType === 'submission_file') {
      const f = await r.get('submissionFile', b.orgId, b.targetId);
      const req = f && (await r.get('uploadRequest', b.orgId, f.requestId));
      return req?.createdBy ?? null;
    }
    return null;
  }

  /** After a clean verdict: swap replacements and drafts in; earlier objects become deletion candidates. */
  async #attach(tx: SharingTx, b: BlobRow, now: Date) {
    if (b.targetType === 'draft') {
      const doc = await tx.getForUpdate('document', b.orgId, b.targetId);
      if (!doc || doc.status !== 'active')
        return void (await this.#enqueue(tx, b.orgId, 'delete_blob', b.id, now));
      if (doc.draftUpdatedAt && b.completedAt && doc.draftUpdatedAt > b.completedAt) {
        // A newer draft already landed; this older save is obsolete.
        return void (await this.#enqueue(tx, b.orgId, 'delete_blob', b.id, now));
      }
      await tx.update('document', b.orgId, doc.id, {
        draftBlobId: b.id,
        draftUpdatedAt: b.completedAt ?? now,
        updatedAt: now,
      });
      if (doc.draftBlobId) await this.#enqueue(tx, b.orgId, 'delete_blob', doc.draftBlobId, now);
      return;
    }
    if (b.targetType === 'transfer_replace') {
      const f = await tx.getForUpdate('transferFile', b.orgId, b.targetId);
      if (!f || f.status !== 'current')
        return void (await this.#enqueue(tx, b.orgId, 'delete_blob', b.id, now));
      await tx.update('transferFile', b.orgId, f.id, {
        blobId: b.id,
        ext: b.ext,
        size: b.size ?? f.size,
        revision: f.revision + 1,
        replacedAt: now,
        replacementNote: b.note,
        updatedAt: now,
      });
      await this.#enqueue(tx, b.orgId, 'delete_blob', f.blobId, now);
      await tx.audit.append({
        actor: {
          type: b.createdBy ? 'user' : 'system',
          ...(b.createdBy ? { id: b.createdBy } : {}),
        },
        action: 'share.transfer.file_replaced',
        target: { type: 'share_transfer', id: f.transferId },
        orgId: b.orgId,
        metadata: { file_id: f.id, revision: f.revision + 1 },
      });
      return;
    }
    if (b.targetType === 'transfer_file' && b.createdBy) {
      const f = await tx.get('transferFile', b.orgId, b.targetId);
      if (f)
        await this.#notify(
          tx,
          b.orgId,
          b.createdBy,
          'file.available',
          { type: 'share_transfer', id: f.transferId },
          `"${f.name}" finished processing and is available.`,
          false,
        );
    }
  }

  async #failJob(job: JobRow, claim: string, e: unknown) {
    const code = (e as { code?: unknown })?.code;
    const err =
      `${(e as Error)?.name ?? 'Error'}${typeof code === 'string' ? `:${code.slice(0, 40)}` : ''}`.slice(
        0,
        100,
      );
    await this.#d.store.transaction(async (tx) => {
      const j = await tx.getForUpdate('job', job.orgId, job.id);
      if (!j || j.claim !== claim) return;
      const now = this.#now();
      const attempts = j.attempts + 1;
      if (attempts >= this.#c.scanMaxAttempts) {
        await tx.remove('job', job.orgId, job.id);
        if (job.kind === 'scan') {
          // Fail closed: a file whose checks never completed never becomes available.
          const b = await tx.getForUpdate('blob', job.orgId, job.subjectId);
          if (b?.status === 'quarantined') {
            await tx.update('blob', b.orgId, b.id, {
              status: 'rejected',
              rejectReason: 'scan_failed',
              scannedAt: now,
            });
            await this.#enqueue(tx, b.orgId, 'delete_blob', b.id, now);
          }
        } else if (job.kind === 'delete_blob') {
          // Keep retrying deletion later rather than forgetting an object.
          await this.#enqueue(
            tx,
            job.orgId,
            'delete_blob',
            job.subjectId,
            new Date(now.getTime() + 6 * 3_600_000),
          );
        }
        return;
      }
      await tx.update('job', job.orgId, job.id, {
        attempts,
        claim: null,
        lockedUntil: null,
        lastError: err,
        runAfter: new Date(now.getTime() + Math.min(3_600_000, 30_000 * 2 ** attempts)),
      });
    });
  }

  /**
   * Retention pass (scheduled, retryable, batch-bounded). Disclosed policy: docs/security/sharing-retention.md.
   *  - temporary transfers: files deleted at expiry (also after revocation, at the original expiry)
   *  - deleted transfers and upload requests past `deleteAfter`: files deleted
   *  - unfinished uploads past their session: aborted and released
   *  - link events, aggregates, attempt counters and notifications: removed after their retention periods
   */
  async runRetention(opts: { batch?: number } = {}) {
    const batch = opts.batch ?? 200;
    const s = this.#d.store;
    const now = this.#now();
    const out = {
      transfersExpired: 0,
      transfersPurged: 0,
      requestsPurged: 0,
      uploadsAbandoned: 0,
      events: 0,
      stats: 0,
      attempts: 0,
      notifications: 0,
    };
    for (const t of await s.dueTransfers(now, batch)) {
      await s.transaction(async (tx) => {
        const cur = await tx.getForUpdate('transfer', t.orgId, t.id);
        if (!cur) return;
        if (cur.status === 'active' && cur.expiresAt && cur.expiresAt <= now) {
          cur.status = 'expired';
          await tx.update('transfer', t.orgId, t.id, { status: 'expired', updatedAt: now });
          out.transfersExpired++;
        }
        const purge =
          cur.status === 'deleted' ||
          (cur.kind === 'temporary' &&
            (cur.status === 'expired' || cur.status === 'revoked') &&
            !!cur.expiresAt &&
            cur.expiresAt <= now);
        if (!purge) return;
        const files = await tx.list(
          'transferFile',
          t.orgId,
          { transferId: t.id, status: 'current' },
          { limit: 100_000 },
        );
        for (const f of files) {
          await tx.update('transferFile', t.orgId, f.id, { status: 'removed', updatedAt: now });
          await this.#enqueue(tx, t.orgId, 'delete_blob', f.blobId, now);
        }
        for (const b of await tx.list(
          'blob',
          t.orgId,
          { targetType: 'transfer_replace' },
          { limit: 100_000 },
        ))
          if (files.some((f) => f.id === b.targetId) && !['deleted', 'deleting'].includes(b.status))
            await this.#enqueue(tx, t.orgId, 'delete_blob', b.id, now);
        await tx.update('transfer', t.orgId, t.id, { status: 'purged', updatedAt: now });
        await tx.audit.append({
          actor: { type: 'system' },
          action: 'share.transfer.purged',
          target: { type: 'share_transfer', id: t.id },
          orgId: t.orgId,
          metadata: { files: files.length, kind: cur.kind },
        });
        out.transfersPurged++;
      });
    }
    for (const r of await s.dueUploadRequests(now, batch)) {
      await s.transaction(async (tx) => {
        const cur = await tx.getForUpdate('uploadRequest', r.orgId, r.id);
        if (!cur || cur.status === 'purged' || !cur.deleteAfter || cur.deleteAfter > now) return;
        const files = await tx.list(
          'submissionFile',
          r.orgId,
          { requestId: r.id, status: 'current' },
          { limit: 100_000 },
        );
        for (const f of files) {
          await tx.update('submissionFile', r.orgId, f.id, { status: 'removed' });
          await this.#enqueue(tx, r.orgId, 'delete_blob', f.blobId, now);
        }
        await tx.update('uploadRequest', r.orgId, r.id, { status: 'purged', updatedAt: now });
        await tx.audit.append({
          actor: { type: 'system' },
          action: 'share.request.purged',
          target: { type: 'upload_request', id: r.id },
          orgId: r.orgId,
          metadata: { files: files.length },
        });
        out.requestsPurged++;
      });
    }
    for (const b of await s.staleUploads(now, batch)) {
      await s.transaction(async (tx) => {
        const cur = await tx.getForUpdate('blob', b.orgId, b.id);
        if (!cur || cur.status !== 'uploading') return;
        await this.#detachUpload(tx, cur, now);
        out.uploadsAbandoned++;
      });
    }
    const day = 86_400_000;
    out.events = await s.purgeEvents(
      new Date(now.getTime() - this.#c.eventRetentionDays * day),
      5000,
    );
    out.stats = await s.purgeStats(
      dayKey(new Date(now.getTime() - this.#c.statRetentionDays * day)),
      5000,
    );
    out.attempts = await s.purgeAttempts(new Date(now.getTime() - day), 5000);
    out.notifications = await s.purgeNotifications(
      new Date(now.getTime() - this.#c.notificationRetentionDays * day),
      5000,
    );
    return out;
  }
}

// ---------------------------------------------------------------------------------------------------
// Views (never expose salts, token hashes or password hashes)
// ---------------------------------------------------------------------------------------------------

export function fileStatus(
  s: BlobRow['status'],
): 'uploading' | 'processing' | 'available' | 'rejected' | 'deleted' {
  return s === 'uploading'
    ? 'uploading'
    : s === 'quarantined'
      ? 'processing'
      : s === 'clean'
        ? 'available'
        : s === 'rejected'
          ? 'rejected'
          : 'deleted';
}

function nextStatus(
  row: { status: 'active' | 'suspended' | 'revoked'; operatorHold: boolean },
  action: 'revoke' | 'suspend' | 'resume',
) {
  if (row.status === 'revoked')
    throw new DomainError('conflict', 'a revoked link cannot be changed');
  if (action === 'revoke') return 'revoked' as const;
  if (action === 'suspend') return 'suspended' as const;
  if (row.operatorHold)
    throw new DomainError(
      'forbidden',
      'this link was suspended by the platform after an abuse review',
    );
  return 'active' as const;
}

function folderName(raw: string | undefined): string {
  const v = (raw ?? '').trim();
  // eslint-disable-next-line no-control-regex
  if (v.length > 100 || /[\u0000-\u001f]/.test(v))
    throw new DomainError('invalid_request', 'invalid folder');
  return v;
}
function tagList(raw: string[] | undefined): string[] {
  const tags = [...new Set((raw ?? []).map((t) => t.trim().toLowerCase()).filter(Boolean))];
  if (tags.length > 20 || tags.some((t) => !/^[a-z0-9][a-z0-9 _-]{0,39}$/.test(t)))
    throw new DomainError('invalid_request', 'invalid tags');
  return tags;
}

function totals(stats: ReadonlyArray<{ kind: string; bot: boolean; count: number }>) {
  const out: Record<string, { count: number; bots: number }> = {};
  for (const s of stats) {
    const t = (out[s.kind] ??= { count: 0, bots: 0 });
    if (s.bot) t.bots += s.count;
    else t.count += s.count;
  }
  return out;
}

const documentView = (d: DocumentRow) => ({
  id: d.id,
  title: d.title,
  createdBy: d.createdBy,
  requireApproval: d.requireApproval,
  hasDraft: !!d.draftBlobId,
  draftUpdatedAt: d.draftUpdatedAt,
  publishedVersionId: d.publishedVersionId,
  publishedAt: d.publishedAt,
  createdAt: d.createdAt,
  updatedAt: d.updatedAt,
});
const versionView = (v: VersionRow) => ({
  id: v.id,
  documentId: v.documentId,
  number: v.number,
  fileName: v.fileName,
  note: v.note,
  createdAt: v.createdAt,
  publishedAt: v.publishedAt,
  replacementNote: v.replacementNote,
});
function transferView(t: TransferRow, now?: Date) {
  return {
    id: t.id,
    title: t.title,
    message: t.message,
    kind: t.kind,
    status:
      t.status === 'active' && t.expiresAt && now && t.expiresAt <= now ? 'expired' : t.status,
    expiresAt: t.expiresAt,
    filesDeletedAt: t.kind === 'temporary' ? t.expiresAt : null,
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
  };
}
const uploadView = (b: BlobRow, fileId: string | null, name: string) => ({
  uploadId: b.id,
  fileId,
  name,
  size: b.declaredSize,
  partSize: b.partSize,
  partCount: b.partCount,
  expiresAt: b.uploadExpiresAt,
});
const eventView = (e: EventRow) => ({
  kind: e.kind,
  at: e.createdAt,
  identity: e.email
    ? { email: e.email, authenticated: true }
    : e.declaredName
      ? { name: e.declaredName, authenticated: false }
      : null,
  fileId: e.fileId,
  likelyAutomated: e.bot,
});

interface ResolvedTarget {
  usable: boolean;
  transfer: TransferRow | undefined;
  document: DocumentRow | undefined;
  version: VersionRow | undefined;
}

export type { EffectiveLinkState };
