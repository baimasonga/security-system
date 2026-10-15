import { AuditBuffer } from '@trust/audit';
import {
  UNIQUE_LOOKUPS,
  USAGE_METRICS,
  type AbuseRow,
  type AttemptState,
  type BlobRow,
  type JobRow,
  type Kind,
  type ListOptions,
  type Rows,
  type ShortLinkQuery,
  type ShortLinkRow,
  type SharingRepo,
  type SharingStore,
  type SharingTx,
  type StatRow,
  type TransferRow,
  type UniqueField,
  type UniqueKind,
  type UploadRequestRow,
  type UsageMetric,
} from '@trust/sharing';
import type { Clock } from '@trust/shared-types';
import { appendAuditInTx } from './pg-audit-log.ts';
import {
  UNIQUE_VIOLATION,
  pgErr,
  serialized,
  withTransaction,
  type PgPool,
  type Queryable,
} from './pg.ts';

// Column types: t text, i bigint/integer (returned as number), b boolean, d timestamptz, j jsonb.
type Col = 't' | 'i' | 'b' | 'd' | 'j';
interface TableSpec {
  table: string;
  cols: Record<string, Col>;
  order: string;
}

const snake = (s: string) => s.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

// Every column is listed explicitly: SQL is built only from these constants, never from request input.
const SPECS: Record<Kind, TableSpec> = {
  account: {
    table: 'share_accounts',
    order: 'created_at',
    cols: { id: 't', orgId: 't', createdAt: 'd' },
  },
  blob: {
    table: 'share_blobs',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      objectKey: 't',
      ext: 't',
      contentType: 't',
      declaredSize: 'i',
      size: 'i',
      sha256: 't',
      status: 't',
      rejectReason: 't',
      multipartId: 't',
      partSize: 'i',
      partCount: 'i',
      uploadExpiresAt: 'd',
      targetType: 't',
      targetId: 't',
      note: 't',
      createdBy: 't',
      createdAt: 'd',
      completedAt: 'd',
      scannedAt: 'd',
      deletedAt: 'd',
    },
  },
  document: {
    table: 'share_documents',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      title: 't',
      createdBy: 't',
      draftBlobId: 't',
      draftUpdatedAt: 'd',
      publishedVersionId: 't',
      publishedAt: 'd',
      requireApproval: 'b',
      status: 't',
      createdAt: 'd',
      updatedAt: 'd',
    },
  },
  version: {
    table: 'share_versions',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      documentId: 't',
      number: 'i',
      blobId: 't',
      fileName: 't',
      note: 't',
      createdBy: 't',
      createdAt: 'd',
      publishedAt: 'd',
      replacementNote: 't',
    },
  },
  transfer: {
    table: 'share_transfers',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      createdBy: 't',
      title: 't',
      message: 't',
      kind: 't',
      status: 't',
      expiresAt: 'd',
      createdAt: 'd',
      updatedAt: 'd',
    },
  },
  transferFile: {
    table: 'share_transfer_files',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      transferId: 't',
      blobId: 't',
      name: 't',
      folderPath: 't',
      ext: 't',
      size: 'i',
      status: 't',
      revision: 'i',
      replacedAt: 'd',
      replacementNote: 't',
      createdAt: 'd',
      updatedAt: 'd',
    },
  },
  link: {
    table: 'share_links',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      salt: 't',
      tokenHash: 't',
      createdBy: 't',
      label: 't',
      targetType: 't',
      targetId: 't',
      versionMode: 't',
      versionId: 't',
      permission: 't',
      passwordHash: 't',
      expiresAt: 'd',
      maxDownloads: 'i',
      downloadCount: 'i',
      restriction: 't',
      recipients: 'j',
      notifyOnAccess: 'b',
      status: 't',
      statusReason: 't',
      operatorHold: 'b',
      createdAt: 'd',
      updatedAt: 'd',
    },
  },
  comment: {
    table: 'share_comments',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      documentId: 't',
      versionId: 't',
      linkId: 't',
      authorUserId: 't',
      body: 't',
      page: 'i',
      createdAt: 'd',
    },
  },
  review: {
    table: 'share_reviews',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      documentId: 't',
      versionId: 't',
      linkId: 't',
      reviewerUserId: 't',
      decision: 't',
      note: 't',
      createdAt: 'd',
      updatedAt: 'd',
    },
  },
  shortLink: {
    table: 'short_links',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      kind: 't',
      domainId: 't',
      code: 't',
      salt: 't',
      lookupKey: 't',
      destinationType: 't',
      destinationUrl: 't',
      targetId: 't',
      status: 't',
      statusReason: 't',
      operatorHold: 'b',
      expiresAt: 'd',
      passwordHash: 't',
      requireAuth: 'b',
      label: 't',
      folder: 't',
      tags: 'j',
      createdBy: 't',
      createdAt: 'd',
      updatedAt: 'd',
    },
  },
  destination: {
    table: 'short_link_destinations',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      shortLinkId: 't',
      destinationType: 't',
      destinationUrl: 't',
      targetId: 't',
      changedBy: 't',
      reason: 't',
      createdAt: 'd',
    },
  },
  uploadRequest: {
    table: 'upload_requests',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      salt: 't',
      tokenHash: 't',
      createdBy: 't',
      title: 't',
      instructions: 't',
      requirements: 'j',
      deadline: 'd',
      maxFileBytes: 'i',
      maxTotalBytes: 'i',
      passwordHash: 't',
      status: 't',
      operatorHold: 'b',
      notify: 'b',
      deleteAfter: 'd',
      createdAt: 'd',
      updatedAt: 'd',
    },
  },
  submission: {
    table: 'upload_submissions',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      requestId: 't',
      secretHash: 't',
      submitterName: 't',
      submitterEmail: 't',
      status: 't',
      createdAt: 'd',
      submittedAt: 'd',
    },
  },
  submissionFile: {
    table: 'upload_submission_files',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      requestId: 't',
      submissionId: 't',
      blobId: 't',
      requirementKey: 't',
      name: 't',
      ext: 't',
      size: 'i',
      status: 't',
      createdAt: 'd',
    },
  },
  event: {
    table: 'share_events',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      subjectType: 't',
      subjectId: 't',
      kind: 't',
      userId: 't',
      email: 't',
      fileId: 't',
      bot: 'b',
      referrerHost: 't',
      declaredName: 't',
      createdAt: 'd',
    },
  },
  notification: {
    table: 'share_notifications',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      userId: 't',
      kind: 't',
      subjectType: 't',
      subjectId: 't',
      message: 't',
      createdAt: 'd',
      readAt: 'd',
    },
  },
  job: {
    table: 'share_jobs',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      kind: 't',
      subjectId: 't',
      payload: 'j',
      runAfter: 'd',
      attempts: 'i',
      claim: 't',
      lockedUntil: 'd',
      lastError: 't',
      createdAt: 'd',
    },
  },
  domain: {
    table: 'share_domains',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      hostname: 't',
      verificationToken: 't',
      status: 't',
      createdAt: 'd',
      verifiedAt: 'd',
      checkedAt: 'd',
    },
  },
  brand: {
    table: 'share_brands',
    order: 'updated_at',
    cols: { id: 't', orgId: 't', displayName: 't', accentColor: 't', updatedAt: 'd' },
  },
  abuse: {
    table: 'abuse_reports',
    order: 'created_at',
    cols: {
      id: 't',
      orgId: 't',
      subjectType: 't',
      subjectId: 't',
      reference: 't',
      category: 't',
      details: 't',
      reporterEmail: 't',
      status: 't',
      createdAt: 'd',
      resolvedAt: 'd',
      resolvedBy: 't',
      resolution: 't',
    },
  },
};

const SELECT: Record<Kind, string> = Object.fromEntries(
  (Object.entries(SPECS) as Array<[Kind, TableSpec]>).map(([k, s]) => [
    k,
    `SELECT ${Object.keys(s.cols).map(snake).join(', ')} FROM ${s.table}`,
  ]),
) as Record<Kind, string>;

function fromRow<K extends Kind>(kind: K, r: Record<string, unknown>): Rows[K] {
  const out: Record<string, unknown> = {};
  for (const [field, type] of Object.entries(SPECS[kind].cols)) {
    const v = r[snake(field)];
    out[field] = v === null || v === undefined ? null : type === 'i' ? Number(v) : v;
  }
  return out as unknown as Rows[K];
}
const toParam = (type: Col, v: unknown) =>
  v === undefined ? null : type === 'j' ? JSON.stringify(v) : v;

function fieldsOf(kind: Kind, obj: object): string[] {
  const cols = SPECS[kind].cols;
  return Object.keys(obj).filter((k) => k in cols);
}

function rethrowDuplicate(kind: Kind, e: unknown): never {
  if (pgErr(e).code === UNIQUE_VIOLATION) throw new Error(`duplicate:${kind}`);
  throw e;
}

const likeEscape = (s: string) => s.replace(/[\\%_]/g, (c) => `\\${c}`);

class PgSharingRepo implements SharingRepo {
  readonly #db: Queryable;
  constructor(db: Queryable) {
    this.#db = db;
  }

  async insert<K extends Kind>(kind: K, row: Rows[K]): Promise<void> {
    const spec = SPECS[kind];
    const fields = Object.keys(spec.cols);
    const values = fields.map((f) =>
      toParam(spec.cols[f]!, (row as unknown as Record<string, unknown>)[f]),
    );
    await this.#db
      .query(
        `INSERT INTO ${spec.table} (${fields.map(snake).join(', ')}) VALUES (${fields.map((_, i) => `$${i + 1}`).join(', ')})`,
        values,
      )
      .catch((e) => rethrowDuplicate(kind, e));
  }

  async #one<K extends Kind>(
    kind: K,
    sql: string,
    params: unknown[],
  ): Promise<Rows[K] | undefined> {
    const r = await this.#db.query(sql, params);
    return r.rows[0] ? fromRow(kind, r.rows[0]) : undefined;
  }
  get<K extends Kind>(kind: K, orgId: string, id: string) {
    return this.#one(kind, `${SELECT[kind]} WHERE id = $1 AND org_id = $2`, [id, orgId]);
  }
  getForUpdate<K extends Kind>(kind: K, orgId: string, id: string) {
    return this.#one(kind, `${SELECT[kind]} WHERE id = $1 AND org_id = $2 FOR UPDATE`, [id, orgId]);
  }
  findUnique<K extends UniqueKind>(kind: K, field: UniqueField<K>, value: string) {
    if (!(UNIQUE_LOOKUPS[kind] as readonly string[]).includes(field as string))
      throw new Error('not a unique lookup');
    return this.#one(kind, `${SELECT[kind]} WHERE ${snake(field as string)} = $1`, [value]);
  }

  async update<K extends Kind>(kind: K, orgId: string, id: string, patch: Partial<Rows[K]>) {
    const spec = SPECS[kind];
    const fields = fieldsOf(kind, patch).filter((f) => f !== 'id' && f !== 'orgId');
    if (!fields.length) return;
    const values = fields.map((f) =>
      toParam(spec.cols[f]!, (patch as unknown as Record<string, unknown>)[f]),
    );
    await this.#db
      .query(
        `UPDATE ${spec.table} SET ${fields.map((f, i) => `${snake(f)} = $${i + 3}`).join(', ')} WHERE id = $1 AND org_id = $2`,
        [id, orgId, ...values],
      )
      .catch((e) => rethrowDuplicate(kind, e));
  }

  async remove(kind: 'job' | 'domain', orgId: string, id: string) {
    await this.#db.query(`DELETE FROM ${SPECS[kind].table} WHERE id = $1 AND org_id = $2`, [
      id,
      orgId,
    ]);
  }

  async list<K extends Kind>(
    kind: K,
    orgId: string,
    where: Partial<Rows[K]> = {},
    opts: ListOptions = {},
  ) {
    const spec = SPECS[kind];
    const params: unknown[] = [orgId];
    const conds = ['org_id = $1'];
    for (const f of fieldsOf(kind, where)) {
      const v = (where as unknown as Record<string, unknown>)[f];
      if (v === null) conds.push(`${snake(f)} IS NULL`);
      else {
        params.push(toParam(spec.cols[f]!, v));
        conds.push(`${snake(f)} = $${params.length}`);
      }
    }
    params.push(Math.max(1, Math.min(100_000, opts.limit ?? 500)));
    const dir = opts.order === 'oldest' ? 'ASC' : 'DESC';
    const r = await this.#db.query(
      `${SELECT[kind]} WHERE ${conds.join(' AND ')} ORDER BY ${spec.order} ${dir}, id ${dir} LIMIT $${params.length}`,
      params,
    );
    return r.rows.map((x) => fromRow(kind, x));
  }

  async lockAccount(orgId: string, now: Date) {
    await this.#db.query(
      'INSERT INTO share_accounts (id, org_id, created_at) VALUES ($1, $1, $2) ON CONFLICT (id) DO NOTHING',
      [orgId, now],
    );
    await this.#db.query('SELECT id FROM share_accounts WHERE id = $1 FOR UPDATE', [orgId]);
  }

  async storageBytes(orgId: string) {
    const r = await this.#db.query(
      "SELECT COALESCE(SUM(COALESCE(size, declared_size)), 0) AS n FROM share_blobs WHERE org_id = $1 AND status <> 'deleted'",
      [orgId],
    );
    return Number(r.rows[0]!.n);
  }

  async addUsage(orgId: string, period: string, metric: UsageMetric, amount: number) {
    const r = await this.#db.query(
      `INSERT INTO share_usage (org_id, period, metric, amount) VALUES ($1, $2, $3, $4)
       ON CONFLICT (org_id, period, metric) DO UPDATE SET amount = share_usage.amount + EXCLUDED.amount
       RETURNING amount`,
      [orgId, period, metric, amount],
    );
    return Number(r.rows[0]!.amount);
  }

  async usage(orgId: string, period: string) {
    const r = await this.#db.query(
      'SELECT metric, amount FROM share_usage WHERE org_id = $1 AND period = $2',
      [orgId, period],
    );
    const out = Object.fromEntries(USAGE_METRICS.map((m) => [m, 0])) as Record<UsageMetric, number>;
    for (const row of r.rows) out[row.metric as UsageMetric] = Number(row.amount);
    return out;
  }

  async blobReferenced(orgId: string, blobId: string) {
    const r = await this.#db.query(
      `SELECT EXISTS (SELECT 1 FROM share_documents WHERE org_id = $1 AND draft_blob_id = $2 AND status = 'active')
           OR EXISTS (SELECT 1 FROM share_versions v JOIN share_documents d ON d.id = v.document_id AND d.org_id = v.org_id
                      WHERE v.org_id = $1 AND v.blob_id = $2 AND d.status = 'active')
           OR EXISTS (SELECT 1 FROM share_transfer_files WHERE org_id = $1 AND blob_id = $2 AND status = 'current')
           OR EXISTS (SELECT 1 FROM upload_submission_files WHERE org_id = $1 AND blob_id = $2 AND status = 'current') AS used`,
      [orgId, blobId],
    );
    return r.rows[0]!.used === true;
  }

  async nextVersionNumber(orgId: string, documentId: string) {
    const r = await this.#db.query(
      'SELECT COALESCE(MAX(number), 0) + 1 AS n FROM share_versions WHERE org_id = $1 AND document_id = $2',
      [orgId, documentId],
    );
    return Number(r.rows[0]!.n);
  }

  async searchShortLinks(orgId: string, q: ShortLinkQuery): Promise<ShortLinkRow[]> {
    const params: unknown[] = [orgId];
    const conds = ['org_id = $1'];
    if (q.q) {
      params.push(`%${likeEscape(q.q)}%`);
      const p = `$${params.length}`;
      conds.push(`(code ILIKE ${p} OR label ILIKE ${p} OR destination_url ILIKE ${p})`);
    }
    if (q.folder) {
      params.push(q.folder);
      conds.push(`folder = $${params.length}`);
    }
    if (q.tag) {
      params.push(q.tag);
      conds.push(`tags @> jsonb_build_array($${params.length}::text)`);
    }
    if (q.status) {
      params.push(q.status);
      conds.push(`status = $${params.length}`);
    }
    params.push(Math.max(1, Math.min(1000, q.limit ?? 200)));
    const r = await this.#db.query(
      `${SELECT.shortLink} WHERE ${conds.join(' AND ')} ORDER BY created_at DESC, id DESC LIMIT $${params.length}`,
      params,
    );
    return r.rows.map((x) => fromRow('shortLink', x));
  }

  async claimJobs(now: Date, limit: number, claim: string, lockedUntil: Date): Promise<JobRow[]> {
    const r = await this.#db.query(
      `UPDATE share_jobs SET claim = $1, locked_until = $2
       WHERE id IN (SELECT id FROM share_jobs WHERE run_after <= $3 AND (locked_until IS NULL OR locked_until <= $3)
                    ORDER BY run_after LIMIT $4 FOR UPDATE SKIP LOCKED)
       RETURNING ${Object.keys(SPECS.job.cols).map(snake).join(', ')}`,
      [claim, lockedUntil, now, Math.max(1, Math.min(100, limit))],
    );
    return r.rows.map((x) => fromRow('job', x));
  }

  async dueTransfers(now: Date, limit: number): Promise<TransferRow[]> {
    const r = await this.#db.query(
      `${SELECT.transfer}
       WHERE (status = 'active' AND expires_at <= $1)
          OR status = 'deleted'
          OR (status = 'expired' AND kind = 'temporary')
          OR (status = 'revoked' AND kind = 'temporary' AND expires_at <= $1)
       ORDER BY expires_at NULLS FIRST, id LIMIT $2`,
      [now, limit],
    );
    return r.rows.map((x) => fromRow('transfer', x));
  }

  async dueUploadRequests(now: Date, limit: number): Promise<UploadRequestRow[]> {
    const r = await this.#db.query(
      `${SELECT.uploadRequest} WHERE status <> 'purged' AND delete_after <= $1 ORDER BY delete_after, id LIMIT $2`,
      [now, limit],
    );
    return r.rows.map((x) => fromRow('uploadRequest', x));
  }

  async staleUploads(now: Date, limit: number): Promise<BlobRow[]> {
    const r = await this.#db.query(
      `${SELECT.blob} WHERE status = 'uploading' AND upload_expires_at <= $1 ORDER BY upload_expires_at, id LIMIT $2`,
      [now, limit],
    );
    return r.rows.map((x) => fromRow('blob', x));
  }

  async listAbuse(status: AbuseRow['status'] | undefined, limit: number) {
    const r = status
      ? await this.#db.query(
          `${SELECT.abuse} WHERE status = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
          [status, limit],
        )
      : await this.#db.query(`${SELECT.abuse} ORDER BY created_at DESC, id DESC LIMIT $1`, [limit]);
    return r.rows.map((x) => fromRow('abuse', x));
  }

  getAbuseForUpdate(id: string) {
    return this.#one('abuse', `${SELECT.abuse} WHERE id = $1 FOR UPDATE`, [id]);
  }

  async bumpStat(row: Omit<StatRow, 'count'>, n: number) {
    await this.#db.query(
      `INSERT INTO share_stats (org_id, subject_type, subject_id, day, kind, bot, referrer_host, count)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (org_id, subject_type, subject_id, day, kind, bot, referrer_host)
       DO UPDATE SET count = share_stats.count + EXCLUDED.count`,
      [row.orgId, row.subjectType, row.subjectId, row.day, row.kind, row.bot, row.referrerHost, n],
    );
  }

  async listStats(
    orgId: string,
    subjectType: StatRow['subjectType'],
    subjectId: string,
    sinceDay: string,
  ) {
    const r = await this.#db.query(
      `SELECT org_id, subject_type, subject_id, to_char(day, 'YYYY-MM-DD') AS day, kind, bot, referrer_host, count
       FROM share_stats WHERE org_id = $1 AND subject_type = $2 AND subject_id = $3 AND day >= $4
       ORDER BY day, kind`,
      [orgId, subjectType, subjectId, sinceDay],
    );
    return r.rows.map((x) => ({
      orgId: x.org_id as string,
      subjectType: x.subject_type as StatRow['subjectType'],
      subjectId: x.subject_id as string,
      day: x.day as string,
      kind: x.kind as string,
      bot: x.bot as boolean,
      referrerHost: x.referrer_host as string,
      count: Number(x.count),
    }));
  }

  async findAttempt(key: string): Promise<AttemptState | undefined> {
    const r = await this.#db.query(
      'SELECT count, locked_until FROM share_attempts WHERE key = $1',
      [key],
    );
    const row = r.rows[0];
    return row
      ? { count: Number(row.count), lockedUntil: row.locked_until as Date | null }
      : undefined;
  }

  async recordAttemptFailure(
    key: string,
    now: Date,
    max: number,
    lockMs: number,
  ): Promise<AttemptState> {
    const lock = new Date(now.getTime() + lockMs);
    const r = await this.#db.query(
      `INSERT INTO share_attempts (key, count, locked_until, updated_at)
       VALUES ($1, 1, CASE WHEN 1 >= $2 THEN $3::timestamptz END, $4)
       ON CONFLICT (key) DO UPDATE SET
         count = share_attempts.count + 1,
         locked_until = CASE WHEN share_attempts.count + 1 >= $2 THEN $3::timestamptz END,
         updated_at = $4
       RETURNING count, locked_until`,
      [key, max, lock, now],
    );
    return { count: Number(r.rows[0]!.count), lockedUntil: r.rows[0]!.locked_until as Date | null };
  }

  async clearAttempt(key: string) {
    await this.#db.query('DELETE FROM share_attempts WHERE key = $1', [key]);
  }

  async #purge(table: string, column: string, before: unknown, limit: number) {
    const r = await this.#db.query(
      `DELETE FROM ${table} WHERE ctid IN (SELECT ctid FROM ${table} WHERE ${column} < $1 LIMIT $2)`,
      [before, limit],
    );
    return r.rowCount ?? 0;
  }
  purgeEvents(before: Date, limit: number) {
    return this.#purge('share_events', 'created_at', before, limit);
  }
  purgeStats(beforeDay: string, limit: number) {
    return this.#purge('share_stats', 'day', beforeDay, limit);
  }
  purgeAttempts(before: Date, limit: number) {
    return this.#purge('share_attempts', 'updated_at', before, limit);
  }
  purgeNotifications(before: Date, limit: number) {
    return this.#purge('share_notifications', 'created_at', before, limit);
  }
}

export class PgSharingStore extends PgSharingRepo implements SharingStore {
  readonly #pool: PgPool;
  readonly #clock: Clock;
  readonly #auditShards: number;
  constructor(pool: PgPool, clock: Clock, opts?: { auditShards?: number }) {
    super(pool);
    this.#pool = pool;
    this.#clock = clock;
    this.#auditShards = opts?.auditShards ?? 1;
  }

  transaction<T>(fn: (tx: SharingTx) => Promise<T>): Promise<T> {
    return withTransaction(this.#pool, async (client) => {
      const buffer = new AuditBuffer(); // fresh per attempt (see withTransaction retry contract)
      const tx = Object.assign(new PgSharingRepo(serialized(client)), {
        audit: buffer,
      }) as unknown as SharingTx;
      const out = await fn(tx);
      await appendAuditInTx(client, this.#clock, buffer.drain(), this.#auditShards);
      return out;
    });
  }
}
