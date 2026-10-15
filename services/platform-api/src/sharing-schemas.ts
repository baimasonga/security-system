import { z } from 'zod';

// Strict request schemas for file sharing and short links (ADR-021). Unknown fields are rejected everywhere.

const str = (max: number) => z.string().min(1).max(max);
const id = z.string().regex(/^[a-z]{2,4}_[0-9a-f]{24}$/);
const date = z.string().datetime();
const password = z.string().min(8).max(128);
const email = z.string().min(3).max(254);
const urlToken = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const grant = z.string().min(10).max(1024);
const size = z
  .number()
  .int()
  .min(1)
  .max(2 ** 50);
const reason = z.string().min(3).max(500);

export const sharingOrgParams = z.object({ orgId: id }).strict();
export const idParams = z.object({ orgId: id, id }).strict();
export const docVersionParams = z.object({ orgId: id, id, versionId: id }).strict();
export const transferFileParams = z.object({ orgId: id, id, fileId: id }).strict();

export const documentBody = z
  .object({ title: str(200), require_approval: z.boolean().optional() })
  .strict();
export const exportBody = z
  .object({ note: z.string().max(1000).optional(), file_name: str(200).optional() })
  .strict();
export const publishBody = z
  .object({ version_id: id, replacement_note: z.string().max(1000).optional() })
  .strict();

export const transferBody = z
  .object({
    title: str(200),
    message: z.string().max(2000).optional(),
    kind: z.enum(['temporary', 'persistent']),
    expires_at: date.nullable().optional(),
  })
  .strict();
export const transferPatchBody = z
  .object({
    title: str(200).optional(),
    message: z.string().max(2000).nullable().optional(),
    expires_at: date.nullable().optional(),
  })
  .strict();
export const optionalReasonBody = z.object({ reason: z.string().max(500).optional() }).strict();

export const uploadBody = z
  .object({
    target: z.enum(['transfer', 'replace', 'draft']),
    transfer_id: id.optional(),
    file_id: id.optional(),
    document_id: id.optional(),
    name: str(255),
    folder_path: z.string().max(1000).optional(),
    size,
    note: z.string().max(1000).optional(),
  })
  .strict();
export const partsBody = z
  .object({ part_numbers: z.array(z.number().int().min(1).max(10_000)).min(1).max(100) })
  .strict();
export const emptyBody = z.object({}).strict();

export const ownerFileBody = z
  .object({ type: z.enum(['draft', 'version', 'transfer_file', 'submission_file']), id })
  .strict();

export const linkBody = z
  .object({
    target_type: z.enum(['transfer', 'document']),
    target_id: id,
    version_mode: z.enum(['latest', 'fixed']).optional(),
    version_id: id.optional(),
    permission: z.enum(['view', 'download', 'review']),
    password: password.optional(),
    expires_at: date.optional(),
    max_downloads: z.number().int().min(1).max(100_000).optional(),
    restriction: z.enum(['none', 'members', 'recipients']).optional(),
    recipients: z.array(email).max(50).optional(),
    notify_on_access: z.boolean().optional(),
    label: z.string().max(200).optional(),
  })
  .strict();
export const linkPatchBody = z
  .object({
    label: z.string().max(200).nullable().optional(),
    expires_at: date.nullable().optional(),
    max_downloads: z.number().int().min(1).max(100_000).nullable().optional(),
    password: password.nullable().optional(),
    restriction: z.enum(['none', 'members', 'recipients']).optional(),
    recipients: z.array(email).max(50).optional(),
    notify_on_access: z.boolean().optional(),
    permission: z.enum(['view', 'download', 'review']).optional(),
    version_id: id.optional(),
  })
  .strict();
export const statusBody = z
  .object({
    action: z.enum(['revoke', 'suspend', 'resume']),
    reason: z.string().max(500).optional(),
  })
  .strict();
export const linksQuery = z.object({ target_id: id.optional() }).strict();

export const shortLinkBody = z
  .object({
    kind: z.enum(['public', 'confidential']),
    destination_type: z.enum(['external', 'share', 'request']),
    destination_url: z.string().min(1).max(2048).optional(),
    target_id: id.optional(),
    alias: z.string().min(3).max(64).optional(),
    domain_id: id.optional(),
    expires_at: date.optional(),
    password: password.optional(),
    require_auth: z.boolean().optional(),
    label: z.string().max(200).optional(),
    folder: z.string().max(100).optional(),
    tags: z.array(z.string().max(40)).max(20).optional(),
  })
  .strict();
export const shortLinkPatchBody = z
  .object({
    destination_url: z.string().min(1).max(2048).optional(),
    target_id: id.optional(),
    reason: z.string().max(500).optional(),
    expires_at: date.nullable().optional(),
    password: password.nullable().optional(),
    require_auth: z.boolean().optional(),
    label: z.string().max(200).nullable().optional(),
    folder: z.string().max(100).optional(),
    tags: z.array(z.string().max(40)).max(20).optional(),
  })
  .strict();
export const shortLinksQuery = z
  .object({
    q: z.string().max(200).optional(),
    folder: z.string().max(100).optional(),
    tag: z.string().max(40).optional(),
    status: z.enum(['active', 'suspended', 'revoked']).optional(),
  })
  .strict();
export const bulkBody = z
  .object({
    ids: z.array(id).min(1).max(100),
    action: z.enum(['revoke', 'suspend', 'resume', 'move', 'tag', 'untag']),
    folder: z.string().max(100).optional(),
    tag: z.string().max(40).optional(),
    reason: z.string().max(500).optional(),
  })
  .strict();

export const uploadRequestBody = z
  .object({
    title: str(200),
    instructions: z.string().max(4000).optional(),
    requirements: z
      .array(
        z
          .object({
            key: z.string().regex(/^[a-z0-9_-]{1,40}$/),
            label: str(100),
            accept: z
              .array(z.string().regex(/^[a-z0-9]{1,8}$/))
              .max(30)
              .optional(),
            required: z.boolean().optional(),
            max_files: z.number().int().min(1).max(50).optional(),
          })
          .strict(),
      )
      .min(1)
      .max(20),
    deadline: date,
    max_file_bytes: size,
    max_total_bytes: size,
    password: password.optional(),
    notify: z.boolean().optional(),
    retention_days: z.number().int().min(1).max(3650).nullable().optional(),
  })
  .strict();
export const requestActionBody = z.object({ action: z.enum(['close', 'delete']) }).strict();

export const notificationsReadBody = z.object({ ids: z.array(id).min(1).max(100) }).strict();
export const brandingBody = z
  .object({ display_name: str(200), accent_color: z.string().regex(/^#[0-9a-fA-F]{6}$/) })
  .strict();
export const domainBody = z.object({ hostname: str(253) }).strict();

// ---- public ---------------------------------------------------------------------------------------
export const shareTokenParams = z.object({ token: urlToken }).strict();
export const openBody = z.object({ password: z.string().min(1).max(128).optional() }).strict();
export const fileUrlBody = z
  .object({ grant, file_id: id, disposition: z.enum(['inline', 'attachment']) })
  .strict();
export const acknowledgeBody = z
  .object({ grant, declared_name: z.string().max(100).optional() })
  .strict();
export const commentBody = z
  .object({ grant, body: str(2000), page: z.number().int().min(1).max(100_000).optional() })
  .strict();
export const decisionBody = z
  .object({
    grant,
    decision: z.enum(['approved', 'changes_requested']),
    note: z.string().max(1000).optional(),
  })
  .strict();
export const shortCodeParams = z
  .object({ code: z.string().regex(/^[A-Za-z0-9-]{3,64}$/) })
  .strict();
export const confidentialParams = z
  .object({ code: z.string().regex(/^[A-Za-z0-9_-]{16}$/) })
  .strict();
export const submissionStartBody = z
  .object({ grant, name: str(200), email: email.optional() })
  .strict();
export const submissionUploadBody = z
  .object({ requirement_key: z.string().regex(/^[a-z0-9_-]{1,40}$/), name: str(255), size })
  .strict();
export const submissionUploadParams = z.object({ token: urlToken, uploadId: id }).strict();
export const abuseBody = z
  .object({
    reference: str(2048),
    category: z.enum(['phishing', 'malware', 'spam', 'other']),
    details: z.string().max(4000).optional(),
    email: email.optional(),
  })
  .strict();

// ---- operator -----------------------------------------------------------------------------------
export const abuseQuery = z
  .object({ status: z.enum(['open', 'actioned', 'dismissed']).optional() })
  .strict();
export const abuseParams = z.object({ id }).strict();
export const abuseResolveBody = z
  .object({ action: z.enum(['suspend', 'dismiss']), reason })
  .strict();
export const holdParams = z
  .object({ orgId: id, type: z.enum(['short', 'share', 'request']), id })
  .strict();
export const holdBody = z.object({ hold: z.boolean(), reason }).strict();
