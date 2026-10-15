import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { PublicContext, SharingService } from '@trust/sharing';
import { DomainError, type UserPrincipal } from '@trust/shared-types';
import type { Container } from '../container.ts';
import { authenticated, bearer, operator, parse, principalOf, toWire } from '../http.ts';
import * as s from '../sharing-schemas.ts';

const date = (v: string | null | undefined) =>
  v === undefined ? undefined : v === null ? null : new Date(v);
const dateOpt = (v: string | undefined) => (v === undefined ? undefined : new Date(v));

/**
 * File sharing, documents, short links and upload requests (ADR-021).
 *  - Workspace routes: session-authenticated and org-scoped; the service authorizes membership and role.
 *  - Public routes: unauthenticated by default, rate-limited per IP; an optional bearer session identifies
 *    restricted recipients and reviewers. Link state is re-evaluated on every request.
 *  - Operator routes: platform-operator only, mandatory reason, audited.
 */
export function registerSharingRoutes(
  app: FastifyInstance,
  c: Container,
  pages: { link: string },
): void {
  const sh = c.sharing;
  if (!sh) return;
  const pre = { preHandler: authenticated(c) };
  const P = '/v1/organizations/:orgId/sharing';
  const org = (req: FastifyRequest) => parse(s.sharingOrgParams, req.params).orgId;
  const ids = (req: FastifyRequest) => parse(s.idParams, req.params);
  const me = (req: FastifyRequest) => principalOf(req);
  const created = <T>(reply: { status(n: number): { send(b: unknown): T } }, body: unknown) =>
    reply.status(201).send(toWire(body));

  // ---- overview -------------------------------------------------------------------------------
  app.get(`${P}/overview`, pre, async (req) => toWire(await sh.overview(me(req), org(req))));

  // ---- documents ------------------------------------------------------------------------------
  app.get(`${P}/documents`, pre, async (req) => ({
    items: toWire(await sh.listDocuments(me(req), org(req))),
  }));
  app.post(`${P}/documents`, pre, async (req, reply) => {
    const b = parse(s.documentBody, req.body);
    return created(
      reply,
      await sh.createDocument(me(req), org(req), {
        title: b.title,
        requireApproval: b.require_approval,
      }),
    );
  });
  app.get(`${P}/documents/:id`, pre, async (req) => {
    const p = ids(req);
    return toWire(await sh.getDocument(me(req), p.orgId, p.id));
  });
  app.post(`${P}/documents/:id/export`, pre, async (req, reply) => {
    const p = ids(req);
    const b = parse(s.exportBody, req.body);
    return created(
      reply,
      await sh.exportVersion(me(req), p.orgId, p.id, { note: b.note, fileName: b.file_name }),
    );
  });
  app.post(`${P}/documents/:id/publish`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.publishBody, req.body);
    return toWire(
      await sh.publishVersion(me(req), p.orgId, p.id, {
        versionId: b.version_id,
        replacementNote: b.replacement_note,
      }),
    );
  });
  app.post(`${P}/documents/:id/delete`, pre, async (req) => {
    const p = ids(req);
    parse(s.emptyBody, req.body);
    return toWire(await sh.deleteDocument(me(req), p.orgId, p.id));
  });
  app.get(`${P}/documents/:id/versions/:versionId/review`, pre, async (req) => {
    const p = parse(s.docVersionParams, req.params);
    return toWire(await sh.reviewThread(me(req), p.orgId, p.id, p.versionId));
  });

  // ---- transfers ------------------------------------------------------------------------------
  app.get(`${P}/transfers`, pre, async (req) => ({
    items: toWire(await sh.listTransfers(me(req), org(req))),
  }));
  app.post(`${P}/transfers`, pre, async (req, reply) => {
    const b = parse(s.transferBody, req.body);
    return created(
      reply,
      await sh.createTransfer(me(req), org(req), {
        title: b.title,
        message: b.message,
        kind: b.kind,
        expiresAt: date(b.expires_at),
      }),
    );
  });
  app.get(`${P}/transfers/:id`, pre, async (req) => {
    const p = ids(req);
    return toWire(await sh.getTransfer(me(req), p.orgId, p.id));
  });
  app.patch(`${P}/transfers/:id`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.transferPatchBody, req.body);
    return toWire(
      await sh.updateTransfer(me(req), p.orgId, p.id, {
        title: b.title,
        message: b.message,
        expiresAt: date(b.expires_at),
      }),
    );
  });
  app.post(`${P}/transfers/:id/revoke`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.optionalReasonBody, req.body);
    return toWire(await sh.revokeTransfer(me(req), p.orgId, p.id, b.reason));
  });
  app.post(`${P}/transfers/:id/delete`, pre, async (req) => {
    const p = ids(req);
    parse(s.emptyBody, req.body);
    return toWire(await sh.deleteTransfer(me(req), p.orgId, p.id));
  });
  app.post(`${P}/transfers/:id/files/:fileId/remove`, pre, async (req) => {
    const p = parse(s.transferFileParams, req.params);
    parse(s.emptyBody, req.body);
    return toWire(await sh.removeTransferFile(me(req), p.orgId, p.id, p.fileId));
  });

  // ---- resumable uploads (bytes go directly to object storage) ---------------------------------
  app.post(`${P}/uploads`, pre, async (req, reply) => {
    const b = parse(s.uploadBody, req.body);
    return created(
      reply,
      await sh.beginUpload(me(req), org(req), {
        target: b.target,
        transferId: b.transfer_id,
        fileId: b.file_id,
        documentId: b.document_id,
        name: b.name,
        folderPath: b.folder_path,
        size: b.size,
        note: b.note,
      }),
    );
  });
  app.post(`${P}/uploads/:id/parts`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.partsBody, req.body);
    return toWire(await sh.signUploadParts(me(req), p.orgId, p.id, b.part_numbers));
  });
  app.get(`${P}/uploads/:id`, pre, async (req) => {
    const p = ids(req);
    return toWire(await sh.uploadStatus(me(req), p.orgId, p.id));
  });
  app.post(`${P}/uploads/:id/complete`, pre, async (req) => {
    const p = ids(req);
    parse(s.emptyBody, req.body);
    return toWire(await sh.completeUpload(me(req), p.orgId, p.id));
  });
  app.post(`${P}/uploads/:id/abort`, pre, async (req) => {
    const p = ids(req);
    parse(s.emptyBody, req.body);
    return toWire(await sh.abortUpload(me(req), p.orgId, p.id));
  });
  app.post(`${P}/files/download`, pre, async (req) => {
    const b = parse(s.ownerFileBody, req.body);
    return toWire(await sh.ownerFileUrl(me(req), org(req), b));
  });

  // ---- share links ----------------------------------------------------------------------------
  app.get(`${P}/links`, pre, async (req) => {
    const q = parse(s.linksQuery, req.query);
    return { items: toWire(await sh.listLinks(me(req), org(req), { targetId: q.target_id })) };
  });
  app.post(`${P}/links`, pre, async (req, reply) => {
    const b = parse(s.linkBody, req.body);
    return created(
      reply,
      await sh.createLink(me(req), org(req), {
        targetType: b.target_type,
        targetId: b.target_id,
        versionMode: b.version_mode,
        versionId: b.version_id,
        permission: b.permission,
        password: b.password,
        expiresAt: dateOpt(b.expires_at),
        maxDownloads: b.max_downloads,
        restriction: b.restriction,
        recipients: b.recipients,
        notifyOnAccess: b.notify_on_access,
        label: b.label,
      }),
    );
  });
  app.get(`${P}/links/:id`, pre, async (req) => {
    const p = ids(req);
    return toWire(await sh.getLink(me(req), p.orgId, p.id));
  });
  app.patch(`${P}/links/:id`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.linkPatchBody, req.body);
    return toWire(
      await sh.updateLink(me(req), p.orgId, p.id, {
        label: b.label,
        expiresAt: date(b.expires_at),
        maxDownloads: b.max_downloads,
        password: b.password,
        restriction: b.restriction,
        recipients: b.recipients,
        notifyOnAccess: b.notify_on_access,
        permission: b.permission,
        versionId: b.version_id,
      }),
    );
  });
  app.post(`${P}/links/:id/status`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.statusBody, req.body);
    return toWire(await sh.setLinkStatus(me(req), p.orgId, p.id, b.action, b.reason));
  });
  app.get(`${P}/links/:id/activity`, pre, async (req) => {
    const p = ids(req);
    return toWire(await sh.linkActivity(me(req), p.orgId, p.id));
  });

  // ---- short links ----------------------------------------------------------------------------
  app.get(`${P}/short-links`, pre, async (req) => {
    const q = parse(s.shortLinksQuery, req.query);
    return { items: toWire(await sh.listShortLinks(me(req), org(req), q)) };
  });
  app.post(`${P}/short-links`, pre, async (req, reply) => {
    const b = parse(s.shortLinkBody, req.body);
    return created(
      reply,
      await sh.createShortLink(me(req), org(req), {
        kind: b.kind,
        destinationType: b.destination_type,
        destinationUrl: b.destination_url,
        targetId: b.target_id,
        alias: b.alias,
        domainId: b.domain_id,
        expiresAt: dateOpt(b.expires_at),
        password: b.password,
        requireAuth: b.require_auth,
        label: b.label,
        folder: b.folder,
        tags: b.tags,
      }),
    );
  });
  app.post(`${P}/short-links/bulk`, pre, async (req) => {
    const b = parse(s.bulkBody, req.body);
    return toWire(await sh.bulkShortLinks(me(req), org(req), b));
  });
  app.get(`${P}/short-links/:id`, pre, async (req) => {
    const p = ids(req);
    return toWire(await sh.getShortLink(me(req), p.orgId, p.id));
  });
  app.patch(`${P}/short-links/:id`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.shortLinkPatchBody, req.body);
    return toWire(
      await sh.updateShortLink(me(req), p.orgId, p.id, {
        destinationUrl: b.destination_url,
        targetId: b.target_id,
        reason: b.reason,
        expiresAt: date(b.expires_at),
        password: b.password,
        requireAuth: b.require_auth,
        label: b.label,
        folder: b.folder,
        tags: b.tags,
      }),
    );
  });
  app.post(`${P}/short-links/:id/status`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.statusBody, req.body);
    return toWire(await sh.setShortLinkStatus(me(req), p.orgId, p.id, b.action, b.reason));
  });
  app.get(`${P}/short-links/:id/history`, pre, async (req) => {
    const p = ids(req);
    return { items: toWire(await sh.shortLinkHistory(me(req), p.orgId, p.id)) };
  });
  app.get(`${P}/short-links/:id/stats`, pre, async (req) => {
    const p = ids(req);
    return toWire(await sh.shortLinkStats(me(req), p.orgId, p.id));
  });
  app.get(`${P}/short-links/:id/qr.svg`, pre, async (req, reply) => {
    const p = ids(req);
    const qr = await sh.shortLinkQr(me(req), p.orgId, p.id);
    return reply
      .type('image/svg+xml')
      .header(
        'content-disposition',
        `attachment; filename="${qr.fileName.replace(/[^A-Za-z0-9._-]/g, '_')}"`,
      )
      .send(qr.svg);
  });

  // ---- upload requests ------------------------------------------------------------------------
  app.get(`${P}/upload-requests`, pre, async (req) => ({
    items: toWire(await sh.listUploadRequests(me(req), org(req))),
  }));
  app.post(`${P}/upload-requests`, pre, async (req, reply) => {
    const b = parse(s.uploadRequestBody, req.body);
    return created(
      reply,
      await sh.createUploadRequest(me(req), org(req), {
        title: b.title,
        instructions: b.instructions,
        requirements: b.requirements.map((r) => ({
          key: r.key,
          label: r.label,
          accept: r.accept,
          required: r.required,
          maxFiles: r.max_files,
        })),
        deadline: new Date(b.deadline),
        maxFileBytes: b.max_file_bytes,
        maxTotalBytes: b.max_total_bytes,
        password: b.password,
        notify: b.notify,
        retentionDays: b.retention_days,
      }),
    );
  });
  app.get(`${P}/upload-requests/:id`, pre, async (req) => {
    const p = ids(req);
    return toWire(await sh.getUploadRequest(me(req), p.orgId, p.id));
  });
  app.post(`${P}/upload-requests/:id/status`, pre, async (req) => {
    const p = ids(req);
    const b = parse(s.requestActionBody, req.body);
    return toWire(await sh.closeUploadRequest(me(req), p.orgId, p.id, b.action));
  });

  // ---- notifications, branding, domains -------------------------------------------------------
  app.get(`${P}/notifications`, pre, async (req) => ({
    items: toWire(await sh.listNotifications(me(req), org(req))),
  }));
  app.post(`${P}/notifications/read`, pre, async (req) => {
    const b = parse(s.notificationsReadBody, req.body);
    return toWire(await sh.markNotificationsRead(me(req), org(req), b.ids));
  });
  app.get(`${P}/branding`, pre, async (req) => toWire(await sh.getBranding(me(req), org(req))));
  app.put(`${P}/branding`, pre, async (req) => {
    const b = parse(s.brandingBody, req.body);
    return toWire(
      await sh.setBranding(me(req), org(req), {
        displayName: b.display_name,
        accentColor: b.accent_color,
      }),
    );
  });
  app.get(`${P}/domains`, pre, async (req) => ({
    items: toWire(await sh.listDomains(me(req), org(req))),
  }));
  app.post(`${P}/domains`, pre, async (req, reply) => {
    const b = parse(s.domainBody, req.body);
    return created(reply, await sh.addDomain(me(req), org(req), b));
  });
  app.post(`${P}/domains/:id/verify`, pre, async (req) => {
    const p = ids(req);
    parse(s.emptyBody, req.body);
    return toWire(await sh.verifyDomain(me(req), p.orgId, p.id));
  });
  app.post(`${P}/domains/:id/remove`, pre, async (req) => {
    const p = ids(req);
    parse(s.emptyBody, req.body);
    return toWire(await sh.removeDomain(me(req), p.orgId, p.id));
  });

  registerPublicSharingRoutes(app, c, sh, pages);
  registerSharingAdminRoutes(app, c, sh);
}

function registerPublicSharingRoutes(
  app: FastifyInstance,
  c: Container,
  sh: SharingService,
  pages: { link: string },
) {
  const limited = {
    config: { rateLimit: { max: c.config.rateLimits.sharing ?? 60, timeWindow: '1 minute' } },
  };
  const header = (req: FastifyRequest, name: string) => {
    const v = req.headers[name];
    return typeof v === 'string' ? v.slice(0, 1024) : undefined;
  };
  // An optional session identifies restricted recipients and reviewers. A presented-but-invalid token is an error.
  const ctx = async (req: FastifyRequest): Promise<PublicContext> => {
    let principal: UserPrincipal | undefined;
    if (req.headers.authorization) principal = await c.auth.authenticate(bearer(req));
    return { principal, userAgent: header(req, 'user-agent'), referer: header(req, 'referer') };
  };
  const token = (req: FastifyRequest) => parse(s.shareTokenParams, req.params).token;
  const secret = (req: FastifyRequest) => {
    const v = header(req, 'x-submission-secret');
    if (!v) throw new DomainError('unauthenticated', 'submission not found');
    return v;
  };

  // ---- short-link resolution ----------------------------------------------------------------
  app.get('/l/:code', limited, async (req, reply) => {
    const { code } = parse(s.shortCodeParams, req.params);
    const r = await sh.resolveShortLink(req.headers.host, code, await ctx(req));
    if ('location' in r) return reply.redirect(r.location, 302);
    return reply.type('text/html; charset=utf-8').send(pages.link);
  });
  app.get('/d/:code', limited, async (req, reply) => {
    const { code } = parse(s.confidentialParams, req.params);
    const r = await sh.resolveConfidential(code, await ctx(req));
    return reply.redirect(r.location, 302);
  });
  app.post('/v1/public/short-links/:code/unlock', limited, async (req) => {
    const { code } = parse(s.shortCodeParams, req.params);
    const b = parse(s.openBody, req.body);
    return toWire(await sh.unlockShortLink(req.headers.host, code, b, await ctx(req)));
  });

  // ---- shares ---------------------------------------------------------------------------------
  const S = '/v1/public/shares/:token';
  app.post(`${S}/open`, limited, async (req) =>
    toWire(await sh.openShare(token(req), parse(s.openBody, req.body), await ctx(req))),
  );
  app.post(`${S}/files/url`, limited, async (req) => {
    const b = parse(s.fileUrlBody, req.body);
    return toWire(
      await sh.shareFileUrl(
        token(req),
        { grant: b.grant, fileId: b.file_id, disposition: b.disposition },
        await ctx(req),
      ),
    );
  });
  app.post(`${S}/acknowledge`, limited, async (req) => {
    const b = parse(s.acknowledgeBody, req.body);
    return toWire(
      await sh.acknowledgeShare(
        token(req),
        { grant: b.grant, declaredName: b.declared_name },
        await ctx(req),
      ),
    );
  });
  app.get(`${S}/comments`, limited, async (req) =>
    toWire(await sh.reviewComments(token(req), header(req, 'x-share-grant'), await ctx(req))),
  );
  app.post(`${S}/comments`, limited, async (req, reply) => {
    const b = parse(s.commentBody, req.body);
    return reply
      .status(201)
      .send(
        toWire(
          await sh.addComment(
            token(req),
            { grant: b.grant, body: b.body, page: b.page },
            await ctx(req),
          ),
        ),
      );
  });
  app.post(`${S}/review`, limited, async (req) => {
    const b = parse(s.decisionBody, req.body);
    return toWire(
      await sh.decideReview(
        token(req),
        { grant: b.grant, decision: b.decision, note: b.note },
        await ctx(req),
      ),
    );
  });

  // ---- upload requests ------------------------------------------------------------------------
  const R = '/v1/public/upload-requests/:token';
  app.post(`${R}/open`, limited, async (req) =>
    toWire(await sh.openUploadRequest(token(req), parse(s.openBody, req.body), await ctx(req))),
  );
  app.post(`${R}/submissions`, limited, async (req, reply) => {
    const b = parse(s.submissionStartBody, req.body);
    return reply.status(201).send(toWire(await sh.startSubmission(token(req), b, await ctx(req))));
  });
  app.get(`${R}/submission`, limited, async (req) =>
    toWire(await sh.submissionStatus(token(req), secret(req))),
  );
  app.post(`${R}/submission/submit`, limited, async (req) => {
    parse(s.emptyBody, req.body);
    return toWire(await sh.submit(token(req), secret(req), await ctx(req)));
  });
  app.post(`${R}/uploads`, limited, async (req, reply) => {
    const b = parse(s.submissionUploadBody, req.body);
    return reply.status(201).send(
      toWire(
        await sh.beginSubmissionUpload(token(req), secret(req), {
          requirementKey: b.requirement_key,
          name: b.name,
          size: b.size,
        }),
      ),
    );
  });
  const up = (req: FastifyRequest) => parse(s.submissionUploadParams, req.params);
  app.post(`${R}/uploads/:uploadId/parts`, limited, async (req) => {
    const p = up(req);
    const b = parse(s.partsBody, req.body);
    return toWire(await sh.signSubmissionParts(p.token, secret(req), p.uploadId, b.part_numbers));
  });
  app.get(`${R}/uploads/:uploadId`, limited, async (req) => {
    const p = up(req);
    return toWire(await sh.submissionUploadStatus(p.token, secret(req), p.uploadId));
  });
  app.post(`${R}/uploads/:uploadId/complete`, limited, async (req) => {
    const p = up(req);
    parse(s.emptyBody, req.body);
    return toWire(await sh.completeSubmissionUpload(p.token, secret(req), p.uploadId));
  });
  app.post(`${R}/uploads/:uploadId/abort`, limited, async (req) => {
    const p = up(req);
    parse(s.emptyBody, req.body);
    return toWire(await sh.abortSubmissionUpload(p.token, secret(req), p.uploadId));
  });

  // ---- abuse reports --------------------------------------------------------------------------
  app.post(
    '/v1/public/abuse-reports',
    { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const b = parse(s.abuseBody, req.body);
      return reply.status(202).send(toWire(await sh.reportAbuse(b)));
    },
  );
}

function registerSharingAdminRoutes(app: FastifyInstance, c: Container, sh: SharingService) {
  const pre = { preHandler: operator(c) };
  app.get('/v1/admin/sharing/abuse-reports', pre, async (req) => {
    const q = parse(s.abuseQuery, req.query);
    return { items: toWire(await sh.listAbuseReports(q.status)) };
  });
  app.post('/v1/admin/sharing/abuse-reports/:id/resolve', pre, async (req) => {
    const { id } = parse(s.abuseParams, req.params);
    const b = parse(s.abuseResolveBody, req.body);
    return toWire(await sh.resolveAbuseReport(principalOf(req).userId, id, b));
  });
  app.post('/v1/admin/organizations/:orgId/sharing/:type/:id/hold', pre, async (req) => {
    const p = parse(s.holdParams, req.params);
    const b = parse(s.holdBody, req.body);
    return toWire(
      await sh.setOperatorHold(principalOf(req).userId, p.orgId, p.type, p.id, b.hold, b.reason),
    );
  });
}
