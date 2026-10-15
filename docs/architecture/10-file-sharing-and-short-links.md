# 10 — File sharing and link shortening (Rokela PDF Pro Web)

Decision record: [ADR-021](../adr/ADR-021-file-sharing-and-short-links.md) · Threats:
[threat-models/02](../threat-models/02-file-sharing-and-short-links.md) · Retention:
[security/sharing-retention.md](../security/sharing-retention.md) · API guide: [api/sharing.md](../api/sharing.md)

## 1. Scope

Users edit a PDF, export it, and share the result; share other permitted formats; collect files through upload
requests; and manage short links and QR codes, all in the workspace's **Files & links** view. Sharing is part of the
platform's architecture, data model, quotas, jobs, audit and cost model, not a set of buttons on top of it.

## 2. Components and trust boundaries

```
 Browser (portal / public pages)            API server (platform-api)                 Private object storage
 ─────────────────────────────              ───────────────────────────               (R2/S3; local store in dev)
 Files & links view  ──JSON, bearer──▶  routes/sharing.ts ──▶ SharingService ──▶ PgSharingStore (PostgreSQL)
 share / request / link pages ─JSON─▶   (zod strict, rate limits)   │  │                 audit (same tx)
        │                                                           │  └─ authorize/identity/entitlements
        │  PUT parts / GET object (signed, short-lived)              │     injected from auth + licensing
        └──────────────────────────────────────────────────▶ content origin ◀── signs URLs, never proxies bytes
                                                                    │
 Job worker (same process, fenced claims) ── scan (basic + ClamAV) ─┘── delete objects ── notification mail
 Maintenance pass ── retention: expire/purge transfers & requests, abandoned uploads, events, aggregates, counters
```

Boundaries: (a) browser ↔ API: sessions or link grants, every request re-authorized; (b) API ↔ storage: operator
credentials, only to the configured endpoint; (c) browser ↔ content origin: signature is the only authority, no
cookies, untrusted bytes served with `nosniff`, fixed type/disposition, CSP (`sandbox` except PDFs), `no-store`;
(d) public internet ↔ public pages: unpredictable tokens, rate limits, password lockout, abuse reporting.

## 3. Integrated workflows

| Workflow                      | How it works                                                                                                                                                       | Evidence (tests)          |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------- |
| 1. Edit → export → share      | Editor saves a **private draft** (upload `target: draft`); `export` creates an immutable version referencing the draft's object; `links` creates a controlled link | sharing.test "1 & 5"      |
| 2. Share latest version       | `version_mode: latest` serves `published_version_id`, which only `publish` changes                                                                                 | "1 & 5"                   |
| 3. Share fixed version        | `version_mode: fixed` + `version_id`; label says "Fixed version N"                                                                                                 | "1 & 5"                   |
| 4. Request files              | Upload request with requirements, deadline, limits, optional password; submitters see only their own files                                                         | "6"                       |
| 5. Review → approve → publish | `require_approval`; review links (restricted, authenticated) collect comments and decisions; publish needs an approval by someone other than the author            | sharing-security "review" |

Every manifest states whether the link serves a **fixed version** or the **latest published version**, the publish
date, and, after a replacement, the sender's explanation and earlier version numbers (safe replacement). Unpublished
drafts and exports are never served by `latest` links.

The full Rokela PDF Pro editor (desktop/web) integrates through the same API: save drafts with
`POST …/uploads {target:'draft'}` + parts + complete, then export/publish. The portal ships a minimal composer that
produces a text PDF and can reopen its own drafts, so the flow is usable and testable without the full editor.

## 4. Data model (migration 0011)

| Record                                     | Table                                                                                                                             | Notes                                                                                                                      |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Organization accounting anchor             | `share_accounts`                                                                                                                  | Row lock for quota checks                                                                                                  |
| Stored objects                             | `share_blobs`                                                                                                                     | Immutable; status `uploading → quarantined → clean/rejected → deleting → deleted`; multipart session, digest, target       |
| Documents, versions                        | `share_documents`, `share_versions`                                                                                               | Private draft pointer, published pointer, approval flag; versions immutable (`(document_id, number)` unique)               |
| Transfers and files                        | `share_transfers`, `share_transfer_files`                                                                                         | Temporary (expiry required) or persistent; folder paths; file revision + replacement note                                  |
| Shared links and access policies           | `share_links`                                                                                                                     | Token hash + salt, permission, password hash, expiry, download limit/count, restriction, recipients, status, operator hold |
| Review                                     | `share_comments`, `share_reviews`                                                                                                 | Per version; one decision per reviewer                                                                                     |
| Short links, aliases, destination history  | `short_links`, `short_link_destinations`                                                                                          | Kind-specific CHECKs enforce public/confidential separation; history append-only                                           |
| Upload requests                            | `upload_requests`, `upload_submissions`, `upload_submission_files`                                                                | Requirements JSON; submission secret hash                                                                                  |
| Recipient invitations and acknowledgements | `share_links.recipients` + `share_events` (`access`, `acknowledge`)                                                               | Named recipients are verified accounts; acknowledgements are explicit events                                               |
| Link events, aggregated analytics          | `share_events`, `share_stats`                                                                                                     | No IPs, titles or file names; bot flag; referrer host only                                                                 |
| Custom domains, ownership verification     | `share_domains`                                                                                                                   | DNS TXT `_rokela-challenge.<host>`                                                                                         |
| Branding                                   | `share_brands`                                                                                                                    | Display name, accent colour                                                                                                |
| Storage, bandwidth, processing, API usage  | `share_blobs` (storage), `share_usage` (monthly metrics)                                                                          | Separate meters                                                                                                            |
| Retention schedules                        | `share_transfers.expires_at`, `upload_requests.delete_after`, `share_blobs.upload_expires_at`, event/aggregate retention settings | Disclosed policy in security/sharing-retention.md                                                                          |
| Jobs, notifications, abuse, attempts       | `share_jobs`, `share_notifications`, `abuse_reports`, `share_attempts`                                                            | Fenced leases; operator review; password lockout                                                                           |

Every child row uses composite `(id, org_id)` foreign keys so it cannot reference another tenant's parent.
Least-privilege grants: see `TABLE_PRIVILEGES` in `db/grants.ts`.

## 5. Security, privacy and abuse controls (summary)

Hashed link passwords + per-link lockout + per-IP rate limits; server-side recipient checks with verified email;
404 for cross-organization ids; quarantine before availability; isolated content origin with safe headers; http(s)
only destinations with SSRF-style host rules and **no server-side fetching** (no link previews); abuse reports,
operator holds, audited resolution; confidential filenames and contents excluded from analytics, audit metadata and
logs; bots counted separately with the caveat that scanners and previews inflate counts; defined event retention.
View-only cannot prevent screenshots or copying, and revocation cannot recall downloaded copies: both statements are
shown to users in the workspace and on every share page.

## 6. Differentiators investigated

| Idea                       | Outcome                                                                                                                                                                                                                                                                                                           |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Document delivery receipts | **Implemented**: identified access, view, download and acknowledgement are distinct events; visits are never presented as reading.                                                                                                                                                                                |
| Safe replacement           | **Implemented**: documents publish a new version with an explanation and history; transfer files are replaced in place (same type) and keep serving the old object until the new one passes checks.                                                                                                               |
| Automatic transfer cleanup | **Implemented** with a disclosed policy including backups (security/sharing-retention.md).                                                                                                                                                                                                                        |
| Recipient watermarks       | Deferred (phase 3): needs a sandboxed PDF processing worker (rendering untrusted PDFs is a code-execution risk), per-recipient derived objects (storage cost), and a delivery reference recorded in receipts. Design: generate on first authorized download, cache per (version, recipient), count as processing. |
| Low-bandwidth delivery     | Partly: resumable transfers implemented. Preview derivatives (downsampled PDF/images) need the same sandboxed worker; deferred to phase 3.                                                                                                                                                                        |
| Submission bundles         | Partly: upload-request requirements form a completeness checklist with per-item status. Sharing a bundle of required documents with a version record is a phase-3 extension of transfers (`requirements` + document versions).                                                                                    |

## 7. Phased build plan

| Phase                              | Contents                                                                                                                                                                                                                                                                                            | Status      |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| 1 — Core (all plans)               | Temporary transfers, resumable uploads, quarantine, share links with password/expiry/limits/revocation, documents with draft/export/publish (latest/fixed), generated and aliased public short links, QR codes, confidential short links, receipts, retention jobs, usage metering, abuse reporting | **Done**    |
| 2 — Collaboration (paid)           | Persistent sharing, upload requests, recipient restrictions, review/approval, notifications (in-app + email), safe replacement, bulk management, search                                                                                                                                             | **Done**    |
| 3 — Brand and scale (higher tiers) | Branding (done), custom-domain verification and routing (done; TLS at the edge is an operator step), advanced analytics referrers (done); watermarking, previews, submission bundles, API tokens for machine clients, CDN edge caching of public downloads                                          | Partly done |
| Production readiness               | Live R2 bucket + CORS rule, ClamAV sidecar, load test of upload/download paths, backup/restore drill including object storage, external security review                                                                                                                                             | Not done    |

## 8. Cost model

Unit prices are **planning assumptions** (Cloudflare R2 list prices as last known: storage ≈ US$0.015/GB-month,
Class A operations ≈ US$4.50/million, Class B ≈ US$0.36/million, no egress fee); verify current prices before
committing. Compute and PostgreSQL costs are shared with the platform.

| Driver     | What triggers it                                       | Meter / limit                              | Approx. unit cost                                                     |
| ---------- | ------------------------------------------------------ | ------------------------------------------ | --------------------------------------------------------------------- |
| Storage    | Live and reserved object bytes                         | `share_storage_bytes` (free 2 GB)          | $0.015 per GB-month                                                   |
| Uploads    | One CreateMultipart + N part PUTs + Complete (Class A) | `upload_bytes`, file size limit            | ~$4.50 per million parts; 8 MiB parts → ~$0.0006 per GB uploaded      |
| Downloads  | One signed GET per delivery (Class B)                  | `bandwidth_bytes` (free 20 GB/month)       | ~$0.36 per million; egress $0 on R2 (would dominate on S3: ~$0.09/GB) |
| Processing | Server read of every object + ClamAV CPU               | `processing_bytes` (free 10 GB/month)      | Class B read + CPU; ClamAV ~1 vCPU-second per 10–50 MB                |
| Retention  | Temporary vs persistent                                | `share_retention_days`, `share_persistent` | Storage × duration; temporary purged at expiry                        |
| API usage  | Authenticated sharing mutations                        | `share_api_requests_per_month`             | Database + compute                                                    |
| Analytics  | Events and daily aggregates                            | retention 180/400 days                     | Small rows; purged                                                    |

Example (free plan worst case): 2 GB stored all month ($0.03) + 20 GB downloaded (≈ 2,500 GETs of 8 MB, <$0.01) +
uploads and scans of 2 GB (<$0.01) ⇒ well under $0.10 per free organization per month on R2. On AWS S3 the same
download volume would cost ≈ $1.80 in egress, which is why bandwidth is metered separately and capped.

## 9. Operations

Configuration: `docs/deploy/first-deploy.md#file-sharing-rollout-adr-021`. Metrics: `sharing_jobs_total{outcome}`,
`sharing_worker_errors_total`, `maintenance_deleted_total{table="sharing_*"}`, plus HTTP route metrics.
Runbook notes: a growing `share_jobs` backlog means the worker or ClamAV is down (files stay `processing`, never
served); an abuse surge is handled by operator holds via `/v1/admin/sharing/...`.
