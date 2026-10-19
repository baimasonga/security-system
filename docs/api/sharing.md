# Sharing API guide (files, documents, short links, upload requests)

Contract: [openapi.yaml](openapi.yaml) (tag `sharing`). Design: [ADR-021](../adr/ADR-021-file-sharing-and-short-links.md).
Workspace routes live under `/v1/organizations/{orgId}/sharing` and need `Authorization: Bearer <session>`. Unknown
fields are rejected. Wire format is snake_case.

## Upload protocol (resumable, direct to storage)

1. `POST …/uploads` `{target, transfer_id | file_id | document_id, name, size, folder_path?, note?}` → `{upload_id,
part_size, part_count, expires_at}`. Quotas and the file-type allowlist apply here.
2. `POST …/uploads/{id}/parts` `{part_numbers:[…]}` → signed URLs. `PUT` each part's exact bytes to its URL
   (no credentials; CORS allowed for the portal origin only).
3. After an interruption: `GET …/uploads/{id}` → `uploaded_parts`; sign and send only the missing ones.
4. `POST …/uploads/{id}/complete` → `processing`. The file becomes `available` after checks; poll the transfer or
   document. Abandoned sessions expire after 24 h.

## Editor integration (external PDF editors)

Save: upload with `target: "draft"` (PDF only). Export: `POST …/documents/{id}/export`. Publish:
`POST …/documents/{id}/publish {version_id, replacement_note?}`. Share: `POST …/links` with
`version_mode: "latest"` (follows publication) or `"fixed"` + `version_id`. Drafts are never reachable by links.

## Public access

`POST /v1/public/shares/{token}/open {password?}` (optional bearer for restricted links) → manifest + `grant`.
`POST …/files/url {grant, file_id, disposition}` → 60-second URL. `POST …/acknowledge {grant, declared_name?}`.
Review links: `GET/POST …/comments`, `POST …/review`. Errors: `401 password_required|unauthenticated`,
`403 forbidden`, `410 link_unavailable {state}`, `429 rate_limited`.

Upload requests: `open` → `submissions {grant, name}` (returns `submission_secret`; send it as
`x-submission-secret`) → `uploads` / parts / complete → `submission/submit`.

## Short links

Public: `{kind:"public", destination_type:"external", destination_url, alias?}` → `/l/{code}` (302). Confidential:
`{kind:"confidential", destination_type:"share"|"request", target_id}` → `/d/{code}`. QR: `GET …/qr.svg`. History,
stats, bulk and search endpoints are listed in the OpenAPI file.

## Plan entitlements

`share_storage_bytes`, `share_max_file_bytes`, `share_retention_days`, `share_persistent`,
`share_bandwidth_bytes_per_month`, `share_api_requests_per_month`, `share_processing_bytes_per_month`,
`share_upload_requests`, `share_custom_domains`, `share_branding`, `share_advanced_analytics`. The most generous valid
license wins; the free baseline applies without one (`GET …/overview` shows the result).
