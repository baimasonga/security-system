-- 0011_file_sharing: transfers, documents/versions, share links, short links, upload requests, receipts,
-- analytics aggregates, background jobs, custom domains, branding, abuse reports and usage (ADR-021).
-- Conventions as 0001: tenant-owned rows carry org_id; children reference parents through COMPOSITE (id, org_id)
-- foreign keys; secrets appear only as hashes; no file names or content in analytics tables.

BEGIN;

CREATE TABLE share_accounts (
  id          text PRIMARY KEY REFERENCES organizations(id),
  org_id      text NOT NULL REFERENCES organizations(id) CHECK (org_id = id),
  created_at  timestamptz NOT NULL
);

CREATE TABLE share_blobs (
  id                text NOT NULL PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  object_key        text NOT NULL UNIQUE CHECK (object_key = 'o/' || org_id || '/' || id),
  ext               text NOT NULL CHECK (ext ~ '^[a-z0-9]{1,8}$'),
  content_type      text NOT NULL,
  declared_size     bigint NOT NULL CHECK (declared_size > 0),
  size              bigint CHECK (size >= 0),
  sha256            text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  status            text NOT NULL CHECK (status IN ('uploading','quarantined','clean','rejected','deleting','deleted')),
  reject_reason     text CHECK (length(reject_reason) <= 100),
  multipart_id      text,
  part_size         bigint NOT NULL CHECK (part_size > 0),
  part_count        integer NOT NULL CHECK (part_count BETWEEN 1 AND 10000),
  upload_expires_at timestamptz,
  target_type       text NOT NULL CHECK (target_type IN ('transfer_file','transfer_replace','draft','submission_file')),
  target_id         text NOT NULL,
  note              text CHECK (length(note) <= 1000),
  created_by        text REFERENCES users(id),
  created_at        timestamptz NOT NULL,
  completed_at      timestamptz,
  scanned_at        timestamptz,
  deleted_at        timestamptz,
  UNIQUE (id, org_id),
  -- Only checked bytes are ever servable: a clean blob has its digest and final size.
  CHECK (status <> 'clean' OR (sha256 IS NOT NULL AND size IS NOT NULL))
);
CREATE INDEX share_blobs_org_live ON share_blobs (org_id) WHERE status <> 'deleted';
CREATE INDEX share_blobs_stale ON share_blobs (upload_expires_at) WHERE status = 'uploading';
CREATE INDEX share_blobs_target ON share_blobs (org_id, target_type, target_id);

CREATE TABLE share_documents (
  id                   text NOT NULL PRIMARY KEY,
  org_id               text NOT NULL REFERENCES organizations(id),
  title                text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  created_by           text NOT NULL REFERENCES users(id),
  draft_blob_id        text,
  draft_updated_at     timestamptz,
  published_version_id text,
  published_at         timestamptz,
  require_approval     boolean NOT NULL,
  status               text NOT NULL CHECK (status IN ('active','deleted')),
  created_at           timestamptz NOT NULL,
  updated_at           timestamptz NOT NULL,
  UNIQUE (id, org_id),
  FOREIGN KEY (draft_blob_id, org_id) REFERENCES share_blobs (id, org_id)
);
CREATE INDEX share_documents_draft ON share_documents (org_id, draft_blob_id) WHERE draft_blob_id IS NOT NULL;

CREATE TABLE share_versions (
  id                text NOT NULL PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  document_id       text NOT NULL,
  number            integer NOT NULL CHECK (number >= 1),
  blob_id           text NOT NULL,
  file_name         text NOT NULL CHECK (length(file_name) BETWEEN 1 AND 200),
  note              text CHECK (length(note) <= 1000),
  created_by        text NOT NULL REFERENCES users(id),
  created_at        timestamptz NOT NULL,
  published_at      timestamptz,
  replacement_note  text CHECK (length(replacement_note) <= 1000),
  UNIQUE (id, org_id),
  UNIQUE (document_id, number),
  FOREIGN KEY (document_id, org_id) REFERENCES share_documents (id, org_id),
  FOREIGN KEY (blob_id, org_id) REFERENCES share_blobs (id, org_id)
);
CREATE INDEX share_versions_blob ON share_versions (org_id, blob_id);
ALTER TABLE share_documents ADD FOREIGN KEY (published_version_id, org_id) REFERENCES share_versions (id, org_id);

CREATE TABLE share_transfers (
  id          text NOT NULL PRIMARY KEY,
  org_id      text NOT NULL REFERENCES organizations(id),
  created_by  text NOT NULL REFERENCES users(id),
  title       text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  message     text CHECK (length(message) <= 2000),
  kind        text NOT NULL CHECK (kind IN ('temporary','persistent')),
  status      text NOT NULL CHECK (status IN ('active','revoked','expired','deleted','purged')),
  expires_at  timestamptz,
  created_at  timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL,
  UNIQUE (id, org_id),
  -- A temporary transfer always has an expiry, so its files always have a deletion date.
  CHECK (kind = 'persistent' OR expires_at IS NOT NULL)
);
CREATE INDEX share_transfers_due ON share_transfers (expires_at) WHERE status IN ('active','revoked','expired','deleted');

CREATE TABLE share_transfer_files (
  id                text NOT NULL PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  transfer_id       text NOT NULL,
  blob_id           text NOT NULL,
  name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  folder_path       text NOT NULL CHECK (length(folder_path) <= 500),
  ext               text NOT NULL,
  size              bigint NOT NULL CHECK (size > 0),
  status            text NOT NULL CHECK (status IN ('current','removed')),
  revision          integer NOT NULL CHECK (revision >= 1),
  replaced_at       timestamptz,
  replacement_note  text CHECK (length(replacement_note) <= 1000),
  created_at        timestamptz NOT NULL,
  updated_at        timestamptz NOT NULL,
  UNIQUE (id, org_id),
  FOREIGN KEY (transfer_id, org_id) REFERENCES share_transfers (id, org_id),
  FOREIGN KEY (blob_id, org_id) REFERENCES share_blobs (id, org_id)
);
CREATE INDEX share_transfer_files_transfer ON share_transfer_files (org_id, transfer_id);
CREATE INDEX share_transfer_files_blob ON share_transfer_files (org_id, blob_id) WHERE status = 'current';

CREATE TABLE share_links (
  id               text NOT NULL PRIMARY KEY,
  org_id           text NOT NULL REFERENCES organizations(id),
  salt             text NOT NULL,
  token_hash       text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  created_by       text NOT NULL REFERENCES users(id),
  label            text CHECK (length(label) <= 200),
  target_type      text NOT NULL CHECK (target_type IN ('transfer','document')),
  target_id        text NOT NULL,
  version_mode     text CHECK (version_mode IN ('latest','fixed')),
  version_id       text,
  permission       text NOT NULL CHECK (permission IN ('view','download','review')),
  password_hash    text,
  expires_at       timestamptz,
  max_downloads    integer CHECK (max_downloads BETWEEN 1 AND 100000),
  download_count   integer NOT NULL CHECK (download_count >= 0),
  restriction      text NOT NULL CHECK (restriction IN ('none','members','recipients')),
  recipients       jsonb NOT NULL CHECK (jsonb_typeof(recipients) = 'array' AND jsonb_array_length(recipients) <= 50),
  notify_on_access boolean NOT NULL,
  status           text NOT NULL CHECK (status IN ('active','suspended','revoked')),
  status_reason    text CHECK (length(status_reason) <= 600),
  operator_hold    boolean NOT NULL,
  created_at       timestamptz NOT NULL,
  updated_at       timestamptz NOT NULL,
  UNIQUE (id, org_id),
  FOREIGN KEY (version_id, org_id) REFERENCES share_versions (id, org_id),
  CHECK ((target_type = 'document') = (version_mode IS NOT NULL)),
  CHECK ((version_mode = 'fixed') = (version_id IS NOT NULL)),
  CHECK (permission <> 'review' OR restriction <> 'none'),
  CHECK (max_downloads IS NULL OR download_count <= max_downloads)
);
CREATE INDEX share_links_target ON share_links (org_id, target_id);

CREATE TABLE share_comments (
  id              text NOT NULL PRIMARY KEY,
  org_id          text NOT NULL REFERENCES organizations(id),
  document_id     text NOT NULL,
  version_id      text NOT NULL,
  link_id         text,
  author_user_id  text NOT NULL REFERENCES users(id),
  body            text NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
  page            integer CHECK (page BETWEEN 1 AND 100000),
  created_at      timestamptz NOT NULL,
  FOREIGN KEY (document_id, org_id) REFERENCES share_documents (id, org_id),
  FOREIGN KEY (version_id, org_id) REFERENCES share_versions (id, org_id),
  FOREIGN KEY (link_id, org_id) REFERENCES share_links (id, org_id)
);
CREATE INDEX share_comments_version ON share_comments (org_id, version_id);

CREATE TABLE share_reviews (
  id                text NOT NULL PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  document_id       text NOT NULL,
  version_id        text NOT NULL,
  link_id           text,
  reviewer_user_id  text NOT NULL REFERENCES users(id),
  decision          text NOT NULL CHECK (decision IN ('approved','changes_requested')),
  note              text CHECK (length(note) <= 1000),
  created_at        timestamptz NOT NULL,
  updated_at        timestamptz NOT NULL,
  UNIQUE (version_id, reviewer_user_id),
  FOREIGN KEY (document_id, org_id) REFERENCES share_documents (id, org_id),
  FOREIGN KEY (version_id, org_id) REFERENCES share_versions (id, org_id),
  FOREIGN KEY (link_id, org_id) REFERENCES share_links (id, org_id)
);
CREATE INDEX share_reviews_document ON share_reviews (org_id, document_id);

CREATE TABLE share_domains (
  id                  text NOT NULL PRIMARY KEY,
  org_id              text NOT NULL REFERENCES organizations(id),
  hostname            text NOT NULL UNIQUE CHECK (hostname = lower(hostname) AND length(hostname) BETWEEN 4 AND 253),
  verification_token  text NOT NULL CHECK (verification_token ~ '^[0-9a-f]{32}$'),
  status              text NOT NULL CHECK (status IN ('pending','verified')),
  created_at          timestamptz NOT NULL,
  verified_at         timestamptz,
  checked_at          timestamptz,
  UNIQUE (id, org_id)
);

CREATE TABLE short_links (
  id                text NOT NULL PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  kind              text NOT NULL CHECK (kind IN ('public','confidential')),
  domain_id         text,
  code              text CHECK (code ~ '^[a-z0-9-]{3,64}$'),
  salt              text,
  lookup_key        text NOT NULL UNIQUE,
  destination_type  text NOT NULL CHECK (destination_type IN ('external','share','request')),
  destination_url   text CHECK (length(destination_url) <= 2048 AND destination_url ~ '^https?://'),
  target_id         text,
  status            text NOT NULL CHECK (status IN ('active','suspended','revoked')),
  status_reason     text CHECK (length(status_reason) <= 600),
  operator_hold     boolean NOT NULL,
  expires_at        timestamptz,
  password_hash     text,
  require_auth      boolean NOT NULL,
  label             text CHECK (length(label) <= 200),
  folder            text NOT NULL CHECK (length(folder) <= 100),
  tags              jsonb NOT NULL CHECK (jsonb_typeof(tags) = 'array' AND jsonb_array_length(tags) <= 20),
  created_by        text NOT NULL REFERENCES users(id),
  created_at        timestamptz NOT NULL,
  updated_at        timestamptz NOT NULL,
  UNIQUE (id, org_id),
  FOREIGN KEY (domain_id, org_id) REFERENCES share_domains (id, org_id) ON DELETE SET NULL (domain_id),
  -- Public marketing links: readable code, external http(s) destination. Confidential links: no readable code,
  -- an unpredictable derived token (only its hash is stored), and an in-platform destination.
  CHECK (kind <> 'public' OR (code IS NOT NULL AND salt IS NULL AND destination_type = 'external' AND destination_url IS NOT NULL AND lookup_key LIKE 'p|%')),
  CHECK (kind <> 'confidential' OR (code IS NULL AND salt IS NOT NULL AND destination_type <> 'external' AND target_id IS NOT NULL AND domain_id IS NULL AND password_hash IS NULL AND NOT require_auth AND lookup_key ~ '^c\|[0-9a-f]{64}$'))
);
CREATE INDEX short_links_org ON short_links (org_id, created_at DESC);

CREATE TABLE short_link_destinations (
  id                text NOT NULL PRIMARY KEY,
  org_id            text NOT NULL REFERENCES organizations(id),
  short_link_id     text NOT NULL,
  destination_type  text NOT NULL CHECK (destination_type IN ('external','share','request')),
  destination_url   text,
  target_id         text,
  changed_by        text NOT NULL REFERENCES users(id),
  reason            text CHECK (length(reason) <= 500),
  created_at        timestamptz NOT NULL,
  FOREIGN KEY (short_link_id, org_id) REFERENCES short_links (id, org_id)
);
CREATE INDEX short_link_destinations_link ON short_link_destinations (org_id, short_link_id);

CREATE TABLE upload_requests (
  id               text NOT NULL PRIMARY KEY,
  org_id           text NOT NULL REFERENCES organizations(id),
  salt             text NOT NULL,
  token_hash       text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  created_by       text NOT NULL REFERENCES users(id),
  title            text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  instructions     text CHECK (length(instructions) <= 4000),
  requirements     jsonb NOT NULL CHECK (jsonb_typeof(requirements) = 'array' AND jsonb_array_length(requirements) BETWEEN 1 AND 20),
  deadline         timestamptz NOT NULL,
  max_file_bytes   bigint NOT NULL CHECK (max_file_bytes > 0),
  max_total_bytes  bigint NOT NULL CHECK (max_total_bytes >= max_file_bytes),
  password_hash    text,
  status           text NOT NULL CHECK (status IN ('open','closed','purged')),
  operator_hold    boolean NOT NULL,
  notify           boolean NOT NULL,
  delete_after     timestamptz,
  created_at       timestamptz NOT NULL,
  updated_at       timestamptz NOT NULL,
  UNIQUE (id, org_id)
);
CREATE INDEX upload_requests_due ON upload_requests (delete_after) WHERE status <> 'purged';

CREATE TABLE upload_submissions (
  id               text NOT NULL PRIMARY KEY,
  org_id           text NOT NULL REFERENCES organizations(id),
  request_id       text NOT NULL,
  secret_hash      text NOT NULL UNIQUE CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
  submitter_name   text NOT NULL CHECK (length(submitter_name) BETWEEN 1 AND 200),
  submitter_email  text CHECK (length(submitter_email) <= 254),
  status           text NOT NULL CHECK (status IN ('open','submitted')),
  created_at       timestamptz NOT NULL,
  submitted_at     timestamptz,
  UNIQUE (id, org_id),
  FOREIGN KEY (request_id, org_id) REFERENCES upload_requests (id, org_id)
);
CREATE INDEX upload_submissions_request ON upload_submissions (org_id, request_id);

CREATE TABLE upload_submission_files (
  id               text NOT NULL PRIMARY KEY,
  org_id           text NOT NULL REFERENCES organizations(id),
  request_id       text NOT NULL,
  submission_id    text NOT NULL,
  blob_id          text NOT NULL,
  requirement_key  text NOT NULL CHECK (requirement_key ~ '^[a-z0-9_-]{1,40}$'),
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  ext              text NOT NULL,
  size             bigint NOT NULL CHECK (size > 0),
  status           text NOT NULL CHECK (status IN ('current','removed')),
  created_at       timestamptz NOT NULL,
  FOREIGN KEY (request_id, org_id) REFERENCES upload_requests (id, org_id),
  FOREIGN KEY (submission_id, org_id) REFERENCES upload_submissions (id, org_id),
  FOREIGN KEY (blob_id, org_id) REFERENCES share_blobs (id, org_id)
);
CREATE INDEX upload_submission_files_request ON upload_submission_files (org_id, request_id);
CREATE INDEX upload_submission_files_blob ON upload_submission_files (org_id, blob_id) WHERE status = 'current';

-- Delivery receipts and link events: ids and coarse attributes only (no file names, titles, IPs or paths).
CREATE TABLE share_events (
  id             text NOT NULL PRIMARY KEY,
  org_id         text NOT NULL REFERENCES organizations(id),
  subject_type   text NOT NULL CHECK (subject_type IN ('share','request')),
  subject_id     text NOT NULL,
  kind           text NOT NULL CHECK (kind IN ('visit','access','view','download','acknowledge','password_failed','denied','comment','review','upload','submitted')),
  user_id        text,
  email          text CHECK (length(email) <= 254),
  file_id        text,
  bot            boolean NOT NULL,
  referrer_host  text NOT NULL CHECK (length(referrer_host) <= 253),
  declared_name  text CHECK (length(declared_name) <= 200),
  created_at     timestamptz NOT NULL
);
CREATE INDEX share_events_subject ON share_events (org_id, subject_type, subject_id, created_at DESC);
CREATE INDEX share_events_retention ON share_events (created_at);

CREATE TABLE share_stats (
  org_id         text NOT NULL REFERENCES organizations(id),
  subject_type   text NOT NULL CHECK (subject_type IN ('share','short','request')),
  subject_id     text NOT NULL,
  day            date NOT NULL,
  kind           text NOT NULL CHECK (length(kind) <= 40),
  bot            boolean NOT NULL,
  referrer_host  text NOT NULL CHECK (length(referrer_host) <= 253),
  count          bigint NOT NULL CHECK (count >= 0),
  PRIMARY KEY (org_id, subject_type, subject_id, day, kind, bot, referrer_host)
);
CREATE INDEX share_stats_day ON share_stats (day);

CREATE TABLE share_notifications (
  id            text NOT NULL PRIMARY KEY,
  org_id        text NOT NULL REFERENCES organizations(id),
  user_id       text NOT NULL REFERENCES users(id),
  kind          text NOT NULL CHECK (length(kind) <= 60),
  subject_type  text NOT NULL,
  subject_id    text NOT NULL,
  message       text NOT NULL CHECK (length(message) <= 1000),
  created_at    timestamptz NOT NULL,
  read_at       timestamptz
);
CREATE INDEX share_notifications_user ON share_notifications (org_id, user_id, created_at DESC);
CREATE INDEX share_notifications_retention ON share_notifications (created_at);

CREATE TABLE share_jobs (
  id            text NOT NULL PRIMARY KEY,
  org_id        text NOT NULL REFERENCES organizations(id),
  kind          text NOT NULL CHECK (kind IN ('scan','delete_blob','notify_email')),
  subject_id    text NOT NULL,
  payload       jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  run_after     timestamptz NOT NULL,
  attempts      integer NOT NULL CHECK (attempts >= 0),
  claim         text,
  locked_until  timestamptz,
  last_error    text CHECK (length(last_error) <= 100),
  created_at    timestamptz NOT NULL,
  CHECK ((claim IS NULL) = (locked_until IS NULL))
);
CREATE INDEX share_jobs_due ON share_jobs (run_after);

CREATE TABLE share_brands (
  id            text PRIMARY KEY REFERENCES organizations(id),
  org_id        text NOT NULL REFERENCES organizations(id) CHECK (org_id = id),
  display_name  text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  accent_color  text NOT NULL CHECK (accent_color ~ '^#[0-9a-f]{6}$'),
  updated_at    timestamptz NOT NULL
);

-- org_id is '' when the reported reference did not resolve (reports must not reveal whether links exist).
CREATE TABLE abuse_reports (
  id              text NOT NULL PRIMARY KEY,
  org_id          text NOT NULL,
  subject_type    text NOT NULL CHECK (subject_type IN ('short','share','request','unknown')),
  subject_id      text,
  reference       text NOT NULL CHECK (length(reference) <= 2048),
  category        text NOT NULL CHECK (category IN ('phishing','malware','spam','other')),
  details         text CHECK (length(details) <= 4000),
  reporter_email  text CHECK (length(reporter_email) <= 254),
  status          text NOT NULL CHECK (status IN ('open','actioned','dismissed')),
  created_at      timestamptz NOT NULL,
  resolved_at     timestamptz,
  resolved_by     text REFERENCES users(id),
  resolution      text CHECK (length(resolution) <= 500)
);
CREATE INDEX abuse_reports_status ON abuse_reports (status, created_at DESC);

CREATE TABLE share_usage (
  org_id  text NOT NULL REFERENCES organizations(id),
  period  text NOT NULL CHECK (period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
  metric  text NOT NULL CHECK (metric IN ('bandwidth_bytes','api_requests','processing_bytes','upload_bytes')),
  amount  bigint NOT NULL CHECK (amount >= 0),
  PRIMARY KEY (org_id, period, metric)
);

-- Password-attempt counters for links and upload requests (key = '<kind>:<id>'); purged by maintenance.
CREATE TABLE share_attempts (
  key           text PRIMARY KEY CHECK (length(key) <= 100),
  count         integer NOT NULL CHECK (count >= 0),
  locked_until  timestamptz,
  updated_at    timestamptz NOT NULL
);
CREATE INDEX share_attempts_updated ON share_attempts (updated_at);

COMMIT;
