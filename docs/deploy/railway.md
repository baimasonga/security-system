# Railway + Cloudflare R2 deployment

Status: configuration written and checked by `tests/deploy-config.test.ts`; **not yet exercised on a live Railway
project**. Treat the first deploy as a rehearsal and follow [first-deploy.md](first-deploy.md) for the platform
checks (operator bootstrap, audit, backups).

## What is automated

| File                                                                                             | Railway service       | Effect                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------------------ | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`railway.json`](../../railway.json)                                                             | API (repository root) | Builds `Dockerfile`; before every deploy runs `migrate` → `db-grants` → `db-check` (a failure stops the deploy, the old version keeps serving); health check `/healthz`; one replica; restart on failure |
| [`infrastructure/railway/clamav/railway.json`](../../infrastructure/railway/clamav/railway.json) | ClamAV (private)      | Builds the official ClamAV image with `StreamMaxLength 300M`                                                                                                                                             |

## 1. Cloudflare R2 (object storage)

1. Create a **private** bucket (e.g. `rokela-shares`): no public access, no `r2.dev` URL.
2. _Manage R2 API Tokens → Create token_: **Object Read & Write**, limited to that bucket. Keep the Access Key ID and
   Secret Access Key in a password manager. Endpoint: `https://<account-id>.r2.cloudflarestorage.com`.
3. Bucket → Settings → **CORS policy** (your real portal origin):
   ```json
   [
     {
       "AllowedOrigins": ["https://app.yourdomain.com"],
       "AllowedMethods": ["PUT", "GET"],
       "AllowedHeaders": ["content-type", "content-length"],
       "ExposeHeaders": ["ETag"],
       "MaxAgeSeconds": 600
     }
   ]
   ```
4. Bucket → **Object lifecycle rules**: abort incomplete multipart uploads after 2 days. Leave versioning off
   ([retention policy](../security/sharing-retention.md)).

## 2. Railway project

1. **Database**: add Railway PostgreSQL (or keep Supabase, [supabase.md](supabase.md)). Create the least-privilege
   application role with [supabase-setup.sql](supabase-setup.sql) (works on any PostgreSQL), and set its password in a
   separate statement.
2. **ClamAV service**: _New → GitHub repo_ (same repository), then in the service's Settings set _Config file path_ to
   `infrastructure/railway/clamav/railway.json`. Give it about 2 GB of memory. Do **not** generate a public domain.
   Note its private hostname (`<name>.railway.internal`).
3. **API service**: _New → GitHub repo_, branch = the repository's default branch. `railway.json` at the root is picked
   up automatically. Add a custom domain (e.g. `app.yourdomain.com`); Railway issues the certificate.

## 3. API service variables

Mark secrets as secret. Platform variables are described in [first-deploy.md §B](first-deploy.md#b-service-variables-railway-service--variables-mark-secrets-as-such).

| Variable                                                         | Value                                                                                             |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `NODE_ENV`                                                       | `production`                                                                                      |
| `PERSISTENCE`                                                    | `postgres`                                                                                        |
| `DATABASE_URL`                                                   | application role connection (`?sslmode=require`)                                                  |
| `DATABASE_MIGRATE_URL`                                           | **owner** connection, used only by the pre-deploy step (migrations and grants)                    |
| `APP_DB_ROLE`                                                    | the application role name (e.g. `trust_app`)                                                      |
| `DB_SCHEMA`                                                      | e.g. `trust`                                                                                      |
| `LICENSE_KEY_PEPPER`, `PSEUDONYM_KEY`, `LICENSE_SIGNING_KEY_PEM` | see first-deploy §A                                                                               |
| `TRUST_PROXY`                                                    | `1`                                                                                               |
| `AUDIT_ANCHOR_URL` or `AUDIT_ANCHOR_DISABLED`                    | witness URL, or `true` for a pilot                                                                |
| `SHARING_STORAGE`                                                | `s3`                                                                                              |
| `SHARING_S3_ENDPOINT`                                            | `https://<account-id>.r2.cloudflarestorage.com`                                                   |
| `SHARING_S3_REGION`                                              | `auto`                                                                                            |
| `SHARING_S3_BUCKET`                                              | `rokela-shares`                                                                                   |
| `SHARING_S3_ACCESS_KEY_ID`, `SHARING_S3_SECRET_ACCESS_KEY`       | from the R2 token                                                                                 |
| `SHARING_SECRET`                                                 | ≥ 48 random characters, distinct from other keys (changing it later invalidates every share link) |
| `SHARING_PUBLIC_ORIGIN`                                          | `https://app.yourdomain.com`                                                                      |
| `CLAMD_HOST`, `CLAMD_PORT`                                       | `<clamav-name>.railway.internal`, `3310`                                                          |

Generate random secrets with `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`.

If `DATABASE_MIGRATE_URL` or `APP_DB_ROLE` is missing, the pre-deploy step fails and the deploy stops; that is
intended (the application role cannot run migrations).

## 4. Smoke test

1. Deploy logs: pre-deploy prints applied migrations, grants and `OK` from the role check; no startup refusals.
2. `https://app.yourdomain.com/healthz` → `{"status":"ok"}`.
3. Create the first operator ([first-deploy §C3](first-deploy.md#c-after-the-first-start)).
4. **Files & links**: upload a small PDF → _processing_ → _available_; download it. (First real check of R2.)
5. Upload the EICAR test string saved as `.txt` → must end _rejected_ (proves ClamAV is reachable; if the ClamAV
   service is down, files stay _processing_ and are finally rejected, never served).
6. Create a temporary transfer expiring soon; after expiry, its object disappears from the bucket.

If step 4 fails, the API logs show `object storage … failed` with the provider's error code (never the credentials).
