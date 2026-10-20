# First deploy checklist (any container host; Railway notes inline)

On Railway with Cloudflare R2, follow [railway.md](railway.md): `railway.json` automates the build, pre-deploy migrations/grants and the health check.

For Sierra Business catalog preparation, customer provisioning and activation acceptance, follow the [Sierra Business rollout](sierra-business-rollout.md) after completing the platform setup below.

Status: written from the code and configuration guards; **not yet exercised on a live host**. The Dockerfile has never been
built in CI or on a Docker daemon (see the status document). Treat the first deploy as a rehearsal.

## A. Before the service starts

1. Database prepared per [supabase.md](supabase.md): schema + `trust_app` role, `npm run migrate`, `npm run db:grants`,
   and `npm run db:check` printing `OK` for the **application** connection string.
2. Generate secrets (password manager or `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`):
   `LICENSE_KEY_PEPPER` and `PSEUDONYM_KEY` (≥ 32 chars each; **never change the pepper later**: it would invalidate every license key).
3. Generate the lease-signing key (Ed25519, PKCS#8 PEM) and keep a **backup of it in a separate secret store**:
   `node -e "const {generateKeyPairSync}=require('crypto');console.log(generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'}))"`.
   Losing it means every device must re-activate; leaking it means anyone can mint leases.

## B. Service variables (Railway: service → Variables; mark secrets as such)

| Variable                                                                                                                     | Value                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NODE_ENV`                                                                                                                   | `production` (the image defaults to `development`)                                                                                                                                                                                                                                                                                 |
| `PERSISTENCE`                                                                                                                | `postgres`                                                                                                                                                                                                                                                                                                                         |
| `DATABASE_URL`                                                                                                               | the `trust_app` string, `?sslmode=require`. **On Railway use the Session pooler address** (user `trust_app.<project-ref>`): the direct `db.<ref>.supabase.co` address is IPv6-only and Railway fails with `ENETUNREACH`                                                                                                            |
| `DB_SCHEMA`                                                                                                                  | `trust`                                                                                                                                                                                                                                                                                                                            |
| `DATABASE_CA_PEM`                                                                                                            | **Supabase: needed.** The CA certificate text from Supabase (dashboard → Database settings → SSL configuration → download), the whole `-----BEGIN CERTIFICATE-----` block. The driver verifies the server fully and Supabase certificates are not publicly trusted. On hosts with files, `DATABASE_CA_FILE` (a path) works instead |
| `LICENSE_KEY_PEPPER`, `PSEUDONYM_KEY`                                                                                        | from step A2                                                                                                                                                                                                                                                                                                                       |
| `LICENSE_SIGNING_KEY_PEM`                                                                                                    | the PEM from step A3 (multi-line value)                                                                                                                                                                                                                                                                                            |
| `TRUST_PROXY`                                                                                                                | `1` — the host's proxy is in front; without it every client looks like one IP to the rate limiter                                                                                                                                                                                                                                  |
| `HOST` / `PORT`                                                                                                              | `0.0.0.0` (image default) / the platform's `PORT` (Railway injects it; the app reads it)                                                                                                                                                                                                                                           |
| `AUDIT_ANCHOR_URL` (+ `AUDIT_ANCHOR_TOKEN`)                                                                                  | the independent witness; **or** `AUDIT_ANCHOR_DISABLED=true` to accept R-13 knowingly for a pilot                                                                                                                                                                                                                                  |
| `DB_POOL_MAX`                                                                                                                | `5`–`10`                                                                                                                                                                                                                                                                                                                           |
| Health check path: `/healthz`. Run **one** instance first. Do not set `DATABASE_INSECURE_TRANSPORT` or `DB_ALLOW_SUPERUSER`. |

## C. After the first start

1. Logs: no "refusing"/"must" errors; warnings from the database-role check should be empty.
2. `curl https://<your-domain>/healthz` → `{"status":"ok"}`; `curl …/v1/keys/trust-bundle` returns a public key (never a private one).
3. **Create the first operator.** Register the account through the API, then promote it from a shell that has the app's `DATABASE_URL`
   (Railway: a one-off command or `railway ssh`; or your own machine):
   ```sh
   curl -X POST https://<domain>/v1/auth/register -H 'content-type: application/json' \
        -d '{"email":"you@example.com","password":"<long passphrase>"}'
   DATABASE_URL=… DB_SCHEMA=trust npm run bootstrap:operator -- --email you@example.com --reason "initial operator"
   ```
   Then log in (`POST /v1/auth/login`) and use the token as `Authorization: Bearer …` on `/v1/admin/*`.
4. Provision a first product, plan, subscription and license through the admin API (`docs/api/openapi.yaml`), then run a real
   activation with the SDK/test client and a refresh. Check `GET /v1/admin/audit/verify` → `ok: true`.
5. Publish an audit anchor (`POST /v1/admin/audit/anchors`) if a witness is configured; check `GET /v1/admin/metrics`.
6. Alerts to set: health check failing, `audit_anchor_last_success_age_seconds`, `rate_limit_fallback_total`, `db_pool_waiting`,
   HTTP 5xx rate (see the capacity runbook).

## D. Before real customers

Backup + restore drill (then `tools/verify-anchor.ts` on the restored copy); a real witness; a load test from the same region;
rotate the owner password out of any shell history; decide who may reach the owner credential (R-13).

## Optional email recovery

For durable delivery, run migration `0010_identity_mail_outbox` and `npm run db:grants` from the new source/image using the owner connection before deploying the corresponding application build. The currently running older image does not contain that migration or its grant policy. The startup guard requires the schema to match the build. Generate a **separate**, stable random 32-byte hex `MAIL_OUTBOX_ENCRYPTION_KEY` in your secret manager; store it as a server environment secret alongside the existing Resend configuration. Do not reuse the MFA key or put any key in source/chat. With this key enabled, reset/verification emails are encrypted and queued atomically, retried after outages/restarts and discarded when their original links expire. Without it, the previous direct-delivery mode remains and does not guarantee retries. See [outbox design, concurrency and rotation limits](../adr/ADR-020-identity-mail-outbox.md).

Run migration `0006_identity_recovery` and then `npm run db:grants` before deploying the browser/recovery release. Do not change existing signing keys or the license-key pepper.

To enable password reset and email verification, configure `RESEND_API_KEY` securely, `EMAIL_FROM` with a verified sending domain, and `PUBLIC_ORIGIN` with the exact public HTTPS origin (for example, `https://trustplatform-api-production.up.railway.app`). The origin must have no credentials, extra path or query. With no email configuration, the portal and existing login continue working; recovery stays disabled. Do not set synthetic development keys in production.

Delivery is asynchronous and provider failures are audited without message contents. A durable encrypted outbox is still pending; shutdown flushes in-flight sends, but a crash can require the user to request another link. Email verification is recorded, not yet a compulsory login gate.

## Authenticator MFA rollout (ADR-017)

Before deploying the MFA release, apply migration `0007_authenticator_mfa` with the owner migration connection (`npm run migrate`), then run `npm run db:grants` with `APP_DB_ROLE` and verify `npm run db:check` using the application connection. The application deliberately refuses an outdated schema; use a migration/pre-deploy job, not the API start command.

Set `MFA_ENCRYPTION_KEY` securely in Railway to a newly generated random 32-byte hex key. Generate it in your password manager or trusted local secret tooling; never paste it into chat, source control or logs. Keep this key stable across instances/redeployments and back it up separately from the database. A lost/replaced key blocks MFA login, including recovery codes. MFA setup stays unavailable when the key is absent; ordinary accounts without MFA continue to work.

Enroll every operator from **Account → Set up authenticator**, confirm a code, save the ten recovery codes offline, then sign in with a new code. Confirmation revokes all sessions and consumes the current code, so wait for the next code or use a recovery code. Enable `REQUIRE_OPERATOR_MFA=true` after enrollment. This setting requires the encryption key and blocks administration for unenrolled operators while still allowing enrollment. Default false supports staged rollout. Disabling MFA requires password, unused factor and a reason, and revokes all sessions. Password reset does not disable MFA.

Privileged operations (ADR-022): once at least **two** operators have enrolled MFA, set `PRIVILEGED_DUAL_CONTROL=true`
(requires `MFA_ENCRYPTION_KEY`). License revocation then needs a second operator's approval; operator promotion and
lifting a freeze always do. New operators can now be promoted with an `operator.grant` request instead of shell access.
Break-glass (self-approval when nobody else is available) works only when external audit anchoring is configured.

Passkeys (ADR-023): set `WEBAUTHN_RP_ID` to your domain (for example `rokela.example`) and `WEBAUTHN_ORIGIN` to the
exact portal address (for example `https://app.rokela.example`, no trailing slash; it must be on that domain).
Optional `WEBAUTHN_RP_NAME` is what phones show (default "Rokela Bai Bureh Warrior"). Changing the RP ID later makes
every registered passkey stop working, so pick the long-term domain. Users then add passkeys under **Account →
Passkeys** and get a **Sign in with a passkey** button.

Device trust (ADR-026) starts in `DEVICE_POLICY=observe`: postures are computed and shown in device passports but
nothing is blocked. Review `device.posture_changed` audit events for a few weeks, then set `DEVICE_POLICY=enforce`
to require re-activation for suspected clones and to shorten offline leases for devices under attack.

## Monthly Quota Rollout (ADR-018)

Apply migration `0008_monthly_quotas` with the schema owner, then run `npm run db:grants` with `APP_DB_ROLE`. The new `quota_charges` table requires SELECT/INSERT for the application role; migration alone does not grant these permissions. Verify `npm run db:check` with the application connection before deployment. A Railway pre-deploy job should run `npm run migrate && npm run db:grants` with the existing owner connection, schema and app-role settings; the API start command remains unchanged.

Numeric `*_monthly` entitlements enable per-license calendar-month metering. Existing monthly entitlements now appear in the portal's license details. No new provider secret is required. See [Monthly Quota Accounting](../api/monthly-quotas.md) for consumption semantics and the execution boundary.

## Billing and Product Update Rollout (ADR-019)

Apply migration `0009_billing_checkout`, then run owner-side `npm run db:grants` with `APP_DB_ROLE`. The application needs SELECT/INSERT/UPDATE on checkout intents and SELECT/INSERT on immutable event receipts. Run `npm run db:check` with the application connection.

Billing stays disabled until the complete Paddle setting group is present. Configure sandbox credentials, an approved payment hostname separate from `PUBLIC_ORIGIN`, server-owned price mapping and signed notification destination first. To use the built-in payment page, add that payment hostname to Railway, set `PADDLE_PAYMENT_URL` to its HTTPS `/checkout` URL, and set the public `PADDLE_CLIENT_TOKEN` for sandbox/live mode. Prove a complete sandbox payment and uncertain-outcome recovery before live mode. See [billing checkout](../api/billing-checkout.md). Seller/payout availability for Sierra Leone must be confirmed with Paddle.

The Node SDK now supports Windows DPAPI protected storage and native asynchronous key providers. DPAPI is not TPM attestation. Signed updates require an independently trusted root, release signing custody, root-approved immutable hosting, and a Windows installer/recovery flow. See [secure updates](../api/secure-updates.md). No update-signing secret is required by the API server; production signing belongs in the release pipeline, separate from license signing.

## File sharing rollout (ADR-021)

Sharing is **off in production** until configured. Apply migration `0011_file_sharing`, then `npm run db:grants` and
`npm run db:check`. Set:

- `SHARING_STORAGE=s3`, `SHARING_S3_ENDPOINT` (e.g. `https://<account>.r2.cloudflarestorage.com`), `SHARING_S3_REGION`
  (`auto` for R2), `SHARING_S3_BUCKET`, `SHARING_S3_ACCESS_KEY_ID`, `SHARING_S3_SECRET_ACCESS_KEY` (secrets; a
  bucket-scoped token with object read/write only).
  For providers recommending virtual-host addressing, set the endpoint to
  `https://<bucket>.<provider-host>`: an endpoint hostname beginning with the exact
  configured bucket followed by a dot omits the bucket from request paths. Other
  endpoints retain path-style addressing. Use the provider's recommended endpoint
  and verify its actual CORS responses, not just the stored CORS configuration.
- `SHARING_SECRET` (≥ 32 random characters, distinct from other keys; changing it changes every share URL).
- `SHARING_PUBLIC_ORIGIN` (or `PUBLIC_ORIGIN`), optional `SHARING_SHORT_ORIGIN` for a short-link host.
- `CLAMD_HOST`/`CLAMD_PORT` for a private ClamAV daemon (StreamMaxLength ≥ the largest plan file size), or
  `SHARING_MALWARE_SCAN_DISABLED=true` to accept structural checks only.
- Optional: `SHARING_BLOCKED_HOSTS`, `SHARING_EVENT_RETENTION_DAYS` (default 180), `SHARING_JOB_INTERVAL_SECONDS`
  (default 5), `RATE_LIMIT_SHARING` (default 60/min per IP).

Bucket: private, versioning off, no public access, CORS allowing `PUT` and `GET` from the portal origin only with
`ETag` exposed, lifecycle rule aborting incomplete multipart uploads after 2 days (see
[sharing-retention](../security/sharing-retention.md)). Grant plan entitlements (`share_*`, see
[api/sharing.md](../api/sharing.md)) for paid features. Before customers: run one upload/download against the live
bucket, confirm an EICAR file is rejected, and confirm expired temporary files disappear from the bucket.
