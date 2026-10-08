# First deploy checklist (any container host; Railway notes inline)

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
