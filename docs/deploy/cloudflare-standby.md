# Cloudflare alternative deployment

## Prepared topology and limits

`infrastructure/cloudflare/` provides a Cloudflare Worker plus one Durable
Object-managed Container. The container uses the existing root Dockerfile and
Node 22/Fastify/PostgreSQL application; this is not a Pages/static deployment or
an attempt to run the API directly in the Workers isolate. The pinned Wrangler
and Containers SDK have their own package lock. A paid account with Containers
access, Docker, Cloudflare deployment permissions and runtime secrets are required
for a real deployment. Verify current plan availability and prices in your account.

Preparation creates no Cloudflare resources and changes no DNS or production
traffic. Defaults disable traffic, workers.dev and preview URLs; no routes are
committed. The Worker returns a fixed no-store 503 until explicitly enabled with a
matching host and valid runtime settings. It routes every accepted request to one
fixed container identity, never a tenant/path-selected instance. Background workers
keep that container active during HTTP inactivity; budget for an active container.
Provider restarts and capacity outages remain possible. This is not automatic
failover or a high-availability guarantee.

## 1. Build and review

From the repository root:

```sh
npm ci
npm ci --ignore-scripts --prefix infrastructure/cloudflare
npm run check
npm run bundle --prefix infrastructure/cloudflare
docker build -t warrior-cloudflare:REVIEWED_COMMIT .
```

The bundle command validates/bundles the Worker without building, uploading or
updating Containers (`--dry-run --containers-rollout none`). The separate Docker
build is required before live deployment. CI validates this Worker bundle and
its dependency audit; that is not evidence of a Cloudflare container start.

## 2. Database and secrets

Keep the existing Supabase/PostgreSQL database, private schema, verified CA and
least-privilege application role. Cloudflare Containers connect over public TLS;
Railway private DNS is not reachable. Hyperdrive, D1 and a new empty database are
not substitutions for this application's current PostgreSQL semantics.

Use the same reviewed application settings as the current deployment. Preserve
license-signing material, license pepper, pseudonym key, MFA key, encrypted-mail
key and sharing key when continuing to use the same data. Generating replacements
can invalidate licenses, MFA, encrypted queues or links. Do not paste secrets into
chat, commit them, bake them into images or use Docker build arguments for them.

Install each runtime setting as a separate Worker secret binding. Each binding
has Cloudflare’s 5 KB value limit; oversized CA chains require a separately reviewed
configuration change rather than truncation or disabling TLS verification. Required keys are `DATABASE_URL`, `DATABASE_CA_PEM`,
`DB_SCHEMA`, `LICENSE_SIGNING_KEY_PEM`, `LICENSE_KEY_PEPPER`, `PSEUDONYM_KEY` and
`PUBLIC_ORIGIN`. Review the explicit allowlist in `config.mjs` for optional feature,
MFA, mail, witness, WebAuthn, storage and provider settings; mirror existing flags
rather than enabling unconfigured features. Preserve full multiline PEM values. The application still performs its normal production validation.

The gateway forces production mode, PostgreSQL persistence/shared rate limiting,
port 8080 and trusted edge forwarding. It rejects owner/migration settings,
transport/superuser bypasses and malware-scan bypasses. Migration credentials must
never be stored in Worker bindings or passed to the runtime container.

Run `node tools/predeploy.ts` from the reviewed image in a trusted one-off runner
before cutover, using a separately protected environment file with the migration
connection, app connection, APP_DB_ROLE, schema and CA. Verify all migrations,
grants and database-profile checks complete. Cloudflare has no Railway-style
predeploy hook here, and container startup must not run DDL. Keep the owner secret
only in that one-off runner; do not publish or retain its environment file.

Install the reviewed runtime bindings through the Cloudflare secret dashboard,
or use the interactive command once per setting (it prompts for the value):

```sh
cd infrastructure/cloudflare
npx wrangler secret put DATABASE_URL
# Repeat for the other required and reviewed optional setting names.
```

If Wrangler requires an initial Worker deployment before accepting secrets, deploy
with the committed disabled-traffic/no-route configuration first. No request can
start the application through that disabled gateway. Installing a secret is not a
successful container-start or database acceptance test.

## 3. Staging and provider dependencies

Use a disposable staging database/schema and separate test secrets for the first
trial; do not run a production-connected shadow instance casually. Configure a
controlled HTTPS hostname in PUBLIC_HOST and the same exact HTTPS origin, without
trailing slash, in the PUBLIC_ORIGIN secret binding. Add an explicit Worker route or
custom domain in the reviewed Cloudflare configuration. Use Cloudflare Access for
operator-only staging; verify that no alternate public route bypasses it.

Do not switch a permanent WebAuthn origin/RP ID casually: existing passkeys are
bound to the original domain. Verify allowed origins, session cookies, email and
webhook destinations, sharing/content host separation and R2 CORS before cutover.
Preserve the canonical production origin if moving traffic for the existing app.

A Railway-private ClamAV hostname is rejected. Before enabling sharing, provision
and verify a scanner reachable through an approved private/authenticated network
path from Cloudflare; never expose an unauthenticated public clamd port or disable
scanning. Verify provider access and email with controlled recipients only. R2,
Supabase, the scanner and external witness retain their own availability risks.
This alternative does not provision or duplicate them.

## 4. Controlled activation and rollback

After staging configuration and one-off predeploy verification, change the reviewed
TRAFFIC_ENABLED variable to the exact string `true`, configure the reviewed host
route, and deploy from this directory:

```sh
npm run deploy
```

This command builds/publishes the Worker and Container and can incur charges.
It is an explicit activation step, not part of the preparation/dry-run commands.
Confirm account/route/image identity before executing it. There is no automatic
DNS change, traffic switch or fallback to Railway in this scaffold.

Before switching production traffic, verify `/healthz` and `/readyz`, served source
bytes, sign-in/MFA, scoped inventory/credential reads, an authorized disposable
write and the relevant synthetic incident/recovery and scanner-refusal flows.
Record the exact image/commit and actual evidence. A green Worker build cannot
establish these results. Check that spoofed forwarding headers cannot evade rate
limits and that an invalid host returns 503.

Drain traffic and stop the old host's application/background workers before
activating the production-connected alternative. Do not let both hosts run their
maintenance, anchoring and delivery workers unless their concurrent behavior and
aggregate database pools have been explicitly verified. Start with one container;
the singleton/max_instances limit does not eliminate overlap during provider
rollouts, so verify fencing/idempotency before approving rolling production use.
There is no autonomous worker-leader election or cross-provider fencing added here.

For rollback, disable new standby traffic, drain/stop its running application and
background workers through provider controls, and verify they stopped before
restarting Railway and restoring the previous traffic route. Setting TRAFFIC_ENABLED
false blocks requests but alone does not stop an already running container's workers
or charges. Never drop the shared database or undo migrations as an automatic rollback.
Keep previous images, secrets and audit history. Verify readiness and synthetic
customer flows after either direction of cutover.

The independent GitHub availability observer still targets Railway's hostname.
Review its fixed destinations when the canonical deployment changes; otherwise a
green old-host check says nothing about Cloudflare. A shared database is still a
single failure domain; database failover, PITR/restore and audit witnessing remain
separate exercises.
