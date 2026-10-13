# Sierra Business production licensing rollout

The Windows 0.33.0 client expects product code `sierra-business` and the boolean entitlement `business_write: true`. Local business sign-in and platform sign-in are separate. This guide prepares the existing platform APIs; it does not claim live provisioning or billing acceptance.

## Prepare the catalog

An existing platform operator can configure the catalog in the operator console or use `npm run provision:sierra`. The first operator must be created through the audited deployment bootstrap described in [first deploy](first-deploy.md), never through a public registration flag.

For the command, set `TRUST_API_ORIGIN` to the trusted API HTTPS origin and supply a short-lived authenticated operator session as `TRUST_OPERATOR_TOKEN` through secure environment settings. Obtain the session through the normal login/MFA flow. Never place credentials in command arguments, chat, source, result files or shell history. In a proxy-managed cloud environment, use the supported environment proxy; Node 24 supports `NODE_USE_ENV_PROXY=1`. The credential binding must be scoped only to the selected API hostname.

Run a preview first. These example settings are illustrative, not approved prices or commercial terms:

```sh
npm run provision:sierra -- --plan-code standard --tier standard --device-limit 1 --reason "prepare Sierra Business catalog"
```

Preview makes only authenticated GET requests and reports missing entries and existing IDs. Exit zero means inspection succeeded, not that production is ready: check the `ready` field. After reviewing the exact tier/device limit, use the same command with `--apply` to create missing entries. Run separately for each approved plan. Allowed tiers are trial, standard, professional, business and enterprise; the server's tier policy controls offline lease duration. The command does not change that policy or establish prices.

Every create uses the existing operator API and its mandatory reason/audit controls. A matching product/plan is reused. A mismatched tier, device limit or non-boolean/disabled `business_write` is refused; existing commercial access is never silently patched. Additional existing entitlements/capabilities are preserved. An inactive product may be hidden from the public catalog and cause a creation conflict; investigate through the operator rather than changing the code or retrying blindly.

Product and plan creation are separate audited transactions. A network failure can leave one or both committed. No POST is automatically retried. Run preview again to inspect authoritative state before rerunning apply. Concurrent creation conflicts require the same inspection. No license key, account token or raw provider error is printed by the command. `--allow-local` permits HTTP only for a loopback development API; never use it for production.

## Provision the customer

1. The customer registers/signs into the platform and supplies the exact organization ID; verify its ownership before provisioning. Registration does not grant operator privileges.
2. In the operator console, select the product and approved plan. Create the customer's subscription using its agreed trial/paid period, then issue the corresponding trial/subscription license. Do not mark a subscription paid based on a client checkout message. Perpetual licenses require an explicit commercial decision.
3. Record the one-time license key through the approved secure customer-delivery process. It cannot be retrieved later and must never enter logs, business backups or ordinary email templates.
4. In Sierra Business's Software license panel, activate using that customer's platform account, MFA where enabled, and the supplied key. Confirm `business_write` permits an authorized local posting; check that the business account's own permissions still apply.
5. Verify refresh, restart, offline use and signed expiry using an isolated acceptance company. Test suspension, reinstatement, renewal, deactivation and revocation without touching live business records. Confirm records, exports and backups remain available when writes are restricted.

The pinned public keys in the installer must match approved publisher keys. Signing private keys never belong in the desktop or this command. Use a trusted publisher configuration update for rotations. The Node SDK currently tolerates bounded five-minute lease clock skew; the C# client uses a hard signed expiry and a 60-second rollback watermark. Neither client can discover a new server revocation while disconnected; existing signed access is bounded by its verification policy.

## Evidence and outstanding work

`tests/integration/sierra-catalog.test.ts` verifies preview, audited apply, duplicate avoidance, partial/ambiguous recovery, ordinary-user refusal, plan mismatch refusal and credential transport boundaries. It provisions `sierra-business` against the real API and exercises activation, offline entitlement expiry, renewal, suspension/reinstatement and revocation through the Node SDK over loopback HTTP. It also runs against PostgreSQL and the least-privilege application role through the existing integration test projects.

This is automated development acceptance, not live Railway/Supabase or physical Windows acceptance. Live work needs an authenticated operator, approved commercial settings, a customer organization, and secure one-time-key delivery. Initial Paddle billing requires seller/payout approval and sandbox webhook/reconciliation acceptance. Windows publisher signing, installation/upgrade and the secure updater remain separate work.
