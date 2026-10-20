# Application management in the Warrior dashboard

This release exposes the existing OPS-002/003 management APIs through **Applications**
in the signed-in portal. It does not add event collection, monitoring health, alerts,
independent probes or an application integration.

## Use the dashboard

1. Sign in and select the correct workspace. Only organization owners/admins can
   manage its applications. A platform operator needs that same organization role.
2. Open **Applications → Register application**. Choose a permanent lowercase code,
   an organization member as owner, criticality, optional licensing product and reason.
   Linking a product does not grant commercial access or monitoring permissions.
3. Open the application and add a development, staging or production environment.
   Open it to add components and select dependencies from that same environment.
4. Use settings to update ownership, criticality, product mapping, component kind
   or dependencies. Every write includes the displayed version and a reviewed reason.
   If it conflicts, use **Refresh**, review current data and submit deliberately again.
5. Disable temporarily or archive permanently using the lifecycle form. Archive
   requires confirmation and retains evidence. Note the record ID before leaving;
   use **Open retained record** at its parent to reopen an archived record. The server
   hides archives from ordinary lists and never allows code reuse.
6. Enroll authenticator MFA under **Account** before managing credentials. In an
   environment, issue a 1–90-day credential, rotate with 0–3600 seconds of overlap,
   or revoke permanently. Each attempt needs a fresh authenticator code and reason.
   Active limits, overlap, freeze, scope and lifecycle restrictions remain server-owned.
   Revocation remains accessible with disabled/archived ancestors. The client clock's
   expiry label is informational; the server determines validity.
7. Save a newly issued secret from its one-time dialog into a server secret manager.
   Closing the dialog, navigating, switching workspace or leaving the page clears it.
   The portal does not store it in local/session storage or IndexedDB. A late response
   cannot display a secret in another workspace. If the response is lost, refresh
   metadata and rotate/revoke with a fresh factor; an old secret cannot be retrieved.
   Do not connect a production sender until OPS-004 and its receiving integration exist.

## Rollout and limits

The existing backend flags must be true: `OPERATIONS_INVENTORY_ENABLED` and
`OPERATIONS_CREDENTIALS_ENABLED`. Credentials require the existing stable
`MFA_ENCRYPTION_KEY`. Do not replace the key. Schema migrations 0017/0018 and
application-role grants are prerequisites, already enabled in the production rollout
recorded in the program handoff. No new secret, provider account or migration is needed
for this UI. A disabled rollout shows an unavailable message, not fake monitoring data.

Use the normal checked PR/CI/default-branch deployment. Railway's existing service has no watch-path filter (all-source default).
The earlier filters caused skipped builds and were removed; prove any future filter
change against a real source update. Observe terminal SUCCESS and health-check evidence;
local browser tests do not establish an authenticated production workflow.

Rollback the portal source if necessary; retain the backend schema and audit evidence.
If backend enablement must also be rolled back, disable credential management before
inventory. Do not reset licensing, alter membership, drop history or replace secrets.

## Verification

- `npm run check`: formatting, lint/boundaries, types and the existing unit suites.
- `npx playwright-core install --with-deps chromium`, then `npm run test:portal`.
  A preinstalled browser can be selected with `CHROMIUM_PATH=/usr/bin/chromium`.
  Tests run a disposable local API/store with fake identities, real authenticator
  factors and a real browser under the existing CSP. They do not send emails or
  issue production credentials.
- Browser coverage includes nested inventory, dependencies, select-value preservation,
  issuance/rotation/revocation, disabled and archived parents, retained-record lookup,
  cursor pagination, MFA replay refusal, disabled rollout, mobile overflow, modal
  cleanup, absence of browser-storage secrets and a delayed response/workspace race.
- Applicable PostgreSQL regression: `npm run test:db --
services/platform-api/test/operations.test.ts
services/platform-api/test/operations-credentials.test.ts` against a throwaway DB.
  No backend authority, schema, transaction or retention behavior changes in this UI.

## Respond to an automatic alert

In an application's environment, find **Automatic alerts**, then choose **Open
response guide** on the affected rule. The guide identifies the component and
shows the rule's reviewed scanner, converter, storage, email or general response
instructions, recovery checks and escalation to the application owner/provider.
Opening or closing a guide makes no API mutation. No command, URL, email or
infrastructure change is executed. Unknown guide codes have no action.

Use **Manage incident** to assign/acknowledge a responder and record resolution.
Carry out provider actions separately through approved private administration.
Require fresh healthy evidence and the guide's synthetic application check before
resolving. Resolution does not repair health; maintenance only mutes notifications.
Scanner failures must never bypass scanning, backup reports never prove restoration,
and email troubleshooting must preserve account confirmation. Never paste secrets,
customer documents, confirmation links or recipient addresses into incident evidence.
