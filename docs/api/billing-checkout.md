# Initial Paddle Subscription Checkout

Billing is optional and fails closed on partial configuration. The implementation upgrades an existing subscription-backed license, including a trial, using a server-selected catalog price. Start a trial or have an operator issue the initial license before checkout. It does not create a second license or reveal another license key.

Configure `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, `PADDLE_ENVIRONMENT` (`sandbox` or `live`), `PADDLE_PAYMENT_URL`, and `PADDLE_PRICE_MAP`. The price map is a JSON object of local plan IDs to Paddle catalog price IDs. The payment URL is an approved HTTPS website page hosting Paddle.js. The API now supplies a `/checkout` page on a separate payment origin: set the payment URL to its public HTTPS URL, approve its domain with Paddle, and configure `PADDLE_CLIENT_TOKEN` with the public `test_`/`live_` client token matching the selected environment. The public checkout-options route exposes only that client token and environment, never API or webhook credentials. External approved payment pages remain supported without this optional client token. Production billing also requires `PUBLIC_ORIGIN` for the account portal, different from the payment origin. Add the payment hostname as a separate Railway custom domain pointing at the same service. The server serves checkout HTML only on the configured payment host and refuses the account portal/device scripts on that host. A different CSP alone would not isolate IndexedDB or other origin storage. Do not enter keys in chat or source. Confirm seller/payout eligibility and sandbox delivery before live operation.

The adapter uses Paddle's [official OpenAPI](https://github.com/PaddleHQ/paddle-openapi/blob/main/v1/openapi.yaml). The transaction-create operation documents catalog items, automatic collection, custom data and the approved payment URL. It does not document an idempotency header. The server therefore reserves one durable intent and makes one creation attempt; it never retries an ambiguous submission automatically.

## Customer Flow

1. Sign in and select the correct organization.
2. Open license details. Configured plans are available through `GET /v1/billing/catalog`; disabled billing returns an empty list.
3. An organization admin/owner creates checkout using `POST /v1/organizations/{orgId}/licenses/{licenseId}/checkout` with `{ plan_id, idempotency_key }`. Persist one 16–128 character operation ID per logical checkout and reuse it on retries. Client price, amount and entitlement fields are rejected.
4. If status is `ready`, follow `checkout_url` to review the recurring price and terms before paying. `submitting`/`uncertain` requires waiting or support; another POST does not create a second transaction.
5. `GET` on the same path reports checkout and current subscription state to an organization admin/owner. Ordinary members retain license reads but cannot read payment links. The portal and SDK expose both operations. Checkout creation, a return URL, and the payment-page UI are never proof of settlement.

There is one checkout intent per license. Duplicate recurring subscriptions, plan-change checkout and replacing a canceled provider subscription are deliberately unavailable until a separate transition/reconciliation workflow exists. The backend does not automatically refund purchases or charge invoices.

## Signed Notifications

Configure Paddle's notification destination as `/v1/billing/webhooks/paddle` on the deployed API origin. The route preserves original JSON bytes and verifies the `Paddle-Signature` timestamp/HMAC. No session token authorizes this route. Subscribe to `transaction.completed`, `subscription.activated`, `subscription.updated`, `subscription.past_due`, `subscription.paused`, `subscription.canceled`, and `subscription.resumed`.

A mapped completed recurring transaction establishes provider subscription identity and atomically updates the existing subscription's current plan and paid-period boundary. Subsequent supported notifications update that binding. Active state requires a future period end. Past-due/paused/canceled states follow existing licensing restrictions; server state takes effect on future requests/refresh, while previously issued offline leases remain time-bounded. License revocation/suspension is never cleared by payment.

Event identity and body digests prevent altered replays. Older events are recorded as ignored. Equal-time distinct events, unknown intent/subscription mappings, changed catalog prices, provider trials or malformed paid periods fail closed for operator investigation. Irrelevant event types are acknowledged without granting access. Receipts, subscription changes and audit append commit together. Provider bodies, payment/customer data and secrets are not stored in the event ledger or logged.

## Uncertain Outcomes and Support

For an uncertain transaction creation, an operator finds the candidate transaction in Paddle and calls `POST /v1/admin/organizations/{orgId}/licenses/{licenseId}/checkout/reconcile` with `{ transaction_id, reason }`. The adapter retrieves and checks its server-created intent, catalog price, quantity, automatic collection and bound payment URL before recording it. This endpoint reconciles transaction identity; it does not independently settle a subscription or resolve equal-time commercial-state conflicts. Investigate those conflicts in Paddle and use existing audited subscription administration or a subsequent authoritative provider notification. Do not resubmit the checkout to work around uncertainty.

Before deploying, apply migration `0009_billing_checkout` and app grants. Verify sandbox checkout, signed notification delivery, duplicates, out-of-order events, revocation and uncertain-outcome recovery. Local fake provider responses test control flow; they do not establish live payments, seller approval or payout availability.
