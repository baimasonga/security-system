# Mobile app analytics implementation plan

Status: requested 25 October 2026; first slice reads GitHub APK metadata.
Mobile usage/device/country collection is not enabled.
Owner request: monitor mobile downloads, usage, location and devices in Warrior.
Confirmed: Rokela PDF, baimasonga/Rokelapdf-online, Capacitor Android app in mobile/.
The public /android page links directly to the android GitHub release APK.
User selected country via IP only: no GPS or location permission prompts.
No paid analytics provider or resource provisioning is included.

## Product placement

Add a Mobile analytics view inside an application's existing monitoring page.
Display a date range, source, last successful import/receipt and collection coverage.
Use separate Downloads, Usage, Devices and Geography sections. Unconnected sources
show Not connected; missing data never becomes zero. Stale data carries its timestamp.
This must ship as an actual dashboard/API/integration slice, not just a CLI report.

## Metrics and evidence

| Metric               | Definition                                                            | Source and limits                                                                                     |
| -------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Store downloads      | Provider-defined aggregate downloads/acquisitions                     | Authorized store reports; keep provider definitions, dates and revisions visible                      |
| Direct APK downloads | Completed file responses observed by the delivery service             | Distinguish requests, completed transfers and retries/range requests; bots and caches affect coverage |
| First launches       | First accepted launch for an app-scoped installation identity         | Reinstalls/reset identities can count again; not a verified store install                             |
| Active installations | Distinct reporting installations in a UTC day/7-day/30-day window     | Not unique people; opt-outs and offline clients limit coverage                                        |
| Feature usage        | Allow-listed feature events and bounded foreground duration           | Client assertions; never document names, text, URLs or arbitrary event attributes                     |
| Errors               | Allow-listed error codes by app release/platform                      | No raw exception messages, stack traces or file paths                                                 |
| Devices              | Counts by Android/iOS, OS major version, app release and device class | No IMEI, phone number, advertising ID, serial number or fingerprinting                                |
| Geography            | Aggregate country/region, with source and unknown counts              | Coarse, optional; neither locale nor store territory is physical location                             |

Do not combine store acquisitions and first launches into an install total.
Do not infer uninstall from inactivity. Do not sum daily distinct counts to claim
monthly distinct users. Preserve late-arrival and corrected-report semantics.

## Collection and authorization boundary

Existing ADR-027 telemetry intentionally strips identity and is not a durable,
application-scoped analytics feed. Preserve that contract. Specify a separate
strict collector and migration before adding new identifiers or location fields.

- Bind data to an existing organization/application/environment on the server.
  Clients cannot choose another tenant by sending organization IDs in a payload.
- Store integration credentials stay on the server. Never embed Warrior operator,
  backend-reporting or app-store API secrets in a mobile binary.
- Installation enrollment and ingestion need a reviewed public-client threat model:
  bounded capability scope/expiry, rate limits, replay/deduplication, quotas and
  revocation. Possession of an app binary or installation key does not prove a human,
  genuine device or trustworthy analytics. Attestation, if added, is a separate signal.
- Reads require existing scoped operator/organization authority; test cross-tenant
  queries and revoked membership. Analytics grants no license or device-management power.
- Start with aggregate store imports where available. Select the mobile SDK adapter
  only after inspecting the actual app framework and its consent/login lifecycle.
- Offline queues must be bounded and retry-safe. Analytics failure must never block
  launch, login, conversion, downloads or access to user documents.

## Location and privacy defaults

User decision: country derived server-side from IP only. No region/city, GPS,
continuous tracking, device-owner map or location permission prompt is included.
Resolve the address transiently through a reviewed local/provider mechanism and
trusted ingress path; do not retain raw IPs in analytics. Forwarded IP or country
headers from arbitrary callers are untrusted. Account for proxies/VPNs, lookup
failures and restricted-network behavior with an explicit unknown country.
Store territory and language/timezone must never substitute for IP-derived country.

Proposed retention: raw usage events 30 days; daily aggregates 90 days. App-scoped
installation IDs are pseudonymous, not anonymous. Specify opt-out, identifier reset,
deletion and aggregation behavior before enrollment ships; update Security Center's
data categories and the app's disclosures. Suppress small geographic cohorts and
prevent filters from trivially reconstructing suppressed counts. Select and test
an explicit cohort threshold in the contract.

## Delivery order and acceptance

1. Confirm app/repository/framework, store or APK delivery source, intended audience
   and coarse location requirement. Inspect real source capabilities and reporting delays.
2. Specify the event/import contracts, retention/deletion, permissions and threat model.
   Keep client assertions separate from authenticated provider reports.
3. Implement the first scoped store-import or mobile-ingestion adapter with persistence,
   deduplication and negative tests; no production collection before configuration.
4. Ship dashboard reads and charts with that adapter. Test empty/disconnected/stale,
   cross-tenant, opt-out, duplicate/offline/reordered events and time-window boundaries.
5. Integrate into a test build of the actual app or a store test source. Verify one
   event reaches the correct dashboard, a duplicate does not inflate counts, opt-out
   stops collection, and offline upload does not interrupt normal app behavior.
6. Publish through GitHub, observe deployment and verify the feature in Warrior.
   Report synthetic/local tests separately from real mobile/store acceptance.

No app-store API access or mobile source is established by this document. Do not
present this plan as a working dashboard or populate it with fabricated production data.

## First slice: current APK distribution evidence

Operator console → Mobile app downloads reads a fixed public GitHub release endpoint
through GET /v1/admin/mobile-distribution. Existing operator middleware runs before
outbound access. Unknown query fields are rejected; no caller-provided destinations,
credentials or provider error text are accepted or returned. HTTPS redirects are
refused; response reads have a five-second deadline and 256 KiB limit. Exact tag,
asset name, upload state and fixed download URL are validated with bounded counts.
Only numeric counters/identifiers and timestamps leave the adapter. Concurrent reads
share one request, successes cache five minutes, and failures cache 30 seconds.

The current asset ID and creation time are shown with its counter. Asset replacement
can reset counts; this is not a historical total, verified installation or user count.
No country data comes from this source. Mobile usage, devices and IP-country remain
explicitly Not connected. No client secret or new production database table is added.

Threat checks: non-operators cannot cause requests; destination injection is rejected;
malformed, oversized, redirected, failed or missing provider evidence cannot become a
zero/healthy count. Provider descriptions and URLs cannot enter rendered HTML. This
fixed public integration is separate from the tenant-scoped mobile collector design.
