# ADR-030: Rokela Android usage analytics

Status: implemented, pending deployment and production acceptance. 25 October 2026.

The owner requested direct APK downloads, usage, device summaries and country from
IP, explicitly excluding GPS. GitHub downloads remain separate from app reports.

Introduce a fixed Rokela Android public collector, not a tenant-selectable endpoint.
Reports are anonymous client assertions, not authenticated devices or people. A
random installation identifier is hashed before storage, never linked to account,
license or document. Clients can forge/rotate it; analytics has no authorization
consequences. Collect only allow-listed app-open/home-screen tool-selection event types, release,
Android major version and device class. No arbitrary text, filenames, URLs, GPS,
account identifiers, serials or advertising IDs. Strict schemas reject extra fields.

Limit bodies/batches, per-IP requests, total retained events and event age. UUID
retries deduplicate within retention; conflicting payloads are rejected. Store
committed reports in a separate bounded PostgreSQL table; the mobile client uses a
bounded offline queue and never waits before a document operation. Queries remain
platform-operator-only and fixed to Rokela; this adds no cross-tenant authority.

Country is approximate IP geolocation, resolved locally using an operator-supplied country MMDB, such as DB-IP Lite
(CC BY 4.0; attribution in the dashboard). No data file is bundled. No IP is sent to a third
party or persisted in analytics. Derive IP through the explicit mobile trusted
proxy-hop configuration; never accept an app-provided IP/country field. If that boundary is
unconfigured or lookup fails, report Unknown, not a proxy's country. No GPS or OS
location permission is added. Record the data edition and acknowledge VPN error.

Raw reports retained 30 days, bounded batch deletion through maintenance. The view
reports a rolling window, not lifetime totals. Reporting installations are distinct random IDs in each rolling window, not verified
first installs. Countries with fewer than five reporting installations are omitted; no country drill-down or device-level map.
Device groups may overlap across OS/releases and are never summed as unique people.

Negative tests must cover malformed/private fields, duplicate/conflicting events,
quota/concurrency/retention, clock bounds, authorization, spoofed country inputs,
lookup failures and client queue limits/retry behavior. Audit/identity/license
features remain independent. Confirm the deployed API, migration/grants, rebuilt
APK and one real report in Warrior before calling the integration live.
