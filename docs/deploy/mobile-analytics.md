# Rokela Android analytics deployment through GitHub

Deploy through the existing GitHub-connected branch. The Docker build downloads
and validates the DB-IP Lite monthly edition pinned by `COUNTRY_DATA_EDITION` in
`Dockerfile`. It copies the local country database and its provenance manifest into
the runtime image and sets `MOBILE_COUNTRY_DATABASE`. No Railway console change or
new paid service is needed for this build process. A provider outage leaves the
country database unavailable without preventing the platform from deploying.

The separate **Mobile country data verification** GitHub workflow validates the
same pinned edition, fails visibly on download/validation problems, and retains a
JSON provenance artifact (source, edition, build date, size, checksum and license).
It does not send visitor IPs to DB-IP. Attribution appears in Warrior's usage panel.
To refresh the monthly edition, update `COUNTRY_DATA_EDITION` through GitHub and
let the normal checks/deployment run. Old data expires after 120 days; the workflow
also runs monthly to detect an unusable pinned edition. It does not automatically
change the pin or publish unreviewed data updates.

## IP source and readiness

The image requests Railway edge IP mode, but it is enabled only when the platform's
project, service, production-environment and public-domain values exactly match the
known Warrior deployment. The incoming Host must also be the direct Warrior public
domain. The app uses Railway's documented `X-Real-IP` header, never the caller's
country header or an arbitrary forwarded chain. Other deployments default to unknown.

Reference: [Railway public networking specs](https://github.com/railwayapp/docs/blob/main/content/docs/networking/public-networking/specs-and-limits.md),
Request Headers. The endpoint used by the native app is the direct Railway domain;
putting another proxy in front requires revisiting this trust boundary. The header
is trusted because of the configured deployment/edge boundary, not because a client
can spell its name. Private-network callers inside the project remain trusted for
this boundary; reports remain unverified and must never carry security authority.
`MOBILE_USE_RAILWAY_IP=0` disables this mode. Existing explicit
`MOBILE_TRUSTED_PROXY_HOPS` supports separately verified ingress topologies.

**Operator console → Mobile app usage** now distinguishes:

- Country database: not configured, unavailable, expired, or ready, with build date.
- Country IP source: configured or not configured.
- Actual received country groups: displayed only for at least five reporting IDs.

Ready settings do not establish receipt from a real device. Install the newly
released direct-download APK, open it and select a tool, then refresh the usage
panel. Confirm a recent receipt and release version. Small country groups remain
hidden; VPNs and carrier routing can make IP geography inaccurate. No GPS or
location permission is used. Database paths and loader error details are not exposed.

## Privacy and limits

Migration 0026 and runtime-role grants follow the normal startup process. The app
contains no backend keys. Its usage-sharing switch clears pending reports; received
reports expire after 30 days. Offline reports expire after seven days. Existing
APKs require an update; browser previews and Google Play builds do not report.

A tool selection is not a successful conversion, a reporting ID is not a verified
person/device, and a download is not an install. The GitHub APK asset counter does
not include every Cloudflare-cached website download. No website total is inferred.

Only country codes are saved with reports; no raw IP is stored in analytics or sent
to a geolocation provider. Infrastructure access logs have their own policies. Reads
require platform-operator access; there is no per-device export or geography filter.

Limits: 16 KiB requests, 20 events per batch, 120 requests/minute per configured
source address (socket address otherwise), seven-day event age, five-minute future
clock tolerance, 100,000 retained records. Capacity/rate failures never block PDF
use. Anonymous senders can forge or rotate IDs; never use these counts for licensing,
security decisions, billing or identity.
