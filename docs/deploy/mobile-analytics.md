# Rokela Android analytics deployment

Deploy Warrior first through its existing GitHub-connected branch. Apply migration
0026 and the normal runtime-role grants through the existing startup process.
Then build/release the companion Rokelapdf-online Android APK through GitHub Actions.
The app posts only fixed anonymous metadata to Warrior; it contains no backend keys.

Open **Operator console → Mobile app usage → Refresh mobile usage** after installing
and opening the new APK. Confirm a recent receipt and the release version. A tool
selection is not a successful conversion, and an APK download is not an install.
The usage-sharing switch clears pending reports; reports already received expire
through normal 30-day retention. Offline reports expire after seven days. No GPS
permission or precise location is used.

## Optional country lookup, without a paid service

1. Obtain a current country MMDB from the official DB-IP Lite download page
   (https://db-ip.com/db/download/ip-to-country-lite), respecting its CC BY 4.0
   attribution. Keep the edition/date and checksum in deployment records. The
   dashboard includes DB-IP attribution. The file is not bundled in this change.
2. Make the decompressed `.mmdb` available on the Warrior service's filesystem and
   set `MOBILE_COUNTRY_DATABASE` to its absolute path. Maintain a monthly replacement
   process and restart after replacement (the reader caches the file).
3. Verify the actual ingress path and which proxy appends each X-Forwarded-For hop.
   Set `MOBILE_TRUSTED_PROXY_HOPS` to that verified count (1–5); default 0 disables
   country inference. Ensure the service cannot bypass that trusted ingress. Do not
   guess the count or accept a client-supplied country header.
4. Check a controlled request through that ingress. Unknown is correct for absent,
   invalid or unmapped IPs and lookup failures. Country groups appear only with at
   least five reporting installation IDs. VPNs and proxies reduce accuracy.

Only the country code is saved with the report; no raw IP is stored in analytics or
sent to a geolocation provider. Infrastructure access logs have their own policies.
`country_lookup_configured` indicates settings are present, not database validity.
There is no per-device lookup or export. All reads require platform-operator access.

Limits: 16 KiB requests, 20 events per batch, 120 requests/minute per configured
source address (socket address otherwise), seven-day event age, five-minute future
clock tolerance, 100,000 retained records. Capacity/rate failures must never block
PDF use. Anonymous senders can forge or rotate IDs; never use these counts for
licensing, security decisions, billing or identity.
