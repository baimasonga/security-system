# Native update evidence and staging

## Boundaries

The trusted host configures a stable Windows DPAPI store, target, installed build
sequence, staging root and approved builders. Feeds, HTTP responses, evidence and
artifact bytes are untrusted. Only signed metadata accepted against the protected
current root supplies the artifact URL, size and digests. Evidence URLs are suffixes
on that same URL; URLs inside evidence are never fetched. The API has no public
custom transport or plaintext-store fallback. Internal test seams are friend-assembly
access only. No update or failure may modify customer documents or license state.

## Controls and acceptance

- Observe and persist valid metadata before fetching; retain its sequence on errors.
- Verify exact evidence digests before interpreting it. Bound UTF-8 JSON to 2 MiB
  and depth 32; reject duplicates. Validate CycloneDX artifact hashes and exactly
  one in-toto/SLSA subject and approved builder. Builder text alone is not an
  independent CI attestation; the release authority endorses these pinned bytes.
- System TLS/name checks stay enabled. Redirects, compression, cookies, origin
  changes and non-200 responses fail. Deadlines cover streamed bodies; declared
  and streamed lengths are independently bounded before writing more bytes.
- Generate staging names under a host-controlled local root, never from metadata.
  Refuse link/reparse-point ancestors. Restrict new directory ACLs to the current
  user and keep an artifact read-sharing lease. Flush exact bytes and check SHA-256.
- Reverify/commit the original envelope against current protected state at completion.
  Concurrent new releases, incompatible root rotations, expiration, clock rollback
  or persistence failure remove the partial file and return no staged result.
- Return fixed refusal messages, never HTTP error bodies, private URLs or filenames.
  Cleanup failures are surfaced. Neither staging nor evidence authorizes execution;
  publisher identity, installation recovery and final host policy remain necessary.

Real HTTPS acceptance covers certificate refusal, trusted-CA success, redirects and
stalled bodies. Native Windows acceptance covers DPAPI commits, ACL protection and
failed replacement. Negative controls independently weaken digests, builder policy,
artifact integrity, stream bounds, final authority, cleanup, redirects and deadlines.

## Limits

The same Windows user or an administrator can alter/roll back all host state;
DPAPI is not hardware rollback protection. Trusted staging directories must not be
network/synchronized shares. Approved artifact origins are trusted host/root policy,
not a general server-side URL fetch service. Successful staging proves byte/evidence
checks at its completion time, not ongoing support, future revocation delivery,
publisher approval, successful installation or a production recovery exercise.
