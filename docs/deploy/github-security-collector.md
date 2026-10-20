# Read-only GitHub security collection

## Decision and trust boundary

The operator-local collector `tools/collect-github-security.ts` retrieves open
Dependabot or secret-scanning alert metadata and emits a normalized report for
Warrior's existing Security & recovery import. It does not install a GitHub token
in Warrior, change repository settings, execute remediation, or grant commercial
access. The imported report retains unverified `admin_report` provenance: local
provider authentication does not attest a subsequently editable imported document.

The collector verifies that the requested commit exists in the repository, then
retrieves the current open-alert inventory. GitHub's alert API does not scan that
commit. The revision is a repository commit reference, not proof that a scanner
executed on that revision. Completion time is collection time and the run ID is an
operator-supplied numeric correlation reference, not verified CI execution evidence.

## Controls and failure behavior

Only the fixed HTTPS `api.github.com` origin is contacted. Repository and revision
selectors are strictly validated; neither events, inventory nor provider links can
supply a destination. Redirects are refused, including repository-move redirects.
The proxy-aware client retains inherited proxy and CA settings; TLS verification
is never disabled. Credentials are accepted only from `GITHUB_SECURITY_TOKEN`, not
command arguments or files. Use a dedicated fine-grained read-only token scoped to
the target repository: Contents read plus Dependabot alerts read or Secret scanning
alerts read, as appropriate. Existing broad operator credentials are not required.

Requests have a fixed timeout, a streamed byte cap, a 100-finding cap and no automatic
retries. Any pagination, denial, rate limit, unexpected response, malformed alert or
oversized result fails with a generic diagnostic and no report. A denied/unavailable
provider must never become a clean scan. The collector emits stdout only after the
entire requested collection validates. Raw provider responses may contain secrets;
they remain bounded in memory and are never logged, written to disk or imported.
Repository identity is lowercased before fingerprinting; use the same casing for
manual exports to keep fingerprints stable. Original reports remain immutable.

## Use

Install repository dependencies with `npm ci`. Set `GITHUB_SECURITY_TOKEN` through
your shell's secret manager, without putting the token in shell history or chat.
Run from a trusted workstation, preserving any managed proxy and CA settings:

```sh
node tools/collect-github-security.ts \
  --source github_dependabot --repository OWNER/REPO \
  --revision COMMIT_SHA --run-id RUN_NUMBER --component COMPONENT_ID \
  > normalized-scan.json
```

Use `--source github_secret_scanning` for secret alerts. Do not enable shell tracing,
log provider bodies, or save raw exports. On failure no JSON is emitted; check the
exit status before using an output file. Review the normalized JSON, then import
it under the matching environment/component in Applications → Security & recovery.
The current cap intentionally refuses more than 100 open findings instead of
presenting an incomplete report as a complete inventory.

This local read-only integration does not provide scheduled server collection,
independent attestation, production restore evidence or external notifications.
It does not remove Railway's deployment gate for the existing posture UI/API.
