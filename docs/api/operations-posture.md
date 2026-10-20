# OPS-008 security posture and recovery evidence

Initial implementation: authenticated, scoped imports and human remediation;
no infrastructure remediation, scan execution or restore execution.

Use a separate default-off `OPERATIONS_POSTURE_ENABLED` flag, requiring inventory.
Owners/admins have `ops:manage_security`; reads require `ops:read`. Recheck current
membership, session and freeze inside the organization transaction. Operators and
events credentials gain no bypass. Scope always comes from the authenticated URL.
Active ancestry is required for imports/actions; archived records remain readable.

Routes under `/v1/organizations/{orgId}/operations/applications/{applicationId}/environments/{environmentId}`:

- `GET /security`: bounded scan/finding/recovery lists with explicit truncation,
  assessment time, freshness and `admin_report` provenance.
- `POST /security/scans`: strict normalized GitHub Dependabot/secret-scanning export,
  component, commit SHA, numeric run ID, completion time and at most 100 findings.
  Findings contain only SHA-256 fingerprints, severity and public CVE/GHSA advisory
  IDs (dependency findings only). Never upload raw provider responses, secrets,
  filenames, source lines, private URLs, arbitrary titles or package metadata.
  Completed and failed scans are distinct; failed scans contain no findings.
  Canonical digest deduplicates exact imports; changed content creates a new report.
  Every report owns its finding snapshots. Importing another report never silently
  resolves, rewrites or reopens previously triaged findings.
- `PATCH /security/findings/{findingId}`: expected version, state
  `open|acknowledged|resolved|accepted_risk`, active same-org assignee or null and
  reason `assignment|security_response`. Resolution/risk acceptance require an
  assignee. The UI must say these are administrator decisions, not a verified fix.
- `POST /security/recovery`: immutable backup/restore/rollback reports with component,
  start/completion/recovery-point times, result, bounded recovery targets, integrity,
  application and audit check results, SHA-256 artifact digest and reason `initial_setup`.
  A reported successful restore/rollback requires all three checks to pass. RTO and
  restore RPO are calculated from timestamps. Successful backup does not establish
  restore success. All records remain unverified administrator reports; no supplied
  flag or digest can grant independent-verification status.

Scan times must fall within the past 30 days and cannot be future-dated. Recovery
reports cover at most 365 days, cannot be future-dated, and have ordered finite
timestamps; restore points cannot follow the start of restoration. Reads explicitly
mark scans older than seven days and backup reports older than one day as stale.
Restore reports older than 90 days are stale; failed reports never become passes.
Freshness is based on persisted monotonic server assessment time, not browser time.

Environment caps: 100 scan reports, 2,000 finding snapshots and 100 recovery reports.
Reads return 25 scans, 200 prioritized findings and 25 recovery reports, signaling
truncation. Caps fail closed; this slice grants no deletion or implicit retention.
Mutations and audit commit atomically; the app role cannot delete evidence or
change immutable report/finding identity. Rollback disables the flag and retains
records and audit. Source imports do not consume commercial quotas.

The GitHub export normalizer runs locally with the caller's existing GitHub access,
outputs only the reviewed schema and never sends credentials to Warrior. Its output
is still unverified import evidence. Automatic provider authentication, independent
monitoring/witnessing, production backup/restore drills and physical desktop release
acceptance remain separate work and must not be inferred from this interface.
