# Security findings and recovery reports

Deploy migration 0024, apply app-role grants and verify the database profile through
`node tools/predeploy.ts`. Enable `OPERATIONS_POSTURE_ENABLED=true` alongside
inventory. Rollback disables only posture and retains evidence, findings and audit.
No source credential, email provider or infrastructure access is granted.

Open Applications → application → environment → Security & recovery. Owners/admins
can import a normalized scan, assign/triage findings and record backup, restore or
rollback reports. These are explicitly unverified administrator reports. Enter
actual exercise times/check outcomes and an artifact digest; no time fields are
prefilled as though a drill had happened. Never upload backup files or raw secret
exports. A successful backup cannot create a restore record.

## GitHub imports

For authenticated read-only collection without raw exports, use the
[bounded GitHub collector](github-security-collector.md). It verifies the repository
commit, collects current open alerts and produces the existing normalized report.
Imports remain unverified administrator evidence. The manual pipeline below remains
available for previously captured trusted exports.

Use your existing authenticated GitHub CLI in a trusted local shell. The normalizer
consumes JSON from standard input and writes only the reviewed metadata schema.
For example, use a protected local pipeline (substitute the actual component ID,
checked commit, UTC export time and numeric scan/run reference):

```sh
gh api 'repos/OWNER/REPO/dependabot/alerts?state=open&per_page=100' --paginate --slurp |
  node tools/normalize-security-export.ts \
    --source github_dependabot --repository OWNER/REPO \
    --revision COMMIT_SHA --run-id RUN_NUMBER --completed-at UTC_TIMESTAMP \
    --component COMPONENT_ID > normalized-scan.json
```

For secret scanning, use `repos/OWNER/REPO/secret-scanning/alerts?state=open&per_page=100`
and `--source github_secret_scanning`. Raw exports can contain actual secrets: do
not save, print, attach or send them to Warrior. The normalizer strips all source
fields except alert-number-derived fingerprints and reviewed severity/advisory
metadata. It rejects closed/malformed results and more than 100 findings rather
than silently truncating them into a clean-looking report. A provider denial is
not an empty successful scan. Requires appropriate repository security permissions;
no GitHub credential is stored by Warrior.

Import normalized JSON through the UI. Scan runs retain independent snapshots;
new scans never auto-resolve existing remediation decisions. Lists are bounded and
show truncation; environment caps fail closed. The server does not fetch or cryptographically authenticate provider results. The
operator-local collector authenticates its read-only fetch without elevating import
provenance. Neither workflow executes remediation, inspects backup
contents or independently attests a restore. External monitoring/witnessing and
production restore drills still require their separate rollout.

## Isolated restore mechanics exercise

With the disposable onboarding PostgreSQL container listening on loopback 55432:

```sh
node tools/restore-drill-local.ts
```

The tool creates two new random `posture_drill_*` databases, seeds synthetic account
and posture data, exports a consistent PostgreSQL snapshot, restores it into the
second database and checks schema, application data and audit integrity. It verifies
that a source user created after the snapshot is absent from the restored snapshot.
It prints only bounded metrics and the dump digest, and removes both test databases.
The dump remains in process memory. No production URL, credential, export or backup
is used. Timing describes a tiny local fixture, not production RPO/RTO, failover,
WAL/PITR coverage, provider backups, encrypted storage or object-file restoration.
