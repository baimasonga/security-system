# Automatic operations alerts rollout

Deploy the checked source with `node tools/predeploy.ts`: migration 0023, application
role grants and database profile verification must succeed before starting the API.
Enable `OPERATIONS_AUTOMATION_ENABLED=true` only alongside inventory, ingestion,
health and incidents. Preserve existing credentials and MFA keys.

In Applications, select an active environment and component. Owners/admins can
create an event-count or heartbeat rule, evaluate it, disable it or place it in
maintenance. Rules are immutable definitions; disable an obsolete rule and create
its replacement. Notifications initially appear only in the creator's authenticated
portal. No email/webhook provider is configured by this release.

Use synthetic inventory and a separately scoped events credential issued through
fresh MFA for acceptance. Verify a matching failure opens one automatic incident,
concurrent evaluations do not duplicate it, maintenance suppresses notifications and
fresh successful heartbeat evidence resolves it after the recovery window. Verify
both transition notifications and audit history. Revoke the test credential and
archive synthetic inventory afterward. Never send private documents or real alerts.

Rollback: set `OPERATIONS_AUTOMATION_ENABLED=false` and redeploy. Keep migration,
rules, incidents, notification metadata and audit history; do not down-migrate or
delete records to roll back. This stops rule evaluation/delivery without changing
licensing, manual incidents or source authentication. External monitoring and
restore verification remain separate release gates.
