# Operations/security implementation status and agent handoff

Updated: 19 October 2026.

## Current state

Planning handoff only. No operations-monitoring API, integration credential, probe,
incident engine or live Rokela PDF connection was added by this documentation change.
The baseline source review is `d61d350`; recheck current code before starting.

| Task    | State                               | Verification/evidence                                                                  |
| ------- | ----------------------------------- | -------------------------------------------------------------------------------------- |
| OPS-001 | Ready; not implemented              | Program, proposed ADR and draft threat model supplied. Contract decisions remain open. |
| OPS-002 | Not started; depends on OPS-001     | None                                                                                   |
| OPS-003 | Not started; depends on OPS-002     | None                                                                                   |
| OPS-004 | Not started; depends on OPS-003     | None                                                                                   |
| OPS-005 | Not started; depends on OPS-002/004 | None                                                                                   |
| OPS-006 | Not started; depends on OPS-004/005 | None                                                                                   |
| OPS-007 | Not started; depends on OPS-004/006 | Rokela PDF brief only; no live connection.                                             |
| OPS-008 | Not started; depends on OPS-006     | Existing recovery runbook is not restore evidence.                                     |

## Next action: OPS-001

Read AGENTS.md and CLAUDE.md, then the program, ADR-029, threat model and Rokela PDF
brief. Inspect existing RBAC, Product/organization models, audit transaction helpers,
telemetry schemas/storage and route contracts. Finalize the scoped monitoring
contract and resolve ADR questions before adding endpoints or migrations. Keep the
existing client telemetry privacy boundary intact.

No live credentials are needed for this task. Production endpoint/credential setup
and controlled test-alert destinations remain later rollout prerequisites.

## Evidence rules

- The owner reports Business Admin was tried first; source contains provisioning and
  development acceptance support. This handoff does not independently verify its live deployment.
- A feature is implemented only when code and tests exist. A test fixture is not a
  production credential, a screenshot is not an access-control test, and documentation
  is not evidence that a provider, backup, external anchor or alert channel is configured.
- For each finished task record commit/PR, tests and failures, configuration applied,
  verification environment and remaining limits. Use links or safe summaries, not secrets.

## Handoff entry template

Copy this section for each implementation change:

```text
Task ID / state:
Commit or PR:
Implemented behavior and affected contracts:
Tests and commands (include negative/mutation/PG/load checks where applicable):
Verification environment and observed results:
Configuration applied (names only; no secret values):
Known gaps / blockers / assumptions:
Rollback notes:
Next ready task and exact next action:
```
