# Agent entry point

Read [CLAUDE.md](CLAUDE.md) before changing this repository. Its security invariants,
architecture boundaries, documentation requirements and verification commands apply
to every agent, regardless of the coding tool used.

## Operations and security program

For cross-application monitoring work, read these in order:

1. [Implementation program](docs/programs/operations-security.md): scope, constraints,
   task dependencies and acceptance criteria.
2. [Progress and handoff](docs/programs/operations-security-status.md): current task,
   evidence, blockers and the next action. Do not treat planned features as implemented.
3. [ADR-029](docs/adr/ADR-029-application-operations.md) and the
   [threat model](docs/threat-models/06-application-monitoring.md).
4. [Rokela PDF integration brief](docs/integrations/rokela-pdf.md) when working on the
   second application integration.

Choose the first ready task in the status file. Reconcile its baseline with current
code before implementing it. Keep changes bounded to that task and preserve existing
Business Admin licensing and customer access. Update the status file in the same
change with tests, commit/PR evidence, remaining gaps and a concrete next action.

`npm run check` must pass before any push, as required by CLAUDE.md. Changes involving
database or security boundaries additionally require the applicable PostgreSQL,
negative-path, mutation and load checks described there. A local test or passing CI
is not evidence of a live integration or a successful restore exercise.

Never place credentials, private links, file contents or production exports in this
handoff. Missing live credentials block only live verification, not independent
specification, implementation and local testing. Do not make production changes or
send alerts to real recipients merely because a task describes a future rollout.
