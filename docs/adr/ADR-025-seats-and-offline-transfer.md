# ADR-025: Named-user seats and offline transfer

Status: accepted. Affects trust boundaries: **yes** (who may activate; revocation reach).

## Context

Enterprise customers buy a number of named users, independent of how many machines each person uses. The
requirement ([architecture/09](../architecture/09-advanced-feature-requirements.md#billing-capabilities-usage-and-seats)):
seat assignments are unique and require organization administration; device slots and human seats are different
resources; offline transfer requires online revocation/confirmation with bounded existing-lease validity and cannot
promise instantaneous offline revocation.

## Decision

**Seat-based licenses.** A license is seat-based when its resolved entitlements (plan + overrides) contain a positive
integer `seats`. Nothing changes for other licenses.

- Seats are rows `(license, user)` — unique — in the license's organization. Only organization admins and owners
  (`license:manage_seats`) assign or remove them, only to members of that organization. Assignment runs under the
  license's exclusive lock, so concurrent assignments never exceed the limit (verified on PostgreSQL by breaking the
  lock and watching the concurrency test fail). A frozen organization cannot assign seats (ADR-022).
- Activating a seat-based license requires the activating person to hold a seat (`403 seat_required`). Device slots
  still apply separately: a seat is a person, a slot is a machine.
- Removing a seat deactivates every active activation that person made on the license, in the same transaction, and
  returns `offline_leases_valid_until`: the latest expiry of those devices' current leases.

**Offline transfer.** Moving a license to another machine is an online confirmation on the old activation
(deactivate the device, or remove the seat) followed by a normal activation on the new machine. The platform cannot
reach an offline machine, so the old device keeps its current lease until it expires; the API and the portal state
that date explicitly instead of implying instantaneous revocation. The bound is the lease TTL policy (ADR-002).

## Consequences

- Refresh does not re-check seats (no extra query on the hot path): removing a seat deactivates the person's
  activations, so their next refresh fails.
- Seat history is in the audit log (`seat.assigned`, `seat.unassigned`); the table keeps only current seats.
