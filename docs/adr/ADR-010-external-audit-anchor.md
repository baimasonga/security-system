# ADR-010 — Publish the audit anchor to an external witness

- Status: Accepted · Date: 2026-10-08 · Affects trust boundaries: **yes** (new outbound integration, new operator surface)
- Closes the _detection_ part of threat-model risk **R-13**. Builds on [ADR-008](ADR-008-partitioned-audit-chains.md) (chains,
  heads, `anchor`).

## Context

The audit log is tamper-evident against everyone _except_ a party who can write to the database with superuser rights:
they can disable the immutability triggers, rewrite history, recompute every later hash and the head rows, and the log
still verifies (shown by test: `verifyChain` passes on a perfect rewrite). Evidence that outlives that attacker must be
held somewhere they cannot reach. ADR-008 made one small value — the `anchor`, a digest of every chain head — cheap to
produce; this ADR decides how it leaves the system and how it is used.

## Decision

1. **Publish a manifest, not just a digest.** `{ v: 1, created_at, anchor, chains: [{chain, seq, hash}…] }`. A bare digest
   only proves "the log was exactly this at time T"; after the log grows it can no longer be checked. With the list, every
   witnessed `(chain, seq, hash)` can be looked up later: it must still be the event stored at that position, which —
   together with `verifyChain` proving each chain is internally linked — proves the whole prefix is unchanged. This
   also detects deleted chains, rolled-back logs, and complete consistent rewrites.
2. **Verify first, then witness.** A publication runs the full `verifyChain`. A log that fails is **never** published
   (that would bless the tampering); instead the `audit_chain_broken` critical security signal is raised, a metric is
   incremented and the attempt is logged. A failing witness is recorded and retried at the next tick; it never blocks
   or fails user requests.
3. **A small port, one real adapter.** `AnchorSink.publish(manifest)`; the adapter is an HTTPS `POST` to a URL the
   _operator_ configures (`AUDIT_ANCHOR_URL`, optional bearer `AUDIT_ANCHOR_TOKEN`), with a 10 s timeout, no redirects,
   an `Idempotency-Key` equal to the anchor, and an optional `X-Witness-Receipt` reference stored with the record. The
   destination is never request-controlled. Errors recorded and logged are short fixed strings — never the URL, token or
   response body.
4. **Configuration fails closed.** In production `AUDIT_ANCHOR_URL` is required, or `AUDIT_ANCHOR_DISABLED=true` must
   be set to accept R-13 explicitly (startup warns). https is required (loopback http only outside production); URLs with
   credentials are refused; tokens must be ≥ 16 characters; interval `AUDIT_ANCHOR_INTERVAL_SECONDS` 60–86400 (default
   3600). A first publication is attempted ~5 s after start.
5. **A local, append-only index** (`audit_anchors`, migration 0004): id, time, anchor, chains, events, destination
   (origin + path), status, receipt, short error. It stores no manifests (they grow with the number of chains) and is not
   evidence — the witness is. It is used to skip an unchanged state and to expose freshness
   (`audit_anchor_last_success_age_seconds`, −1 = never).
6. **Operator surface** (all operator-only, strict bodies): `GET /v1/admin/audit/anchors` (index),
   `POST /v1/admin/audit/anchors` (publish now, mandatory `reason`, audited as `audit.anchor_published|_failed|_refused`),
   `POST /v1/admin/audit/anchors/check` (read-only: is the live log consistent with a manifest the witness holds; up to
   5,000 chains). `GET /v1/admin/audit/verify` no longer returns the per-chain list.
7. **Offline checker** `tools/verify-anchor.ts` (needs only `DATABASE_URL`): verifies the chains, then checks _every_
   manifest in a file (a single manifest or the JSON-Lines log of a witness). Exit 0/1/2. Run it from a machine that
   fetched the witness data independently.
8. **Reference witness** `tools/anchor-witness.ts` (hash-chained JSONL, bearer auth, idempotent) for development and
   tests. It is deliberately not a production witness.

## What the witness must be

A system the platform operator and a database superuser cannot rewrite: object storage with retention lock / WORM in a
_separate_ account, a transparency log, a notary or a third party. If the same people can alter both the database and the
witness, nothing has been added. Publishing from several instances is harmless (same state ⇒ same anchor ⇒ idempotent).

## Alternatives considered

| Option                              | Why not                                                                                                                                                                     |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Publish only the digest             | Cannot be checked after the log grows (see 1)                                                                                                                               |
| Sign manifests with the license key | A key from the platform's own keyring does not make the witness independent, and mixing key purposes is a separate risk; the witness's append-only property is what matters |
| Merkle tree over all events         | Larger change, no benefit over per-chain heads for this threat; per-chain heads are already hash-linked                                                                     |
| Publish on every audit append       | Puts an external dependency in the hot path (ADR-008 removed one global bottleneck for a reason)                                                                            |
| Build/host the witness ourselves    | Would sit inside the trust domain being protected; the operator chooses an independent one                                                                                  |

## Consequences

- A complete, self-consistent rewrite, a removed chain, or a rolled-back log is detected at the next check, with the
  position (`chain`, `seq`). Detection window = publication interval + time to run a check.
- Operators get freshness and failure metrics and an audited manual publish.
  − **Full verification per publication is O(log size)** (≈ 2.5 s per 130k events measured), and runs in a REPEATABLE READ
  read-only snapshot. At very large logs raise the interval or move to incremental verification from the last anchored
  heads (future work).
  − Manifest size grows with the number of chains (~150 B each; 10k organizations ≈ 1.5 MB per publication). Witness
  storage and the `check` endpoint limit (5,000 chains) reflect that; use the CLI for larger logs.
  − An attacker who also controls the application's secrets could publish a _forged_ current state — but cannot alter what
  the witness already holds, so earlier anchors still expose the rewrite of anything older.
  − Only history up to the last anchor is protected; events newer than the last successful publication are not.
