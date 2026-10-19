# OPS-004 collector contention and retention evidence

19 October 2026; accepted upstream baseline `b5da658` plus this ingestion change.

Run against a disposable **local** PostgreSQL database:

```sh
DATABASE_URL=<local-disposable-database> node tools/loadtest/operations-events.ts
```

The tool creates and drops its own isolated schema. It drives real loopback HTTP,
uses an actual integration-secret digest and real credential verification, and
requires `SHOW fsync = on`. Its synthetic credential is seeded locally; genuine
MFA issuance is independently exercised by the HTTP behavioral suite.

Observed and asserted: 20 contending senders with pool size 2 produce exactly one
stored receipt and nineteen duplicates for the same UUID. A mixed conflict batch
stores nothing. Eleven more 100-event batches produce exactly 1,101 total rows;
both storage counters equal the persisted byte sum, **678,216 bytes**. Two
concurrent over-quota attempts both return 429 and create no rows.

Advancing the injected server clock to thirty days produces retention batches
**1,000, 101, 0**, releases every accounted byte and leaves both storage counts at
zero. All 1,101 aggregate counts remain at thirty days, then disappear at ninety
days. The expired old retry is rejected; the audit chain verifies. End-to-end
scenario duration was **3,172 ms**, including migrations/account setup, so that
number is not a sustained throughput or latency measurement.

The historical V1 report measures licensing flows, global audit contention and a
longer soak on a different runtime. This short collector-specific integrity run
cannot establish a capacity improvement/regression relative to those figures.
The implementation preserves licensing transactions and uses separate monitoring
counters; the full PG regression suite supplies the separate compatibility gate.
No production data, external destination, alert or live Rokela PDF service was used.
This replay ran alongside regression verification. Artifact: `/tmp/ops4-contention-final.log` in this execution environment.
