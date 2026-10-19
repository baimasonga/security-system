# OPS-005 health read integrity smoke

Baseline: `381a31b` plus OPS-005. The collector contention tool now also checks
20 concurrent authenticated health snapshots through real loopback HTTP on a
PostgreSQL pool of two connections, with fsync verified on. All must return healthy
for the stored fresh assertion; advancing the server clock exactly 180 seconds
must return stale. Existing assertions still require 1,101 event rows, 19 duplicate
receipts, one atomic conflict, two quota refusals, retention batches 1,000/101/0,
678,216 released bytes, zero remaining storage accounting and a verified audit.

The first replay passed in 7,678 ms including setup while other suites shared the
same machine. That duration is not directly comparable to OPS-004's isolated replay.
Health uses an organization transaction and bounded inventory (100 components),
with latest-report primary-key lookups. History ranges cover at most 24 hours and
return at most 1,001 internal rows (1,000 public rows plus truncation detection);
a scoped hour/type/outcome index supports that read without sorting all 90 days.
Latest-heartbeat deletion joins the existing bounded metadata retention batches.

The licensing throughput and soak figures in [load-test-v1.md](load-test-v1.md) measure
signed activation/refresh flows and global audit behavior. This workload neither
changes those locks nor establishes equivalent capacity. Existing licensing checks
remain part of the full PostgreSQL regression and CI load smokes. No production
throughput, failover, independent monitor or optional-provider availability claim
follows from this test.
