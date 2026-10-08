-- 0002_retention_indexes: make retention deletes cheap.
-- Found by load testing: challenges are written on every device call, so the table grows with traffic and
-- the retention DELETE (`WHERE expires_at < $1`) had no supporting index. Leases accumulate one row per
-- issued lease and need the same treatment.
-- (On a very large existing table, create these CONCURRENTLY outside a transaction instead.)

BEGIN;

CREATE INDEX challenges_expires_idx ON challenges (expires_at);
CREATE INDEX leases_expires_idx ON leases (expires_at);

COMMIT;
