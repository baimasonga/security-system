-- 0003_partitioned_audit: partition the audit log into independent hash chains (ADR-008).
--
-- Why: a single global chain, serialized across the commit, capped the whole platform at ~1/(3-4*RTT)
-- audited transactions per second. Now each organization (optionally sharded) has its own chain, so only
-- appenders to the SAME chain contend.
--
-- Existing events keep their original (global) seq / prev_hash / hash untouched and form the 'legacy' chain,
-- which continues to verify but is never extended.

BEGIN;

-- 1. chain id + a global display order -------------------------------------------------------------
ALTER TABLE audit_events DROP CONSTRAINT audit_events_pkey;
ALTER TABLE audit_events ADD COLUMN chain_id text NOT NULL DEFAULT 'legacy';
ALTER TABLE audit_events ALTER COLUMN chain_id DROP DEFAULT;  -- every new row must name its chain
ALTER TABLE audit_events ADD COLUMN gseq bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE audit_events ADD PRIMARY KEY (chain_id, seq);
CREATE UNIQUE INDEX audit_events_gseq_uq ON audit_events (gseq);

DROP INDEX audit_events_org_idx;                                  -- was (org_id, seq): seq is per chain now
CREATE INDEX audit_events_org_gseq_idx ON audit_events (org_id, gseq);

-- 2. one head row per chain: the append lock AND the tamper-evidence cross-check ---------------------
CREATE TABLE audit_chains (
  chain_id    text PRIMARY KEY,
  head_seq    bigint NOT NULL CHECK (head_seq >= 0),
  head_hash   text   NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
) WITH (fillfactor = 70);  -- room for HOT updates: head columns are not indexed

-- Seed the legacy chain head from the last pre-existing event (no rows => no legacy chain).
INSERT INTO audit_chains (chain_id, head_seq, head_hash)
SELECT 'legacy', seq, hash FROM audit_events WHERE chain_id = 'legacy' ORDER BY seq DESC LIMIT 1;

-- 3. head rows may only move forward, never be renamed or removed ---------------------------------
CREATE FUNCTION audit_chains_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.chain_id <> OLD.chain_id THEN
      RAISE EXCEPTION 'audit_chains.chain_id is immutable';
    END IF;
    IF NEW.head_seq < OLD.head_seq THEN
      RAISE EXCEPTION 'audit_chains head may not move backwards';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'audit_chains rows cannot be deleted';
END $$;
CREATE TRIGGER audit_chains_no_regress BEFORE UPDATE OR DELETE ON audit_chains
  FOR EACH ROW EXECUTE FUNCTION audit_chains_guard();
CREATE TRIGGER audit_chains_no_truncate BEFORE TRUNCATE ON audit_chains
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();

COMMIT;
