-- ADR-010: record of audit anchors published to an external append-only witness.
-- This is METADATA only (the witness holds the manifest). It is append-only like the audit log, but note that
-- the database cannot vouch for itself: the external witness is the evidence, this table is the operator's index.
BEGIN;

CREATE TABLE audit_anchors (
  id          text PRIMARY KEY,
  created_at  timestamptz NOT NULL,
  anchor      text    NOT NULL CHECK (anchor ~ '^[0-9a-f]{64}$'),
  chains      integer NOT NULL CHECK (chains >= 0),
  events      bigint  NOT NULL CHECK (events >= 0),
  destination text    NOT NULL,                         -- origin + path of the witness, never credentials
  status      text    NOT NULL CHECK (status IN ('published', 'failed')),
  receipt     text,                                     -- witness-issued reference, if any
  error       text                                      -- short, secret-free reason when status = 'failed'
);
CREATE INDEX audit_anchors_created_idx ON audit_anchors (created_at DESC, id);

CREATE FUNCTION audit_anchors_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_anchors is append-only';
END $$;
CREATE TRIGGER audit_anchors_no_update BEFORE UPDATE OR DELETE ON audit_anchors
  FOR EACH ROW EXECUTE FUNCTION audit_anchors_immutable();
CREATE TRIGGER audit_anchors_no_truncate BEFORE TRUNCATE ON audit_anchors
  FOR EACH STATEMENT EXECUTE FUNCTION audit_anchors_immutable();

COMMIT;
