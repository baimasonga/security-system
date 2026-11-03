BEGIN;
ALTER TABLE update_reservations ADD CONSTRAINT update_reservation_publication_binding
 UNIQUE(product_id,request_id,platform,channel,sequence);
CREATE TABLE update_publications (
 product_id text NOT NULL,
 request_id uuid NOT NULL,
 platform text NOT NULL,
 channel text NOT NULL,
 sequence bigint NOT NULL,
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 envelope jsonb NOT NULL CHECK(jsonb_typeof(envelope)='object'),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object'),
 published_at timestamptz NOT NULL CHECK(isfinite(published_at) AND published_at>=created_at),
 PRIMARY KEY(product_id,request_id),
 UNIQUE(product_id,platform,channel,sequence),
 FOREIGN KEY(product_id,request_id,platform,channel,sequence)
  REFERENCES update_reservations(product_id,request_id,platform,channel,sequence)
);
CREATE TRIGGER update_publication_immutable BEFORE UPDATE OR DELETE ON update_publications
FOR EACH ROW EXECUTE FUNCTION update_reservation_immutable();
COMMIT;
