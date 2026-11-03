BEGIN;
CREATE TABLE update_registries (
 product_id text PRIMARY KEY REFERENCES products(id),
 product_code text NOT NULL UNIQUE,
 root jsonb NOT NULL CHECK(jsonb_typeof(root)='object'),
 targets jsonb NOT NULL CHECK(jsonb_typeof(targets)='array' AND jsonb_array_length(targets)<=32),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at)
);
CREATE TABLE update_reservations (
 product_id text NOT NULL REFERENCES update_registries(product_id),
 request_id uuid NOT NULL,
 platform text NOT NULL CHECK(platform ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 channel text NOT NULL CHECK(channel ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 sequence bigint NOT NULL CHECK(sequence BETWEEN 1 AND 9007199254740991),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 PRIMARY KEY(product_id,request_id),
 UNIQUE(product_id,platform,channel,sequence)
);
CREATE FUNCTION update_reservation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'update reservation immutable' USING ERRCODE='23514'; END; $$;
CREATE TRIGGER update_reservation_immutable BEFORE UPDATE OR DELETE ON update_reservations
FOR EACH ROW EXECUTE FUNCTION update_reservation_immutable();
CREATE FUNCTION update_registry_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE t jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'update registry retained' USING ERRCODE='23514'; END IF;
 FOR t IN SELECT value FROM jsonb_array_elements(NEW.targets) LOOP
  IF jsonb_typeof(t)<>'object' OR NOT(t ?& ARRAY['platform','channel','reservedSequence'])
     OR (SELECT count(*) FROM jsonb_object_keys(t))<>3
     OR jsonb_typeof(t->'platform')<>'string' OR jsonb_typeof(t->'channel')<>'string'
     OR (t->>'platform') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'
     OR (t->>'channel') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'
     OR jsonb_typeof(t->'reservedSequence')<>'number'
  THEN RAISE EXCEPTION 'invalid update target' USING ERRCODE='23514'; END IF;
  IF (t->>'reservedSequence')::numeric<0 OR (t->>'reservedSequence')::numeric>9007199254740991
     OR trunc((t->>'reservedSequence')::numeric)<>(t->>'reservedSequence')::numeric
  THEN RAISE EXCEPTION 'invalid update sequence' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.targets) AS entry(value) GROUP BY entry.value->>'platform',entry.value->>'channel' HAVING count(*)>1)
 THEN RAISE EXCEPTION 'duplicate update target' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.product_id<>OLD.product_id OR NEW.product_code<>OLD.product_code OR NEW.root<>OLD.root OR NEW.created_at<>OLD.created_at OR NEW.updated_at<OLD.updated_at
  THEN RAISE EXCEPTION 'update registry identity immutable' USING ERRCODE='23514'; END IF;
  FOR t IN SELECT value FROM jsonb_array_elements(OLD.targets) LOOP
   IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.targets) n WHERE n->>'platform'=t->>'platform'
     AND n->>'channel'=t->>'channel' AND (n->>'reservedSequence')::numeric>=(t->>'reservedSequence')::numeric)
   THEN RAISE EXCEPTION 'update sequence rollback' USING ERRCODE='23514'; END IF;
  END LOOP;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER update_registry_identity_guard BEFORE INSERT OR UPDATE OR DELETE ON update_registries
FOR EACH ROW EXECUTE FUNCTION update_registry_identity_guard();
COMMIT;
