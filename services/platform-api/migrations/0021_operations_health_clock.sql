BEGIN;
ALTER TABLE operations_accounts ADD COLUMN health_observed_at timestamptz;
ALTER TABLE operations_accounts ADD CONSTRAINT operations_health_clock_finite
 CHECK(health_observed_at IS NULL OR isfinite(health_observed_at));
CREATE FUNCTION operations_health_clock_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.health_observed_at IS NOT NULL AND
    (NEW.health_observed_at IS NULL OR NEW.health_observed_at < OLD.health_observed_at) THEN
  RAISE EXCEPTION 'operations health clock cannot regress' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER operations_health_clock_guard BEFORE UPDATE ON operations_accounts
 FOR EACH ROW EXECUTE FUNCTION operations_health_clock_guard();
COMMIT;
