BEGIN;
CREATE TABLE operations_incidents (
 id text PRIMARY KEY CHECK(id ~ '^opi_[a-f0-9]{24}$'),
 org_id text NOT NULL, application_id text NOT NULL, environment_id text NOT NULL, component_id text NOT NULL,
 source text NOT NULL CHECK(source='manual_triage'),
 severity text NOT NULL CHECK(severity IN ('informational','warning','critical')),
 state text NOT NULL CHECK(state IN ('open','acknowledged','resolved')),
 assignee_user_id text REFERENCES users(id), created_by_user_id text NOT NULL REFERENCES users(id),
 version integer NOT NULL CHECK(version>=1),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
 acknowledged_at timestamptz CHECK(isfinite(acknowledged_at) AND acknowledged_at>=created_at AND acknowledged_at<=updated_at),
 resolved_at timestamptz CHECK(isfinite(resolved_at) AND resolved_at>=created_at AND resolved_at<=updated_at),
 CHECK((state='resolved')=(resolved_at IS NOT NULL)),
 CHECK(state<>'acknowledged' OR acknowledged_at IS NOT NULL),
 CHECK(state<>'open' OR acknowledged_at IS NULL),
 FOREIGN KEY(org_id,application_id,environment_id,component_id) REFERENCES operations_components(org_id,application_id,environment_id,id)
);
CREATE UNIQUE INDEX operations_incidents_active_idx ON operations_incidents(org_id,application_id,environment_id,component_id,source) WHERE state<>'resolved';
CREATE INDEX operations_incidents_scope_idx ON operations_incidents(org_id,application_id,environment_id,id);
CREATE FUNCTION operations_incident_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
   IF NEW.version<>1 OR NEW.state<>'open' OR NEW.acknowledged_at IS NOT NULL OR NEW.resolved_at IS NOT NULL THEN
     RAISE EXCEPTION 'invalid incident creation' USING ERRCODE='23514';
   END IF;
 ELSE
   IF ROW(NEW.id,NEW.org_id,NEW.application_id,NEW.environment_id,NEW.component_id,NEW.source,NEW.severity,NEW.created_by_user_id,NEW.created_at)
      IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.application_id,OLD.environment_id,OLD.component_id,OLD.source,OLD.severity,OLD.created_by_user_id,OLD.created_at)
      OR OLD.state='resolved' OR NEW.version<>OLD.version+1 OR NEW.updated_at<OLD.updated_at
      OR (OLD.state='acknowledged' AND NEW.state='open')
      OR (OLD.acknowledged_at IS NOT NULL AND NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at) THEN
     RAISE EXCEPTION 'invalid incident transition' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER operations_incident_guard BEFORE INSERT OR UPDATE ON operations_incidents FOR EACH ROW EXECUTE FUNCTION operations_incident_guard();
COMMIT;
