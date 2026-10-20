BEGIN;
CREATE TABLE operations_alert_rules (
 id text PRIMARY KEY CHECK(id ~ '^opr_[a-f0-9]{24}$'),
 org_id text NOT NULL,
 application_id text NOT NULL,
 environment_id text NOT NULL,
 component_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('event_count','heartbeat')),
 event_type text CHECK(event_type IN ('upload.failed','conversion.failed','scanner.unavailable','malware.detected','email.delivery_failed')),
 threshold integer NOT NULL CHECK(threshold BETWEEN 1 AND 1000),
 window_seconds integer NOT NULL CHECK(window_seconds BETWEEN 60 AND 3600),
 severity text NOT NULL CHECK(severity IN ('informational','warning','critical')),
 runbook text NOT NULL CHECK(runbook IN ('investigate_component','check_scanner','check_converter','check_storage','check_email')),
 enabled boolean NOT NULL,
 maintenance_until timestamptz CHECK(isfinite(maintenance_until)),
 created_by_user_id text NOT NULL REFERENCES users(id),
 version integer NOT NULL CHECK(version>=1),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
 evaluated_at timestamptz CHECK(isfinite(evaluated_at)),
 bad_since timestamptz CHECK(isfinite(bad_since)),
 recovery_since timestamptz CHECK(isfinite(recovery_since)),
 incident_id text,
 observation text NOT NULL CHECK(observation IN ('unknown','healthy','breaching','inactive')),
 observed_count integer NOT NULL CHECK(observed_count BETWEEN 0 AND 1000),
 CHECK((kind='event_count' AND event_type IS NOT NULL) OR (kind='heartbeat' AND event_type IS NULL AND threshold=1)),
 UNIQUE(org_id,application_id,environment_id,component_id,id),
 FOREIGN KEY(org_id,application_id,environment_id,component_id) REFERENCES operations_components(org_id,application_id,environment_id,id)
);
ALTER TABLE operations_incidents DROP CONSTRAINT operations_incidents_source_check;
ALTER TABLE operations_incidents ADD COLUMN rule_id text;
ALTER TABLE operations_incidents ADD CHECK((source='manual_triage' AND rule_id IS NULL) OR (source='automatic_rule' AND rule_id IS NOT NULL));
ALTER TABLE operations_incidents ADD FOREIGN KEY(org_id,application_id,environment_id,component_id,rule_id) REFERENCES operations_alert_rules(org_id,application_id,environment_id,component_id,id);
DROP INDEX operations_incidents_active_idx;
CREATE UNIQUE INDEX operations_incidents_active_idx ON operations_incidents(org_id,application_id,environment_id,component_id,source) WHERE state<>'resolved' AND source='manual_triage';
CREATE UNIQUE INDEX operations_incidents_rule_active_idx ON operations_incidents(org_id,application_id,environment_id,component_id,rule_id) WHERE state<>'resolved' AND source='automatic_rule';
CREATE OR REPLACE FUNCTION operations_incident_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN
   IF NEW.version<>1 OR NEW.state<>'open' OR NEW.acknowledged_at IS NOT NULL OR NEW.resolved_at IS NOT NULL THEN
     RAISE EXCEPTION 'invalid incident creation' USING ERRCODE='23514';
   END IF;
 ELSE
   IF ROW(NEW.id,NEW.org_id,NEW.application_id,NEW.environment_id,NEW.component_id,NEW.source,NEW.rule_id,NEW.severity,NEW.created_by_user_id,NEW.created_at)
      IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.application_id,OLD.environment_id,OLD.component_id,OLD.source,OLD.rule_id,OLD.severity,OLD.created_by_user_id,OLD.created_at)
      OR OLD.state='resolved' OR NEW.version<>OLD.version+1 OR NEW.updated_at<OLD.updated_at
      OR (OLD.state='acknowledged' AND NEW.state='open')
      OR (OLD.acknowledged_at IS NOT NULL AND NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at) THEN
     RAISE EXCEPTION 'invalid incident transition' USING ERRCODE='23514';
   END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE UNIQUE INDEX operations_incidents_scope_id ON operations_incidents(org_id,application_id,environment_id,id);
CREATE TABLE operations_alert_notifications (
 id text PRIMARY KEY CHECK(id ~ '^opn_[a-f0-9]{24}$'),
 org_id text NOT NULL,
 application_id text NOT NULL,
 environment_id text NOT NULL,
 incident_id text NOT NULL,
 recipient_user_id text NOT NULL REFERENCES users(id),
 transition text NOT NULL CHECK(transition IN ('opened','resolved')),
 state text NOT NULL CHECK(state IN ('pending','claimed','delivered','failed')),
 attempts integer NOT NULL CHECK(attempts>=0),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 available_at timestamptz NOT NULL CHECK(isfinite(available_at)),
 deadline timestamptz NOT NULL CHECK(isfinite(deadline)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 claim_token text,
 lease_until timestamptz CHECK(isfinite(lease_until)),
 delivered_at timestamptz CHECK(isfinite(delivered_at)),
 CHECK((state='claimed')=(claim_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK((state='delivered')=(delivered_at IS NOT NULL)),
 CHECK(deadline=created_at+interval '72 hours' AND expires_at=created_at+interval '30 days'),
 UNIQUE(incident_id,recipient_user_id,transition),
 FOREIGN KEY(org_id,application_id,environment_id,incident_id) REFERENCES operations_incidents(org_id,application_id,environment_id,id),
 FOREIGN KEY(org_id,application_id,environment_id) REFERENCES operations_environments(org_id,application_id,id)
);
CREATE INDEX operations_alert_rules_scope_idx ON operations_alert_rules(org_id,application_id,environment_id,id);
CREATE INDEX operations_alert_notifications_scope_idx ON operations_alert_notifications(org_id,application_id,environment_id,created_at);
CREATE INDEX operations_alert_notifications_due_idx ON operations_alert_notifications(available_at) WHERE state IN ('pending','claimed');
CREATE INDEX operations_incidents_retention_idx ON operations_incidents(resolved_at) WHERE state='resolved';
CREATE FUNCTION operations_alert_rule_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (ROW(NEW.id,NEW.org_id,NEW.application_id,NEW.environment_id,NEW.component_id,NEW.kind,NEW.event_type,NEW.threshold,NEW.window_seconds,NEW.severity,NEW.runbook,NEW.created_by_user_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.application_id,OLD.environment_id,OLD.component_id,OLD.kind,OLD.event_type,OLD.threshold,OLD.window_seconds,OLD.severity,OLD.runbook,OLD.created_by_user_id,OLD.created_at) OR NEW.version<>OLD.version+1 OR NEW.updated_at<OLD.updated_at OR (OLD.evaluated_at IS NOT NULL AND (NEW.evaluated_at IS NULL OR NEW.evaluated_at<OLD.evaluated_at))) THEN RAISE EXCEPTION 'invalid rule transition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER operations_alert_rule_guard BEFORE UPDATE ON operations_alert_rules FOR EACH ROW EXECUTE FUNCTION operations_alert_rule_guard();
CREATE FUNCTION operations_incident_retention_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.state<>'resolved' OR OLD.resolved_at>clock_timestamp()-interval '365 days' THEN RAISE EXCEPTION 'incident retention protected' USING ERRCODE='23514'; END IF;
 RETURN OLD;
END; $$;
CREATE TRIGGER operations_incident_retention_guard BEFORE DELETE ON operations_incidents FOR EACH ROW EXECUTE FUNCTION operations_incident_retention_guard();
CREATE FUNCTION operations_notification_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.expires_at>clock_timestamp() THEN RAISE EXCEPTION 'notification retention protected' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.id,NEW.org_id,NEW.application_id,NEW.environment_id,NEW.incident_id,NEW.recipient_user_id,NEW.transition,NEW.created_at,NEW.deadline,NEW.expires_at) IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.application_id,OLD.environment_id,OLD.incident_id,OLD.recipient_user_id,OLD.transition,OLD.created_at,OLD.deadline,OLD.expires_at) OR OLD.state IN ('delivered','failed')
   OR (NEW.state='claimed' AND (NEW.attempts<>OLD.attempts+1 OR NEW.claim_token IS NOT DISTINCT FROM OLD.claim_token))
   OR (NEW.state<>'claimed' AND NEW.attempts<>OLD.attempts)
  THEN RAISE EXCEPTION 'invalid notification transition' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER operations_notification_guard BEFORE UPDATE OR DELETE ON operations_alert_notifications FOR EACH ROW EXECUTE FUNCTION operations_notification_guard();
COMMIT;
