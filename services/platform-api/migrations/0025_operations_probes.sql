-- Latest outside-in check made by Warrior itself (ADR-029 probe amendment). Kept apart from
-- backend heartbeats so a probe is never presented as the application's own report.
BEGIN;
CREATE TABLE operations_probe_results (
 org_id text NOT NULL, application_id text NOT NULL, environment_id text NOT NULL, component_id text NOT NULL,
 status text NOT NULL CHECK(status IN ('healthy','unavailable')),
 occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 CHECK(occurred_at<=received_at AND occurred_at>=received_at-interval '120 seconds'),
 CHECK(expires_at>received_at),
 PRIMARY KEY(org_id,application_id,environment_id,component_id),
 FOREIGN KEY(org_id,application_id,environment_id,component_id) REFERENCES operations_components(org_id,application_id,environment_id,id)
);
CREATE INDEX operations_probe_results_expiry_idx ON operations_probe_results(expires_at,org_id);
CREATE INDEX operations_probe_results_org_expiry_idx ON operations_probe_results(org_id,expires_at);
ALTER TABLE operations_alert_rules DROP CONSTRAINT operations_alert_rules_kind_check;
ALTER TABLE operations_alert_rules ADD CONSTRAINT operations_alert_rules_kind_check CHECK(kind IN ('event_count','heartbeat','probe'));
ALTER TABLE operations_alert_rules DROP CONSTRAINT operations_alert_rules_check;
ALTER TABLE operations_alert_rules ADD CONSTRAINT operations_alert_rules_check CHECK((kind='event_count' AND event_type IS NOT NULL) OR (kind IN ('heartbeat','probe') AND event_type IS NULL AND threshold=1));
COMMIT;
