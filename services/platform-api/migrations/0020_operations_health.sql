-- Latest eligible backend assertion. Historical events never imply current health.
BEGIN;
CREATE TABLE operations_heartbeats (
 org_id text NOT NULL, application_id text NOT NULL, environment_id text NOT NULL, component_id text NOT NULL,
 status text NOT NULL CHECK(status IN ('healthy','unknown','degraded','unavailable')),
 occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 CHECK(occurred_at<=received_at AND occurred_at>=received_at-interval '120 seconds'),
 CHECK(expires_at>received_at),
 PRIMARY KEY(org_id,application_id,environment_id,component_id),
 FOREIGN KEY(org_id,application_id,environment_id,component_id) REFERENCES operations_components(org_id,application_id,environment_id,id)
);
CREATE INDEX operations_heartbeats_expiry_idx ON operations_heartbeats(expires_at,org_id);
CREATE INDEX operations_heartbeats_org_expiry_idx ON operations_heartbeats(org_id,expires_at);
CREATE INDEX operations_event_aggregates_history_idx ON operations_event_aggregates(org_id,application_id,environment_id,component_id,hour,type,outcome);
COMMIT;
