-- Durable event identities, quotas and aggregate retention. No commercial state changes.
BEGIN;
CREATE UNIQUE INDEX operations_components_scope_id ON operations_components(org_id,application_id,environment_id,id);
CREATE UNIQUE INDEX operations_credentials_scope_id ON operations_credentials(org_id,application_id,environment_id,id);
CREATE TABLE operations_events (
  org_id text NOT NULL,
  application_id text NOT NULL,
  environment_id text NOT NULL,
  id text NOT NULL CHECK(id ~ '^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$'),
  component_id text NOT NULL,
  credential_id text NOT NULL,
  source text NOT NULL CHECK(source='backend_report'),
  type text NOT NULL,
  attributes jsonb NOT NULL CHECK(jsonb_typeof(attributes)='object'),
  occurred_at text NOT NULL,
  received_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
  size_bytes integer NOT NULL CHECK(size_bytes>=512 AND size_bytes<=262656),
  PRIMARY KEY(org_id,application_id,environment_id,id),
  FOREIGN KEY(org_id,application_id,environment_id,component_id) REFERENCES operations_components(org_id,application_id,environment_id,id),
  FOREIGN KEY(org_id,application_id,environment_id,credential_id) REFERENCES operations_credentials(org_id,application_id,environment_id,id)
);
CREATE INDEX operations_events_expiry_idx ON operations_events(expires_at,org_id);
CREATE INDEX operations_events_scope_expiry_idx ON operations_events(org_id,expires_at,id);
CREATE INDEX operations_events_component_time_idx ON operations_events(org_id,application_id,environment_id,component_id,received_at);
CREATE TABLE operations_event_counters (
  org_id text NOT NULL REFERENCES organizations(id),
  key text NOT NULL,
  count bigint NOT NULL CHECK(count>=0),
  bytes bigint NOT NULL CHECK(bytes>=0),
  request_times bigint[] NOT NULL DEFAULT '{}' CHECK(cardinality(request_times)<=60),
  expires_at timestamptz,
  PRIMARY KEY(org_id,key)
);
CREATE INDEX operations_event_counters_expiry_idx ON operations_event_counters(expires_at,org_id) WHERE expires_at IS NOT NULL;
CREATE INDEX operations_event_counters_org_expiry_idx ON operations_event_counters(org_id,expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE operations_event_aggregates (
  outcome text NOT NULL CHECK(length(outcome)<=64),
  org_id text NOT NULL,
  application_id text NOT NULL,
  environment_id text NOT NULL,
  component_id text NOT NULL,
  type text NOT NULL,
  hour timestamptz NOT NULL,
  count bigint NOT NULL CHECK(count>0),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY(org_id,application_id,environment_id,component_id,type,hour,outcome),
  FOREIGN KEY(org_id,application_id,environment_id,component_id) REFERENCES operations_components(org_id,application_id,environment_id,id)
);
CREATE INDEX operations_event_aggregates_expiry_idx ON operations_event_aggregates(expires_at,org_id);
CREATE INDEX operations_event_aggregates_org_expiry_idx ON operations_event_aggregates(org_id,expires_at);
COMMIT;
