-- Device trust (ADR-026): server-observed signals with a retention bound, and the derived posture per device.
CREATE TABLE device_signals (
  id text PRIMARY KEY,
  org_id text NOT NULL,
  device_id text NOT NULL,
  kind text NOT NULL CHECK (kind IN
    ('installation_switch','installation_mismatch','invalid_device_proof','step_up_completed')),
  provenance text NOT NULL CHECK (provenance = 'server_observed'),
  observed_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > observed_at),
  attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
  FOREIGN KEY (device_id, org_id) REFERENCES devices (id, org_id)
);
CREATE INDEX device_signals_device ON device_signals (org_id, device_id, observed_at);
CREATE INDEX device_signals_expiry ON device_signals (expires_at);

CREATE TABLE device_posture (
  device_id text PRIMARY KEY,
  org_id text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('ALLOW','OBSERVE','STEP_UP_AUTH','RESTRICT','SUSPEND','DENY')),
  reasons jsonb NOT NULL,
  review_at timestamptz,
  updated_at timestamptz NOT NULL,
  FOREIGN KEY (device_id, org_id) REFERENCES devices (id, org_id)
);
