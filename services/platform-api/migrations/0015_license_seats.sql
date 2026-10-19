-- Named-user seats on seat-based licenses (ADR-025). Seats and device slots are different resources.
CREATE TABLE license_seats (
  org_id text NOT NULL,
  license_id text NOT NULL,
  user_id text NOT NULL REFERENCES users(id),
  assigned_by text NOT NULL,
  assigned_at timestamptz NOT NULL,
  PRIMARY KEY (license_id, user_id),
  FOREIGN KEY (license_id, org_id) REFERENCES licenses (id, org_id)
);
CREATE INDEX license_seats_org ON license_seats (org_id, license_id, assigned_at);
